//! Composite chains — emit a high-weight finding when constituent signals
//! co-occur. A single sensitive API has no intent; the chain does.
//! See `docs/SIGNALS.md` § Composite chains.

use super::capability_dep::capabilities;
use super::{finding, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};

fn has(signals: &[Signal], ty: &SignalType) -> bool {
    signals.iter().any(|s| &s.signal_type == ty)
}

/// Detect chains given the artifact and the single-signal findings already produced.
pub fn detect(current: &VersionArtifact, singles: &[Signal]) -> Vec<Signal> {
    let mut out = Vec::new();
    let caps = capabilities(current);

    // --- Stealer chain ---------------------------------------------------
    // network/secret capability in an install script + a new lifecycle script.
    // Mirrors the Shai-Hulud / Miasma steal-and-exfil pattern.
    let stealer = has(singles, &SignalType::NewLifecycleScript)
        && has(singles, &SignalType::CapabilityDep)
        && (caps.network && caps.secret_read);
    if stealer {
        out.push(finding(
            SignalType::Other {
                name: "stealer_chain".into(),
            },
            Severity::Critical,
            weights::STEALER_CHAIN,
            serde_json::json!({
                "chain": "stealer",
                "constituents": ["new_lifecycle_script", "capability_dep"],
                "capabilities": { "network": caps.network, "secret_read": caps.secret_read },
            }),
        ));
    }

    // --- Out-of-pipeline poison ------------------------------------------
    // provenance missing + tarball/repo mismatch. Orphan-commit review-bypass.
    let out_of_pipeline =
        !current.provenance_verified && has(singles, &SignalType::TarballMismatch);
    if out_of_pipeline {
        out.push(finding(
            SignalType::Other {
                name: "out_of_pipeline_chain".into(),
            },
            Severity::Critical,
            weights::OUT_OF_PIPELINE_CHAIN,
            serde_json::json!({
                "chain": "out_of_pipeline",
                "constituents": ["provenance_missing", "tarball_repo_mismatch"],
            }),
        ));
    }

    // --- Native-exec smuggling -------------------------------------------
    // binding.gyp introduced + obfuscation markers.
    let native_exec =
        has(singles, &SignalType::BindingGyp) && has(singles, &SignalType::Obfuscation);
    if native_exec {
        out.push(finding(
            SignalType::Other {
                name: "native_exec_chain".into(),
            },
            Severity::Critical,
            weights::NATIVE_EXEC_CHAIN,
            serde_json::json!({
                "chain": "native_exec_smuggling",
                "constituents": ["binding_gyp_introduced", "obfuscation_markers"],
            }),
        ));
    }

    // --- Lookalike dropper -----------------------------------------------
    // A typosquatted name that also runs code at install time. Name resemblance
    // is suspicious; resemblance + install-time execution is a dropper.
    let install_exec = super::LIFECYCLE_KEYS.iter().any(|k| {
        current
            .manifest
            .scripts
            .get(*k)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    });
    if has(singles, &SignalType::Typosquat) && install_exec {
        out.push(finding(
            SignalType::Other {
                name: "lookalike_dropper".into(),
            },
            Severity::Critical,
            weights::LOOKALIKE_DROPPER_CHAIN,
            serde_json::json!({
                "chain": "lookalike_dropper",
                "constituents": ["typosquat", "install_lifecycle_script"],
            }),
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::{extract_signals, FileEntry, Manifest, VersionArtifact};
    use std::collections::BTreeMap;

    fn manifest(scripts: &[(&str, &str)]) -> Manifest {
        let mut m = BTreeMap::new();
        for (k, v) in scripts {
            m.insert((*k).to_string(), (*v).to_string());
        }
        Manifest {
            scripts: m,
            ..Default::default()
        }
    }

    #[test]
    fn stealer_chain_fires_on_full_pattern() {
        // postinstall added that reads env + phones home.
        let current = VersionArtifact {
            manifest: manifest(&[(
                "postinstall",
                "node -e \"require('https').request(process.env.NPM_TOKEN)\"",
            )]),
            ..Default::default()
        };
        let prior = VersionArtifact {
            manifest: manifest(&[("build", "tsc")]),
            ..Default::default()
        };

        let signals = extract_signals(&current, Some(&prior));
        assert!(
            signals.iter().any(
                |s| matches!(&s.signal_type, SignalType::Other { name } if name == "stealer_chain")
            ),
            "expected stealer_chain in {signals:?}"
        );
    }

    #[test]
    fn benign_native_addon_no_chain() {
        // Legitimate native module: binding.gyp present in both, readable build.
        let current = VersionArtifact {
            manifest: manifest(&[("install", "node-gyp rebuild")]),
            files: vec![FileEntry {
                path: "binding.gyp".into(),
                size: 100,
            }],
            ..Default::default()
        };
        let prior = VersionArtifact {
            manifest: manifest(&[("install", "node-gyp rebuild")]),
            files: vec![FileEntry {
                path: "binding.gyp".into(),
                size: 100,
            }],
            ..Default::default()
        };
        let signals = extract_signals(&current, Some(&prior));
        assert!(
            !signals.iter().any(
                |s| matches!(&s.signal_type, SignalType::Other { name } if name.ends_with("_chain"))
            ),
            "benign native addon should emit no chain: {signals:?}"
        );
    }

    #[test]
    fn out_of_pipeline_chain_fires() {
        let current = VersionArtifact {
            claimed_repo: Some("https://github.com/acme/widget".into()),
            provenance_repo: Some("https://github.com/attacker/fork".into()),
            provenance_verified: false,
            ..Default::default()
        };
        let signals = extract_signals(&current, None);
        assert!(
            signals.iter().any(|s| matches!(&s.signal_type, SignalType::Other { name } if name == "out_of_pipeline_chain")),
        );
    }

    #[test]
    fn native_exec_chain_fires() {
        let blob = "A".repeat(400);
        let current = VersionArtifact {
            manifest: manifest(&[("install", &format!("eval(Buffer.from('{blob}','base64'))"))]),
            files: vec![FileEntry {
                path: "binding.gyp".into(),
                size: 100,
            }],
            ..Default::default()
        };
        // No prior → binding.gyp counts as introduced.
        let signals = extract_signals(&current, None);
        assert!(
            signals.iter().any(|s| matches!(&s.signal_type, SignalType::Other { name } if name == "native_exec_chain")),
            "expected native_exec_chain in {signals:?}"
        );
    }
}
