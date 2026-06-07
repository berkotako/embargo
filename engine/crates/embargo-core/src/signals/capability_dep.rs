//! `new_capability_dep` — a newly added dependency, or an install script, that
//! touches a sensitive capability: network, filesystem, or `child_process`.
//! Benign in isolation; load-bearing inside the stealer chain.

use super::{finding, install_script_text, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};
use serde::Serialize;

/// Capability markers we scan install-script source text for.
const NETWORK_MARKERS: &[&str] = &[
    "require('http')",
    "require(\"http\")",
    "require('https')",
    "require(\"https\")",
    "require('net')",
    "require(\"net\")",
    "require('dns')",
    "require(\"dns\")",
    "fetch(",
    "XMLHttpRequest",
    "http.request",
    "https.request",
];
const PROCESS_MARKERS: &[&str] = &[
    "require('child_process')",
    "require(\"child_process\")",
    "child_process",
    "execSync",
    "spawnSync",
    "spawn(",
    "exec(",
];
const FS_SECRET_MARKERS: &[&str] = &[
    "process.env",
    ".npmrc",
    ".aws/credentials",
    "id_rsa",
    "readFileSync",
    "/etc/passwd",
    "ssh/",
];

/// Capability flags found in this artifact. Re-used by the chain detector.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct Capabilities {
    pub network: bool,
    pub process: bool,
    pub secret_read: bool,
}

impl Capabilities {
    pub fn any(&self) -> bool {
        self.network || self.process || self.secret_read
    }
}

/// Scan an artifact's install scripts for capability markers (pure).
pub fn capabilities(artifact: &VersionArtifact) -> Capabilities {
    let text = install_script_text(artifact);
    Capabilities {
        network: NETWORK_MARKERS.iter().any(|m| text.contains(m)),
        process: PROCESS_MARKERS.iter().any(|m| text.contains(m)),
        secret_read: FS_SECRET_MARKERS.iter().any(|m| text.contains(m)),
    }
}

/// Dependencies added versus the prior version.
fn added_deps(current: &VersionArtifact, prior: Option<&VersionArtifact>) -> Vec<String> {
    current
        .manifest
        .dependencies
        .keys()
        .filter(|name| {
            prior
                .map(|p| !p.manifest.dependencies.contains_key(*name))
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

pub fn detect(current: &VersionArtifact, prior: Option<&VersionArtifact>) -> Vec<Signal> {
    let caps = capabilities(current);
    let new_deps = added_deps(current, prior);

    // Fire only when an install script exercises a sensitive capability.
    // A new dependency alone is not enough — that is normal churn.
    if !caps.any() {
        return vec![];
    }

    vec![finding(
        SignalType::CapabilityDep,
        Severity::Medium,
        weights::CAPABILITY_DEP,
        serde_json::json!({
            "network": caps.network,
            "process": caps.process,
            "secret_read": caps.secret_read,
            "new_dependencies": new_deps,
        }),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::Manifest;
    use std::collections::BTreeMap;

    fn artifact(scripts: &[(&str, &str)], deps: &[&str]) -> VersionArtifact {
        let mut smap = BTreeMap::new();
        for (k, v) in scripts {
            smap.insert((*k).to_string(), (*v).to_string());
        }
        let mut dmap = BTreeMap::new();
        for d in deps {
            dmap.insert((*d).to_string(), "1.0.0".to_string());
        }
        VersionArtifact {
            manifest: Manifest {
                scripts: smap,
                dependencies: dmap,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn benign_build_script_no_capability() {
        let current = artifact(&[("postinstall", "node-gyp rebuild")], &["node-gyp"]);
        assert!(detect(&current, None).is_empty());
    }

    #[test]
    fn benign_new_dep_without_capability_use() {
        let current = artifact(&[("build", "tsc")], &["typescript", "left-pad"]);
        let prior = artifact(&[("build", "tsc")], &[]);
        assert!(detect(&current, Some(&prior)).is_empty());
    }

    #[test]
    fn malicious_postinstall_reads_env_and_phones_home() {
        let current = artifact(
            &[(
                "postinstall",
                "node -e \"require('https').request(process.env.NPM_TOKEN)\"",
            )],
            &[],
        );
        let signals = detect(&current, None);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::CapabilityDep);
    }

    #[test]
    fn capabilities_flags_set_correctly() {
        let current = artifact(
            &[(
                "postinstall",
                "require('child_process').execSync(process.env.X)",
            )],
            &[],
        );
        let caps = capabilities(&current);
        assert!(caps.process);
        assert!(caps.secret_read);
        assert!(!caps.network);
    }
}
