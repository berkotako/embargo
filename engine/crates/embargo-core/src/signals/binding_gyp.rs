//! `binding_gyp_introduced` — a `binding.gyp` file appeared in the tarball.
//! It is an install-time native-compilation/exec vector that survives
//! `--ignore-scripts` disabling of lifecycle scripts.

use super::{finding, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};

fn has_binding_gyp(artifact: &VersionArtifact) -> bool {
    artifact.files.iter().any(|f| {
        let name = f.path.rsplit('/').next().unwrap_or(&f.path);
        name == "binding.gyp"
    })
}

pub fn detect(current: &VersionArtifact, prior: Option<&VersionArtifact>) -> Vec<Signal> {
    if !has_binding_gyp(current) {
        return vec![];
    }
    // Only a *newly introduced* binding.gyp is suspicious; a native addon that
    // always shipped one is expected.
    let prior_had = prior.map(has_binding_gyp).unwrap_or(false);
    if prior_had {
        return vec![];
    }

    vec![finding(
        SignalType::BindingGyp,
        Severity::High,
        weights::BINDING_GYP,
        serde_json::json!({
            "file": "binding.gyp",
            "previously_present": false,
        }),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::FileEntry;

    fn artifact_with_files(paths: &[&str]) -> VersionArtifact {
        VersionArtifact {
            files: paths
                .iter()
                .map(|p| FileEntry {
                    path: (*p).to_string(),
                    size: 100,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn benign_no_binding_gyp() {
        let current = artifact_with_files(&["index.js", "package.json", "lib/util.js"]);
        assert!(detect(&current, None).is_empty());
    }

    #[test]
    fn benign_native_addon_always_had_binding_gyp() {
        let current = artifact_with_files(&["binding.gyp", "src/addon.cc"]);
        let prior = artifact_with_files(&["binding.gyp", "src/addon.cc"]);
        assert!(detect(&current, Some(&prior)).is_empty());
    }

    #[test]
    fn malicious_binding_gyp_introduced() {
        let current = artifact_with_files(&["index.js", "binding.gyp", "build.cc"]);
        let prior = artifact_with_files(&["index.js"]);
        let signals = detect(&current, Some(&prior));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::BindingGyp);
    }

    #[test]
    fn nested_binding_gyp_detected() {
        let current = artifact_with_files(&["index.js", "deps/native/binding.gyp"]);
        let signals = detect(&current, None);
        assert_eq!(signals.len(), 1);
    }
}
