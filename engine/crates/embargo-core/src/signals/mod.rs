//! Signal extraction — pure detection over a version artifact and its predecessor.
//!
//! Per `docs/SIGNALS.md`: detectors take `(current, prior)` and return weighted
//! findings, never verdicts. No I/O happens here — fetching/parsing tarballs is
//! the engine I/O layer's job. The verdict (HOLD/DENY) is decided downstream by
//! policy thresholds in `scoring.rs`.

use crate::types::{Severity, Signal, SignalType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod binding_gyp;
pub mod capability_dep;
pub mod chains;
pub mod lifecycle_script;
pub mod maintainer;
pub mod obfuscation;
pub mod republish;
pub mod tarball_mismatch;
pub mod typosquat;

/// Default starting weights (0–100). Tune against real traffic; see SIGNALS.md.
pub mod weights {
    pub const NEW_LIFECYCLE_SCRIPT: u32 = 60;
    pub const BINDING_GYP: u32 = 55;
    pub const CAPABILITY_DEP: u32 = 35;
    pub const TARBALL_MISMATCH: u32 = 65;
    pub const OBFUSCATION: u32 = 40;
    pub const REPUBLISH: u32 = 60;
    pub const MAINTAINER_CHANGE: u32 = 30;
    pub const TYPOSQUAT: u32 = 50;
    // Composite chains score higher than any single constituent.
    pub const STEALER_CHAIN: u32 = 95;
    pub const OUT_OF_PIPELINE_CHAIN: u32 = 90;
    pub const NATIVE_EXEC_CHAIN: u32 = 85;
    pub const LOOKALIKE_DROPPER_CHAIN: u32 = 92;
}

/// A parsed package version, normalized from the tarball + registry metadata.
/// The I/O layer builds this; detectors only read it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionArtifact {
    pub package: String,
    pub version: String,
    pub manifest: Manifest,
    /// Files present in the published tarball (path + size).
    pub files: Vec<FileEntry>,
    /// Resolved source text of lifecycle scripts and any local files they invoke.
    /// Keyed by script name (e.g. "postinstall") or file path.
    pub script_sources: BTreeMap<String, String>,
    pub publisher: Publisher,
    /// Repository URL declared in package.json.
    pub claimed_repo: Option<String>,
    /// Repository URL from a verified build-provenance attestation, if any.
    pub provenance_repo: Option<String>,
    /// Whether a build-provenance attestation verified for this version.
    pub provenance_verified: bool,
    /// Versions published by the same token in the trailing hour (worm signal).
    pub republish_burst: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// All npm scripts; lifecycle keys (preinstall/install/postinstall) are the risky ones.
    pub scripts: BTreeMap<String, String>,
    pub dependencies: BTreeMap<String, String>,
    pub repository: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Publisher {
    /// npm username that published this version.
    pub npm_user: String,
    /// Maintainer set recorded for this version.
    pub maintainers: Vec<String>,
}

/// The install-time lifecycle script names. These run code on `npm install`.
pub const LIFECYCLE_KEYS: &[&str] = &["preinstall", "install", "postinstall"];

/// Run all detectors over `(current, prior)` and append any composite chains.
/// `prior` is the immediately-preceding published version, when known.
pub fn extract_signals(current: &VersionArtifact, prior: Option<&VersionArtifact>) -> Vec<Signal> {
    let mut signals = Vec::new();

    signals.extend(lifecycle_script::detect(current, prior));
    signals.extend(binding_gyp::detect(current, prior));
    signals.extend(capability_dep::detect(current, prior));
    signals.extend(tarball_mismatch::detect(current));
    signals.extend(obfuscation::detect(current));
    signals.extend(republish::detect(current));
    signals.extend(maintainer::detect(current, prior));
    signals.extend(typosquat::detect(current));

    // Composite chains compose the single findings above into intent.
    let chain_signals = chains::detect(current, &signals);
    signals.extend(chain_signals);

    signals
}

/// Construct a finding. `detected_at` is set to now — detectors stay otherwise pure.
pub(crate) fn finding(
    signal_type: SignalType,
    severity: Severity,
    weight: u32,
    evidence: serde_json::Value,
) -> Signal {
    Signal {
        id: Uuid::new_v4(),
        signal_type,
        severity,
        weight,
        evidence,
        detected_at: chrono::Utc::now(),
    }
}

/// Helper: concatenate all install-lifecycle script sources for scanning.
pub(crate) fn install_script_text(artifact: &VersionArtifact) -> String {
    let mut buf = String::new();
    for key in LIFECYCLE_KEYS {
        if let Some(cmd) = artifact.manifest.scripts.get(*key) {
            buf.push_str(cmd);
            buf.push('\n');
        }
        if let Some(src) = artifact.script_sources.get(*key) {
            buf.push_str(src);
            buf.push('\n');
        }
    }
    buf
}
