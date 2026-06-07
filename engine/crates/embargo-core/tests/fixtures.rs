//! Integration test: load the on-disk fixture packages into `VersionArtifact`s
//! and assert the signal pipeline produces the right findings. Runs against the
//! pure core (no database). See `engine/fixtures/README.md`.

use embargo_core::signals::{
    extract_signals, FileEntry, Manifest, Publisher, VersionArtifact, LIFECYCLE_KEYS,
};
use embargo_core::types::SignalType;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// Load a fixture package directory into a `VersionArtifact`.
fn load_artifact(dir: &Path) -> VersionArtifact {
    let pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("package.json")).unwrap()).unwrap();

    // scripts + dependencies
    let mut scripts = BTreeMap::new();
    if let Some(obj) = pkg.get("scripts").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            scripts.insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }
    let mut dependencies = BTreeMap::new();
    if let Some(obj) = pkg.get("dependencies").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            dependencies.insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }

    // repository: string or { url }
    let claimed_repo = match pkg.get("repository") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Object(o)) => {
            o.get("url").and_then(|v| v.as_str()).map(String::from)
        }
        _ => None,
    };

    // file list (recursive walk), skipping the metadata sidecar
    let mut files = Vec::new();
    walk(dir, dir, &mut files);

    // resolve install-script source files (e.g. `node scripts/setup.js`)
    let mut script_sources = BTreeMap::new();
    for key in LIFECYCLE_KEYS {
        if let Some(cmd) = scripts.get(*key) {
            let mut combined = String::new();
            for token in cmd.split_whitespace() {
                if token.ends_with(".js") || token.ends_with(".cjs") || token.ends_with(".mjs") {
                    let p = dir.join(token);
                    if let Ok(src) = std::fs::read_to_string(&p) {
                        combined.push_str(&src);
                        combined.push('\n');
                    }
                }
            }
            if !combined.is_empty() {
                script_sources.insert((*key).to_string(), combined);
            }
        }
    }

    // optional sidecar with out-of-band metadata
    let mut provenance_repo = None;
    let mut provenance_verified = false;
    let mut republish_burst = 0u32;
    let mut publisher = Publisher::default();
    let sidecar_path = dir.join("embargo-fixture.json");
    if let Ok(text) = std::fs::read_to_string(&sidecar_path) {
        let s: serde_json::Value = serde_json::from_str(&text).unwrap();
        provenance_repo = s
            .get("provenance_repo")
            .and_then(|v| v.as_str())
            .map(String::from);
        provenance_verified = s
            .get("provenance_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        republish_burst = s
            .get("republish_burst")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        if let Some(p) = s.get("publisher") {
            publisher.npm_user = p
                .get("npm_user")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(arr) = p.get("maintainers").and_then(|v| v.as_array()) {
                publisher.maintainers = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
        }
    }

    VersionArtifact {
        package: pkg
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        version: pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        manifest: Manifest {
            scripts,
            dependencies,
            repository: claimed_repo.clone(),
        },
        files,
        script_sources,
        publisher,
        claimed_repo,
        provenance_repo,
        provenance_verified,
        republish_burst,
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<FileEntry>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
        } else {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "embargo-fixture.json" {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push(FileEntry { path: rel, size });
        }
    }
}

fn has_type(signals: &[embargo_core::types::Signal], ty: &SignalType) -> bool {
    signals.iter().any(|s| &s.signal_type == ty)
}

fn has_chain(signals: &[embargo_core::types::Signal], name: &str) -> bool {
    signals
        .iter()
        .any(|s| matches!(&s.signal_type, SignalType::Other { name: n } if n == name))
}

fn load_pair(
    scenario: &str,
) -> (
    VersionArtifact,
    Option<VersionArtifact>,
    VersionArtifact,
    Option<VersionArtifact>,
) {
    let root = fixtures_root().join(scenario);
    let benign = load_artifact(&root.join("benign"));
    let benign_prior = root
        .join("benign_prior")
        .is_dir()
        .then(|| load_artifact(&root.join("benign_prior")));
    let malicious = load_artifact(&root.join("malicious"));
    let malicious_prior = root
        .join("malicious_prior")
        .is_dir()
        .then(|| load_artifact(&root.join("malicious_prior")));
    (benign, benign_prior, malicious, malicious_prior)
}

#[test]
fn stealer_chain_fixture() {
    let (benign, benign_prior, malicious, malicious_prior) = load_pair("stealer_chain");

    let bad = extract_signals(&malicious, malicious_prior.as_ref());
    assert!(
        has_type(&bad, &SignalType::NewLifecycleScript),
        "expected lifecycle signal: {bad:?}"
    );
    assert!(
        has_type(&bad, &SignalType::CapabilityDep),
        "expected capability signal: {bad:?}"
    );
    assert!(
        has_chain(&bad, "stealer_chain"),
        "expected stealer_chain: {bad:?}"
    );

    let good = extract_signals(&benign, benign_prior.as_ref());
    assert!(
        good.is_empty(),
        "benign should produce no signals: {good:?}"
    );
}

#[test]
fn binding_gyp_fixture() {
    let (benign, benign_prior, malicious, malicious_prior) = load_pair("binding_gyp");

    let bad = extract_signals(&malicious, malicious_prior.as_ref());
    assert!(
        has_type(&bad, &SignalType::BindingGyp),
        "expected binding.gyp signal: {bad:?}"
    );

    // Benign native addon shipped binding.gyp in both versions → not "introduced".
    let good = extract_signals(&benign, benign_prior.as_ref());
    assert!(
        !has_type(&good, &SignalType::BindingGyp),
        "benign addon should not fire: {good:?}"
    );
}

#[test]
fn tarball_mismatch_fixture() {
    let (benign, benign_prior, malicious, malicious_prior) = load_pair("tarball_mismatch");

    let bad = extract_signals(&malicious, malicious_prior.as_ref());
    assert!(
        has_type(&bad, &SignalType::TarballMismatch),
        "expected mismatch signal: {bad:?}"
    );
    assert!(
        has_chain(&bad, "out_of_pipeline_chain"),
        "expected out_of_pipeline_chain: {bad:?}"
    );

    let good = extract_signals(&benign, benign_prior.as_ref());
    assert!(
        !has_type(&good, &SignalType::TarballMismatch),
        "benign should not fire: {good:?}"
    );
    assert!(
        !has_chain(&good, "out_of_pipeline_chain"),
        "benign should not chain: {good:?}"
    );
}
