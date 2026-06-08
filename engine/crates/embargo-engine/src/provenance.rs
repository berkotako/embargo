//! npm provenance verification.
//!
//! npm's attestations endpoint returns a list of attestations, each a Sigstore
//! bundle wrapping an in-toto Statement whose predicate is SLSA build
//! provenance. We decode the DSSE payload, pull out the source repository and
//! build workflow, and decide a `Provenance` verdict.
//!
//! Scope note: this performs **structural** verification — the attestation is
//! present, is SLSA provenance, and names a source repo. Full cryptographic
//! verification of the Sigstore signature (Fulcio cert chain + Rekor inclusion)
//! is a tracked hardening follow-up; `verify()` is the single seam where it
//! slots in. Until then we never report `Verified` for a missing or
//! structurally-broken attestation, so the gate fails safe.

use base64::Engine as _;
use embargo_core::types::Provenance;

/// What we extract from a provenance attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceInfo {
    pub source_repo: Option<String>,
    pub workflow: Option<String>,
    pub predicate_type: String,
}

const SLSA_PREDICATE_PREFIXES: &[&str] = &[
    "https://slsa.dev/provenance/",
    "https://in-toto.io/attestation/",
];

/// Parse npm's `/-/npm/v1/attestations/{name}@{version}` response into the
/// provenance info we care about. Returns None if no provenance attestation is
/// present (e.g. only a publish attestation, or an unparseable body).
pub fn parse(attestations: &serde_json::Value) -> Option<ProvenanceInfo> {
    let list = attestations.get("attestations")?.as_array()?;

    for att in list {
        // The DSSE payload is base64 in bundle.dsseEnvelope.payload.
        let payload_b64 = att
            .pointer("/bundle/dsseEnvelope/payload")
            .and_then(|p| p.as_str());
        let Some(payload_b64) = payload_b64 else {
            continue;
        };
        let Ok(payload_bytes) = base64::engine::general_purpose::STANDARD.decode(payload_b64)
        else {
            continue;
        };
        let Ok(statement) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
            continue;
        };

        let predicate_type = statement
            .get("predicateType")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();

        // Only SLSA build-provenance statements carry source/workflow we trust.
        let is_provenance = SLSA_PREDICATE_PREFIXES
            .iter()
            .any(|prefix| predicate_type.starts_with(prefix))
            && predicate_type.contains("provenance");
        if !is_provenance {
            continue;
        }

        let source_repo = extract_source_repo(&statement);
        let workflow = extract_workflow(&statement);

        return Some(ProvenanceInfo {
            source_repo,
            workflow,
            predicate_type,
        });
    }

    None
}

/// Decide a `Provenance` verdict from a parsed attestation and the package's
/// claimed repository. Structural verification (see module note).
pub fn verify(info: Option<&ProvenanceInfo>, claimed_repo: Option<&str>) -> Provenance {
    let Some(info) = info else {
        return Provenance::Absent;
    };

    let Some(repo) = info.source_repo.clone() else {
        return Provenance::Invalid {
            reason: "provenance attestation has no source repository".into(),
        };
    };

    // If the package declares a repo, it must match the attested source.
    if let Some(claimed) = claimed_repo {
        if normalize_repo(claimed) != normalize_repo(&repo) {
            return Provenance::Invalid {
                reason: format!(
                    "attested source {repo} does not match declared repository {claimed}"
                ),
            };
        }
    }

    Provenance::Verified {
        workflow: info.workflow.clone().unwrap_or_default(),
        repo,
    }
}

/// SLSA v1 puts the source under resolvedDependencies / externalParameters;
/// SLSA v0.2 under predicate.materials or invocation.configSource. Probe both.
fn extract_source_repo(statement: &serde_json::Value) -> Option<String> {
    // SLSA v1: predicate.buildDefinition.resolvedDependencies[].uri
    if let Some(deps) = statement
        .pointer("/predicate/buildDefinition/resolvedDependencies")
        .and_then(|d| d.as_array())
    {
        for dep in deps {
            if let Some(uri) = dep.get("uri").and_then(|u| u.as_str()) {
                if uri.contains("github.com") || uri.contains("gitlab.com") {
                    return Some(clean_uri(uri));
                }
            }
        }
    }
    // SLSA v1: externalParameters.workflow.repository
    if let Some(repo) = statement
        .pointer("/predicate/buildDefinition/externalParameters/workflow/repository")
        .and_then(|r| r.as_str())
    {
        return Some(clean_uri(repo));
    }
    // SLSA v0.2: predicate.invocation.configSource.uri
    if let Some(uri) = statement
        .pointer("/predicate/invocation/configSource/uri")
        .and_then(|u| u.as_str())
    {
        return Some(clean_uri(uri));
    }
    // SLSA v0.2: predicate.materials[].uri
    if let Some(materials) = statement
        .pointer("/predicate/materials")
        .and_then(|m| m.as_array())
    {
        for m in materials {
            if let Some(uri) = m.get("uri").and_then(|u| u.as_str()) {
                if uri.contains("github.com") || uri.contains("gitlab.com") {
                    return Some(clean_uri(uri));
                }
            }
        }
    }
    None
}

fn extract_workflow(statement: &serde_json::Value) -> Option<String> {
    statement
        .pointer("/predicate/buildDefinition/externalParameters/workflow/path")
        .and_then(|p| p.as_str())
        .map(String::from)
        .or_else(|| {
            statement
                .pointer("/predicate/invocation/configSource/entryPoint")
                .and_then(|p| p.as_str())
                .map(String::from)
        })
}

/// Strip `git+`, scheme, `.git`, commit fragment, and trailing slash.
fn clean_uri(uri: &str) -> String {
    let s = uri.trim();
    let s = s.strip_prefix("git+").unwrap_or(s);
    let s = s.split(['@', '#']).next().unwrap_or(s); // drop @ref / #commit
    s.trim_end_matches(".git").trim_end_matches('/').to_string()
}

/// Normalize for comparison: drop scheme, `.git`, trailing slash; lowercase.
fn normalize_repo(url: &str) -> String {
    let s = clean_uri(url).to_lowercase();
    s.strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .or_else(|| s.strip_prefix("git://"))
        .or_else(|| s.strip_prefix("ssh://git@"))
        .unwrap_or(&s)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an npm attestations response wrapping a SLSA v1 provenance
    /// statement for `repo` / `workflow`.
    fn attestations_json(repo: &str, workflow: &str) -> serde_json::Value {
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{ "name": "pkg", "digest": { "sha512": "abc" } }],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": { "repository": repo, "path": workflow }
                    },
                    "resolvedDependencies": [{ "uri": format!("git+{repo}.git") }]
                }
            }
        });
        let payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).unwrap());
        serde_json::json!({
            "attestations": [
                { "predicateType": "https://slsa.dev/provenance/v1",
                  "bundle": { "dsseEnvelope": { "payload": payload } } }
            ]
        })
    }

    #[test]
    fn parses_slsa_provenance() {
        let json = attestations_json(
            "https://github.com/acme/demo",
            ".github/workflows/release.yml",
        );
        let info = parse(&json).expect("should parse provenance");
        assert_eq!(
            info.source_repo.as_deref(),
            Some("https://github.com/acme/demo")
        );
        assert_eq!(
            info.workflow.as_deref(),
            Some(".github/workflows/release.yml")
        );
    }

    #[test]
    fn verify_matches_claimed_repo() {
        let json = attestations_json("https://github.com/acme/demo", "release.yml");
        let info = parse(&json);
        let p = verify(info.as_ref(), Some("git+https://github.com/acme/demo.git"));
        assert!(matches!(p, Provenance::Verified { .. }));
    }

    #[test]
    fn verify_rejects_repo_mismatch() {
        let json = attestations_json("https://github.com/attacker/fork", "release.yml");
        let info = parse(&json);
        let p = verify(info.as_ref(), Some("https://github.com/acme/demo"));
        assert!(matches!(p, Provenance::Invalid { .. }));
    }

    #[test]
    fn absent_when_no_attestations() {
        let json = serde_json::json!({ "attestations": [] });
        assert!(parse(&json).is_none());
        assert!(matches!(verify(None, Some("x")), Provenance::Absent));
    }

    #[test]
    fn ignores_non_provenance_predicate() {
        // A publish attestation (not provenance) must not be treated as provenance.
        let statement = serde_json::json!({
            "predicateType": "https://github.com/npm/attestation/publish/v0.1",
            "predicate": {}
        });
        let payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).unwrap());
        let json = serde_json::json!({
            "attestations": [
                { "bundle": { "dsseEnvelope": { "payload": payload } } }
            ]
        });
        assert!(parse(&json).is_none());
    }
}
