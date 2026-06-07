//! `tarball_repo_mismatch` — the published artifact's provenance attests to a
//! different source repository than the one declared in package.json. Mirrors
//! out-of-pipeline / orphan-commit review-bypass publishes.

use super::{finding, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};

/// Normalize a repo URL for comparison: strip protocol, `git+`, `.git`, and
/// trailing slashes; lowercase. So `git+https://github.com/a/b.git` == `github.com/a/b`.
fn normalize_repo(url: &str) -> String {
    let s = url.trim().to_lowercase();
    let s = s.strip_prefix("git+").unwrap_or(&s);
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .or_else(|| s.strip_prefix("git://"))
        .or_else(|| s.strip_prefix("ssh://git@"))
        .unwrap_or(s);
    let s = s.strip_suffix(".git").unwrap_or(s);
    s.trim_end_matches('/').to_string()
}

pub fn detect(current: &VersionArtifact) -> Vec<Signal> {
    // Only meaningful when we have a verified provenance repo to compare against.
    let (Some(claimed), Some(attested)) = (&current.claimed_repo, &current.provenance_repo) else {
        return vec![];
    };

    let claimed_n = normalize_repo(claimed);
    let attested_n = normalize_repo(attested);

    if claimed_n != attested_n {
        return vec![finding(
            SignalType::TarballMismatch,
            Severity::High,
            weights::TARBALL_MISMATCH,
            serde_json::json!({
                "claimed_repo": claimed,
                "attested_repo": attested,
            }),
        )];
    }

    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(claimed: Option<&str>, attested: Option<&str>) -> VersionArtifact {
        VersionArtifact {
            claimed_repo: claimed.map(String::from),
            provenance_repo: attested.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn benign_matching_repos_normalized() {
        let current = artifact(
            Some("git+https://github.com/acme/widget.git"),
            Some("https://github.com/acme/widget"),
        );
        assert!(detect(&current).is_empty());
    }

    #[test]
    fn benign_no_provenance_no_finding() {
        let current = artifact(Some("https://github.com/acme/widget"), None);
        assert!(detect(&current).is_empty());
    }

    #[test]
    fn malicious_repo_mismatch_fires() {
        let current = artifact(
            Some("https://github.com/acme/widget"),
            Some("https://github.com/attacker/widget-fork"),
        );
        let signals = detect(&current);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::TarballMismatch);
    }
}
