//! `maintainer_change` — the publishing identity changed versus the prior
//! version (new npm user not in the prior maintainer set). Token-hijack tell.

use super::{finding, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};

pub fn detect(current: &VersionArtifact, prior: Option<&VersionArtifact>) -> Vec<Signal> {
    let Some(prior) = prior else {
        // First-ever publish: no maintainer history to compare against.
        return vec![];
    };

    let publisher = current.publisher.npm_user.trim();
    if publisher.is_empty() {
        return vec![];
    }

    let known = prior.publisher.maintainers.iter().any(|m| m == publisher)
        || prior.publisher.npm_user == publisher;

    if !known {
        return vec![finding(
            SignalType::MaintainerChange,
            Severity::Medium,
            weights::MAINTAINER_CHANGE,
            serde_json::json!({
                "new_publisher": publisher,
                "prior_maintainers": prior.publisher.maintainers,
            }),
        )];
    }

    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::Publisher;

    fn artifact(npm_user: &str, maintainers: &[&str]) -> VersionArtifact {
        VersionArtifact {
            publisher: Publisher {
                npm_user: npm_user.to_string(),
                maintainers: maintainers.iter().map(|s| s.to_string()).collect(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn benign_known_maintainer_publishes() {
        let current = artifact("alice", &["alice", "bob"]);
        let prior = artifact("bob", &["alice", "bob"]);
        assert!(detect(&current, Some(&prior)).is_empty());
    }

    #[test]
    fn malicious_unknown_publisher_fires() {
        let current = artifact("mallory", &["mallory"]);
        let prior = artifact("alice", &["alice", "bob"]);
        let signals = detect(&current, Some(&prior));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::MaintainerChange);
    }

    #[test]
    fn first_publish_no_finding() {
        let current = artifact("alice", &["alice"]);
        assert!(detect(&current, None).is_empty());
    }
}
