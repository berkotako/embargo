//! `republish_anomaly` — a sudden token-driven burst of versions in a short
//! window, the fingerprint of a self-propagating worm (Shai-Hulud / Miasma).

use super::{finding, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};

/// More than this many versions published by one token within the trailing hour
/// is anomalous for a normal release cadence.
const BURST_THRESHOLD: u32 = 5;

pub fn detect(current: &VersionArtifact) -> Vec<Signal> {
    if current.republish_burst > BURST_THRESHOLD {
        return vec![finding(
            SignalType::Republish,
            Severity::High,
            weights::REPUBLISH,
            serde_json::json!({
                "versions_last_hour": current.republish_burst,
                "threshold": BURST_THRESHOLD,
            }),
        )];
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(burst: u32) -> VersionArtifact {
        VersionArtifact {
            republish_burst: burst,
            ..Default::default()
        }
    }

    #[test]
    fn benign_normal_cadence() {
        assert!(detect(&artifact(1)).is_empty());
        assert!(detect(&artifact(5)).is_empty());
    }

    #[test]
    fn malicious_burst_fires() {
        let signals = detect(&artifact(40));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::Republish);
    }
}
