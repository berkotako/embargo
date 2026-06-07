//! `obfuscation_markers` — high-entropy / packed payloads and known stealer
//! patterns in install-script source. Bounded, heuristic static scan.

use super::{finding, install_script_text, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};

/// Cap the amount of text we scan so a giant minified blob can't blow the budget.
const SCAN_BUDGET_BYTES: usize = 512 * 1024;

/// Known dynamic-exec / decode patterns frequently seen in stealer payloads.
const STEALER_PATTERNS: &[&str] = &[
    "eval(",
    "Function(",
    "Buffer.from(", // commonly Buffer.from(<base64>, 'base64')
    "atob(",
    "\\x", // hex-escaped string literals
    "fromCharCode",
    "globalThis[",
];

/// Shannon entropy of a byte slice (bits per byte, 0–8).
fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Length of the longest run of non-whitespace characters (proxy for a packed
/// single-line payload).
fn longest_token(text: &str) -> usize {
    text.split_whitespace().map(str::len).max().unwrap_or(0)
}

pub fn detect(current: &VersionArtifact) -> Vec<Signal> {
    let mut text = install_script_text(current);
    if text.len() > SCAN_BUDGET_BYTES {
        text.truncate(SCAN_BUDGET_BYTES);
    }
    if text.trim().is_empty() {
        return vec![];
    }

    let matched: Vec<&str> = STEALER_PATTERNS
        .iter()
        .filter(|p| text.contains(**p))
        .copied()
        .collect();

    let ent = entropy(text.as_bytes());
    let longest = longest_token(&text);

    // Heuristic: a known dynamic-exec pattern combined with either a very long
    // packed token or high overall entropy. Tuned to avoid firing on ordinary
    // readable scripts.
    let packed = longest >= 200 || ent >= 5.2;
    let suspicious = !matched.is_empty() && packed;

    if suspicious {
        return vec![finding(
            SignalType::Obfuscation,
            Severity::Medium,
            weights::OBFUSCATION,
            serde_json::json!({
                "patterns": matched,
                "entropy_bits": (ent * 100.0).round() / 100.0,
                "longest_token": longest,
            }),
        )];
    }

    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::Manifest;
    use std::collections::BTreeMap;

    fn artifact_with_postinstall(cmd: &str) -> VersionArtifact {
        let mut scripts = BTreeMap::new();
        scripts.insert("postinstall".to_string(), cmd.to_string());
        VersionArtifact {
            manifest: Manifest {
                scripts,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn benign_readable_build_script() {
        let current = artifact_with_postinstall("node-gyp rebuild && echo done");
        assert!(detect(&current).is_empty());
    }

    #[test]
    fn benign_eval_in_short_readable_code_does_not_fire() {
        // eval present but not packed — stays under the bar (bias to fewer FPs).
        let current = artifact_with_postinstall("eval(userConfig)");
        assert!(detect(&current).is_empty());
    }

    #[test]
    fn malicious_packed_base64_eval_fires() {
        let blob = "A".repeat(400);
        let cmd = format!("eval(Buffer.from('{blob}','base64').toString())");
        let current = artifact_with_postinstall(&cmd);
        let signals = detect(&current);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::Obfuscation);
    }

    #[test]
    fn empty_scripts_no_finding() {
        let current = VersionArtifact::default();
        assert!(detect(&current).is_empty());
    }
}
