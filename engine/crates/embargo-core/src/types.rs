use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Resolution verdict for a (package, version) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    /// Served normally.
    Allow,
    /// Stripped from packument; re-evaluated when cooldown expires or on manual review.
    Hold,
    /// Stripped permanently; shown in console quarantine.
    Deny,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Allow => write!(f, "ALLOW"),
            Verdict::Hold => write!(f, "HOLD"),
            Verdict::Deny => write!(f, "DENY"),
        }
    }
}

/// Why a version was held or denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    /// Version was published less than `cooldown_hours` ago.
    Cooldown { remaining_hours: u64 },
    /// Provenance attestation absent or unverifiable.
    ProvenanceMissing,
    /// A signal chain scored above the DENY threshold.
    SignalChain { chain_id: String, score: u32 },
    /// Direct advisory/CVE match — always DENY.
    Advisory { advisory_id: String },
    /// Manually denied by an operator.
    ManualDeny { approver: String, reason: String },
    /// Overridden to ALLOW by a time-boxed, audited approval (exception workflow).
    ApprovedException { approver: String, reason: String },
}

/// Severity of a signal finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Build-provenance attestation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Valid SLSA/npm build-provenance attestation verified.
    Verified { workflow: String, repo: String },
    /// Attestation present but verification failed.
    Invalid { reason: String },
    /// No attestation found.
    Absent,
}

impl Provenance {
    pub fn is_verified(&self) -> bool {
        matches!(self, Provenance::Verified { .. })
    }
}

/// A single weighted signal finding on a (package, version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub id: Uuid,
    pub signal_type: SignalType,
    pub severity: Severity,
    /// Raw weight contribution (0–100). Policy thresholds decide verdicts.
    pub weight: u32,
    pub evidence: serde_json::Value,
    pub detected_at: DateTime<Utc>,
}

/// Known signal types. New types are added here and in `docs/SIGNALS.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    NewLifecycleScript,
    BindingGyp,
    CapabilityDep,
    Republish,
    MaintainerChange,
    TarballMismatch,
    Obfuscation,
    AdvisoryMatch,
    ProvenanceAbsent,
    SandboxEgressAttempt,
    /// eBPF chain: secret read → serialize → non-allowlisted egress.
    EbpfCompromiseChain,
    /// Catch-all for future signals not yet modelled.
    Other {
        name: String,
    },
}

/// The computed verdict for a (package, version) pair, ready for caching and serving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionVerdict {
    pub package: String,
    pub version: String,
    pub verdict: Verdict,
    pub reasons: Vec<HoldReason>,
    pub signals: Vec<Signal>,
    pub provenance: Option<Provenance>,
    pub computed_at: DateTime<Utc>,
    /// When None, the verdict does not expire (ALLOW/DENY). When Some, re-evaluate at this time.
    pub expires_at: Option<DateTime<Utc>>,
}

impl VersionVerdict {
    pub fn allow(package: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            version: version.into(),
            verdict: Verdict::Allow,
            reasons: vec![],
            signals: vec![],
            provenance: None,
            computed_at: Utc::now(),
            expires_at: None,
        }
    }
}
