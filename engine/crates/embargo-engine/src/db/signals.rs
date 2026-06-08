//! Per-version signal store. The extractor writes findings here; resolve reads
//! them back to escalate verdicts. The structured columns let the console query
//! by type/severity; `evidence` round-trips the full finding.

use anyhow::Result;
use embargo_core::types::{Severity, Signal, SignalType};
use sqlx::PgPool;

/// Replace all signals for a (package, version) with a freshly-extracted set.
/// Idempotent: re-running extraction overwrites rather than duplicating.
pub async fn replace_for_version(
    pool: &PgPool,
    package: &str,
    version: &str,
    signals: &[Signal],
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query!(
        "DELETE FROM signals WHERE package = $1 AND version = $2",
        package,
        version
    )
    .execute(&mut *tx)
    .await?;

    for s in signals {
        sqlx::query!(
            r#"
            INSERT INTO signals (id, package, version, signal_type, severity, weight, evidence, detected_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            s.id,
            package,
            version,
            signal_type_tag(&s.signal_type),
            severity_tag(s.severity),
            s.weight as i32,
            s.evidence,
            s.detected_at,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Append a single signal (e.g. an L3 containment event reported via
/// ReportEvent) without disturbing previously-extracted findings.
pub async fn append(pool: &PgPool, package: &str, version: &str, signal: &Signal) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO signals (id, package, version, signal_type, severity, weight, evidence, detected_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        signal.id,
        package,
        version,
        signal_type_tag(&signal.signal_type),
        severity_tag(signal.severity),
        signal.weight as i32,
        signal.evidence,
        signal.detected_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Read all signals recorded for a (package, version).
pub async fn get_for_version(pool: &PgPool, package: &str, version: &str) -> Result<Vec<Signal>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, signal_type, severity, weight, evidence, detected_at
        FROM signals
        WHERE package = $1 AND version = $2
        ORDER BY detected_at
        "#,
        package,
        version,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Signal {
            id: r.id,
            signal_type: parse_signal_type(&r.signal_type),
            severity: parse_severity(&r.severity),
            weight: r.weight.max(0) as u32,
            evidence: r.evidence,
            detected_at: r.detected_at,
        })
        .collect())
}

/// Stable text tag for a signal type. Composite chains carry their chain name.
fn signal_type_tag(t: &SignalType) -> String {
    match t {
        SignalType::NewLifecycleScript => "new_lifecycle_script".into(),
        SignalType::BindingGyp => "binding_gyp".into(),
        SignalType::CapabilityDep => "capability_dep".into(),
        SignalType::Republish => "republish".into(),
        SignalType::MaintainerChange => "maintainer_change".into(),
        SignalType::TarballMismatch => "tarball_mismatch".into(),
        SignalType::Obfuscation => "obfuscation".into(),
        SignalType::Typosquat => "typosquat".into(),
        SignalType::AdvisoryMatch => "advisory_match".into(),
        SignalType::ProvenanceAbsent => "provenance_absent".into(),
        SignalType::SandboxEgressAttempt => "sandbox_egress_attempt".into(),
        SignalType::EbpfCompromiseChain => "ebpf_compromise_chain".into(),
        SignalType::Other { name } => name.clone(),
    }
}

fn parse_signal_type(tag: &str) -> SignalType {
    match tag {
        "new_lifecycle_script" => SignalType::NewLifecycleScript,
        "binding_gyp" => SignalType::BindingGyp,
        "capability_dep" => SignalType::CapabilityDep,
        "republish" => SignalType::Republish,
        "maintainer_change" => SignalType::MaintainerChange,
        "tarball_mismatch" => SignalType::TarballMismatch,
        "obfuscation" => SignalType::Obfuscation,
        "typosquat" => SignalType::Typosquat,
        "advisory_match" => SignalType::AdvisoryMatch,
        "provenance_absent" => SignalType::ProvenanceAbsent,
        "sandbox_egress_attempt" => SignalType::SandboxEgressAttempt,
        "ebpf_compromise_chain" => SignalType::EbpfCompromiseChain,
        other => SignalType::Other {
            name: other.to_string(),
        },
    }
}

fn severity_tag(s: Severity) -> String {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
    .into()
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}
