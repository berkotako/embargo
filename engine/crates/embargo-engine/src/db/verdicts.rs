use anyhow::Result;
use chrono::{DateTime, Utc};
use embargo_core::types::{Verdict, VersionVerdict};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn upsert(pool: &PgPool, v: &VersionVerdict) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO verdicts (id, package, version, verdict, reasons, signals, provenance, computed_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (package, version) DO UPDATE
          SET verdict = EXCLUDED.verdict,
              reasons = EXCLUDED.reasons,
              signals = EXCLUDED.signals,
              provenance = EXCLUDED.provenance,
              computed_at = EXCLUDED.computed_at,
              expires_at = EXCLUDED.expires_at
        "#,
        Uuid::new_v4(),
        v.package,
        v.version,
        v.verdict as i16,
        serde_json::to_value(&v.reasons)?,
        serde_json::to_value(&v.signals)?,
        serde_json::to_value(&v.provenance)?,
        v.computed_at,
        v.expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(
    pool: &PgPool,
    package: &str,
    version: &str,
) -> Result<Option<VersionVerdict>> {
    let row = sqlx::query!(
        r#"
        SELECT package, version, verdict, reasons, signals, provenance, computed_at, expires_at
        FROM verdicts
        WHERE package = $1 AND version = $2
        "#,
        package,
        version,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };

    Ok(Some(VersionVerdict {
        package: row.package,
        version: row.version,
        verdict: int_to_verdict(row.verdict)?,
        reasons: serde_json::from_value(row.reasons)?,
        signals: serde_json::from_value(row.signals)?,
        provenance: serde_json::from_value(row.provenance)?,
        computed_at: row.computed_at,
        expires_at: row.expires_at,
    }))
}

pub async fn list_by_verdict(
    pool: &PgPool,
    verdict: Verdict,
    limit: i64,
    offset: i64,
) -> Result<Vec<VersionVerdict>> {
    let rows = sqlx::query!(
        r#"
        SELECT package, version, verdict, reasons, signals, provenance, computed_at, expires_at
        FROM verdicts
        WHERE verdict = $1
        ORDER BY computed_at DESC
        LIMIT $2 OFFSET $3
        "#,
        verdict as i16,
        limit,
        offset,
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(VersionVerdict {
                package: row.package,
                version: row.version,
                verdict: int_to_verdict(row.verdict)?,
                reasons: serde_json::from_value(row.reasons)?,
                signals: serde_json::from_value(row.signals)?,
                provenance: serde_json::from_value(row.provenance)?,
                computed_at: row.computed_at,
                expires_at: row.expires_at,
            })
        })
        .collect()
}

fn int_to_verdict(v: i16) -> Result<Verdict> {
    match v {
        1 => Ok(Verdict::Allow),
        2 => Ok(Verdict::Hold),
        3 => Ok(Verdict::Deny),
        other => anyhow::bail!("unknown verdict discriminant: {}", other),
    }
}
