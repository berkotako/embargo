use anyhow::Result;
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
        verdict_to_int(v.verdict),
        serde_json::to_value(&v.reasons)?,
        serde_json::to_value(&v.signals)?,
        // Store SQL NULL (not JSON `null`) when there is no provenance, so the
        // read path can round-trip it back to Option::None.
        v.provenance.as_ref().map(serde_json::to_value).transpose()?,
        v.computed_at,
        v.expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(pool: &PgPool, package: &str, version: &str) -> Result<Option<VersionVerdict>> {
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
        provenance: match row.provenance {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(serde_json::from_value(v)?),
        },
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
        verdict_to_int(verdict),
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
                provenance: match row.provenance {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => Some(serde_json::from_value(v)?),
                },
                computed_at: row.computed_at,
                expires_at: row.expires_at,
            })
        })
        .collect()
}

/// Canonical (de)serialization for the `verdicts.verdict` SMALLINT column.
/// The schema documents `1=ALLOW 2=HOLD 3=DENY` — use these helpers everywhere
/// rather than `as i16` (the Rust enum discriminants are 0/1/2 and would not
/// round-trip through `int_to_verdict`).
fn verdict_to_int(v: Verdict) -> i16 {
    match v {
        Verdict::Allow => 1,
        Verdict::Hold => 2,
        Verdict::Deny => 3,
    }
}

fn int_to_verdict(v: i16) -> Result<Verdict> {
    match v {
        1 => Ok(Verdict::Allow),
        2 => Ok(Verdict::Hold),
        3 => Ok(Verdict::Deny),
        other => anyhow::bail!("unknown verdict discriminant: {}", other),
    }
}
