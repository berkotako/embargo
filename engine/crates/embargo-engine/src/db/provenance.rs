//! Provenance verification store. The extractor writes a verdict per version;
//! resolve reads it to enforce the require_provenance policy gate.

use anyhow::Result;
use embargo_core::types::Provenance;
use sqlx::PgPool;

/// Upsert the provenance verdict for a (package, version).
pub async fn set(pool: &PgPool, package: &str, version: &str, prov: &Provenance) -> Result<()> {
    let (status, repo, workflow, reason) = match prov {
        Provenance::Verified { workflow, repo } => {
            ("verified", Some(repo.clone()), Some(workflow.clone()), None)
        }
        Provenance::Invalid { reason } => ("invalid", None, None, Some(reason.clone())),
        Provenance::Absent => ("absent", None, None, None),
    };

    sqlx::query!(
        r#"
        INSERT INTO provenance (package, version, status, source_repo, workflow, reason, checked_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (package, version) DO UPDATE
          SET status = EXCLUDED.status,
              source_repo = EXCLUDED.source_repo,
              workflow = EXCLUDED.workflow,
              reason = EXCLUDED.reason,
              checked_at = NOW()
        "#,
        package,
        version,
        status,
        repo,
        workflow,
        reason,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Read the recorded provenance verdict, if the extractor has checked it.
pub async fn get(pool: &PgPool, package: &str, version: &str) -> Result<Option<Provenance>> {
    let row = sqlx::query!(
        r#"
        SELECT status, source_repo, workflow, reason
        FROM provenance
        WHERE package = $1 AND version = $2
        "#,
        package,
        version,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };

    let prov = match row.status.as_str() {
        "verified" => Provenance::Verified {
            workflow: row.workflow.unwrap_or_default(),
            repo: row.source_repo.unwrap_or_default(),
        },
        "invalid" => Provenance::Invalid {
            reason: row.reason.unwrap_or_default(),
        },
        _ => Provenance::Absent,
    };
    Ok(Some(prov))
}
