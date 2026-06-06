use anyhow::Result;
use chrono::{DateTime, Utc};
use embargo_core::audit::{Actor, AuditAction, AuditEntry, AuditTarget};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Append an audit entry with SHA-256 hash chaining.
/// The prev_hash is computed by the database layer so concurrent writes serialize correctly.
pub async fn append(
    pool: &PgPool,
    actor: &Actor,
    action: AuditAction,
    target: &AuditTarget,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) -> Result<AuditEntry> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    // Fetch the hash of the last entry to chain to.
    let prev_hash: Option<String> = sqlx::query_scalar!(
        "SELECT content_hash FROM audit_log ORDER BY sequence DESC LIMIT 1"
    )
    .fetch_optional(pool)
    .await?
    .flatten();

    // Build entry (without content_hash — computed after).
    let entry = AuditEntry {
        id,
        actor: actor.clone(),
        action,
        target: target.clone(),
        before: before.cloned(),
        after: after.cloned(),
        timestamp: now,
        prev_hash: prev_hash.clone(),
    };

    // Compute this entry's hash over its canonical JSON (excluding content_hash field).
    let canonical = serde_json::to_string(&entry)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    if let Some(ph) = &prev_hash {
        hasher.update(ph.as_bytes());
    }
    let content_hash = hex::encode(hasher.finalize());

    sqlx::query!(
        r#"
        INSERT INTO audit_log
          (id, actor, action, target, before_state, after_state, timestamp, prev_hash, content_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        id,
        serde_json::to_value(actor)?,
        serde_json::to_value(&entry.action)?,
        serde_json::to_value(target)?,
        before.map(|v| serde_json::to_value(v)).transpose()?,
        after.map(|v| serde_json::to_value(v)).transpose()?,
        now,
        prev_hash,
        content_hash,
    )
    .execute(pool)
    .await?;

    Ok(entry)
}
