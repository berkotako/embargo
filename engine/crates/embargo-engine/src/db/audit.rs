use anyhow::Result;
use chrono::Utc;
use embargo_core::audit::{Actor, AuditAction, AuditEntry, AuditTarget};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Append an audit entry with SHA-256 hash chaining.
/// Each entry's hash folds in the prior entry's hash, making tampering evident.
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

    // Fetch the hash of the last entry to chain to (content_hash is NOT NULL).
    let prev_hash: Option<String> =
        sqlx::query_scalar!("SELECT content_hash FROM audit_log ORDER BY sequence DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;

    // Build entry (the chain hash is derived below, not stored on the struct).
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

    // Hash the canonical content (excludes prev_hash) and fold in the predecessor.
    let mut hasher = Sha256::new();
    hasher.update(entry.canonical_content().as_bytes());
    if let Some(ph) = &prev_hash {
        hasher.update(ph.as_bytes());
    }
    let content_hash = hex::encode(hasher.finalize());

    // The `action` column is TEXT; serialize the enum to its snake_case tag.
    let action_str = serde_json::to_value(&entry.action)?
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let actor_json = serde_json::to_value(actor)?;
    let target_json = serde_json::to_value(target)?;
    let before_json: Option<serde_json::Value> = before.cloned();
    let after_json: Option<serde_json::Value> = after.cloned();

    sqlx::query!(
        r#"
        INSERT INTO audit_log
          (id, actor, action, target, before_state, after_state, timestamp, prev_hash, content_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        id,
        actor_json,
        action_str,
        target_json,
        before_json,
        after_json,
        now,
        prev_hash,
        content_hash,
    )
    .execute(pool)
    .await?;

    Ok(entry)
}
