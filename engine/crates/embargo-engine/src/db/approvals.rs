use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Approval {
    pub id: Uuid,
    pub package: String,
    pub version: String,
    pub requester_id: Uuid,
    pub approver_id: Uuid,
    pub justification: String,
    pub expires_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Active,
    Expired,
    Revoked,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalStatus::Active => "active",
            ApprovalStatus::Expired => "expired",
            ApprovalStatus::Revoked => "revoked",
        }
    }
}

/// Returns an active, unexpired approval for the exact (package, version) pair.
pub async fn get_active(pool: &PgPool, package: &str, version: &str) -> Result<Option<Approval>> {
    let row = sqlx::query!(
        r#"
        SELECT id, package, version, requester_id, approver_id, justification, expires_at, status, created_at
        FROM approvals
        WHERE package = $1
          AND version = $2
          AND status = 'active'
          AND expires_at > NOW()
        LIMIT 1
        "#,
        package,
        version,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };

    Ok(Some(Approval {
        id: row.id,
        package: row.package,
        version: row.version,
        requester_id: row.requester_id,
        approver_id: row.approver_id,
        justification: row.justification,
        expires_at: row.expires_at,
        status: ApprovalStatus::Active,
        created_at: row.created_at,
    }))
}

pub async fn create(
    pool: &PgPool,
    package: &str,
    version: &str,
    requester_id: Uuid,
    approver_id: Uuid,
    justification: &str,
    ttl_hours: u64,
) -> Result<Approval> {
    let id = Uuid::new_v4();
    let expires_at = Utc::now() + chrono::Duration::hours(ttl_hours as i64);

    sqlx::query!(
        r#"
        INSERT INTO approvals (id, package, version, requester_id, approver_id, justification, expires_at, status, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', NOW())
        "#,
        id,
        package,
        version,
        requester_id,
        approver_id,
        justification,
        expires_at,
    )
    .execute(pool)
    .await?;

    Ok(Approval {
        id,
        package: package.to_string(),
        version: version.to_string(),
        requester_id,
        approver_id,
        justification: justification.to_string(),
        expires_at,
        status: ApprovalStatus::Active,
        created_at: Utc::now(),
    })
}

/// List recent approvals (newest first), marking expired ones.
pub async fn list(pool: &PgPool, limit: i64) -> Result<Vec<Approval>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, package, version, requester_id, approver_id, justification,
               expires_at, status, created_at
        FROM approvals
        ORDER BY created_at DESC
        LIMIT $1
        "#,
        limit,
    )
    .fetch_all(pool)
    .await?;

    let now = Utc::now();
    Ok(rows
        .into_iter()
        .map(|row| {
            let status = match row.status.as_str() {
                "revoked" => ApprovalStatus::Revoked,
                "active" if row.expires_at <= now => ApprovalStatus::Expired,
                "active" => ApprovalStatus::Active,
                _ => ApprovalStatus::Expired,
            };
            Approval {
                id: row.id,
                package: row.package,
                version: row.version,
                requester_id: row.requester_id,
                approver_id: row.approver_id,
                justification: row.justification,
                expires_at: row.expires_at,
                status,
                created_at: row.created_at,
            }
        })
        .collect())
}

pub async fn revoke(pool: &PgPool, approval_id: Uuid, reason: &str) -> Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE approvals
        SET status = 'revoked', revocation_reason = $2
        WHERE id = $1 AND status = 'active'
        "#,
        approval_id,
        reason,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
