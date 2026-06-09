use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Approval {
    pub id: Uuid,
    pub package: String,
    pub version: String,
    pub requester_id: Uuid,
    /// None until a (different) admin approves the request.
    pub approver_id: Option<Uuid>,
    pub justification: String,
    /// None until approved; set to `now + ttl_hours` at approval time.
    pub expires_at: Option<DateTime<Utc>>,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Requested, awaiting a second admin's approval (separation of duties).
    Pending,
    Active,
    Expired,
    Revoked,
    /// A pending request an admin declined.
    Rejected,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Active => "active",
            ApprovalStatus::Expired => "expired",
            ApprovalStatus::Revoked => "revoked",
            ApprovalStatus::Rejected => "rejected",
        }
    }
}

/// Returns an active, unexpired approval for the exact (package, version) pair.
/// Pending requests never match here — they do not grant until approved.
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

/// Open a *pending* exception request (separation of duties: it does not grant
/// until a different admin approves it). `approver_id`/`expires_at` stay null;
/// the requested TTL is stored for the approval step.
pub async fn request(
    pool: &PgPool,
    package: &str,
    version: &str,
    requester_id: Uuid,
    justification: &str,
    ttl_hours: u64,
) -> Result<Approval> {
    let id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO approvals (id, package, version, requester_id, justification, ttl_hours, status, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW())
        "#,
        id,
        package,
        version,
        requester_id,
        justification,
        ttl_hours as i64,
    )
    .execute(pool)
    .await?;

    Ok(Approval {
        id,
        package: package.to_string(),
        version: version.to_string(),
        requester_id,
        approver_id: None,
        justification: justification.to_string(),
        expires_at: None,
        status: ApprovalStatus::Pending,
        created_at: Utc::now(),
    })
}

/// Approve a pending request. Enforces separation of duties: the approver must
/// be a different principal than the requester. Sets the exception active with
/// expiry `now + ttl_hours`. Errors if the request is missing, not pending, or a
/// self-approval.
pub async fn approve(pool: &PgPool, id: Uuid, approver_id: Uuid) -> Result<Approval> {
    let row = sqlx::query!(
        r#"
        UPDATE approvals
        SET status = 'active',
            approver_id = $2,
            expires_at = NOW() + make_interval(hours => COALESCE(ttl_hours, 24)::int)
        WHERE id = $1
          AND status = 'pending'
          AND requester_id <> $2
        RETURNING id, package, version, requester_id, approver_id, justification, expires_at, created_at
        "#,
        id,
        approver_id,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        // Distinguish self-approval from not-pending for a clear message.
        let existing = sqlx::query!(
            "SELECT requester_id, status FROM approvals WHERE id = $1",
            id
        )
        .fetch_optional(pool)
        .await?;
        match existing {
            None => bail!("approval request not found"),
            Some(e) if e.status != "pending" => {
                bail!("approval request is not pending (status: {})", e.status)
            }
            Some(e) if e.requester_id == approver_id => {
                bail!("separation of duties: you cannot approve your own request")
            }
            Some(_) => bail!("approval request could not be approved"),
        }
    };

    Ok(Approval {
        id: row.id,
        package: row.package,
        version: row.version,
        requester_id: row.requester_id,
        approver_id: row.approver_id,
        justification: row.justification,
        expires_at: row.expires_at,
        status: ApprovalStatus::Active,
        created_at: row.created_at,
    })
}

/// Decline a pending request.
pub async fn reject(pool: &PgPool, id: Uuid, approver_id: Uuid, reason: &str) -> Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE approvals
        SET status = 'rejected', approver_id = $2, revocation_reason = $3
        WHERE id = $1 AND status = 'pending'
        "#,
        id,
        approver_id,
        reason,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Seed an already-active approval directly (used by tests and the internal gRPC
/// admin path). The SoD-enforced flow is `request` + `approve`.
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
        approver_id: Some(approver_id),
        justification: justification.to_string(),
        expires_at: Some(expires_at),
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
                "pending" => ApprovalStatus::Pending,
                "revoked" => ApprovalStatus::Revoked,
                "rejected" => ApprovalStatus::Rejected,
                "active" if row.expires_at.is_some_and(|e| e <= now) => ApprovalStatus::Expired,
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
