//! Watchlist store. Operators add packages/scopes to track; the tracking worker
//! reads `due()` entries, re-resolves them, and calls `mark_checked()`. All
//! state is persisted in Postgres — there is no in-memory tracking state.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchEntry {
    pub id: Uuid,
    pub target: String,
    pub kind: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Minimum allowed check interval (mirrors the DB CHECK constraint).
pub const MIN_INTERVAL_SECONDS: i64 = 60;

/// Add a target to the watchlist. Idempotent on `target`: re-adding an existing
/// target updates its kind/interval and re-enables it rather than erroring.
pub async fn add(
    pool: &PgPool,
    target: &str,
    kind: &str,
    interval_seconds: i64,
    created_by: Option<Uuid>,
) -> Result<WatchEntry> {
    let interval = interval_seconds.max(MIN_INTERVAL_SECONDS);
    let r = sqlx::query!(
        r#"
        INSERT INTO watchlist (target, kind, interval_seconds, created_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (target) DO UPDATE
          SET kind = EXCLUDED.kind,
              interval_seconds = EXCLUDED.interval_seconds,
              enabled = TRUE,
              updated_at = NOW()
        RETURNING id, target, kind, enabled, interval_seconds,
                  last_checked_at, last_status, created_at
        "#,
        target,
        kind,
        interval,
        created_by,
    )
    .fetch_one(pool)
    .await?;
    Ok(WatchEntry {
        id: r.id,
        target: r.target,
        kind: r.kind,
        enabled: r.enabled,
        interval_seconds: r.interval_seconds,
        last_checked_at: r.last_checked_at,
        last_status: r.last_status,
        created_at: r.created_at,
    })
}

/// List all watchlist entries, newest first.
pub async fn list(pool: &PgPool) -> Result<Vec<WatchEntry>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, target, kind, enabled, interval_seconds,
               last_checked_at, last_status, created_at
        FROM watchlist
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| WatchEntry {
            id: r.id,
            target: r.target,
            kind: r.kind,
            enabled: r.enabled,
            interval_seconds: r.interval_seconds,
            last_checked_at: r.last_checked_at,
            last_status: r.last_status,
            created_at: r.created_at,
        })
        .collect())
}

/// Enable or disable tracking for an entry. Returns whether a row matched.
pub async fn set_enabled(pool: &PgPool, id: Uuid, enabled: bool) -> Result<bool> {
    let n = sqlx::query!(
        "UPDATE watchlist SET enabled = $2, updated_at = NOW() WHERE id = $1",
        id,
        enabled,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Change the check interval (clamped to the minimum). Returns whether a row matched.
pub async fn set_interval(pool: &PgPool, id: Uuid, interval_seconds: i64) -> Result<bool> {
    let interval = interval_seconds.max(MIN_INTERVAL_SECONDS);
    let n = sqlx::query!(
        "UPDATE watchlist SET interval_seconds = $2, updated_at = NOW() WHERE id = $1",
        id,
        interval,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Remove an entry. Returns whether a row matched.
pub async fn remove(pool: &PgPool, id: Uuid) -> Result<bool> {
    let n = sqlx::query!("DELETE FROM watchlist WHERE id = $1", id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Entries due for a check at `now`: enabled, and either never checked or last
/// checked at least `interval_seconds` ago. Ordered oldest-checked first so the
/// worker makes progress fairly.
pub async fn due(pool: &PgPool, now: DateTime<Utc>, limit: i64) -> Result<Vec<WatchEntry>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, target, kind, enabled, interval_seconds,
               last_checked_at, last_status, created_at
        FROM watchlist
        WHERE enabled
          AND (last_checked_at IS NULL
               OR EXTRACT(EPOCH FROM ($1::timestamptz - last_checked_at)) >= interval_seconds)
        ORDER BY last_checked_at ASC NULLS FIRST
        LIMIT $2
        "#,
        now,
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| WatchEntry {
            id: r.id,
            target: r.target,
            kind: r.kind,
            enabled: r.enabled,
            interval_seconds: r.interval_seconds,
            last_checked_at: r.last_checked_at,
            last_status: r.last_status,
            created_at: r.created_at,
        })
        .collect())
}

/// Record the result of a tracking check, advancing `last_checked_at`.
pub async fn mark_checked(pool: &PgPool, id: Uuid, status: &str, at: DateTime<Utc>) -> Result<()> {
    sqlx::query!(
        "UPDATE watchlist SET last_checked_at = $2, last_status = $3, updated_at = NOW() WHERE id = $1",
        id,
        at,
        status,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn pool() -> PgPool {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn add_list_toggle_due_remove_roundtrip() {
        let pool = pool().await;
        let target = format!("wl-itest-{}", Uuid::new_v4());

        // add
        let e = add(&pool, &target, "package", 120, None).await.unwrap();
        assert_eq!(e.target, target);
        assert!(e.enabled);
        assert_eq!(e.interval_seconds, 120);

        // a never-checked enabled entry is due now
        let due_now = due(&pool, Utc::now(), 1000).await.unwrap();
        assert!(
            due_now.iter().any(|x| x.id == e.id),
            "new entry must be due"
        );

        // mark checked → no longer due until the interval elapses
        mark_checked(&pool, e.id, "ok", Utc::now()).await.unwrap();
        let due_after = due(&pool, Utc::now(), 1000).await.unwrap();
        assert!(
            !due_after.iter().any(|x| x.id == e.id),
            "just-checked entry must not be due"
        );
        // …but it IS due once enough time has passed.
        let later = Utc::now() + chrono::Duration::seconds(200);
        let due_later = due(&pool, later, 1000).await.unwrap();
        assert!(due_later.iter().any(|x| x.id == e.id));

        // disable → never due
        assert!(set_enabled(&pool, e.id, false).await.unwrap());
        let due_disabled = due(&pool, later, 1000).await.unwrap();
        assert!(!due_disabled.iter().any(|x| x.id == e.id));

        // interval clamps to the minimum
        assert!(set_interval(&pool, e.id, 5).await.unwrap());
        let listed = list(&pool).await.unwrap();
        let found = listed.iter().find(|x| x.id == e.id).unwrap();
        assert_eq!(found.interval_seconds, MIN_INTERVAL_SECONDS);

        // remove
        assert!(remove(&pool, e.id).await.unwrap());
        assert!(!list(&pool).await.unwrap().iter().any(|x| x.id == e.id));
    }
}
