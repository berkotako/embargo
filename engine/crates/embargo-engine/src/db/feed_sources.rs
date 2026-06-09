//! Runtime-managed known-malicious feed sources. CRUD + the worker's `due()` /
//! `mark_synced()`. All state in Postgres; operators manage sources from the
//! console.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Minimum sync interval (mirrors the DB CHECK constraint).
pub const MIN_INTERVAL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedSource {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub ecosystem: String,
    pub format: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub created_at: DateTime<Utc>,
}

fn row_to_source(r: FeedSourceRow) -> FeedSource {
    FeedSource {
        id: r.id,
        name: r.name,
        url: r.url,
        ecosystem: r.ecosystem,
        format: r.format,
        enabled: r.enabled,
        interval_seconds: r.interval_seconds,
        last_synced_at: r.last_synced_at,
        last_status: r.last_status,
        created_at: r.created_at,
    }
}

struct FeedSourceRow {
    id: Uuid,
    name: String,
    url: String,
    ecosystem: String,
    format: String,
    enabled: bool,
    interval_seconds: i64,
    last_synced_at: Option<DateTime<Utc>>,
    last_status: Option<String>,
    created_at: DateTime<Utc>,
}

pub async fn list(pool: &PgPool) -> Result<Vec<FeedSource>> {
    let rows = sqlx::query_as!(
        FeedSourceRow,
        r#"
        SELECT id, name, url, ecosystem, format, enabled, interval_seconds,
               last_synced_at, last_status, created_at
        FROM feed_sources
        ORDER BY name
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row_to_source).collect())
}

pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<FeedSource>> {
    let row = sqlx::query_as!(
        FeedSourceRow,
        r#"
        SELECT id, name, url, ecosystem, format, enabled, interval_seconds,
               last_synced_at, last_status, created_at
        FROM feed_sources WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(row_to_source))
}

/// Add a source (idempotent on `name`: re-adding updates url/ecosystem/format).
pub async fn add(
    pool: &PgPool,
    name: &str,
    url: &str,
    ecosystem: &str,
    format: &str,
    created_by: Option<Uuid>,
) -> Result<FeedSource> {
    let row = sqlx::query_as!(
        FeedSourceRow,
        r#"
        INSERT INTO feed_sources (name, url, ecosystem, format, created_by)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (name) DO UPDATE
          SET url = EXCLUDED.url, ecosystem = EXCLUDED.ecosystem,
              format = EXCLUDED.format, updated_at = NOW()
        RETURNING id, name, url, ecosystem, format, enabled, interval_seconds,
                  last_synced_at, last_status, created_at
        "#,
        name,
        url,
        ecosystem,
        format,
        created_by,
    )
    .fetch_one(pool)
    .await?;
    Ok(row_to_source(row))
}

pub async fn set_enabled(pool: &PgPool, id: Uuid, enabled: bool) -> Result<bool> {
    let n = sqlx::query!(
        "UPDATE feed_sources SET enabled = $2, updated_at = NOW() WHERE id = $1",
        id,
        enabled,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

pub async fn set_interval(pool: &PgPool, id: Uuid, interval_seconds: i64) -> Result<bool> {
    let interval = interval_seconds.max(MIN_INTERVAL_SECONDS);
    let n = sqlx::query!(
        "UPDATE feed_sources SET interval_seconds = $2, updated_at = NOW() WHERE id = $1",
        id,
        interval,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

pub async fn remove(pool: &PgPool, id: Uuid) -> Result<bool> {
    let n = sqlx::query!("DELETE FROM feed_sources WHERE id = $1", id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Enabled sources due for a sync: never synced, or last synced ≥ interval ago.
pub async fn due(pool: &PgPool, now: DateTime<Utc>, limit: i64) -> Result<Vec<FeedSource>> {
    let rows = sqlx::query_as!(
        FeedSourceRow,
        r#"
        SELECT id, name, url, ecosystem, format, enabled, interval_seconds,
               last_synced_at, last_status, created_at
        FROM feed_sources
        WHERE enabled
          AND (last_synced_at IS NULL
               OR EXTRACT(EPOCH FROM ($1::timestamptz - last_synced_at)) >= interval_seconds)
        ORDER BY last_synced_at ASC NULLS FIRST
        LIMIT $2
        "#,
        now,
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row_to_source).collect())
}

pub async fn mark_synced(pool: &PgPool, id: Uuid, status: &str, at: DateTime<Utc>) -> Result<()> {
    sqlx::query!(
        "UPDATE feed_sources SET last_synced_at = $2, last_status = $3, updated_at = NOW() WHERE id = $1",
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
    async fn add_toggle_due_remove() {
        let pool = pool().await;
        let name = format!("itest-feed-{}", Uuid::new_v4());

        let s = add(
            &pool,
            &name,
            "https://example.test/m.json",
            "npm",
            "datadog-manifest",
            None,
        )
        .await
        .unwrap();
        assert!(!s.enabled, "new source starts disabled");

        // disabled → not due
        assert!(!due(&pool, Utc::now(), 1000)
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == s.id));
        // enable + short interval → due (never synced)
        assert!(set_enabled(&pool, s.id, true).await.unwrap());
        assert!(set_interval(&pool, s.id, MIN_INTERVAL_SECONDS)
            .await
            .unwrap());
        assert!(due(&pool, Utc::now(), 1000)
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == s.id));
        // mark synced → not due until interval passes
        mark_synced(&pool, s.id, "ok: 5", Utc::now()).await.unwrap();
        assert!(!due(&pool, Utc::now(), 1000)
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == s.id));
        let later = Utc::now() + chrono::Duration::seconds(MIN_INTERVAL_SECONDS + 10);
        assert!(due(&pool, later, 1000)
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == s.id));

        assert!(remove(&pool, s.id).await.unwrap());
        assert!(get(&pool, s.id).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn datadog_defaults_seeded() {
        let pool = pool().await;
        let all = list(&pool).await.unwrap();
        assert!(all
            .iter()
            .any(|s| s.name == "datadog-npm" && s.ecosystem == "npm" && !s.enabled));
        assert!(all
            .iter()
            .any(|s| s.name == "datadog-pypi" && s.ecosystem == "pypi"));
    }
}
