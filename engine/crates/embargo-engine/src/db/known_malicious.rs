//! Known-malicious store. Feed syncs (`feeds`) replace the rows for a given
//! (source, ecosystem); the resolve hot path calls `is_malicious`. An
//! `ecosystem` column keeps non-npm (e.g. PyPI) entries from ever matching an
//! npm resolve — they're stored for visibility/counts only.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

/// Sentinel version meaning "every version of this package is malicious".
pub const ALL_VERSIONS: &str = "*";

/// Source name for operator-added (manual) blocklist entries.
pub const MANUAL_SOURCE: &str = "manual";

/// The ecosystem Embargo gates and enforces at resolve time.
pub const NPM_ECOSYSTEM: &str = "npm";

/// A single known-malicious entry (for the console "Known Packages" view).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub package: String,
    pub version: String,
    pub source: String,
    pub ecosystem: String,
    pub synced_at: DateTime<Utc>,
}

/// Per-(source, ecosystem) rollup: how many entries and when last refreshed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    pub source: String,
    pub ecosystem: String,
    pub count: i64,
    pub last_synced_at: DateTime<Utc>,
}

/// Return the feed source flagging this npm (package, version), if any. Only npm
/// entries are consulted — Embargo gates npm.
pub async fn is_malicious(pool: &PgPool, package: &str, version: &str) -> Result<Option<String>> {
    let row = sqlx::query!(
        r#"
        SELECT source
        FROM known_malicious
        WHERE ecosystem = 'npm' AND package = $1 AND (version = $2 OR version = '*')
        LIMIT 1
        "#,
        package,
        version,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.source))
}

/// Atomically replace all entries for (`source`, `ecosystem`) with `entries`
/// (a list of (package, version) pairs; use [`ALL_VERSIONS`] for package-wide).
/// Returns the number of rows written. Bulk-inserted via UNNEST.
pub async fn replace_source(
    pool: &PgPool,
    source: &str,
    ecosystem: &str,
    entries: &[(String, String)],
) -> Result<u64> {
    let mut tx = pool.begin().await?;
    sqlx::query!(
        "DELETE FROM known_malicious WHERE source = $1 AND ecosystem = $2",
        source,
        ecosystem,
    )
    .execute(&mut *tx)
    .await?;

    let mut written = 0u64;
    if !entries.is_empty() {
        for chunk in entries.chunks(10_000) {
            let packages: Vec<&str> = chunk.iter().map(|(p, _)| p.as_str()).collect();
            let versions: Vec<&str> = chunk.iter().map(|(_, v)| v.as_str()).collect();
            let n = sqlx::query!(
                r#"
                INSERT INTO known_malicious (package, version, source, ecosystem)
                SELECT u.package, u.version, $3, $4
                FROM UNNEST($1::text[], $2::text[]) AS u(package, version)
                ON CONFLICT (ecosystem, source, package, version) DO NOTHING
                "#,
                &packages as &[&str],
                &versions as &[&str],
                source,
                ecosystem,
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            written += n;
        }
    }
    tx.commit().await?;
    Ok(written)
}

/// List entries, optionally filtered by a package substring (case-insensitive).
/// Newest first. `search` characters `%`/`_` are escaped to literals.
pub async fn list(
    pool: &PgPool,
    search: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Entry>> {
    let pattern = search.map(|s| {
        let esc = s
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{esc}%")
    });
    let rows = sqlx::query!(
        r#"
        SELECT package, version, source, ecosystem, synced_at
        FROM known_malicious
        WHERE ($1::text IS NULL OR package ILIKE $1)
        ORDER BY synced_at DESC, package ASC
        LIMIT $2 OFFSET $3
        "#,
        pattern.as_deref(),
        limit,
        offset,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Entry {
            package: r.package,
            version: r.version,
            source: r.source,
            ecosystem: r.ecosystem,
            synced_at: r.synced_at,
        })
        .collect())
}

/// Per-(source, ecosystem) counts and most-recent sync time.
pub async fn status(pool: &PgPool) -> Result<Vec<SourceStatus>> {
    let rows = sqlx::query!(
        r#"
        SELECT source, ecosystem, COUNT(*) AS "count!", MAX(synced_at) AS "last_synced_at!"
        FROM known_malicious
        GROUP BY source, ecosystem
        ORDER BY source, ecosystem
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| SourceStatus {
            source: r.source,
            ecosystem: r.ecosystem,
            count: r.count,
            last_synced_at: r.last_synced_at,
        })
        .collect())
}

/// Add (or refresh) a single npm manual block.
pub async fn add_one(pool: &PgPool, package: &str, version: &str) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO known_malicious (package, version, source, ecosystem)
        VALUES ($1, $2, $3, 'npm')
        ON CONFLICT (ecosystem, source, package, version) DO UPDATE SET synced_at = NOW()
        "#,
        package,
        version,
        MANUAL_SOURCE,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a single entry. Returns whether a row matched.
pub async fn remove_one(
    pool: &PgPool,
    ecosystem: &str,
    source: &str,
    package: &str,
    version: &str,
) -> Result<bool> {
    let n = sqlx::query!(
        "DELETE FROM known_malicious WHERE ecosystem = $1 AND source = $2 AND package = $3 AND version = $4",
        ecosystem,
        source,
        package,
        version,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
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
    async fn replace_lookup_and_ecosystem_isolation() {
        let pool = pool().await;
        let src = format!("itest-{}", uuid::Uuid::new_v4());
        let pkg_all = format!("evil-all-{}", uuid::Uuid::new_v4());
        let pkg_pin = format!("evil-pin-{}", uuid::Uuid::new_v4());
        let pypi_pkg = format!("pypi-evil-{}", uuid::Uuid::new_v4());

        replace_source(
            &pool,
            &src,
            NPM_ECOSYSTEM,
            &[
                (pkg_all.clone(), ALL_VERSIONS.into()),
                (pkg_pin.clone(), "1.2.3".into()),
            ],
        )
        .await
        .unwrap();
        // A PyPI entry under the same package name must NOT affect npm lookups.
        replace_source(
            &pool,
            &src,
            "pypi",
            &[(pypi_pkg.clone(), ALL_VERSIONS.into())],
        )
        .await
        .unwrap();

        assert_eq!(
            is_malicious(&pool, &pkg_all, "9.9.9")
                .await
                .unwrap()
                .as_deref(),
            Some(src.as_str())
        );
        assert_eq!(
            is_malicious(&pool, &pkg_pin, "1.2.3")
                .await
                .unwrap()
                .as_deref(),
            Some(src.as_str())
        );
        assert!(is_malicious(&pool, &pkg_pin, "1.2.4")
            .await
            .unwrap()
            .is_none());
        // the pypi-only package is invisible to npm resolves
        assert!(is_malicious(&pool, &pypi_pkg, "1.0.0")
            .await
            .unwrap()
            .is_none());

        // status rolls up per (source, ecosystem)
        let st = status(&pool).await.unwrap();
        assert!(st
            .iter()
            .any(|s| s.source == src && s.ecosystem == "npm" && s.count == 2));
        assert!(st
            .iter()
            .any(|s| s.source == src && s.ecosystem == "pypi" && s.count == 1));

        // cleanup
        replace_source(&pool, &src, NPM_ECOSYSTEM, &[])
            .await
            .unwrap();
        replace_source(&pool, &src, "pypi", &[]).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn manual_add_list_remove() {
        let pool = pool().await;
        let pkg = format!("manual-evil-{}", uuid::Uuid::new_v4());

        add_one(&pool, &pkg, ALL_VERSIONS).await.unwrap();
        let listed = list(&pool, Some(&pkg), 100, 0).await.unwrap();
        assert!(listed
            .iter()
            .any(|e| e.package == pkg && e.source == MANUAL_SOURCE && e.ecosystem == "npm"));
        assert_eq!(
            is_malicious(&pool, &pkg, "9.9.9").await.unwrap().as_deref(),
            Some(MANUAL_SOURCE)
        );
        assert!(
            remove_one(&pool, NPM_ECOSYSTEM, MANUAL_SOURCE, &pkg, ALL_VERSIONS)
                .await
                .unwrap()
        );
        assert!(is_malicious(&pool, &pkg, "9.9.9").await.unwrap().is_none());
    }
}
