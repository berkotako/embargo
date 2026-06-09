//! Known-malicious feed store. A periodic sync (`feeds::sync_known_malicious`)
//! replaces the rows for a source; the resolve hot path calls `is_malicious`.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

/// Sentinel version meaning "every version of this package is malicious".
pub const ALL_VERSIONS: &str = "*";

/// Source name for operator-added (manual) blocklist entries.
pub const MANUAL_SOURCE: &str = "manual";

/// A single known-malicious entry (for the console "Known Packages" view).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub package: String,
    pub version: String,
    pub source: String,
    pub synced_at: DateTime<Utc>,
}

/// Per-source rollup: how many entries and when last refreshed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    pub source: String,
    pub count: i64,
    pub last_synced_at: DateTime<Utc>,
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
        SELECT package, version, source, synced_at
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
            synced_at: r.synced_at,
        })
        .collect())
}

/// Per-source counts and most-recent sync time.
pub async fn status(pool: &PgPool) -> Result<Vec<SourceStatus>> {
    let rows = sqlx::query!(
        r#"
        SELECT source, COUNT(*) AS "count!", MAX(synced_at) AS "last_synced_at!"
        FROM known_malicious
        GROUP BY source
        ORDER BY source
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| SourceStatus {
            source: r.source,
            count: r.count,
            last_synced_at: r.last_synced_at,
        })
        .collect())
}

/// Add (or refresh) a single entry — used for operator-added manual blocks.
pub async fn add_one(pool: &PgPool, package: &str, version: &str, source: &str) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO known_malicious (package, version, source)
        VALUES ($1, $2, $3)
        ON CONFLICT (source, package, version) DO UPDATE SET synced_at = NOW()
        "#,
        package,
        version,
        source,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a single entry. Returns whether a row matched.
pub async fn remove_one(pool: &PgPool, package: &str, version: &str, source: &str) -> Result<bool> {
    let n = sqlx::query!(
        "DELETE FROM known_malicious WHERE package = $1 AND version = $2 AND source = $3",
        package,
        version,
        source,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Return the feed source that flags this (package, version), if any. Matches an
/// exact pinned version or a package-wide (`*`) entry.
pub async fn is_malicious(pool: &PgPool, package: &str, version: &str) -> Result<Option<String>> {
    let row = sqlx::query!(
        r#"
        SELECT source
        FROM known_malicious
        WHERE package = $1 AND (version = $2 OR version = '*')
        LIMIT 1
        "#,
        package,
        version,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.source))
}

/// Atomically replace all entries for `source` with `entries` (a list of
/// (package, version) pairs; use [`ALL_VERSIONS`] for package-wide). Returns the
/// number of rows written. Bulk-inserted via UNNEST for throughput.
pub async fn replace_source(
    pool: &PgPool,
    source: &str,
    entries: &[(String, String)],
) -> Result<u64> {
    let mut tx = pool.begin().await?;
    sqlx::query!("DELETE FROM known_malicious WHERE source = $1", source)
        .execute(&mut *tx)
        .await?;

    let mut written = 0u64;
    if !entries.is_empty() {
        // Chunk to keep parameter arrays a sane size.
        for chunk in entries.chunks(10_000) {
            let packages: Vec<&str> = chunk.iter().map(|(p, _)| p.as_str()).collect();
            let versions: Vec<&str> = chunk.iter().map(|(_, v)| v.as_str()).collect();
            let n = sqlx::query!(
                r#"
                INSERT INTO known_malicious (package, version, source)
                SELECT u.package, u.version, $3
                FROM UNNEST($1::text[], $2::text[]) AS u(package, version)
                ON CONFLICT (source, package, version) DO NOTHING
                "#,
                &packages as &[&str],
                &versions as &[&str],
                source,
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
    async fn replace_and_lookup() {
        let pool = pool().await;
        let src = format!("itest-{}", uuid::Uuid::new_v4());
        let pkg_all = format!("evil-all-{}", uuid::Uuid::new_v4());
        let pkg_pinned = format!("evil-pin-{}", uuid::Uuid::new_v4());

        let entries = vec![
            (pkg_all.clone(), ALL_VERSIONS.to_string()),
            (pkg_pinned.clone(), "1.2.3".to_string()),
        ];
        let n = replace_source(&pool, &src, &entries).await.unwrap();
        assert_eq!(n, 2);

        // package-wide match: any version flagged
        assert_eq!(
            is_malicious(&pool, &pkg_all, "9.9.9")
                .await
                .unwrap()
                .as_deref(),
            Some(src.as_str())
        );
        // pinned: only the exact version
        assert_eq!(
            is_malicious(&pool, &pkg_pinned, "1.2.3")
                .await
                .unwrap()
                .as_deref(),
            Some(src.as_str())
        );
        assert!(is_malicious(&pool, &pkg_pinned, "1.2.4")
            .await
            .unwrap()
            .is_none());
        // unknown package
        assert!(is_malicious(&pool, "totally-fine-pkg", "1.0.0")
            .await
            .unwrap()
            .is_none());

        // replace is idempotent: re-running with one entry removes the others
        let n2 = replace_source(&pool, &src, &[(pkg_pinned.clone(), "1.2.3".into())])
            .await
            .unwrap();
        assert_eq!(n2, 1);
        assert!(is_malicious(&pool, &pkg_all, "9.9.9")
            .await
            .unwrap()
            .is_none());

        // cleanup
        replace_source(&pool, &src, &[]).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn manual_add_list_status_remove() {
        let pool = pool().await;
        let pkg = format!("manual-evil-{}", uuid::Uuid::new_v4());

        add_one(&pool, &pkg, ALL_VERSIONS, MANUAL_SOURCE)
            .await
            .unwrap();

        // search finds the manual entry
        let listed = list(&pool, Some(&pkg), 100, 0).await.unwrap();
        assert!(listed
            .iter()
            .any(|e| e.package == pkg && e.source == MANUAL_SOURCE));

        // status rolls up the manual source
        let st = status(&pool).await.unwrap();
        assert!(st.iter().any(|s| s.source == MANUAL_SOURCE && s.count >= 1));

        // a manual all-versions block flags any version on lookup
        assert_eq!(
            is_malicious(&pool, &pkg, "9.9.9").await.unwrap().as_deref(),
            Some(MANUAL_SOURCE)
        );

        // remove clears it
        assert!(remove_one(&pool, &pkg, ALL_VERSIONS, MANUAL_SOURCE)
            .await
            .unwrap());
        assert!(is_malicious(&pool, &pkg, "9.9.9").await.unwrap().is_none());
    }
}
