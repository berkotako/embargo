//! Feed ingestion worker.
//!
//! Syncs each enabled feed source (`db::feed_sources`) into `db::known_malicious`
//! on its interval. Sources are managed at runtime from the console — operators
//! add a curated dataset URL and toggle it on. Today the Datadog manifest format
//! (`{ "pkg": null | ["1.0.0", ...] }`) is supported.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::time::Duration;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::db::{self, feed_sources::FeedSource};
use crate::grpc::EngineState;

/// How often to scan for due sources.
const TICK: Duration = Duration::from_secs(30);
/// Max sources synced per pass.
const BATCH: i64 = 10;

/// Spawn the detached feed-sync worker. Runs for the process lifetime; a source
/// is only fetched when enabled and due, so an all-disabled deployment is idle.
pub fn spawn(state: EngineState) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("feed sync worker started");
        loop {
            tokio::time::sleep(TICK).await;
            if let Err(e) = run_pass(&state).await {
                tracing::warn!(error = %e, "feed sync pass failed");
            }
        }
    })
}

async fn run_pass(state: &EngineState) -> Result<()> {
    let due = db::feed_sources::due(&state.pool, Utc::now(), BATCH).await?;
    for src in due {
        let status = match sync_one(state, &src).await {
            Ok(n) => format!("ok: {n} entries"),
            Err(e) => {
                tracing::warn!(source = %src.name, error = %e, "feed sync failed");
                format!("error: {e}")
            }
        };
        db::feed_sources::mark_synced(&state.pool, src.id, &status, Utc::now()).await?;
    }
    Ok(())
}

/// Sync a single source now (manual trigger). Records status; returns rows written.
pub async fn sync_source(state: &EngineState, id: Uuid) -> Result<u64> {
    let src = db::feed_sources::get(&state.pool, id)
        .await?
        .ok_or_else(|| anyhow!("feed source not found"))?;
    let result = sync_one(state, &src).await;
    let status = match &result {
        Ok(n) => format!("ok: {n} entries"),
        Err(e) => format!("error: {e}"),
    };
    db::feed_sources::mark_synced(&state.pool, src.id, &status, Utc::now()).await?;
    result
}

async fn sync_one(state: &EngineState, src: &FeedSource) -> Result<u64> {
    let body = reqwest::get(&src.url)
        .await
        .context("fetch feed")?
        .error_for_status()
        .context("feed HTTP status")?
        .text()
        .await
        .context("read feed body")?;
    let entries = match src.format.as_str() {
        "datadog-manifest" => parse_manifest(&body)?,
        other => return Err(anyhow!("unsupported feed format: {other}")),
    };
    let written =
        db::known_malicious::replace_source(&state.pool, &src.name, &src.ecosystem, &entries)
            .await?;
    Ok(written)
}

/// Parse a manifest of the form `{ "pkg": null | ["1.0.0", ...] }` into
/// (package, version) pairs. A `null` value means every version is malicious and
/// maps to a single [`db::known_malicious::ALL_VERSIONS`] row.
pub fn parse_manifest(body: &str) -> Result<Vec<(String, String)>> {
    use serde_json::Value;
    let map: serde_json::Map<String, Value> =
        serde_json::from_str(body).context("parse feed manifest JSON")?;
    let mut out = Vec::with_capacity(map.len());
    for (pkg, versions) in map {
        match versions {
            Value::Null => out.push((pkg, db::known_malicious::ALL_VERSIONS.to_string())),
            Value::Array(vs) => {
                for v in vs {
                    if let Some(s) = v.as_str() {
                        out.push((pkg.clone(), s.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_null_and_list_entries() {
        let json = r#"{
            "evil-all": null,
            "@scope/compromised": ["1.0.0", "1.0.1"],
            "weird": 42
        }"#;
        let mut e = parse_manifest(json).unwrap();
        e.sort();
        assert!(e.contains(&("evil-all".into(), "*".into())));
        assert!(e.contains(&("@scope/compromised".into(), "1.0.0".into())));
        assert!(e.contains(&("@scope/compromised".into(), "1.0.1".into())));
        assert!(!e.iter().any(|(p, _)| p == "weird"));
    }
}
