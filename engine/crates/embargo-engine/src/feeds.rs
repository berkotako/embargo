//! External feed ingestion.
//!
//! The known-malicious feed: a periodic sync of a curated dataset (default
//! Datadog's `malicious-software-packages-dataset` npm manifest, Apache-2.0 —
//! see NOTICE) into `db::known_malicious`, where a match is an immediate DENY on
//! resolve. Opt-in via `known_malicious_feed.enabled`.

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::task::JoinHandle;

use crate::db;
use crate::grpc::EngineState;

/// Spawn the known-malicious feed sync loop, or `None` when disabled.
pub fn spawn(state: EngineState) -> Option<JoinHandle<()>> {
    let cfg = state.config.known_malicious_feed.clone();
    if !cfg.enabled {
        tracing::info!("known-malicious feed disabled (set known_malicious_feed.enabled=true)");
        return None;
    }
    Some(tokio::spawn(async move {
        // Floor the cadence so a misconfig can't hammer the upstream.
        let interval = Duration::from_secs(cfg.interval_secs.max(300));
        tracing::info!(url = %cfg.url, source = %cfg.source, "known-malicious feed enabled");
        loop {
            match sync_known_malicious(&state, &cfg.url, &cfg.source).await {
                Ok(n) => {
                    tracing::info!(source = %cfg.source, entries = n, "known-malicious feed synced")
                }
                Err(e) => tracing::warn!(error = %e, "known-malicious feed sync failed"),
            }
            tokio::time::sleep(interval).await;
        }
    }))
}

/// Fetch the manifest at `url`, parse it, and atomically replace the stored
/// entries for `source`. Returns the number of (package, version) rows written.
pub async fn sync_known_malicious(state: &EngineState, url: &str, source: &str) -> Result<u64> {
    let body = reqwest::get(url)
        .await
        .context("fetch known-malicious manifest")?
        .error_for_status()
        .context("known-malicious manifest HTTP status")?
        .text()
        .await
        .context("read known-malicious manifest body")?;
    let entries = parse_manifest(&body)?;
    let written = db::known_malicious::replace_source(&state.pool, source, &entries).await?;
    Ok(written)
}

/// Parse a manifest of the form `{ "pkg": null | ["1.0.0", ...], ... }` into
/// (package, version) pairs. A `null` value means every version is malicious and
/// maps to a single [`db::known_malicious::ALL_VERSIONS`] row.
pub fn parse_manifest(body: &str) -> Result<Vec<(String, String)>> {
    use serde_json::Value;
    let map: serde_json::Map<String, Value> =
        serde_json::from_str(body).context("parse known-malicious manifest JSON")?;
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
            // Ignore unexpected shapes rather than failing the whole sync.
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
        // unexpected value shapes are skipped, not fatal
        assert!(!e.iter().any(|(p, _)| p == "weird"));
    }
}
