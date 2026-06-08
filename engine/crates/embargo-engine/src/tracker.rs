//! Watchlist tracking worker.
//!
//! Periodically re-evaluates each enabled watchlist target so a newly-published
//! release is analyzed proactively (cooldown / signals / advisories /
//! typosquatting) instead of only when a client first resolves it. State lives
//! entirely in Postgres (`db::watchlist`); this is a stateless daemon over it,
//! safe to run as a single instance.

use anyhow::{anyhow, Result};
use chrono::Utc;
use std::time::Duration;
use tokio::task::JoinHandle;

use crate::grpc::EngineState;
use crate::{db, extractor, registry};

/// How often to scan for due targets.
const TICK: Duration = Duration::from_secs(30);
/// Max targets processed per pass (bounds upstream fan-out per tick).
const BATCH: i64 = 50;

/// Spawn the tracker as a detached background task. Runs for the process
/// lifetime; per-target failures are logged and recorded, never fatal.
pub fn spawn(state: EngineState) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("watchlist tracker started");
        loop {
            tokio::time::sleep(TICK).await;
            if let Err(e) = run_pass(&state).await {
                tracing::warn!(error = %e, "watchlist tracking pass failed");
            }
        }
    })
}

/// One scan: process every entry currently due for a check.
async fn run_pass(state: &EngineState) -> Result<()> {
    let due = db::watchlist::due(&state.pool, Utc::now(), BATCH).await?;
    for entry in due {
        let status = match track_one(state, &entry).await {
            Ok(detail) => format!("ok: {detail}"),
            Err(e) => {
                tracing::warn!(target = %entry.target, error = %e, "tracking target failed");
                format!("error: {e}")
            }
        };
        db::watchlist::mark_checked(&state.pool, entry.id, &status, Utc::now()).await?;
    }
    Ok(())
}

/// Track a single target: fetch its latest published version and run extraction
/// so the signal/provenance/advisory stores are populated ahead of any resolve.
async fn track_one(state: &EngineState, entry: &db::watchlist::WatchEntry) -> Result<String> {
    // A scope has no single packument; its members are analyzed on client
    // resolve. We still advance its check clock so the cadence is honored.
    if entry.kind != "package" {
        return Ok("scope: members evaluated on resolve".into());
    }

    let packument = state.registry.packument(&entry.target).await?;
    let latest =
        registry::latest_version(&packument).ok_or_else(|| anyhow!("no published versions"))?;

    extractor::extract_and_store(
        state.registry.as_ref(),
        state.advisory.as_ref(),
        &state.pool,
        &entry.target,
        &latest,
    )
    .await?;

    Ok(format!("extracted {}@{latest}", entry.target))
}
