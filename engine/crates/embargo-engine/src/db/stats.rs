//! Aggregate queries for the console dashboard.

use anyhow::Result;
use sqlx::PgPool;

pub struct Dashboard {
    pub held: i64,
    pub denied: i64,
    pub allowed: i64,
    pub advisory_matches: i64,
    /// HOLD counts per day for the last 7 days (oldest first).
    pub held_trend: Vec<i64>,
    /// (signal_type, count) for the top signal types.
    pub top_signals: Vec<(String, i64)>,
    /// Recent containment events (from sandbox/eBPF reports).
    pub recent_events: Vec<ContainmentRow>,
}

pub struct ContainmentRow {
    pub id: uuid::Uuid,
    pub evidence: serde_json::Value,
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

pub async fn dashboard(pool: &PgPool) -> Result<Dashboard> {
    // Verdict counts (1=ALLOW 2=HOLD 3=DENY).
    let counts = sqlx::query!(
        r#"
        SELECT
          COUNT(*) FILTER (WHERE verdict = 2) AS held,
          COUNT(*) FILTER (WHERE verdict = 3) AS denied,
          COUNT(*) FILTER (WHERE verdict = 1) AS allowed
        FROM verdicts
        "#
    )
    .fetch_one(pool)
    .await?;

    let advisory_matches =
        sqlx::query_scalar!("SELECT COUNT(*) FROM signals WHERE signal_type = 'advisory_match'")
            .fetch_one(pool)
            .await?
            .unwrap_or(0);

    // HOLD verdicts per day over the last 7 days.
    let trend_rows = sqlx::query!(
        r#"
        SELECT d::date AS "day!", COALESCE(c.n, 0) AS "n!"
        FROM generate_series(
            (NOW() - INTERVAL '6 days')::date, NOW()::date, INTERVAL '1 day'
        ) AS d
        LEFT JOIN (
            SELECT computed_at::date AS day, COUNT(*) AS n
            FROM verdicts WHERE verdict = 2 GROUP BY computed_at::date
        ) c ON c.day = d::date
        ORDER BY d
        "#
    )
    .fetch_all(pool)
    .await?;
    let held_trend = trend_rows.into_iter().map(|r| r.n).collect();

    // Top signal types (exclude the composite chain pseudo-types for clarity).
    let sig_rows = sqlx::query!(
        r#"
        SELECT signal_type AS "signal_type!", COUNT(*) AS "n!"
        FROM signals
        GROUP BY signal_type
        ORDER BY COUNT(*) DESC
        LIMIT 5
        "#
    )
    .fetch_all(pool)
    .await?;
    let top_signals = sig_rows.into_iter().map(|r| (r.signal_type, r.n)).collect();

    // Recent containment events reported by the sandbox (L3) / eBPF (M4).
    let event_rows = sqlx::query!(
        r#"
        SELECT id, evidence, detected_at
        FROM signals
        WHERE signal_type IN ('sandbox_egress_attempt', 'ebpf_compromise_chain')
        ORDER BY detected_at DESC
        LIMIT 10
        "#
    )
    .fetch_all(pool)
    .await?;
    let recent_events = event_rows
        .into_iter()
        .map(|r| ContainmentRow {
            id: r.id,
            evidence: r.evidence,
            detected_at: r.detected_at,
        })
        .collect();

    Ok(Dashboard {
        held: counts.held.unwrap_or(0),
        denied: counts.denied.unwrap_or(0),
        allowed: counts.allowed.unwrap_or(0),
        advisory_matches,
        held_trend,
        top_signals,
        recent_events,
    })
}

/// Policy dry-run preview: total verdicts and how many are currently blocked.
pub async fn dryrun(pool: &PgPool) -> Result<(i64, i64)> {
    let row = sqlx::query!(
        r#"
        SELECT COUNT(*) AS "total!",
               COUNT(*) FILTER (WHERE verdict IN (2, 3)) AS "blocked!"
        FROM verdicts
        "#
    )
    .fetch_one(pool)
    .await?;
    Ok((row.total, row.blocked))
}
