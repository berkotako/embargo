use anyhow::Result;
use axum::{routing::get, Router};
use tokio::task::JoinHandle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{LogFormat, ObservabilityConfig};

pub fn init(cfg: &ObservabilityConfig) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));

    match cfg.log_format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }

    // TODO(M1): wire OTel OTLP exporter when cfg.otlp_endpoint is set.

    Ok(())
}

pub fn spawn_metrics_server(addr: String) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health/live", get(|| async { "ok" }))
            .route("/health/ready", get(|| async { "ok" }));

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!(%addr, "metrics/health server listening");
        axum::serve(listener, app).await?;
        Ok(())
    })
}

async fn metrics_handler() -> String {
    use prometheus::{Encoder, TextEncoder};
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap_or_default();
    String::from_utf8_lossy(&buffer).to_string()
}
