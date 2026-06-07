mod cache;
mod config;
mod db;
mod generated;
mod grpc;
mod observability;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::Config::load()?;
    observability::init(&cfg.observability)?;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "embargo-engine starting"
    );

    let pool = db::connect(&cfg.database).await?;
    db::migrate(&pool).await?;

    let redis = cache::connect(&cfg.redis).await?;
    let metrics_server = observability::spawn_metrics_server(cfg.metrics_addr.clone());

    let engine = grpc::EngineState::new(pool, redis, cfg.clone());
    let grpc_server = grpc::serve(engine, &cfg).await?;

    // Each arm is JoinHandle<Result<()>>; `??` unwraps the JoinError then the inner Result.
    tokio::select! {
        res = grpc_server => { res??; }
        res = metrics_server => { res??; }
    }

    Ok(())
}
