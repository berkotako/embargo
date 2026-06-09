mod advisory;
mod auth;
mod cache;
mod config;
mod db;
mod extractor;
mod feeds;
mod generated;
mod grpc;
mod http;
mod observability;
mod provenance;
mod registry;
mod tarball;
#[cfg(test)]
mod testutil;
mod tracker;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Both `ring` (via tonic) and `aws-lc-rs` (rustls default) are linked, so
    // rustls cannot auto-select a provider. Pin ring for the gRPC mTLS listener.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let cfg = config::Config::load()?;
    observability::init(&cfg.observability)?;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "embargo-engine starting"
    );

    let pool = db::connect(&cfg.database).await?;
    db::migrate(&pool).await?;

    // First-boot convenience: if there's no active policy yet and a bootstrap
    // file is configured, install it so resolve has something to enforce.
    if !cfg.bootstrap_policy_path.is_empty() && db::policies::get_active(&pool).await?.is_none() {
        match std::fs::read_to_string(&cfg.bootstrap_policy_path) {
            Ok(yaml) => match embargo_core::policy::PolicyRuleset::from_yaml(&yaml) {
                Ok(ruleset) => {
                    db::policies::upsert(
                        &pool,
                        &ruleset,
                        &yaml,
                        uuid::Uuid::nil(),
                        "bootstrap policy",
                    )
                    .await?;
                    info!(path = %cfg.bootstrap_policy_path, "installed bootstrap policy");
                }
                Err(e) => tracing::warn!(error = %e, "bootstrap policy failed to parse; skipping"),
            },
            Err(e) => {
                tracing::warn!(error = %e, path = %cfg.bootstrap_policy_path, "bootstrap policy unreadable; skipping")
            }
        }
    }

    let redis = cache::connect(&cfg.redis).await?;
    let metrics_server = observability::spawn_metrics_server(cfg.metrics_addr.clone());

    let registry = std::sync::Arc::new(registry::HttpRegistryClient::new(
        cfg.upstream_registry.clone(),
    )?);
    let advisory = std::sync::Arc::new(advisory::OsvClient::new(cfg.osv_endpoint.clone())?);

    let auth = std::sync::Arc::new(auth::AuthState::build(&cfg.auth).await?);
    if auth.mode == auth::Mode::Disabled {
        tracing::warn!(
            "admin facade auth is DISABLED — every request is treated as admin. \
             Set auth.mode=oidc for any real deployment."
        );
    }
    let engine = grpc::EngineState::new(pool, redis, cfg.clone(), registry, advisory, auth);

    // JSON admin facade for the console (separate port from gRPC + metrics).
    let admin_server = {
        let addr = cfg.admin_http_addr.clone();
        let router = http::router(engine.clone());
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            info!(%addr, "admin HTTP facade listening");
            axum::serve(listener, router).await?;
            Ok::<(), anyhow::Error>(())
        })
    };

    // Background watchlist tracker (detached daemon over db::watchlist).
    let _tracker = tracker::spawn(engine.clone());
    // Known-malicious feed sync (opt-in; no-op when disabled).
    let _feed = feeds::spawn(engine.clone());

    let grpc_server = grpc::serve(engine, &cfg).await?;

    // Each arm is JoinHandle<Result<()>>; `??` unwraps the JoinError then the inner Result.
    tokio::select! {
        res = grpc_server => { res??; }
        res = metrics_server => { res??; }
        res = admin_server => { res??; }
    }

    Ok(())
}
