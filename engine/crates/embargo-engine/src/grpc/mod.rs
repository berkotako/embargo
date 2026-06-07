pub mod admin_svc;
pub mod engine_svc;

use anyhow::Result;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::config::Config;

/// Shared state injected into all gRPC service handlers.
#[derive(Clone)]
pub struct EngineState {
    pub pool: PgPool,
    pub redis: redis::aio::MultiplexedConnection,
    pub config: Config,
}

impl EngineState {
    pub fn new(pool: PgPool, redis: redis::aio::MultiplexedConnection, config: Config) -> Self {
        Self {
            pool,
            redis,
            config,
        }
    }
}

pub async fn serve(state: EngineState, cfg: &Config) -> Result<JoinHandle<Result<()>>> {
    use crate::generated::embargo::v1::{
        admin_service_server::AdminServiceServer, engine_service_server::EngineServiceServer,
    };

    let addr = cfg.grpc.addr.parse()?;

    let cert = tokio::fs::read(&cfg.tls.cert_pem).await?;
    let key = tokio::fs::read(&cfg.tls.key_pem).await?;
    let ca = tokio::fs::read(&cfg.tls.ca_pem).await?;

    let identity = Identity::from_pem(cert, key);
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(ca));

    let engine_svc = EngineServiceServer::new(engine_svc::EngineServiceImpl::new(state.clone()));
    let admin_svc = AdminServiceServer::new(admin_svc::AdminServiceImpl::new(state));

    let handle = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)?
            .add_service(engine_svc)
            .add_service(admin_svc)
            .serve(addr)
            .await?;
        Ok(())
    });

    tracing::info!(%addr, "gRPC server listening");
    Ok(handle)
}
