pub mod admin_svc;
pub mod engine_svc;

use anyhow::Result;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::advisory::AdvisoryClient;
use crate::auth::AuthState;
use crate::config::Config;
use crate::registry::RegistryClient;

/// Shared state injected into all gRPC service handlers.
#[derive(Clone)]
pub struct EngineState {
    pub pool: PgPool,
    pub redis: redis::aio::MultiplexedConnection,
    pub config: Config,
    /// Upstream registry client used by the background signal extractor.
    pub registry: Arc<dyn RegistryClient>,
    /// Advisory feed (OSV) client used by the extractor for advisory matching.
    pub advisory: Arc<dyn AdvisoryClient>,
    /// Admin facade authentication + RBAC state.
    pub auth: Arc<AuthState>,
    /// Cryptographic provenance trust policy used by the extractor.
    pub provenance: Arc<crate::provenance::sigstore::ProvenancePolicy>,
}

impl EngineState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        redis: redis::aio::MultiplexedConnection,
        config: Config,
        registry: Arc<dyn RegistryClient>,
        advisory: Arc<dyn AdvisoryClient>,
        auth: Arc<AuthState>,
        provenance: Arc<crate::provenance::sigstore::ProvenancePolicy>,
    ) -> Self {
        Self {
            pool,
            redis,
            config,
            registry,
            advisory,
            auth,
            provenance,
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
