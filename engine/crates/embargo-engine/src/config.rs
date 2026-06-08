use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub grpc: GrpcConfig,
    pub tls: TlsConfig,
    pub observability: ObservabilityConfig,
    pub metrics_addr: String,
    /// Address for the JSON admin HTTP facade the console talks to.
    pub admin_http_addr: String,
    /// Upstream npm registry the signal extractor fetches packuments/tarballs from.
    pub upstream_registry: String,
    /// OSV advisory database endpoint for advisory matching.
    pub osv_endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    /// Verdict TTL in seconds. Aligns with cooldown granularity.
    pub verdict_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrpcConfig {
    pub addr: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    pub otlp_endpoint: Option<String>,
    pub log_format: LogFormat,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

impl Config {
    pub fn load() -> Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("config/engine").required(false))
            .add_source(config::Environment::with_prefix("EMBARGO").separator("__"))
            .set_default("database.max_connections", 10)?
            .set_default("redis.verdict_ttl_secs", 300u64)?
            .set_default("grpc.addr", "[::]:50051")?
            .set_default("metrics_addr", "[::]:9090")?
            .set_default("admin_http_addr", "[::]:8080")?
            .set_default("observability.log_format", "json")?
            .set_default("observability.log_level", "info")?
            .set_default("upstream_registry", "https://registry.npmjs.org")?
            .set_default("osv_endpoint", "https://api.osv.dev")?
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}
