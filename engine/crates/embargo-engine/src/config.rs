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
    /// Optional YAML policy installed on first boot when no policy is active.
    #[serde(default)]
    pub bootstrap_policy_path: String,
    /// Admin facade authentication.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Known-malicious package feed (opt-in).
    #[serde(default)]
    pub known_malicious_feed: KnownMaliciousFeedConfig,
}

/// External known-malicious package feed. Default URL is Datadog's
/// malicious-software-packages-dataset npm manifest (Apache-2.0; see NOTICE).
#[derive(Debug, Clone, Deserialize)]
pub struct KnownMaliciousFeedConfig {
    /// Disabled by default — operators opt in.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_km_url")]
    pub url: String,
    /// Logical source name recorded on each entry.
    #[serde(default = "default_km_source")]
    pub source: String,
    /// Re-sync cadence in seconds (default 6h).
    #[serde(default = "default_km_interval")]
    pub interval_secs: u64,
}

fn default_km_url() -> String {
    "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json".into()
}
fn default_km_source() -> String {
    "datadog".into()
}
fn default_km_interval() -> u64 {
    21_600
}

impl Default for KnownMaliciousFeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_km_url(),
            source: default_km_source(),
            interval_secs: default_km_interval(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// "oidc" | "dev" | "disabled" (default).
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub audience: String,
    /// JWKS endpoint (fetched at startup) for `oidc` mode.
    #[serde(default)]
    pub jwks_url: String,
    /// Inline JWKS JSON (wins over jwks_url; useful air-gapped / in tests).
    #[serde(default)]
    pub jwks_inline: String,
    /// Claim holding the user's roles/groups (dotted paths allowed). Default "roles".
    #[serde(default)]
    pub roles_claim: String,
    /// Claim holding the user's email. Default "email".
    #[serde(default)]
    pub email_claim: String,
    /// IdP roles/groups mapped to the Embargo admin role. Default ["embargo-admin"].
    #[serde(default)]
    pub admin_roles: Vec<String>,
    /// IdP roles/groups mapped to the Embargo responder role.
    #[serde(default)]
    pub responder_roles: Vec<String>,
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
