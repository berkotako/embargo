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
    /// Cryptographic provenance (Sigstore) verification trust policy.
    #[serde(default)]
    pub provenance: ProvenanceConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProvenanceConfig {
    /// PEM bundle of trusted Sigstore Fulcio CA certificates (root +
    /// intermediates). Empty disables verification — provenance can never be
    /// reported `Verified`, so `require_provenance` policies fail safe (DENY).
    #[serde(default)]
    pub trust_root_pem: String,
    /// Accepted OIDC issuer URLs in the signing certificate (e.g.
    /// `https://token.actions.githubusercontent.com`). Empty = do not constrain.
    #[serde(default)]
    pub accepted_issuers: Vec<String>,
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
