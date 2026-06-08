//! Authentication + authorization for the admin facade.
//!
//! Three modes (config `auth.mode`):
//! - `oidc` — verify an RS256 bearer JWT against the IdP's JWKS, check
//!   iss/aud/exp, map a roles claim to an Embargo role. Production.
//! - `dev` — trust `X-Embargo-Role` / `X-Embargo-Email` headers. Local only.
//! - `disabled` — no auth; every request is treated as an admin. Logged loudly
//!   at startup. Never run a real deployment this way.
//!
//! RBAC mirrors the console (`viewer` / `responder` / `admin`); the server is the
//! source of truth — the console only reflects what the engine permits.

use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;

use crate::grpc::EngineState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Disabled,
    Dev,
    Oidc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Responder,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ReadVerdicts,
    ReadPolicies,
    ReadAudit,
    ReadApprovals,
    WriteApprovals,
    /// Reserved for the policy-write endpoint (admin-only) once it lands.
    #[allow(dead_code)]
    WritePolicies,
}

impl Role {
    /// Permission model — identical to the console's `lib/rbac.ts`.
    pub fn can(self, p: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Viewer => matches!(p, ReadVerdicts | ReadPolicies | ReadAudit | ReadApprovals),
            Role::Responder => matches!(
                p,
                ReadVerdicts | ReadPolicies | ReadAudit | ReadApprovals | WriteApprovals
            ),
            Role::Admin => true,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Responder => "responder",
            Role::Admin => "admin",
        }
    }

    fn from_header(s: &str) -> Role {
        match s {
            "admin" => Role::Admin,
            "responder" => Role::Responder,
            _ => Role::Viewer,
        }
    }
}

/// The authenticated principal, extracted on every admin request.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub sub: String,
    pub email: String,
    pub role: Role,
}

/// Resolved auth configuration + verification keys, shared via `EngineState`.
pub struct AuthState {
    pub mode: Mode,
    /// kid → decoding key (oidc). A `""` entry is used when tokens carry no kid.
    keys: HashMap<String, DecodingKey>,
    validation: Validation,
    roles_claim: String,
    email_claim: String,
    admin_roles: Vec<String>,
    responder_roles: Vec<String>,
}

impl AuthState {
    /// An open (admin-everywhere) state — used by tests and the disabled mode.
    #[cfg(test)]
    pub fn disabled() -> Self {
        AuthState {
            mode: Mode::Disabled,
            keys: HashMap::new(),
            validation: Validation::new(Algorithm::RS256),
            roles_claim: "roles".into(),
            email_claim: "email".into(),
            admin_roles: vec![],
            responder_roles: vec![],
        }
    }

    /// Build from config. Fetches the JWKS for `oidc` mode (inline JWKS wins).
    pub async fn build(cfg: &crate::config::AuthConfig) -> anyhow::Result<Self> {
        let mode = match cfg.mode.as_str() {
            "oidc" => Mode::Oidc,
            "dev" => Mode::Dev,
            _ => Mode::Disabled,
        };

        let roles_claim = non_empty(&cfg.roles_claim, "roles");
        let email_claim = non_empty(&cfg.email_claim, "email");
        let admin_roles = default_if_empty(&cfg.admin_roles, &["embargo-admin"]);
        let responder_roles = default_if_empty(&cfg.responder_roles, &["embargo-responder"]);

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        if !cfg.issuer.is_empty() {
            validation.set_issuer(std::slice::from_ref(&cfg.issuer));
        }
        if !cfg.audience.is_empty() {
            validation.set_audience(std::slice::from_ref(&cfg.audience));
        } else {
            validation.validate_aud = false;
        }

        let keys = if mode == Mode::Oidc {
            let jwks_json = if !cfg.jwks_inline.is_empty() {
                cfg.jwks_inline.clone()
            } else if !cfg.jwks_url.is_empty() {
                reqwest::get(&cfg.jwks_url)
                    .await?
                    .error_for_status()?
                    .text()
                    .await?
            } else {
                anyhow::bail!("auth.mode=oidc requires auth.jwks_url or auth.jwks_inline");
            };
            parse_jwks(&jwks_json)?
        } else {
            HashMap::new()
        };

        Ok(AuthState {
            mode,
            keys,
            validation,
            roles_claim,
            email_claim,
            admin_roles,
            responder_roles,
        })
    }

    /// Map a set of IdP role/group strings to an Embargo role (most-privileged wins).
    fn role_for(&self, claim_roles: &[String]) -> Role {
        if claim_roles.iter().any(|r| self.admin_roles.contains(r)) {
            Role::Admin
        } else if claim_roles.iter().any(|r| self.responder_roles.contains(r)) {
            Role::Responder
        } else {
            Role::Viewer
        }
    }

    /// Verify a bearer JWT and produce the principal.
    fn verify_token(&self, token: &str) -> Result<AuthUser, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::invalid("malformed token"))?;
        let key = header
            .kid
            .as_deref()
            .and_then(|kid| self.keys.get(kid))
            .or_else(|| self.keys.values().next())
            .ok_or_else(|| AuthError::invalid("no matching signing key"))?;

        let data = decode::<serde_json::Value>(token, key, &self.validation)
            .map_err(|e| AuthError::invalid(&format!("token rejected: {e}")))?;
        let claims = data.claims;

        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let email = claims
            .pointer(&pointerize(&self.email_claim))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let roles = extract_roles(&claims, &self.roles_claim);
        Ok(AuthUser {
            sub,
            email,
            role: self.role_for(&roles),
        })
    }
}

fn non_empty(s: &str, default: &str) -> String {
    if s.is_empty() {
        default.into()
    } else {
        s.into()
    }
}
fn default_if_empty(v: &[String], default: &[&str]) -> Vec<String> {
    if v.is_empty() {
        default.iter().map(|s| s.to_string()).collect()
    } else {
        v.to_vec()
    }
}

/// Turn a (possibly dotted) claim name into a JSON pointer, e.g.
/// `realm_access.roles` → `/realm_access/roles`.
fn pointerize(claim: &str) -> String {
    format!("/{}", claim.replace('.', "/"))
}

/// Pull role strings from a claim that may be an array or a single string.
fn extract_roles(claims: &serde_json::Value, claim: &str) -> Vec<String> {
    match claims.pointer(&pointerize(claim)) {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => vec![],
    }
}

/// Parse a JWKS document into kid → RSA decoding key.
pub fn parse_jwks(json: &str) -> anyhow::Result<HashMap<String, DecodingKey>> {
    let doc: serde_json::Value = serde_json::from_str(json)?;
    let keys = doc
        .get("keys")
        .and_then(|k| k.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = HashMap::new();
    for k in keys {
        let kty = k.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        if kty != "RSA" {
            continue;
        }
        let (Some(n), Some(e)) = (
            k.get("n").and_then(|v| v.as_str()),
            k.get("e").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let key = DecodingKey::from_rsa_components(n, e)?;
        let kid = k
            .get("kid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.insert(kid, key);
    }
    if out.is_empty() {
        anyhow::bail!("JWKS contained no usable RSA keys");
    }
    Ok(out)
}

// ---- extractor + rejection -------------------------------------------------

#[derive(Debug)]
pub struct AuthError(StatusCode, String);
impl AuthError {
    fn invalid(msg: &str) -> Self {
        AuthError(StatusCode::UNAUTHORIZED, msg.to_string())
    }
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl FromRequestParts<EngineState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &EngineState,
    ) -> Result<Self, Self::Rejection> {
        let auth = &state.auth;
        match auth.mode {
            Mode::Disabled => Ok(AuthUser {
                sub: "dev".into(),
                email: "dev@localhost".into(),
                role: Role::Admin,
            }),
            Mode::Dev => {
                let role = parts
                    .headers
                    .get("x-embargo-role")
                    .and_then(|v| v.to_str().ok())
                    .map(Role::from_header)
                    .unwrap_or(Role::Viewer);
                let email = parts
                    .headers
                    .get("x-embargo-email")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("dev@localhost")
                    .to_string();
                Ok(AuthUser {
                    sub: email.clone(),
                    email,
                    role,
                })
            }
            Mode::Oidc => {
                let token =
                    bearer(parts).ok_or_else(|| AuthError::invalid("missing bearer token"))?;
                auth.verify_token(token)
            }
        }
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    // Test keypair (RSA-2048). The public key forms the JWKS; the private key
    // signs test tokens. Not used anywhere outside tests.
    const TEST_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1NuP6rdcQsBc6YnR/leF\nX3YWDtpNnSXxnIcHHhCz5jGIeSNYVbi/mn49voRJoYgBkKAccYM/rdhDkpy+BehW\nhkrblKi8SLyxL9XANIIeJloZGey08WsxevnxiYKt+a33XD5JAoS6/uRS6ozKEiUu\nH6gOuWpQlJUAiMiBfbgcrpjIhpPuavfReczvuEikinm/nphp5T0ibiJpsIE3wOdE\n19Z0Knn+bSOGM3wZk677tivVNSfCYcVo+nZfpA9kmoD0L/GKKcD3ggkhEMD/sODo\nRxiDDYvta4/C8ZhTuca08qd5qjfUjYkKG6d07pdN2bieP9nW1cUOMmuuRNSwnJ4b\nZQIDAQAB\n-----END PUBLIC KEY-----";
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDU24/qt1xCwFzp\nidH+V4VfdhYO2k2dJfGchwceELPmMYh5I1hVuL+afj2+hEmhiAGQoBxxgz+t2EOS\nnL4F6FaGStuUqLxIvLEv1cA0gh4mWhkZ7LTxazF6+fGJgq35rfdcPkkChLr+5FLq\njMoSJS4fqA65alCUlQCIyIF9uByumMiGk+5q99F5zO+4SKSKeb+emGnlPSJuImmw\ngTfA50TX1nQqef5tI4YzfBmTrvu2K9U1J8JhxWj6dl+kD2SagPQv8YopwPeCCSEQ\nwP+w4OhHGIMNi+1rj8LxmFO5xrTyp3mqN9SNiQobp3Tul03ZuJ4/2dbVxQ4ya65E\n1LCcnhtlAgMBAAECggEABRgQ3gy8hOejN/7ExPhFogud0R+UUyB0I2TWQysiXKEi\nCcdSXXedNKgbKvk+sdwi/XN3essptcVcYjo+3SSHfZGpDTbq9Dd5at8/FekCduez\nfHu+HZ3AT2S2TRSQvIFXT1PTERMptOC0XOMFqvpMzxRWIqw5EkIGnNj/kFZDPKjM\nKK0GIWpzOyYrAHKKKUXa6Q5vCIQMz5vhzHSOWTppgDDKbf0Ef/mTiCh8YIsuGdGJ\naTvsOqW287PxhUZpsZhOZ6tZnYOIipt6RlcENidNdVbY45G2KjQTD38JuvObdTC6\nsUJUBWJ/nO63mUR83Odc6qkuyqq4F+u3dhB0wMAnQQKBgQD/Yu8w/qzIeZCRhOG/\nGjsiLW0iw5s3SV6fvs/sqieGAiYv90cHzpsEHpWDcShIopWOrE90gOItZGRJpXt/\nW5JI9epye49Tu6X6dUhHXhtLsDIjRkvC70wZ+gSV5g+RtbaOArG0N3CveDhqNuUQ\n6luTwbyUELKx2zj/hCtKYsfULQKBgQDVXnjdRx0pYnbHBUB4087wqv3zzDAIcu8K\nuLPGEGwfCc6nxRSnlmzGe6nYXcAt+/IywbCyIqSvgTpM5l2+M5JqM8zGcy48VV49\nnnXB3EkaTCirxcgTpeFCJBakfxPplnza4HxR32EemYVqLFq6lgK1rX+LqEsrROH0\nhHp0EPLPGQKBgQDfXcCmsZidnvV60SZA5shhlCmoBj1zlZBVV6az7/6xjp+nxDcz\n9NhQOg+67vW00b7NEphL5Y3s9alhYIMrWQQRHET57GfnbHA3Ju0Yvo5RHMI9Z/ZL\ngNCmx63LDXUAlFYezuxuGy9LyXJOM8UVjmSaTxCI0DH6rSqlEQxr+wmb4QKBgEuw\nR4+3OlED7L6MzmIOQMp+3bcuJ5vXqZRUEPGhwbkA8Z3x+3G3mr6N/6IRH6swRKpc\nqyGFyIW5gcTlsztVcArcdTewhCZC4jtZisxKKGR7v7GvZ1oQ7edYhe+0ZIvoJkI+\nf9tLMlh4fSs8sLKfpDZuZWBVQtUGimEC3a1ulbOBAoGAZZAfLt3V1RYrFR7tzOdx\n978PZrUxWFaCqGDuWxyCymyN3FNXRAQh2CxG528E3ncQtetGltxQ4h5DhqH2riJY\nGfdrWvA2EcGTWhlDc7yoclS3ORfX6VB7mIZmnpWigjKhNeflRgNgwkHHQ986B9jt\niwXXxUW7KANQPUIV5TNvRW0=\n-----END PRIVATE KEY-----";

    fn oidc_state() -> AuthState {
        let mut keys = HashMap::new();
        keys.insert(
            "test-kid".to_string(),
            DecodingKey::from_rsa_pem(TEST_PUB_PEM.as_bytes()).unwrap(),
        );
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        AuthState {
            mode: Mode::Oidc,
            keys,
            validation,
            roles_claim: "roles".into(),
            email_claim: "email".into(),
            admin_roles: vec!["embargo-admin".into()],
            responder_roles: vec!["embargo-responder".into()],
        }
    }

    fn make_token(roles: &[&str], email: &str, expired: bool) -> String {
        let exp = if expired { 1_000 } else { 9_999_999_999u64 };
        let claims = serde_json::json!({
            "sub": "user-1", "email": email, "roles": roles, "exp": exp,
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn role_permission_matrix() {
        assert!(Role::Viewer.can(Permission::ReadVerdicts));
        assert!(!Role::Viewer.can(Permission::WriteApprovals));
        assert!(Role::Responder.can(Permission::WriteApprovals));
        assert!(!Role::Responder.can(Permission::WritePolicies));
        assert!(Role::Admin.can(Permission::WritePolicies));
    }

    #[test]
    fn verifies_valid_token_and_maps_admin_role() {
        let st = oidc_state();
        let user = st
            .verify_token(&make_token(&["embargo-admin"], "a@x.com", false))
            .unwrap();
        assert_eq!(user.role, Role::Admin);
        assert_eq!(user.email, "a@x.com");
    }

    #[test]
    fn maps_responder_and_defaults_viewer() {
        let st = oidc_state();
        assert_eq!(
            st.verify_token(&make_token(&["embargo-responder"], "r@x.com", false))
                .unwrap()
                .role,
            Role::Responder
        );
        assert_eq!(
            st.verify_token(&make_token(&["some-other-group"], "v@x.com", false))
                .unwrap()
                .role,
            Role::Viewer
        );
    }

    #[test]
    fn rejects_expired_token() {
        let st = oidc_state();
        assert!(st
            .verify_token(&make_token(&["embargo-admin"], "a@x.com", true))
            .is_err());
    }

    #[test]
    fn rejects_garbage_token() {
        let st = oidc_state();
        assert!(st.verify_token("not.a.jwt").is_err());
    }

    #[test]
    fn parse_jwks_rejects_empty() {
        assert!(parse_jwks(r#"{"keys":[]}"#).is_err());
    }
}
