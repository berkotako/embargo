//! JSON HTTP admin facade for the console.
//!
//! The console is a browser app and cannot speak the engine's mTLS gRPC, so we
//! expose a small read/write JSON API backed by the same `db` layer and
//! `EngineState`. Responses are shaped (camelCase) to match the console's
//! TypeScript domain types exactly.
//!
//! AuthN/AuthZ: every endpoint runs the `AuthUser` extractor (see `auth.rs`)
//! and enforces RBAC server-side — reads need a viewer, approval writes need a
//! responder, and the audit log records the real principal.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use embargo_core::policy::OnHardSignal;
use embargo_core::types::{HoldReason, Provenance, Signal, Verdict, VersionVerdict};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{AuthUser, Permission};
use crate::db;
use crate::grpc::EngineState;

/// Enforce a permission for the authenticated principal (server-side RBAC).
fn require(user: &AuthUser, p: Permission) -> Result<(), ApiError> {
    if user.role.can(p) {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::FORBIDDEN,
            format!(
                "role '{}' lacks the required permission",
                user.role.as_str()
            ),
        ))
    }
}

/// Stable UUID for an OIDC subject (sub strings aren't UUIDs).
fn user_uuid(sub: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, sub.as_bytes())
}

pub fn router(state: EngineState) -> Router {
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/whoami", get(whoami))
        .route("/api/verdicts", get(list_verdicts))
        .route("/api/policies", get(get_policies))
        .route("/api/policies/dryrun", get(get_dryrun))
        .route("/api/approvals", get(list_approvals).post(create_approval))
        .route("/api/approvals/{id}/revoke", post(revoke_approval))
        .route("/api/audit", get(list_audit))
        .route("/api/dashboard", get(get_dashboard))
        .with_state(state)
}

/// The authenticated principal — the console calls this on load to establish
/// its session and learn the server-enforced role (the UI only reflects it).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WhoAmI {
    email: String,
    role: String,
    /// The facade's auth mode, so the console knows how to authenticate.
    auth_mode: String,
}

async fn whoami(State(state): State<EngineState>, user: AuthUser) -> Json<WhoAmI> {
    let auth_mode = match state.auth.mode {
        crate::auth::Mode::Oidc => "oidc",
        crate::auth::Mode::Dev => "dev",
        crate::auth::Mode::Disabled => "disabled",
    };
    Json(WhoAmI {
        email: user.email,
        role: user.role.as_str().into(),
        auth_mode: auth_mode.into(),
    })
}

// ---- error helper ----------------------------------------------------------

type ApiResult<T> = Result<Json<T>, ApiError>;

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

// ---- DTOs (camelCase to match the console types) ---------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignalDto {
    id: String,
    #[serde(rename = "type")]
    signal_type: String,
    severity: String,
    weight: u32,
    evidence: serde_json::Value,
    detected_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvenanceDto {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerdictDto {
    package: String,
    version: String,
    verdict: String,
    reasons: Vec<String>,
    signals: Vec<SignalDto>,
    provenance: Option<ProvenanceDto>,
    computed_at: String,
    expires_at: Option<String>,
}

fn signal_type_str(s: &Signal) -> String {
    use embargo_core::types::SignalType as T;
    match &s.signal_type {
        T::NewLifecycleScript => "new_lifecycle_script".into(),
        T::BindingGyp => "binding_gyp".into(),
        T::CapabilityDep => "capability_dep".into(),
        T::Republish => "republish".into(),
        T::MaintainerChange => "maintainer_change".into(),
        T::TarballMismatch => "tarball_mismatch".into(),
        T::Obfuscation => "obfuscation".into(),
        T::AdvisoryMatch => "advisory_match".into(),
        T::ProvenanceAbsent => "provenance_absent".into(),
        T::SandboxEgressAttempt => "sandbox_egress_attempt".into(),
        T::EbpfCompromiseChain => "ebpf_compromise_chain".into(),
        T::Other { name } => name.clone(),
    }
}

fn reason_str(r: &HoldReason) -> String {
    match r {
        HoldReason::Cooldown { remaining_hours } => {
            format!("cooldown: {remaining_hours}h remaining")
        }
        HoldReason::ProvenanceMissing => "provenance missing or unverifiable".into(),
        HoldReason::ProvenancePending => "provenance not yet checked".into(),
        HoldReason::SignalChain { chain_id, score } => {
            format!("signal chain {chain_id} (score {score})")
        }
        HoldReason::Advisory { advisory_id } => format!("advisory: {advisory_id}"),
        HoldReason::ManualDeny { reason, .. } => format!("manually denied: {reason}"),
        HoldReason::ApprovedException { reason, .. } => format!("approved exception: {reason}"),
    }
}

fn verdict_to_dto(v: VersionVerdict) -> VerdictDto {
    let verdict = match v.verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Hold => "HOLD",
        Verdict::Deny => "DENY",
    };
    let provenance = v.provenance.map(|p| match p {
        Provenance::Verified { workflow, repo } => ProvenanceDto {
            status: "verified".into(),
            workflow: Some(workflow),
            repo: Some(repo),
            reason: None,
        },
        Provenance::Invalid { reason } => ProvenanceDto {
            status: "invalid".into(),
            workflow: None,
            repo: None,
            reason: Some(reason),
        },
        Provenance::Absent => ProvenanceDto {
            status: "absent".into(),
            workflow: None,
            repo: None,
            reason: None,
        },
    });
    VerdictDto {
        package: v.package,
        version: v.version,
        verdict: verdict.into(),
        reasons: v.reasons.iter().map(reason_str).collect(),
        signals: v
            .signals
            .iter()
            .map(|s| SignalDto {
                id: s.id.to_string(),
                signal_type: signal_type_str(s),
                severity: format!("{:?}", s.severity).to_lowercase(),
                weight: s.weight,
                evidence: s.evidence.clone(),
                detected_at: s.detected_at.to_rfc3339(),
            })
            .collect(),
        provenance,
        computed_at: v.computed_at.to_rfc3339(),
        expires_at: v.expires_at.map(|d| d.to_rfc3339()),
    }
}

// ---- handlers --------------------------------------------------------------

#[derive(Deserialize)]
struct VerdictQuery {
    /// "hold" | "deny"
    verdict: Option<String>,
}

async fn list_verdicts(
    State(state): State<EngineState>,
    user: AuthUser,
    Query(q): Query<VerdictQuery>,
) -> ApiResult<Vec<VerdictDto>> {
    require(&user, Permission::ReadVerdicts)?;
    let filter = match q.verdict.as_deref() {
        Some("deny") => Verdict::Deny,
        _ => Verdict::Hold,
    };
    let rows = db::verdicts::list_by_verdict(&state.pool, filter, 200, 0).await?;
    Ok(Json(rows.into_iter().map(verdict_to_dto).collect()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyRuleDto {
    id: String,
    scope: String,
    cooldown_hours: u64,
    require_provenance: bool,
    on_hard_signal: String,
    fast_track: Vec<String>,
    enabled: bool,
    specificity: u32,
}

async fn get_policies(
    State(state): State<EngineState>,
    user: AuthUser,
) -> ApiResult<Vec<PolicyRuleDto>> {
    require(&user, Permission::ReadPolicies)?;
    let ruleset = db::policies::get_active(&state.pool).await?;
    let rules = ruleset.map(|r| r.rules).unwrap_or_default();
    let dto = rules
        .into_iter()
        .enumerate()
        .map(|(i, r)| PolicyRuleDto {
            id: format!("rule-{i}"),
            specificity: embargo_core::policy::scope_specificity(&r.scope),
            scope: r.scope,
            cooldown_hours: r.cooldown_hours,
            require_provenance: r.require_provenance,
            on_hard_signal: match r.on_hard_signal {
                OnHardSignal::Deny => "deny".into(),
                OnHardSignal::Hold => "hold".into(),
            },
            fast_track: r.fast_track,
            enabled: r.enabled,
        })
        .collect();
    Ok(Json(dto))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DryRunDto {
    total: i64,
    now_blocked: i64,
    would_release: i64,
    affected_pkgs: Vec<String>,
}

async fn get_dryrun(State(state): State<EngineState>, user: AuthUser) -> ApiResult<DryRunDto> {
    require(&user, Permission::ReadPolicies)?;
    let (total, blocked) = db::stats::dryrun(&state.pool).await?;
    Ok(Json(DryRunDto {
        total,
        now_blocked: blocked,
        would_release: 0,
        affected_pkgs: vec![],
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalDto {
    id: String,
    package: String,
    version: String,
    requester_id: String,
    approver_id: Option<String>,
    justification: String,
    expires_at: Option<String>,
    status: String,
    created_at: String,
}

async fn list_approvals(
    State(state): State<EngineState>,
    user: AuthUser,
) -> ApiResult<Vec<ApprovalDto>> {
    require(&user, Permission::ReadApprovals)?;
    let rows = db::approvals::list(&state.pool, 200).await?;
    let dto = rows
        .into_iter()
        .map(|a| ApprovalDto {
            id: a.id.to_string(),
            package: a.package,
            version: a.version,
            requester_id: a.requester_id.to_string(),
            approver_id: Some(a.approver_id.to_string()),
            justification: a.justification,
            expires_at: Some(a.expires_at.to_rfc3339()),
            status: a.status.as_str().into(),
            created_at: a.created_at.to_rfc3339(),
        })
        .collect();
    Ok(Json(dto))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateApprovalBody {
    package: String,
    version: String,
    justification: String,
    ttl_hours: u64,
}

async fn create_approval(
    State(state): State<EngineState>,
    user: AuthUser,
    Json(body): Json<CreateApprovalBody>,
) -> ApiResult<ApprovalDto> {
    require(&user, Permission::WriteApprovals)?;
    // The requester and approver is the authenticated principal.
    let actor_id = user_uuid(&user.sub);
    let a = db::approvals::create(
        &state.pool,
        &body.package,
        &body.version,
        actor_id,
        actor_id,
        &body.justification,
        body.ttl_hours,
    )
    .await?;
    db::audit::append(
        &state.pool,
        &embargo_core::audit::Actor::User {
            id: actor_id,
            email: user.email.clone(),
            role: user.role.as_str().into(),
        },
        embargo_core::audit::AuditAction::ApprovalGranted,
        &embargo_core::audit::AuditTarget::Approval { id: a.id },
        None,
        Some(&json!({ "package": body.package, "version": body.version })),
    )
    .await?;
    Ok(Json(ApprovalDto {
        id: a.id.to_string(),
        package: a.package,
        version: a.version,
        requester_id: a.requester_id.to_string(),
        approver_id: Some(a.approver_id.to_string()),
        justification: a.justification,
        expires_at: Some(a.expires_at.to_rfc3339()),
        status: "active".into(),
        created_at: a.created_at.to_rfc3339(),
    }))
}

#[derive(Deserialize)]
struct RevokeBody {
    reason: Option<String>,
}

async fn revoke_approval(
    State(state): State<EngineState>,
    user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<RevokeBody>,
) -> Result<StatusCode, ApiError> {
    require(&user, Permission::WriteApprovals)?;
    let uuid = uuid::Uuid::parse_str(&id)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid approval id".into()))?;
    db::approvals::revoke(
        &state.pool,
        uuid,
        body.reason.as_deref().unwrap_or("revoked via console"),
    )
    .await?;
    db::audit::append(
        &state.pool,
        &embargo_core::audit::Actor::User {
            id: user_uuid(&user.sub),
            email: user.email.clone(),
            role: user.role.as_str().into(),
        },
        embargo_core::audit::AuditAction::ApprovalRevoked,
        &embargo_core::audit::AuditTarget::Approval { id: uuid },
        None,
        None,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditDto {
    id: String,
    actor: serde_json::Value,
    action: String,
    target: serde_json::Value,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
    timestamp: String,
    prev_hash: Option<String>,
    content_hash: String,
}

async fn list_audit(State(state): State<EngineState>, user: AuthUser) -> ApiResult<Vec<AuditDto>> {
    require(&user, Permission::ReadAudit)?;
    let rows = db::audit::list(&state.pool, 200).await?;
    let dto = rows
        .into_iter()
        .map(|r| AuditDto {
            id: r.id.to_string(),
            actor: r.actor,
            action: r.action,
            target: r.target,
            before: r.before,
            after: r.after,
            timestamp: r.timestamp.to_rfc3339(),
            prev_hash: r.prev_hash,
            content_hash: r.content_hash,
        })
        .collect();
    Ok(Json(dto))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContainmentEventDto {
    id: String,
    pkg: String,
    host: String,
    pipeline: String,
    repo: String,
    attempts: u32,
    time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardDto {
    held: i64,
    denied: i64,
    allowed: i64,
    advisory_matches: i64,
    held_trend: Vec<i64>,
    top_signals: Vec<TopSignalDto>,
    recent_events: Vec<ContainmentEventDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TopSignalDto {
    #[serde(rename = "type")]
    signal_type: String,
    count: i64,
    share: f64,
}

async fn get_dashboard(
    State(state): State<EngineState>,
    user: AuthUser,
) -> ApiResult<DashboardDto> {
    require(&user, Permission::ReadVerdicts)?;
    let d = db::stats::dashboard(&state.pool).await?;
    let total_signals: i64 = d.top_signals.iter().map(|(_, n)| *n).sum();
    let top_signals = d
        .top_signals
        .iter()
        .map(|(t, n)| TopSignalDto {
            signal_type: t.clone(),
            count: *n,
            share: if total_signals > 0 {
                *n as f64 / total_signals as f64
            } else {
                0.0
            },
        })
        .collect();
    let recent_events = d
        .recent_events
        .into_iter()
        .map(|e| {
            let ev = &e.evidence;
            let s = |k: &str| ev.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            ContainmentEventDto {
                id: e.id.to_string(),
                pkg: s("pkg"),
                host: s("host"),
                pipeline: s("pipeline"),
                repo: s("repo"),
                attempts: ev.get("attempts").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
                time: e.detected_at.to_rfc3339(),
                note: ev.get("note").and_then(|v| v.as_str()).map(String::from),
            }
        })
        .collect();
    Ok(Json(DashboardDto {
        held: d.held,
        denied: d.denied,
        allowed: d.allowed,
        advisory_matches: d.advisory_matches,
        held_trend: d.held_trend,
        top_signals,
        recent_events,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for `oneshot`

    const POLICY_YAML: &str = r#"
version: 1
rules:
  - scope: "@acme/*"
    cooldown_hours: 0
    require_provenance: true
    on_hard_signal: deny
    enabled: true
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
"#;

    async fn test_state() -> EngineState {
        test_state_auth(std::sync::Arc::new(crate::auth::AuthState::disabled())).await
    }

    async fn test_state_auth(auth: std::sync::Arc<crate::auth::AuthState>) -> EngineState {
        use sqlx::postgres::PgPoolOptions;
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let redis_url =
            std::env::var("EMBARGO_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&db_url)
            .await
            .unwrap();
        let ruleset = PolicyRuleset::from_yaml(POLICY_YAML).unwrap();
        db::policies::upsert(&pool, &ruleset, POLICY_YAML, uuid::Uuid::nil(), "http-test")
            .await
            .unwrap();
        let redis = redis::Client::open(redis_url.clone())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let cfg = crate::config::Config {
            database: crate::config::DatabaseConfig {
                url: db_url,
                max_connections: 4,
            },
            redis: crate::config::RedisConfig {
                url: redis_url,
                verdict_ttl_secs: 300,
            },
            grpc: crate::config::GrpcConfig {
                addr: "[::]:0".into(),
            },
            tls: crate::config::TlsConfig {
                cert_pem: String::new(),
                key_pem: String::new(),
                ca_pem: String::new(),
            },
            observability: crate::config::ObservabilityConfig {
                otlp_endpoint: None,
                log_format: crate::config::LogFormat::Pretty,
                log_level: "info".into(),
            },
            metrics_addr: "[::]:0".into(),
            admin_http_addr: "[::]:0".into(),
            upstream_registry: "https://registry.npmjs.org".into(),
            osv_endpoint: "https://api.osv.dev".into(),
            auth: crate::config::AuthConfig::default(),
        };
        EngineState::new(
            pool,
            redis,
            cfg,
            std::sync::Arc::new(crate::registry::MockRegistryClient::default()),
            std::sync::Arc::new(crate::advisory::MockAdvisoryClient::default()),
            auth,
        )
    }

    use embargo_core::policy::PolicyRuleset;

    async fn get_json(state: EngineState, uri: &str) -> serde_json::Value {
        let resp = router(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn policies_endpoint_shapes_camelcase() {
        let state = test_state().await;
        let v = get_json(state, "/api/policies").await;
        let rules = v.as_array().unwrap();
        assert!(!rules.is_empty());
        let acme = rules.iter().find(|r| r["scope"] == "@acme/*").unwrap();
        assert_eq!(acme["cooldownHours"], 0);
        assert_eq!(acme["requireProvenance"], true);
        assert_eq!(acme["onHardSignal"], "deny");
        assert_eq!(acme["specificity"], 2); // @scope/* → 2
        assert!(acme["id"].is_string());
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn dashboard_and_verdicts_endpoints_ok() {
        let state = test_state().await;
        let d = get_json(state.clone(), "/api/dashboard").await;
        assert!(d["held"].is_number());
        assert!(d["topSignals"].is_array());
        assert!(d["heldTrend"].as_array().unwrap().len() == 7);

        let held = get_json(state, "/api/verdicts?verdict=hold").await;
        assert!(held.is_array());
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn create_then_list_approval() {
        let state = test_state().await;
        let pkg = format!("http-itest-{}", uuid::Uuid::new_v4());
        let body = serde_json::json!({
            "package": pkg, "version": "1.0.0",
            "justification": "test", "ttlHours": 24
        });
        let resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/approvals")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let list = get_json(state, "/api/approvals").await;
        assert!(list.as_array().unwrap().iter().any(|a| a["package"] == pkg));
    }

    async fn dev_state() -> EngineState {
        let auth = crate::auth::AuthState::build(&crate::config::AuthConfig {
            mode: "dev".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        test_state_auth(std::sync::Arc::new(auth)).await
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn whoami_reflects_role_and_mode() {
        let state = dev_state().await;
        let resp = router(state)
            .oneshot(req_role("GET", "/api/whoami", "responder", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["role"], "responder");
        assert_eq!(v["authMode"], "dev");
        assert_eq!(v["email"], "u@x.com");
    }

    fn req_role(method: &str, uri: &str, role: &str, body: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-embargo-role", role)
            .header("x-embargo-email", "u@x.com");
        if body.is_some() {
            b = b.header("content-type", "application/json");
        }
        b.body(
            body.map(|s| Body::from(s.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn rbac_viewer_can_read_but_not_approve() {
        let state = dev_state().await;

        // viewer GET → 200
        let r = router(state.clone())
            .oneshot(req_role("GET", "/api/policies", "viewer", None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "viewer may read policies");

        // viewer POST approval → 403
        let body = r#"{"package":"p","version":"1.0.0","justification":"x","ttlHours":24}"#;
        let r = router(state)
            .oneshot(req_role("POST", "/api/approvals", "viewer", Some(body)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewer may not approve");
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn rbac_responder_can_approve() {
        let state = dev_state().await;
        let pkg = format!("rbac-{}", uuid::Uuid::new_v4());
        let body =
            format!(r#"{{"package":"{pkg}","version":"1.0.0","justification":"x","ttlHours":24}}"#);
        let r = router(state)
            .oneshot(req_role("POST", "/api/approvals", "responder", Some(&body)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "responder may approve");
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn oidc_mode_rejects_missing_token() {
        let auth = crate::auth::AuthState::build(&crate::config::AuthConfig {
            mode: "oidc".into(),
            jwks_inline: r#"{"keys":[{"kty":"RSA","kid":"test-kid","e":"AQAB","n":"1NuP6rdcQsBc6YnR_leFX3YWDtpNnSXxnIcHHhCz5jGIeSNYVbi_mn49voRJoYgBkKAccYM_rdhDkpy-BehWhkrblKi8SLyxL9XANIIeJloZGey08WsxevnxiYKt-a33XD5JAoS6_uRS6ozKEiUuH6gOuWpQlJUAiMiBfbgcrpjIhpPuavfReczvuEikinm_nphp5T0ibiJpsIE3wOdE19Z0Knn-bSOGM3wZk677tivVNSfCYcVo-nZfpA9kmoD0L_GKKcD3ggkhEMD_sODoRxiDDYvta4_C8ZhTuca08qd5qjfUjYkKG6d07pdN2bieP9nW1cUOMmuuRNSwnJ4bZQ"}]}"#.into(),
            ..Default::default()
        })
        .await
        .unwrap();
        let state = test_state_auth(std::sync::Arc::new(auth)).await;
        let r = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/policies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "oidc requires a token"
        );
    }
}
