use anyhow::Result;
use chrono::Utc;
use embargo_core::{
    policy::PolicyResolver,
    scoring::{compute_verdict, ResolutionInput},
    types::{HoldReason, Verdict},
};
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use tracing::instrument;

use crate::{
    cache::VerdictCache,
    db,
    generated::embargo::v1::{
        engine_service_server::EngineService, ReportEventRequest, ReportEventResponse,
        ResolvePackumentRequest, ResolvePackumentResponse, ResolveRequest, ResolveResponse,
    },
    grpc::EngineState,
};

pub struct EngineServiceImpl {
    state: EngineState,
}

impl EngineServiceImpl {
    pub fn new(state: EngineState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl EngineService for EngineServiceImpl {
    #[instrument(skip(self, req), fields(pkg, ver))]
    async fn resolve(
        &self,
        req: Request<ResolveRequest>,
    ) -> Result<Response<ResolveResponse>, Status> {
        let r = req.into_inner();
        let vi = r
            .version_info
            .ok_or_else(|| Status::invalid_argument("missing version_info"))?;

        tracing::Span::current().record("pkg", &vi.package);
        tracing::Span::current().record("ver", &vi.version);

        let verdict = resolve_one(&self.state, &vi.package, &vi.version, vi.published_at)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(verdict))
    }

    #[instrument(skip(self, req), fields(pkg = %req.get_ref().package))]
    async fn resolve_packument(
        &self,
        req: Request<ResolvePackumentRequest>,
    ) -> Result<Response<ResolvePackumentResponse>, Status> {
        let r = req.into_inner();
        let mut allowed_versions = Vec::new();
        let mut stripped = std::collections::HashMap::new();

        for vi in r.versions {
            let verdict = resolve_one(&self.state, &vi.package, &vi.version, vi.published_at)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            if verdict.verdict == crate::generated::embargo::v1::Verdict::Allow as i32 {
                allowed_versions.push(vi.version);
            } else {
                stripped.insert(vi.version, verdict);
            }
        }

        Ok(Response::new(ResolvePackumentResponse {
            allowed_versions,
            stripped,
        }))
    }

    #[instrument(skip(self, req))]
    async fn report_event(
        &self,
        req: Request<ReportEventRequest>,
    ) -> Result<Response<ReportEventResponse>, Status> {
        let r = req.into_inner();
        tracing::info!(pkg = %r.package, ver = %r.version, event = %r.event_type, weight = r.weight, "containment event received");

        // Persist signal + re-evaluate verdict.
        // For M1: log + invalidate cache so next resolve picks it up.
        let mut cache = VerdictCache::from_conn(
            self.state.redis.clone(),
            self.state.config.redis.verdict_ttl_secs,
        );
        cache
            .invalidate(&r.package, &r.version)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ReportEventResponse {
            accepted: true,
            new_verdict: crate::generated::embargo::v1::Verdict::Hold as i32,
        }))
    }
}

async fn resolve_one(
    state: &EngineState,
    package: &str,
    version: &str,
    published_at: Option<prost_types::Timestamp>,
) -> Result<ResolveResponse> {
    // 1. Check Redis cache.
    let mut cache =
        VerdictCache::from_conn(state.redis.clone(), state.config.redis.verdict_ttl_secs);
    if let Some(cached) = cache.get(package, version).await? {
        // Still valid if not expired.
        let still_valid = cached
            .expires_at
            .map(|exp| exp > Utc::now())
            .unwrap_or(true);
        if still_valid {
            return Ok(verdict_to_proto(cached));
        }
    }

    // 2. Load active policy.
    let ruleset = db::policies::get_active(&state.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no active policy — configure a policy before serving"))?;
    let resolver = PolicyResolver::new(&ruleset)?;

    // 3. Compute verdict.
    let rule = resolver
        .resolve(package)
        .ok_or_else(|| anyhow::anyhow!("no policy rule matched {}", package))?;
    let fast_tracked = resolver.is_fast_tracked(package);
    let pub_at = published_at
        .and_then(|ts| chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32))
        .unwrap_or_else(|| Utc::now() - chrono::Duration::hours(rule.cooldown_hours as i64 + 1));

    let signals = db::verdicts::get(&state.pool, package, version)
        .await?
        .map(|v| v.signals)
        .unwrap_or_default();

    let input = ResolutionInput {
        package,
        version,
        published_at: pub_at,
        provenance: None, // M2: fetch from attestation store
        signals: &signals,
        rule,
        fast_tracked,
        now: Utc::now(),
    };
    let mut verdict = compute_verdict(&input);

    // 3b. Exception workflow: an active, unexpired approval for this exact
    // (package, version) overrides a HOLD/DENY to ALLOW. Approvals are
    // human-granted, time-boxed, and audited (see admin_svc::create_approval).
    if verdict.verdict != Verdict::Allow {
        if let Some(approval) = db::approvals::get_active(&state.pool, package, version).await? {
            verdict.verdict = Verdict::Allow;
            verdict.reasons.push(HoldReason::ApprovedException {
                approver: approval.approver_id.to_string(),
                reason: format!("approved exception (expires {})", approval.expires_at),
            });
            // An approval-overridden ALLOW expires when the approval does, so the
            // gate re-closes automatically once the exception lapses.
            verdict.expires_at = Some(approval.expires_at);
        }
    }

    // 4. Persist + cache.
    db::verdicts::upsert(&state.pool, &verdict).await?;
    cache.set(&verdict).await?;

    Ok(verdict_to_proto(verdict))
}

fn verdict_to_proto(v: embargo_core::types::VersionVerdict) -> ResolveResponse {
    use crate::generated::embargo::v1::Verdict as ProtoVerdict;
    let verdict_int = match v.verdict {
        Verdict::Allow => ProtoVerdict::Allow as i32,
        Verdict::Hold => ProtoVerdict::Hold as i32,
        Verdict::Deny => ProtoVerdict::Deny as i32,
    };
    let reasons: Vec<String> = v.reasons.iter().map(|r| format!("{:?}", r)).collect();
    let expires_at = v.expires_at.map(|dt| Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    });
    ResolveResponse {
        verdict: verdict_int,
        reasons,
        signals: vec![],
        expires_at,
    }
}

// ---------------------------------------------------------------------------
// DB-backed integration tests. Exercise the full resolve path against a real
// Postgres + Redis. Marked #[ignore] so the offline CI job skips them; a
// dedicated services job runs them with `cargo test -- --include-ignored`.
//
// Requires: DATABASE_URL (migrated schema) + a reachable Redis
// (EMBARGO_REDIS_URL, default redis://localhost:6379).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod itests {
    use super::*;
    use crate::config::{
        Config, DatabaseConfig, GrpcConfig, LogFormat, ObservabilityConfig, RedisConfig, TlsConfig,
    };
    use crate::generated::embargo::v1::Verdict as ProtoVerdict;
    use embargo_core::policy::PolicyRuleset;
    use embargo_core::types::{Severity, Signal, SignalType, Verdict, VersionVerdict};
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    const POLICY_YAML: &str = r#"
version: 1
rules:
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
"#;

    async fn test_state() -> EngineState {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let redis_url =
            std::env::var("EMBARGO_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&db_url)
            .await
            .expect("connect postgres");

        // Seed the active "**" policy (idempotent: identical content each time).
        let ruleset = PolicyRuleset::from_yaml(POLICY_YAML).unwrap();
        crate::db::policies::upsert(&pool, &ruleset, POLICY_YAML, Uuid::nil(), "itest")
            .await
            .expect("seed policy");

        let redis = redis::Client::open(redis_url.clone())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .expect("connect redis");

        let config = Config {
            database: DatabaseConfig {
                url: db_url,
                max_connections: 4,
            },
            redis: RedisConfig {
                url: redis_url,
                verdict_ttl_secs: 300,
            },
            grpc: GrpcConfig {
                addr: "[::]:0".into(),
            },
            tls: TlsConfig {
                cert_pem: String::new(),
                key_pem: String::new(),
                ca_pem: String::new(),
            },
            observability: ObservabilityConfig {
                otlp_endpoint: None,
                log_format: LogFormat::Pretty,
                log_level: "info".into(),
            },
            metrics_addr: "[::]:0".into(),
        };

        EngineState::new(pool, redis, config)
    }

    fn ts_hours_ago(h: i64) -> Option<prost_types::Timestamp> {
        let dt = Utc::now() - chrono::Duration::hours(h);
        Some(prost_types::Timestamp {
            seconds: dt.timestamp(),
            nanos: 0,
        })
    }

    fn unique(prefix: &str) -> String {
        format!("itest-{prefix}-{}", Uuid::new_v4())
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn recent_version_is_held_for_cooldown() {
        let state = test_state().await;
        let pkg = unique("hold");
        let res = resolve_one(&state, &pkg, "1.0.0", ts_hours_ago(1))
            .await
            .unwrap();
        assert_eq!(
            res.verdict,
            ProtoVerdict::Hold as i32,
            "recent version must HOLD"
        );
        assert!(
            res.expires_at.is_some(),
            "HOLD must carry a cooldown expiry"
        );
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn aged_version_is_allowed() {
        let state = test_state().await;
        let pkg = unique("allow");
        let res = resolve_one(&state, &pkg, "1.0.0", ts_hours_ago(200))
            .await
            .unwrap();
        assert_eq!(
            res.verdict,
            ProtoVerdict::Allow as i32,
            "aged version must ALLOW"
        );
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn advisory_signal_escalates_to_deny() {
        let state = test_state().await;
        let pkg = unique("advisory");
        let ver = "1.0.0";

        // Pre-store the version with an advisory signal; resolve reads it back.
        let seeded = VersionVerdict {
            package: pkg.clone(),
            version: ver.into(),
            verdict: Verdict::Hold,
            reasons: vec![],
            signals: vec![Signal {
                id: Uuid::new_v4(),
                signal_type: SignalType::AdvisoryMatch,
                severity: Severity::Critical,
                weight: 100,
                evidence: serde_json::json!({ "advisory_id": "GHSA-itest-0001" }),
                detected_at: Utc::now(),
            }],
            provenance: None,
            computed_at: Utc::now(),
            expires_at: None,
        };
        crate::db::verdicts::upsert(&state.pool, &seeded)
            .await
            .unwrap();

        // Even though the version is recent (would HOLD), the advisory forces DENY.
        let res = resolve_one(&state, &pkg, ver, ts_hours_ago(1))
            .await
            .unwrap();
        assert_eq!(res.verdict, ProtoVerdict::Deny as i32, "advisory must DENY");
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn active_approval_overrides_hold() {
        let state = test_state().await;
        let pkg = unique("approval");
        let ver = "1.0.0";

        // A time-boxed approval for this exact version, granted before resolve.
        crate::db::approvals::create(
            &state.pool,
            &pkg,
            ver,
            Uuid::nil(),
            Uuid::nil(),
            "itest exception",
            24,
        )
        .await
        .unwrap();

        // Recent version would HOLD, but the active approval overrides to ALLOW.
        let res = resolve_one(&state, &pkg, ver, ts_hours_ago(1))
            .await
            .unwrap();
        assert_eq!(
            res.verdict,
            ProtoVerdict::Allow as i32,
            "approval must override to ALLOW"
        );
    }
}
