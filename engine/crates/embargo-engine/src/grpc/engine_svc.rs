use anyhow::Result;
use chrono::Utc;
use embargo_core::{
    policy::PolicyResolver,
    scoring::{compute_verdict, ResolutionInput},
    types::{HoldReason, Severity, Signal, SignalType, Verdict},
};
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use tracing::instrument;
use uuid::Uuid;

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

        // Tarball-gate / publish-time-less callers (the L1 direct-tarball gate and
        // the L2 admission gate when it has no publish time) can't recompute
        // cooldown. Return the verdict already computed during packument
        // resolution so the tarball fetch enforces exactly what the packument
        // rewrite decided — closing the direct-tarball bypass. On a true miss we
        // fall through to compute, which fail-safes to HOLD without a publish time.
        if vi.published_at.is_none() {
            if let Some(persisted) = db::verdicts::get(&self.state.pool, &vi.package, &vi.version)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            {
                return Ok(Response::new(verdict_to_proto(persisted)));
            }
        }

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

        // Record the reported event as a signal, then invalidate the cached
        // verdict so the next resolve re-evaluates and can escalate.
        let evidence: serde_json::Value =
            serde_json::from_str(&r.evidence_json).unwrap_or_else(|_| serde_json::json!({}));
        let signal = Signal {
            id: Uuid::new_v4(),
            signal_type: event_type_to_signal(&r.event_type),
            severity: Severity::High,
            weight: r.weight,
            evidence,
            detected_at: Utc::now(),
        };
        db::signals::append(&self.state.pool, &r.package, &r.version, &signal)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut cache = VerdictCache::from_conn(
            self.state.redis.clone(),
            self.state.config.redis.verdict_ttl_secs,
        );
        cache
            .invalidate(&r.package, &r.version)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Re-resolve so the caller learns the post-event verdict.
        let updated = resolve_one(&self.state, &r.package, &r.version, None)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ReportEventResponse {
            accepted: true,
            new_verdict: updated.verdict,
        }))
    }
}

/// Synthesize a hard-deny signal for a known-malicious feed match.
fn known_malicious_signal(source: &str) -> embargo_core::types::Signal {
    embargo_core::types::Signal {
        id: uuid::Uuid::new_v4(),
        signal_type: embargo_core::types::SignalType::KnownMalicious,
        severity: embargo_core::types::Severity::Critical,
        weight: 100,
        evidence: serde_json::json!({ "source": source }),
        detected_at: Utc::now(),
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
    // Fail safe on a missing/unparseable publish time: treat it as just-published
    // so the version HOLDs for the full cooldown rather than slipping through as
    // "aged". A stripped `time` entry must never bypass cooldown.
    let pub_at = published_at
        .and_then(|ts| chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32))
        .unwrap_or_else(Utc::now);

    // Signals and provenance are produced out-of-band by the extractor.
    let mut signals = db::signals::get_for_version(&state.pool, package, version).await?;
    let provenance = db::provenance::get(&state.pool, package, version).await?;

    // Known-malicious feed: a hot-path lookup so a listed version is DENY'd on
    // the first resolve, without waiting for background extraction.
    if let Some(source) = db::known_malicious::is_malicious(&state.pool, package, version).await? {
        signals.push(known_malicious_signal(&source));
    }

    let input = ResolutionInput {
        package,
        version,
        published_at: pub_at,
        provenance: provenance.as_ref(),
        signals: &signals,
        rule,
        fast_tracked,
        now: Utc::now(),
    };
    let mut verdict = compute_verdict(&input);

    // 3b. Exception workflow: an active, unexpired approval for this exact
    // (package, version) overrides a HOLD/DENY to ALLOW. Approvals are
    // human-granted, time-boxed, and audited (see admin_svc::create_approval).
    //
    // Hard external blocks are NOT releasable this way: an advisory/CVE match, a
    // known-malicious feed listing, or an explicit manual denial stays DENY even
    // with an active approval. The exception workflow may only release cooldown,
    // provenance, and behavioral-signal holds — never an external malicious fact.
    let hard_blocked = verdict.reasons.iter().any(|r| r.is_hard_block());
    if verdict.verdict != Verdict::Allow && !hard_blocked {
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

    // 5. If this version is HELD and we have not analyzed it yet (no signals, or
    //    provenance still unchecked), kick off extraction in the background. This
    //    never blocks the hot path; the results land in the stores and escalate
    //    or clear the HOLD on the next resolve.
    if verdict.verdict == Verdict::Hold && (signals.is_empty() || provenance.is_none()) {
        spawn_extraction(state.clone(), package.to_string(), version.to_string());
    }

    Ok(verdict_to_proto(verdict))
}

/// Spawn a detached background extraction. Errors are logged, never surfaced to
/// the caller — the verdict already returned. Idempotent (replace-on-write).
fn spawn_extraction(state: EngineState, package: String, version: String) {
    tokio::spawn(async move {
        match crate::extractor::extract_and_store(
            state.registry.as_ref(),
            state.advisory.as_ref(),
            state.provenance.as_ref(),
            &state.pool,
            &package,
            &version,
        )
        .await
        {
            Ok(signals) => {
                // Always drop the cached verdict: extraction may have recorded
                // signals and/or a provenance result, either of which changes
                // the verdict on the next resolve.
                let mut cache = VerdictCache::from_conn(
                    state.redis.clone(),
                    state.config.redis.verdict_ttl_secs,
                );
                if let Err(e) = cache.invalidate(&package, &version).await {
                    tracing::warn!(%package, %version, error = %e, "cache invalidate after extraction failed");
                }
                tracing::info!(%package, %version, count = signals.len(), "background extraction complete");
            }
            Err(e) => {
                tracing::warn!(%package, %version, error = %e, "background signal extraction failed");
            }
        }
    });
}

/// Map an L3/feed event type string to a signal type.
fn event_type_to_signal(event_type: &str) -> SignalType {
    match event_type {
        "sandbox_egress_attempt" => SignalType::SandboxEgressAttempt,
        "ebpf_chain" | "ebpf_compromise_chain" => SignalType::EbpfCompromiseChain,
        "advisory_match" => SignalType::AdvisoryMatch,
        other => SignalType::Other {
            name: other.to_string(),
        },
    }
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
    use embargo_core::types::{Severity, Signal, SignalType};
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    const POLICY_YAML: &str = r#"
version: 1
rules:
  - scope: "itest-prov-*"
    cooldown_hours: 72
    require_provenance: true
    on_hard_signal: deny
    enabled: true
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
"#;

    async fn test_state_with_clients(
        registry: std::sync::Arc<dyn crate::registry::RegistryClient>,
        advisory: std::sync::Arc<dyn crate::advisory::AdvisoryClient>,
    ) -> EngineState {
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
            admin_http_addr: "[::]:0".into(),
            upstream_registry: "https://registry.npmjs.org".into(),
            osv_endpoint: "https://api.osv.dev".into(),
            bootstrap_policy_path: String::new(),
            auth: crate::config::AuthConfig::default(),
            provenance: crate::config::ProvenanceConfig::default(),
        };

        EngineState::new(
            pool,
            redis,
            config,
            registry,
            advisory,
            std::sync::Arc::new(crate::auth::AuthState::disabled()),
            std::sync::Arc::new(crate::provenance::sigstore::ProvenancePolicy::default()),
        )
    }

    /// State with a custom registry and a clean (no-match) advisory feed.
    async fn test_state_with(
        registry: std::sync::Arc<dyn crate::registry::RegistryClient>,
    ) -> EngineState {
        let advisory = std::sync::Arc::new(crate::advisory::MockAdvisoryClient::default());
        test_state_with_clients(registry, advisory).await
    }

    /// Default state: a registry that serves nothing and a clean advisory feed.
    /// Tests that seed signals directly don't rely on extraction.
    async fn test_state() -> EngineState {
        let registry = std::sync::Arc::new(crate::registry::MockRegistryClient::default());
        test_state_with(registry).await
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

    /// A known-malicious feed match DENYs on resolve even when the version is
    /// aged past cooldown with no other signals (would otherwise ALLOW).
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn known_malicious_feed_denies_on_resolve() {
        let state = test_state().await;
        let pkg = unique("km");
        let ver = "1.0.0";
        let source = format!("itest-{pkg}");
        crate::db::known_malicious::replace_source(
            &state.pool,
            &source,
            "npm",
            &[(pkg.clone(), ver.to_string())],
        )
        .await
        .unwrap();

        let r = resolve_one(&state, &pkg, ver, ts_hours_ago(500))
            .await
            .unwrap();
        assert_eq!(
            r.verdict,
            ProtoVerdict::Deny as i32,
            "known-malicious feed match must DENY"
        );
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

        // The extractor records an advisory match in the signals store.
        let signal = Signal {
            id: Uuid::new_v4(),
            signal_type: SignalType::AdvisoryMatch,
            severity: Severity::Critical,
            weight: 100,
            evidence: serde_json::json!({ "advisory_id": "GHSA-itest-0001" }),
            detected_at: Utc::now(),
        };
        crate::db::signals::replace_for_version(&state.pool, &pkg, ver, &[signal])
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

    /// An active approval releases a cooldown HOLD (the intended exception
    /// workflow) but must NOT release a known-malicious feed DENY — a hard
    /// external block stays DENY even with an approval covering the same version.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn approval_cannot_release_known_malicious() {
        let state = test_state().await;
        let pkg = unique("km-approved");
        let ver = "1.0.0";
        let source = format!("itest-{pkg}");
        crate::db::known_malicious::replace_source(
            &state.pool,
            &source,
            "npm",
            &[(pkg.clone(), ver.to_string())],
        )
        .await
        .unwrap();

        // Grant a time-boxed approval for the exact version a responder might use
        // to try to force it through.
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

        let r = resolve_one(&state, &pkg, ver, ts_hours_ago(500))
            .await
            .unwrap();
        assert_eq!(
            r.verdict,
            ProtoVerdict::Deny as i32,
            "approval must not release a known-malicious DENY"
        );
    }

    /// The tarball gate calls Resolve with no publish time. The engine must
    /// return the verdict persisted during packument resolution (here a DENY),
    /// so a direct tarball fetch enforces exactly what the packument rewrite did.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn resolve_without_publish_time_returns_persisted_verdict() {
        use crate::generated::embargo::v1::{ResolveRequest, VersionInfo};
        let state = test_state().await;
        let pkg = unique("tarball-gate");
        let ver = "1.0.0";

        // Seed the persisted DENY a prior packument resolution would have written.
        let denied = embargo_core::types::VersionVerdict {
            package: pkg.clone(),
            version: ver.into(),
            verdict: Verdict::Deny,
            reasons: vec![HoldReason::KnownMalicious {
                source: "itest".into(),
            }],
            signals: vec![],
            provenance: None,
            computed_at: Utc::now(),
            expires_at: None,
        };
        crate::db::verdicts::upsert(&state.pool, &denied)
            .await
            .unwrap();

        let svc = EngineServiceImpl::new(state.clone());
        let req = tonic::Request::new(ResolveRequest {
            version_info: Some(VersionInfo {
                package: pkg.clone(),
                version: ver.into(),
                published_at: None,
            }),
            caller_service: "gateway-tarball".into(),
        });
        let resp = svc.resolve(req).await.unwrap().into_inner();
        assert_eq!(
            resp.verdict,
            ProtoVerdict::Deny as i32,
            "tarball-gate resolve must return the persisted DENY"
        );
    }

    /// A version with no publish timestamp must HOLD for cooldown (fail safe),
    /// not slip through as "aged".
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn missing_publish_time_holds_for_cooldown() {
        let state = test_state().await;
        let pkg = unique("notime");
        let res = resolve_one(&state, &pkg, "1.0.0", None).await.unwrap();
        assert_eq!(
            res.verdict,
            ProtoVerdict::Hold as i32,
            "missing publish time must HOLD, never bypass cooldown"
        );
    }

    /// Full pipeline: extractor fetches the malicious tarball (vs its benign
    /// predecessor), detects the stealer chain, stores the signals, and the
    /// subsequent resolve escalates the cooldown HOLD to a permanent DENY.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn extraction_then_resolve_denies_stealer() {
        let registry = std::sync::Arc::new(crate::testutil::stealer_registry());
        let state = test_state_with(registry).await;
        let pkg = unique("stealer");
        let ver = "1.1.0";

        // Run the background extractor synchronously for the assertion.
        let signals = crate::extractor::extract_and_store(
            state.registry.as_ref(),
            state.advisory.as_ref(),
            state.provenance.as_ref(),
            &state.pool,
            &pkg,
            ver,
        )
        .await
        .unwrap();
        assert!(
            signals.iter().any(
                |s| matches!(&s.signal_type, SignalType::Other { name } if name == "stealer_chain")
            ),
            "extractor should record the stealer chain: {signals:?}"
        );

        // A recent version would normally HOLD on cooldown; the stored chain
        // signal escalates it to DENY (on_hard_signal: deny).
        let res = resolve_one(&state, &pkg, ver, ts_hours_ago(1))
            .await
            .unwrap();
        assert_eq!(
            res.verdict,
            ProtoVerdict::Deny as i32,
            "stealer chain must escalate to DENY"
        );
    }

    /// require_provenance gate: an unchecked version HOLDs pending the check;
    /// once the extractor records an absent attestation, it DENYs. (Names under
    /// `itest-prov-*` hit the require_provenance rule in POLICY_YAML.)
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn provenance_required_holds_then_denies_when_absent() {
        let registry = std::sync::Arc::new(crate::testutil::benign_registry(false));
        let state = test_state_with(registry).await;
        let pkg = unique("prov");
        let ver = "1.0.0";

        // Aged (past cooldown) but provenance not yet checked → HOLD pending,
        // never an immediate DENY.
        let r1 = resolve_one(&state, &pkg, ver, ts_hours_ago(200))
            .await
            .unwrap();
        assert_eq!(
            r1.verdict,
            ProtoVerdict::Hold as i32,
            "unchecked provenance must HOLD pending"
        );

        // Extract: the mock serves no attestation → Provenance::Absent.
        crate::extractor::extract_and_store(
            state.registry.as_ref(),
            state.advisory.as_ref(),
            state.provenance.as_ref(),
            &state.pool,
            &pkg,
            ver,
        )
        .await
        .unwrap();
        let mut cache = crate::cache::VerdictCache::from_conn(
            state.redis.clone(),
            state.config.redis.verdict_ttl_secs,
        );
        cache.invalidate(&pkg, ver).await.unwrap();

        let r2 = resolve_one(&state, &pkg, ver, ts_hours_ago(200))
            .await
            .unwrap();
        assert_eq!(
            r2.verdict,
            ProtoVerdict::Deny as i32,
            "checked-absent provenance must DENY"
        );
    }

    /// require_provenance gate: a version with a cryptographically valid,
    /// identity-bound attestation passes the gate and (aged, no signals) ALLOWs.
    /// Exercises the full Sigstore path: DSSE signature + Fulcio chain + identity.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn provenance_verified_allows() {
        // A signed bundle for github.com/acme/demo + the trust policy that accepts
        // its (test) CA and OIDC issuer.
        let (attestation, policy) = crate::testutil::signed_provenance(
            "acme/demo",
            ".github/workflows/release.yml",
            "https://token.actions.githubusercontent.com",
        );
        let mut registry = crate::testutil::benign_registry(false);
        registry.attestation = Some(attestation);
        let mut state = test_state_with(std::sync::Arc::new(registry)).await;
        state.provenance = std::sync::Arc::new(policy);

        let pkg = unique("prov");
        let ver = "1.0.0";

        crate::extractor::extract_and_store(
            state.registry.as_ref(),
            state.advisory.as_ref(),
            state.provenance.as_ref(),
            &state.pool,
            &pkg,
            ver,
        )
        .await
        .unwrap();

        let r = resolve_one(&state, &pkg, ver, ts_hours_ago(200))
            .await
            .unwrap();
        assert_eq!(
            r.verdict,
            ProtoVerdict::Allow as i32,
            "cryptographically verified provenance + aged version must ALLOW"
        );
    }

    /// Advisory feed match: extraction records an advisory_match signal from the
    /// feed; resolve converts it to an automatic DENY even for an aged version
    /// that would otherwise be ALLOW.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL + Redis"]
    async fn advisory_feed_match_denies() {
        let registry = std::sync::Arc::new(crate::testutil::benign_registry(false));
        let advisory = std::sync::Arc::new(crate::advisory::MockAdvisoryClient {
            advisories: vec![crate::advisory::Advisory {
                id: "GHSA-feed-0001".into(),
                summary: "malicious code in demo".into(),
                aliases: vec!["CVE-2024-9999".into()],
                severity: None,
            }],
        });
        let state = test_state_with_clients(registry, advisory).await;
        // Non-"itest-prov" name → hits the "**" rule (require_provenance false).
        let pkg = unique("advfeed");
        let ver = "1.0.0";

        let signals = crate::extractor::extract_and_store(
            state.registry.as_ref(),
            state.advisory.as_ref(),
            state.provenance.as_ref(),
            &state.pool,
            &pkg,
            ver,
        )
        .await
        .unwrap();
        assert!(
            signals
                .iter()
                .any(|s| s.signal_type == SignalType::AdvisoryMatch),
            "advisory match must be recorded: {signals:?}"
        );

        // Aged version would be ALLOW; the advisory forces DENY.
        let r = resolve_one(&state, &pkg, ver, ts_hours_ago(200))
            .await
            .unwrap();
        assert_eq!(
            r.verdict,
            ProtoVerdict::Deny as i32,
            "advisory feed match must DENY"
        );
    }
}
