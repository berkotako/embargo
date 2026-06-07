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
