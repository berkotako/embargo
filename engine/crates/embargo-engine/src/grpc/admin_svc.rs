use embargo_core::audit::{Actor, AuditAction, AuditTarget};
use embargo_core::policy::PolicyRuleset;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    db,
    generated::embargo::v1::{
        admin_service_server::AdminService, CreateApprovalRequest, CreateApprovalResponse,
        DeletePolicyRequest, DeletePolicyResponse, GetPolicyRequest, GetPolicyResponse,
        GetVerdictRequest, GetVerdictResponse, ListApprovalsRequest, ListApprovalsResponse,
        ListAuditEntriesRequest, ListAuditEntriesResponse, ListVerdictsRequest,
        ListVerdictsResponse, RevokeApprovalRequest, RevokeApprovalResponse, UpsertPolicyRequest,
        UpsertPolicyResponse,
    },
    grpc::EngineState,
};

pub struct AdminServiceImpl {
    state: EngineState,
}

impl AdminServiceImpl {
    pub fn new(state: EngineState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn get_policy(
        &self,
        _req: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let ruleset = db::policies::get_active(&self.state.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let Some(rs) = ruleset else {
            return Err(Status::not_found("no active policy"));
        };

        use crate::generated::embargo::v1::PolicyRuleProto;
        let rules: Vec<PolicyRuleProto> = rs
            .rules
            .iter()
            .map(|r| PolicyRuleProto {
                scope: r.scope.clone(),
                cooldown_hours: r.cooldown_hours,
                require_provenance: r.require_provenance,
                on_hard_signal: format!("{:?}", r.on_hard_signal).to_lowercase(),
                fast_track: r.fast_track.clone(),
                enabled: r.enabled,
            })
            .collect();

        Ok(Response::new(GetPolicyResponse {
            version: rs.version,
            rules,
            updated_at: None,
        }))
    }

    async fn upsert_policy(
        &self,
        req: Request<UpsertPolicyRequest>,
    ) -> Result<Response<UpsertPolicyResponse>, Status> {
        let r = req.into_inner();
        let yaml = proto_rules_to_yaml(&r).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let ruleset =
            PolicyRuleset::from_yaml(&yaml).map_err(|e| Status::invalid_argument(e.to_string()))?;

        // TODO(M1): extract actor from mTLS peer identity.
        let actor = Actor::System;
        let actor_id = Uuid::nil();

        let audit_id = db::policies::upsert(
            &self.state.pool,
            &ruleset,
            &yaml,
            actor_id,
            &r.justification,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        db::audit::append(
            &self.state.pool,
            &actor,
            AuditAction::PolicyUpdated,
            &AuditTarget::Policy { scope: "**".into() },
            None,
            Some(&serde_json::to_value(&yaml).unwrap_or_default()),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(UpsertPolicyResponse {
            ok: true,
            audit_id: audit_id.to_string(),
        }))
    }

    async fn delete_policy(
        &self,
        _req: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        Err(Status::unimplemented("policy deletion not yet implemented"))
    }

    async fn create_approval(
        &self,
        _req: Request<CreateApprovalRequest>,
    ) -> Result<Response<CreateApprovalResponse>, Status> {
        // Granting an approval requires a real requester + a *different* approver
        // (separation of duties, enforced in db::approvals::approve). Until mTLS
        // peer identity extraction lands (TODO(M1)), this endpoint has no actor
        // to attribute the grant to — a nil actor would let any gRPC caller
        // self-approve. Use the authenticated HTTP facade (/api/approvals).
        Err(Status::unimplemented(
            "approvals must go through the authenticated HTTP API (/api/approvals); \
             gRPC approval creation is disabled until mTLS peer identity is enforced",
        ))
    }

    async fn revoke_approval(
        &self,
        req: Request<RevokeApprovalRequest>,
    ) -> Result<Response<RevokeApprovalResponse>, Status> {
        let r = req.into_inner();
        let id = Uuid::parse_str(&r.approval_id)
            .map_err(|_| Status::invalid_argument("invalid approval_id UUID"))?;
        let ok = db::approvals::revoke(&self.state.pool, id, &r.reason)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RevokeApprovalResponse { ok }))
    }

    async fn list_approvals(
        &self,
        _req: Request<ListApprovalsRequest>,
    ) -> Result<Response<ListApprovalsResponse>, Status> {
        Ok(Response::new(ListApprovalsResponse {
            approvals: vec![],
            next_page_token: String::new(),
        }))
    }

    async fn list_verdicts(
        &self,
        req: Request<ListVerdictsRequest>,
    ) -> Result<Response<ListVerdictsResponse>, Status> {
        use crate::generated::embargo::v1::{Verdict as ProtoVerdict, VerdictProto};
        use embargo_core::types::Verdict;

        let r = req.into_inner();
        let filter_verdict = match r.verdict_filter {
            v if v == ProtoVerdict::Hold as i32 => Verdict::Hold,
            v if v == ProtoVerdict::Deny as i32 => Verdict::Deny,
            _ => Verdict::Hold, // default to quarantine view
        };

        let verdicts = db::verdicts::list_by_verdict(&self.state.pool, filter_verdict, 50, 0)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_verdicts: Vec<VerdictProto> = verdicts
            .iter()
            .map(|v| VerdictProto {
                package: v.package.clone(),
                version: v.version.clone(),
                verdict: match v.verdict {
                    Verdict::Allow => ProtoVerdict::Allow as i32,
                    Verdict::Hold => ProtoVerdict::Hold as i32,
                    Verdict::Deny => ProtoVerdict::Deny as i32,
                },
                reasons: v.reasons.iter().map(|r| format!("{:?}", r)).collect(),
                signals: vec![],
                computed_at: None,
                expires_at: None,
            })
            .collect();

        Ok(Response::new(ListVerdictsResponse {
            verdicts: proto_verdicts,
            next_page_token: String::new(),
        }))
    }

    async fn get_verdict(
        &self,
        req: Request<GetVerdictRequest>,
    ) -> Result<Response<GetVerdictResponse>, Status> {
        let r = req.into_inner();
        let v = db::verdicts::get(&self.state.pool, &r.package, &r.version)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let Some(v) = v else {
            return Err(Status::not_found("verdict not found"));
        };
        use crate::generated::embargo::v1::{Verdict as ProtoVerdict, VerdictProto};
        use embargo_core::types::Verdict;
        Ok(Response::new(GetVerdictResponse {
            verdict: Some(VerdictProto {
                package: v.package,
                version: v.version,
                verdict: match v.verdict {
                    Verdict::Allow => ProtoVerdict::Allow as i32,
                    Verdict::Hold => ProtoVerdict::Hold as i32,
                    Verdict::Deny => ProtoVerdict::Deny as i32,
                },
                reasons: v.reasons.iter().map(|r| format!("{:?}", r)).collect(),
                signals: vec![],
                computed_at: None,
                expires_at: None,
            }),
        }))
    }

    async fn list_audit_entries(
        &self,
        _req: Request<ListAuditEntriesRequest>,
    ) -> Result<Response<ListAuditEntriesResponse>, Status> {
        Ok(Response::new(ListAuditEntriesResponse {
            entries: vec![],
            next_page_token: String::new(),
        }))
    }
}

fn proto_rules_to_yaml(req: &UpsertPolicyRequest) -> Result<String, serde_yaml::Error> {
    use embargo_core::policy::{OnHardSignal, PolicyRule};
    let rules: Vec<PolicyRule> = req
        .rules
        .iter()
        .map(|r| PolicyRule {
            scope: r.scope.clone(),
            cooldown_hours: r.cooldown_hours,
            require_provenance: r.require_provenance,
            on_hard_signal: if r.on_hard_signal == "hold" {
                OnHardSignal::Hold
            } else {
                OnHardSignal::Deny
            },
            fast_track: r.fast_track.clone(),
            enabled: r.enabled,
        })
        .collect();
    let ruleset = PolicyRuleset {
        version: req.schema_version,
        rules,
    };
    serde_yaml::to_string(&ruleset)
}
