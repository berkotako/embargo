//! engine.ReportEvent client. Containment events become high-weight signals
//! (`sandbox_egress_attempt`) that can escalate a verdict to DENY.

use crate::seccomp::BlockedEgress;
use anyhow::{Context, Result};

pub mod pb {
    tonic::include_proto!("embargo.v1");
}

use pb::engine_service_client::EngineServiceClient;
use pb::ReportEventRequest;

/// Build the containment-event request the console feed expects:
/// `{ pkg, host, pipeline, repo, attempts, time, note? }` as evidence JSON.
pub fn build_request(
    package: &str,
    version: &str,
    blocked: &BlockedEgress,
    pipeline: &str,
    repo: &str,
) -> ReportEventRequest {
    let evidence = serde_json::json!({
        "pkg": package,
        "host": blocked.dest.to_string(),
        "pipeline": pipeline,
        "repo": repo,
        "attempts": 1,
        "time": chrono_now(),
        "note": "install attempted outbound connection to a non-allowlisted host",
        "pid": blocked.pid,
    });
    ReportEventRequest {
        event_type: "sandbox_egress_attempt".to_string(),
        package: package.to_string(),
        version: version.to_string(),
        evidence_json: evidence.to_string(),
        // High weight; chains in the engine can escalate this to DENY.
        weight: 90,
        reporter_service: "sandbox".to_string(),
    }
}

/// Send a containment event to the engine over (optionally TLS) gRPC.
pub async fn report(engine_addr: &str, req: ReportEventRequest) -> Result<()> {
    let endpoint = if engine_addr.starts_with("http") {
        engine_addr.to_string()
    } else {
        format!("http://{engine_addr}")
    };
    let mut client = EngineServiceClient::connect(endpoint)
        .await
        .context("connect engine")?;
    client.report_event(req).await.context("ReportEvent")?;
    Ok(())
}

fn chrono_now() -> String {
    // Avoid a chrono dep here; seconds since epoch is enough for the feed.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn builds_containment_event() {
        let blocked = BlockedEgress {
            pid: 1234,
            dest: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
        };
        let req = build_request("evil-pkg", "1.0.0", &blocked, "build/deploy", "acme/app");
        assert_eq!(req.event_type, "sandbox_egress_attempt");
        assert_eq!(req.package, "evil-pkg");
        assert_eq!(req.weight, 90);
        let ev: serde_json::Value = serde_json::from_str(&req.evidence_json).unwrap();
        assert_eq!(ev["host"], "93.184.216.34:443");
        assert_eq!(ev["pkg"], "evil-pkg");
    }
}
