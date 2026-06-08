//! Advisory feed client — matches a (package, version) against OSV / GitHub
//! Advisory data. A match becomes an `advisory_match` signal, which the scoring
//! engine converts to an automatic permanent DENY.
//!
//! Behind a trait so the extractor is testable without network. Queried by the
//! background extractor during the HOLD window, never on the resolve hot path.
//!
//! Continuous re-scanning of already-served versions against refreshed feeds is
//! a follow-up (a periodic advisory-sync job); this slice covers the
//! point-in-time match performed while a version is held.

use anyhow::Result;
use async_trait::async_trait;
use embargo_core::types::{Severity, Signal, SignalType};
use uuid::Uuid;

/// A single advisory affecting a package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub aliases: Vec<String>,
    /// Free-form severity string from the feed (e.g. a CVSS vector), if present.
    pub severity: Option<String>,
}

#[async_trait]
pub trait AdvisoryClient: Send + Sync {
    /// Return advisories affecting `package@version`. An empty vec means clean.
    async fn query(&self, package: &str, version: &str) -> Result<Vec<Advisory>>;
}

/// Convert an advisory into a critical, auto-DENY `advisory_match` signal.
pub fn to_signal(adv: &Advisory) -> Signal {
    Signal {
        id: Uuid::new_v4(),
        signal_type: SignalType::AdvisoryMatch,
        severity: Severity::Critical,
        weight: 100,
        evidence: serde_json::json!({
            "advisory_id": adv.id,
            "summary": adv.summary,
            "aliases": adv.aliases,
            "severity": adv.severity,
        }),
        detected_at: chrono::Utc::now(),
    }
}

/// OSV.dev client. Queries the public batch/query API for npm packages.
pub struct OsvClient {
    http: reqwest::Client,
    endpoint: String,
}

impl OsvClient {
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent("embargo-engine")
            .build()?;
        Ok(Self {
            http,
            endpoint: endpoint.into(),
        })
    }
}

#[async_trait]
impl AdvisoryClient for OsvClient {
    async fn query(&self, package: &str, version: &str) -> Result<Vec<Advisory>> {
        let url = format!("{}/v1/query", self.endpoint.trim_end_matches('/'));
        let body = serde_json::json!({
            "version": version,
            "package": { "name": package, "ecosystem": "npm" }
        });
        let resp: serde_json::Value = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(parse_osv_response(&resp))
    }
}

/// Parse an OSV `/v1/query` response into our `Advisory` list.
pub fn parse_osv_response(resp: &serde_json::Value) -> Vec<Advisory> {
    let Some(vulns) = resp.get("vulns").and_then(|v| v.as_array()) else {
        return vec![];
    };
    vulns
        .iter()
        .filter_map(|v| {
            let id = v.get("id").and_then(|i| i.as_str())?.to_string();
            let summary = v
                .get("summary")
                .and_then(|s| s.as_str())
                .or_else(|| v.get("details").and_then(|d| d.as_str()))
                .unwrap_or("")
                .to_string();
            let aliases = v
                .get("aliases")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let severity = v
                .get("severity")
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|s| s.get("score"))
                .and_then(|sc| sc.as_str())
                .map(String::from);
            Some(Advisory {
                id,
                summary,
                aliases,
                severity,
            })
        })
        .collect()
}

/// In-memory mock for tests — returns a canned advisory list for any query.
#[cfg(test)]
#[derive(Default)]
pub struct MockAdvisoryClient {
    pub advisories: Vec<Advisory>,
}

#[cfg(test)]
#[async_trait]
impl AdvisoryClient for MockAdvisoryClient {
    async fn query(&self, _package: &str, _version: &str) -> Result<Vec<Advisory>> {
        Ok(self.advisories.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn osv_json() -> serde_json::Value {
        serde_json::json!({
            "vulns": [
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "summary": "Prototype pollution in demo",
                    "aliases": ["CVE-2024-0001"],
                    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
                },
                {
                    "id": "GHSA-dddd-eeee-ffff",
                    "details": "Command injection",
                    "aliases": []
                }
            ]
        })
    }

    #[test]
    fn parses_osv_vulns() {
        let advs = parse_osv_response(&osv_json());
        assert_eq!(advs.len(), 2);
        assert_eq!(advs[0].id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(advs[0].summary, "Prototype pollution in demo");
        assert_eq!(advs[0].aliases, vec!["CVE-2024-0001"]);
        assert!(advs[0].severity.is_some());
        // second falls back to `details` for summary
        assert_eq!(advs[1].summary, "Command injection");
    }

    #[test]
    fn empty_response_is_clean() {
        assert!(parse_osv_response(&serde_json::json!({})).is_empty());
        assert!(parse_osv_response(&serde_json::json!({ "vulns": [] })).is_empty());
    }

    #[test]
    fn advisory_becomes_critical_match_signal() {
        let adv = Advisory {
            id: "GHSA-x".into(),
            summary: "bad".into(),
            aliases: vec![],
            severity: None,
        };
        let sig = to_signal(&adv);
        assert_eq!(sig.signal_type, SignalType::AdvisoryMatch);
        assert_eq!(sig.severity, Severity::Critical);
        assert_eq!(sig.weight, 100);
        assert_eq!(sig.evidence.get("advisory_id").unwrap(), "GHSA-x");
    }
}
