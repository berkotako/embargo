//! Registry client — fetches packuments and version tarballs from the upstream
//! npm registry. Behind a trait so the extractor is testable without network.
//!
//! Hot-path note: this is used by the *background* signal extractor, never by
//! the resolve hot path (which only reads cached verdicts).

use anyhow::Result;
use async_trait::async_trait;
use std::collections::BTreeMap;

/// The subset of packument metadata the extractor needs.
#[derive(Debug, Clone, Default)]
pub struct Packument {
    /// Package name; surfaced in logs/console. Not load-bearing for extraction.
    #[allow(dead_code)]
    pub name: String,
    /// version → per-version metadata.
    pub versions: BTreeMap<String, PackumentVersion>,
    /// version (or "created"/"modified") → ISO-8601 publish timestamp.
    pub time: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct PackumentVersion {
    /// Redundant with the map key; kept for self-describing logs.
    #[allow(dead_code)]
    pub version: String,
    pub tarball_url: String,
    pub repository: Option<String>,
    /// npm user that published this version (`_npmUser`).
    pub npm_user: Option<String>,
    pub maintainers: Vec<String>,
}

#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn packument(&self, package: &str) -> Result<Packument>;
    async fn tarball(&self, url: &str) -> Result<Vec<u8>>;
}

/// Real HTTP client against a configurable upstream (default registry.npmjs.org).
pub struct HttpRegistryClient {
    http: reqwest::Client,
    upstream: String,
}

impl HttpRegistryClient {
    pub fn new(upstream: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent("embargo-engine")
            .build()?;
        Ok(Self {
            http,
            upstream: upstream.into(),
        })
    }
}

#[async_trait]
impl RegistryClient for HttpRegistryClient {
    async fn packument(&self, package: &str) -> Result<Packument> {
        let url = format!("{}/{}", self.upstream.trim_end_matches('/'), package);
        let body: serde_json::Value = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(parse_packument(&body))
    }

    async fn tarball(&self, url: &str) -> Result<Vec<u8>> {
        let bytes = self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        Ok(bytes.to_vec())
    }
}

/// Parse a raw packument JSON document into our `Packument` subset.
pub fn parse_packument(body: &serde_json::Value) -> Packument {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut versions = BTreeMap::new();
    if let Some(obj) = body.get("versions").and_then(|v| v.as_object()) {
        for (ver, meta) in obj {
            let tarball_url = meta
                .get("dist")
                .and_then(|d| d.get("tarball"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let npm_user = meta
                .get("_npmUser")
                .and_then(|u| u.get("name"))
                .and_then(|n| n.as_str())
                .map(String::from);
            let maintainers = meta
                .get("maintainers")
                .and_then(|m| m.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            versions.insert(
                ver.clone(),
                PackumentVersion {
                    version: ver.clone(),
                    tarball_url,
                    repository: crate::tarball::parse_repository(meta),
                    npm_user,
                    maintainers,
                },
            );
        }
    }

    let mut time = BTreeMap::new();
    if let Some(obj) = body.get("time").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                time.insert(k.clone(), s.to_string());
            }
        }
    }

    Packument {
        name,
        versions,
        time,
    }
}

/// Pick the version published immediately before `version` per the time map.
/// Returns None for a first-ever publish.
pub fn prior_version(packument: &Packument, version: &str) -> Option<String> {
    let target = packument.time.get(version)?;
    packument
        .time
        .iter()
        .filter(|(k, _)| *k != version && *k != "created" && *k != "modified")
        .filter(|(k, _)| packument.versions.contains_key(*k))
        .filter(|(_, t)| t.as_str() < target.as_str()) // ISO-8601 sorts lexically by time
        .max_by(|a, b| a.1.cmp(b.1))
        .map(|(k, _)| k.clone())
}

/// Count versions published within the hour before `version` (republish burst).
pub fn republish_burst(packument: &Packument, version: &str) -> u32 {
    let Some(target) = packument.time.get(version).and_then(|t| parse_iso(t)) else {
        return 0;
    };
    let window = chrono::Duration::hours(1);
    packument
        .time
        .iter()
        .filter(|(k, _)| *k != "created" && *k != "modified")
        .filter(|(k, _)| packument.versions.contains_key(*k))
        .filter_map(|(_, t)| parse_iso(t))
        .filter(|t| *t < target && (target - *t) <= window)
        .count() as u32
}

fn parse_iso(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

/// In-memory mock for tests — serves canned packuments and tarballs.
#[cfg(test)]
pub struct MockRegistryClient {
    pub packument: Packument,
    /// tarball_url → gz bytes
    pub tarballs: std::collections::HashMap<String, Vec<u8>>,
}

#[cfg(test)]
#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn packument(&self, _package: &str) -> Result<Packument> {
        Ok(self.packument.clone())
    }
    async fn tarball(&self, url: &str) -> Result<Vec<u8>> {
        self.tarballs
            .get(url)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock: no tarball for {url}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packument_json() -> serde_json::Value {
        serde_json::json!({
            "name": "demo",
            "versions": {
                "1.0.0": {
                    "version": "1.0.0",
                    "dist": { "tarball": "https://r/demo/-/demo-1.0.0.tgz" },
                    "repository": "https://github.com/acme/demo",
                    "_npmUser": { "name": "alice" },
                    "maintainers": [{ "name": "alice" }, { "name": "bob" }]
                },
                "1.1.0": {
                    "version": "1.1.0",
                    "dist": { "tarball": "https://r/demo/-/demo-1.1.0.tgz" },
                    "_npmUser": { "name": "mallory" },
                    "maintainers": [{ "name": "mallory" }]
                }
            },
            "time": {
                "created": "2024-01-01T00:00:00.000Z",
                "1.0.0": "2024-01-01T00:00:00.000Z",
                "1.1.0": "2024-06-01T00:00:00.000Z",
                "modified": "2024-06-01T00:00:00.000Z"
            }
        })
    }

    #[test]
    fn parses_versions_and_publisher() {
        let p = parse_packument(&packument_json());
        assert_eq!(p.versions.len(), 2);
        let v110 = p.versions.get("1.1.0").unwrap();
        assert_eq!(v110.tarball_url, "https://r/demo/-/demo-1.1.0.tgz");
        assert_eq!(v110.npm_user.as_deref(), Some("mallory"));
        let v100 = p.versions.get("1.0.0").unwrap();
        assert_eq!(
            v100.repository.as_deref(),
            Some("https://github.com/acme/demo")
        );
        assert_eq!(v100.maintainers, vec!["alice", "bob"]);
    }

    #[test]
    fn prior_version_picks_predecessor() {
        let p = parse_packument(&packument_json());
        assert_eq!(prior_version(&p, "1.1.0").as_deref(), Some("1.0.0"));
        assert_eq!(prior_version(&p, "1.0.0"), None); // first publish
    }
}
