//! Feed ingestion worker.
//!
//! Syncs each enabled feed source (`db::feed_sources`) into `db::known_malicious`
//! on its interval. Sources are managed at runtime from the console — operators
//! add a curated dataset URL and toggle it on. Today the Datadog manifest format
//! (`{ "pkg": null | ["1.0.0", ...] }`) is supported.

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use std::net::IpAddr;
use std::time::Duration;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::db::{self, feed_sources::FeedSource};
use crate::grpc::EngineState;

/// How often to scan for due sources.
const TICK: Duration = Duration::from_secs(30);
/// Max sources synced per pass.
const BATCH: i64 = 10;
/// Cap the feed body we read into memory (curated datasets are small).
const MAX_FEED_BYTES: u64 = 64 * 1024 * 1024;

/// Spawn the detached feed-sync worker. Runs for the process lifetime; a source
/// is only fetched when enabled and due, so an all-disabled deployment is idle.
pub fn spawn(state: EngineState) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("feed sync worker started");
        loop {
            tokio::time::sleep(TICK).await;
            if let Err(e) = run_pass(&state).await {
                tracing::warn!(error = %e, "feed sync pass failed");
            }
        }
    })
}

async fn run_pass(state: &EngineState) -> Result<()> {
    let due = db::feed_sources::due(&state.pool, Utc::now(), BATCH).await?;
    for src in due {
        let status = match sync_one(state, &src).await {
            Ok(n) => format!("ok: {n} entries"),
            Err(e) => {
                tracing::warn!(source = %src.name, error = %e, "feed sync failed");
                format!("error: {e}")
            }
        };
        db::feed_sources::mark_synced(&state.pool, src.id, &status, Utc::now()).await?;
    }
    Ok(())
}

/// Sync a single source now (manual trigger). Records status; returns rows written.
pub async fn sync_source(state: &EngineState, id: Uuid) -> Result<u64> {
    let src = db::feed_sources::get(&state.pool, id)
        .await?
        .ok_or_else(|| anyhow!("feed source not found"))?;
    let result = sync_one(state, &src).await;
    let status = match &result {
        Ok(n) => format!("ok: {n} entries"),
        Err(e) => format!("error: {e}"),
    };
    db::feed_sources::mark_synced(&state.pool, src.id, &status, Utc::now()).await?;
    result
}

async fn sync_one(state: &EngineState, src: &FeedSource) -> Result<u64> {
    let body = fetch_feed_guarded(&src.url).await?;
    let entries = match src.format.as_str() {
        "datadog-manifest" => parse_manifest(&body)?,
        other => return Err(anyhow!("unsupported feed format: {other}")),
    };
    let written =
        db::known_malicious::replace_source(&state.pool, &src.name, &src.ecosystem, &entries)
            .await?;
    Ok(written)
}

/// Fetch a feed URL with SSRF protection: the host must resolve only to public
/// addresses, the connection is pinned to a validated IP (defeating DNS
/// rebinding), redirects are disabled (so a public host can't 302 into the
/// internal range), and the request is time- and size-bounded.
///
/// Feed URLs are operator/console-supplied, so this is the primary SSRF surface;
/// without these checks a URL like `http://169.254.169.254/…` would let the
/// engine read cloud metadata or internal services.
async fn fetch_feed_guarded(url_str: &str) -> Result<String> {
    let url = reqwest::Url::parse(url_str).context("parse feed URL")?;
    match url.scheme() {
        "http" | "https" => {}
        s => bail!("feed URL scheme {s} is not allowed (http/https only)"),
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("feed URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("feed URL has no port"))?;

    // Resolve and require *every* resolved address to be public.
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve feed host {host}"))?
        .collect();
    if addrs.is_empty() {
        bail!("feed host {host} did not resolve");
    }
    if let Some(bad) = addrs.iter().find(|a| !is_public_ip(a.ip())) {
        bail!(
            "feed host {host} resolves to a non-public address {} (SSRF guard)",
            bad.ip()
        );
    }

    // Pin the connection to the validated address so a re-resolve can't rebind to
    // an internal IP between the check and the connect.
    let client = reqwest::Client::builder()
        .user_agent("embargo-engine")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .resolve(host, addrs[0])
        .build()
        .context("build feed client")?;

    let resp = client
        .get(url.clone())
        .send()
        .await
        .context("fetch feed")?
        .error_for_status()
        .context("feed HTTP status")?;

    // Reject an over-large declared body up front; the overall timeout bounds a
    // body that lies about (or omits) its length.
    if let Some(len) = resp.content_length() {
        if len > MAX_FEED_BYTES {
            bail!("feed body declares {len} bytes, over the {MAX_FEED_BYTES} cap");
        }
    }
    let bytes = resp.bytes().await.context("read feed body")?;
    if bytes.len() as u64 > MAX_FEED_BYTES {
        bail!("feed body exceeds {MAX_FEED_BYTES} bytes");
    }
    String::from_utf8(bytes.to_vec()).context("feed body is not UTF-8")
}

/// Whether an IP is a public (globally-routable) unicast address. Rejects
/// loopback, private (RFC1918), link-local (incl. cloud metadata 169.254.x),
/// shared/CGNAT, ULA, multicast, and unspecified ranges.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let shared_cgnat = o[0] == 100 && (64..=127).contains(&o[1]); // 100.64.0.0/10
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || o[0] == 0
                || shared_cgnat)
        }
        IpAddr::V6(v6) => {
            // Map IPv4-in-IPv6 back to the v4 rules.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_ula
                || is_link_local)
        }
    }
}

/// Parse a manifest of the form `{ "pkg": null | ["1.0.0", ...] }` into
/// (package, version) pairs. A `null` value means every version is malicious and
/// maps to a single [`db::known_malicious::ALL_VERSIONS`] row.
pub fn parse_manifest(body: &str) -> Result<Vec<(String, String)>> {
    use serde_json::Value;
    let map: serde_json::Map<String, Value> =
        serde_json::from_str(body).context("parse feed manifest JSON")?;
    let mut out = Vec::with_capacity(map.len());
    for (pkg, versions) in map {
        match versions {
            Value::Null => out.push((pkg, db::known_malicious::ALL_VERSIONS.to_string())),
            Value::Array(vs) => {
                for v in vs {
                    if let Some(s) = v.as_str() {
                        out.push((pkg.clone(), s.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_guard_rejects_internal_addresses() {
        use std::net::IpAddr;
        let blocked = [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",         // ULA
            "fe80::1",         // link-local
            "::ffff:10.0.0.1", // v4-mapped private
        ];
        for ip in blocked {
            assert!(
                !is_public_ip(ip.parse::<IpAddr>().unwrap()),
                "{ip} must be rejected"
            );
        }
        let allowed = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ];
        for ip in allowed {
            assert!(
                is_public_ip(ip.parse::<IpAddr>().unwrap()),
                "{ip} must be allowed"
            );
        }
    }

    #[test]
    fn parses_null_and_list_entries() {
        let json = r#"{
            "evil-all": null,
            "@scope/compromised": ["1.0.0", "1.0.1"],
            "weird": 42
        }"#;
        let mut e = parse_manifest(json).unwrap();
        e.sort();
        assert!(e.contains(&("evil-all".into(), "*".into())));
        assert!(e.contains(&("@scope/compromised".into(), "1.0.0".into())));
        assert!(e.contains(&("@scope/compromised".into(), "1.0.1".into())));
        assert!(!e.iter().any(|(p, _)| p == "weird"));
    }
}
