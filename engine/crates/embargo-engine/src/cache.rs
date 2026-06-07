use anyhow::Result;
use embargo_core::types::VersionVerdict;
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;

use crate::config::RedisConfig;

pub struct VerdictCache {
    conn: MultiplexedConnection,
    ttl_secs: u64,
}

impl VerdictCache {
    /// Wrap an already-established shared connection — used on the hot path so
    /// resolve does not open a new Redis connection per request.
    /// `MultiplexedConnection` is a cheap-to-clone handle to one shared socket.
    pub fn from_conn(conn: MultiplexedConnection, ttl_secs: u64) -> Self {
        Self { conn, ttl_secs }
    }

    pub async fn get(&mut self, package: &str, version: &str) -> Result<Option<VersionVerdict>> {
        let key = cache_key(package, version);
        let bytes: Option<Vec<u8>> = self.conn.get(&key).await?;
        let Some(bytes) = bytes else { return Ok(None) };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub async fn set(&mut self, verdict: &VersionVerdict) -> Result<()> {
        let key = cache_key(&verdict.package, &verdict.version);
        let bytes = serde_json::to_vec(verdict)?;
        // Use a shorter TTL if the verdict expires before the default cache TTL.
        let ttl = if let Some(exp) = verdict.expires_at {
            let remaining = (exp - chrono::Utc::now()).num_seconds().max(1) as u64;
            remaining.min(self.ttl_secs)
        } else {
            self.ttl_secs
        };
        self.conn.set_ex::<_, _, ()>(&key, bytes, ttl).await?;
        Ok(())
    }

    pub async fn invalidate(&mut self, package: &str, version: &str) -> Result<()> {
        let key = cache_key(package, version);
        self.conn.del::<_, ()>(&key).await?;
        Ok(())
    }
}

fn cache_key(package: &str, version: &str) -> String {
    format!("embargo:verdict:{}:{}", package, version)
}

pub async fn connect(cfg: &RedisConfig) -> Result<MultiplexedConnection> {
    let client = redis::Client::open(cfg.url.as_str())?;
    let conn = client.get_multiplexed_async_connection().await?;
    Ok(conn)
}
