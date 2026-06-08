use anyhow::Result;
use sqlx::PgPool;

use crate::config::DatabaseConfig;

pub mod approvals;
pub mod audit;
pub mod policies;
pub mod provenance;
pub mod signals;
pub mod stats;
pub mod verdicts;

pub async fn connect(cfg: &DatabaseConfig) -> Result<PgPool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .connect(&cfg.url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}
