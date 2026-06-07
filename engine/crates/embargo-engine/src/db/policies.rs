use anyhow::Result;
use embargo_core::policy::PolicyRuleset;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn get_active(pool: &PgPool) -> Result<Option<PolicyRuleset>> {
    let row = sqlx::query!(
        r#"
        SELECT yaml_content
        FROM policies
        WHERE active = true
        ORDER BY updated_at DESC
        LIMIT 1
        "#
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let ruleset = PolicyRuleset::from_yaml(&row.yaml_content)?;
    Ok(Some(ruleset))
}

pub async fn upsert(
    pool: &PgPool,
    ruleset: &PolicyRuleset,
    yaml_content: &str,
    actor_id: Uuid,
    justification: &str,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    // Deactivate the current policy and install the new one atomically.
    let mut tx = pool.begin().await?;
    sqlx::query!("UPDATE policies SET active = false WHERE active = true")
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        r#"
        INSERT INTO policies (id, schema_version, yaml_content, active, actor_id, justification, updated_at)
        VALUES ($1, $2, $3, true, $4, $5, NOW())
        "#,
        id,
        ruleset.version as i32,
        yaml_content,
        actor_id,
        justification,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}
