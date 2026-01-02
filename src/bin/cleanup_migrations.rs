use sqlx::PgPool;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres_user:pass123@localhost:5432/keyrunes".to_string());
    let pool = PgPool::connect(&url).await?;

    println!("Cleaning up _sqlx_migrations in {}...", url);

    let to_remove = vec![
        "20260101164000_sync_tenant_schemas",
        "20260101165000_sync_public_organizations",
        "20260101_add_schema_fields",
    ];

    for m in to_remove {
        let res = sqlx::query(
            "DELETE FROM _sqlx_migrations WHERE version = split_part($1, '_', 1)::bigint",
        )
        .bind(m)
        .execute(&pool)
        .await?;
        println!("  Removed {}: {} rows", m, res.rows_affected());
    }

    Ok(())
}
