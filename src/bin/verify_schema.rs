use sqlx::PgPool;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let urls = vec![
        env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres_user:pass123@localhost:5432/keyrunes".to_string()
        }),
        "postgres://postgres_user:pass123@localhost:5432/keyrunes_test".to_string(),
    ];

    for url in urls {
        println!("\nChecking database: {}", url);
        let pool = PgPool::connect(&url).await?;

        let res = sqlx::query!(
            "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('information_schema', 'pg_catalog') AND table_schema NOT LIKE 'pg_toast%'"
        )
        .fetch_all(&pool)
        .await?;

        for r in res {
            let schema = r.table_schema.as_deref().unwrap_or("unknown");
            let table = r.table_name.as_deref().unwrap_or("unknown");

            let col_res = sqlx::query!(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = 'external_id'",
                schema,
                table
            )
            .fetch_optional(&pool)
            .await?;

            let has_ext = if col_res.is_some() {
                "[HAS EXT_ID]"
            } else {
                "[NO EXT_ID]"
            };
            println!("  {}.{} {}", schema, table, has_ext);
        }
    }
    Ok(())
}
