use keyrunes::repository::sqlx_impl::{PgGroupRepository, PgOrganizationRepository};
use keyrunes::services::organization_service::{CreateOrganizationRequest, OrganizationService};
use serial_test::serial;
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

async fn setup_db() -> PgPool {
    dotenvy::dotenv().ok();
    let database_url = if let Ok(url) = env::var("TEST_DATABASE_URL") {
        url
    } else if let Ok(url_str) = env::var("DATABASE_URL") {
        if let Ok(mut url) = Url::parse(&url_str) {
            url.set_path("keyrunes_test");
            url.to_string()
        } else {
            "postgres://postgres_user:pass123@localhost:5432/keyrunes_test".to_string()
        }
    } else {
        "postgres://postgres_user:pass123@localhost:5432/keyrunes_test".to_string()
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    MIGRATOR.run(&pool).await.expect("Failed to run migrations");

    sqlx::query!("TRUNCATE TABLE organizations, groups, users CASCADE")
        .execute(&pool)
        .await
        .expect("Failed to clean up tables");

    pool
}

#[tokio::test]
#[serial]
async fn test_rotate_org_key() {
    // Setup
    let pool = setup_db().await;
    let repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let service = OrganizationService::new(repo, group_repo);

    let namespace = format!("test_org_{}", Uuid::new_v4().to_string().replace('-', ""));
    let req = CreateOrganizationRequest {
        name: "Test Org".to_string(),
        description: Some("Test Desc".to_string()),
        namespace,
        base_url: None,
    };

    let org = service.create_organization(req).await.unwrap();
    let initial_key = org.secret_key;

    // Act
    let new_key = service.rotate_org_key(org.organization_id).await.unwrap();

    // Assert
    assert_ne!(initial_key, new_key);

    let updated_org = service
        .get_organization_by_id(org.organization_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_org.secret_key, new_key);
}
