use keyrunes::constants::DEFAULT_NAMESPACE;
use keyrunes::repository::sqlx_impl::{PgPolicyRepository, PgUserRepository};
use keyrunes::repository::{NewUser, PolicyEffect, UserRepository};
use keyrunes::services::policy_service::{CreatePolicyRequest, PolicyService};
use serial_test::serial;
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

// Setup test database
async fn setup_db() -> PgPool {
    dotenvy::dotenv().ok();
    let database_url = if let Ok(url) = env::var("TEST_DATABASE_URL") {
        url
    } else if let Ok(url_str) = env::var("DATABASE_URL") {
        if let Ok(mut url) = Url::parse(&url_str) {
            url.set_path("keyrunes");
            url.to_string()
        } else {
            "postgres://postgres_user:pass123@localhost:5432/keyrunes".to_string()
        }
    } else {
        "postgres://postgres_user:pass123@localhost:5432/keyrunes".to_string()
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    MIGRATOR.run(&pool).await.expect("Failed to run migrations");

    sqlx::query!("TRUNCATE TABLE policies, user_policies, users, organizations CASCADE")
        .execute(&pool)
        .await
        .expect("Failed to clean up tables");

    sqlx::query!("INSERT INTO organizations (organization_id, name, external_id, secret_key, description, namespace) VALUES (1, 'Test Org', $1, $2, 'Default Test Org', $3)", Uuid::new_v4(), Uuid::new_v4(), DEFAULT_NAMESPACE)
        .execute(&pool)
        .await
        .expect("Failed to insert default organization");

    pool
}

#[tokio::test]
#[serial]
async fn test_create_and_get_policy() {
    // Setup
    let pool = setup_db().await;
    let repo = Arc::new(PgPolicyRepository::new(pool));
    let service = PolicyService::new(repo);

    let req = CreatePolicyRequest {
        organization_id: 1,
        name: "test_policy".to_string(),
        description: Some("Test Policy".to_string()),
        resource: "document:123".to_string(),
        action: "read".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };

    // Act
    let created = service
        .create_policy(req.clone(), DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Assert
    assert_eq!(created.name, req.name);
    assert_eq!(created.resource, req.resource);

    let found = service
        .get_policy_by_name("test_policy", 1, DEFAULT_NAMESPACE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.policy_id, created.policy_id);
}

#[tokio::test]
#[serial]
async fn test_create_duplicate_policy_name() {
    // Setup
    let pool = setup_db().await;
    let repo = Arc::new(PgPolicyRepository::new(pool));
    let service = PolicyService::new(repo);

    let req = CreatePolicyRequest {
        organization_id: 1,
        name: "duplicate_policy".to_string(),
        description: None,
        resource: "*".to_string(),
        action: "*".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };

    service
        .create_policy(req.clone(), DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Act
    let result = service.create_policy(req, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_err());
}

#[tokio::test]
#[serial]
async fn test_assign_policy_and_evaluate_permission() {
    // Setup
    let pool = setup_db().await;
    let policy_repo = Arc::new(PgPolicyRepository::new(pool.clone()));
    let user_repo = PgUserRepository::new(pool.clone());
    let service = PolicyService::new(policy_repo.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "policy_user@test.com".to_string(),
        username: "policy_user".to_string(),
        password_hash: "pass".to_string(),
        first_login: false,
        organization_id: 1,
    };
    let user = user_repo
        .insert_user(new_user, DEFAULT_NAMESPACE)
        .await
        .unwrap();

    let req = CreatePolicyRequest {
        organization_id: 1,
        name: "read_docs".to_string(),
        description: None,
        resource: "docs:*".to_string(),
        action: "read".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    let policy = service.create_policy(req, DEFAULT_NAMESPACE).await.unwrap();

    // Act
    service
        .assign_policy_to_user(user.user_id, policy.policy_id, None, DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Act
    let user_policies = user_repo
        .get_user_policies(user.user_id, DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Assert
    assert!(
        service
            .evaluate_permission(&user_policies, "docs:report", "read")
            .await
    );
    assert!(
        !service
            .evaluate_permission(&user_policies, "docs:report", "write")
            .await
    );
}

#[tokio::test]
#[serial]
async fn test_list_policies() {
    // Setup
    let pool = setup_db().await;
    let repo = Arc::new(PgPolicyRepository::new(pool));
    let service = PolicyService::new(repo);

    let req1 = CreatePolicyRequest {
        organization_id: 1,
        name: "p1".to_string(),
        description: None,
        resource: "r1".to_string(),
        action: "a1".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    let req2 = CreatePolicyRequest {
        organization_id: 1,
        name: "p2".to_string(),
        description: None,
        resource: "r2".to_string(),
        action: "a2".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };

    service
        .create_policy(req1, DEFAULT_NAMESPACE)
        .await
        .unwrap();
    service
        .create_policy(req2, DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Act
    let list = service.list_policies(1, DEFAULT_NAMESPACE).await.unwrap();

    // Assert
    assert_eq!(list.len(), 2);
}
