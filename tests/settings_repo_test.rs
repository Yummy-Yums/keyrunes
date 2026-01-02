use keyrunes::constants::DEFAULT_NAMESPACE;
use keyrunes::repository::sqlx_impl::PgSettingsRepository;
use keyrunes::repository::{CreateSettings, SettingsRepository};
use serial_test::serial;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use url::Url;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

async fn setup_test_db() -> PgSettingsRepository {
    dotenvy::dotenv().ok();

    let database_url = if let Ok(url) = std::env::var("TEST_DATABASE_URL") {
        url
    } else if let Ok(url_str) = std::env::var("DATABASE_URL") {
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

    sqlx::query!("TRUNCATE TABLE settings RESTART IDENTITY")
        .execute(&pool)
        .await
        .expect("Failed to clean up settings table");

    PgSettingsRepository::new(pool)
}

#[tokio::test]
#[serial]
async fn test_create_and_get_settings() {
    // Setup
    let repo = setup_test_db().await;
    let new_settings = CreateSettings {
        organization_id: None,
        key: "test_key".to_string(),
        value: "test_value".to_string(),
        description: Some("Test Description".to_string()),
    };

    // Act
    let created = repo
        .create_settings(new_settings.clone(), DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Assert
    assert!(created.is_some());
    let created = created.unwrap();
    assert_eq!(created.key, "test_key");
    assert_eq!(created.value, "test_value");

    // Act
    let found = repo
        .get_settings_by_key("test_key", DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Assert
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.key, "test_key");
    assert_eq!(found.value, "test_value");
    assert_eq!(found.description, Some("Test Description".to_string()));
}

#[tokio::test]
#[serial]
async fn test_update_settings() {
    let repo = setup_test_db().await;

    let new_settings = CreateSettings {
        organization_id: None,
        key: "update_key".to_string(),
        value: "initial_value".to_string(),
        description: None,
    };
    repo.create_settings(new_settings, DEFAULT_NAMESPACE)
        .await
        .unwrap();

    repo.update_settings_by_key("update_key", "updated_value", DEFAULT_NAMESPACE)
        .await
        .unwrap();

    let found = repo
        .get_settings_by_key("update_key", DEFAULT_NAMESPACE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.value, "updated_value");
}

#[tokio::test]
#[serial]
async fn test_delete_settings() {
    let repo = setup_test_db().await;

    let new_settings = CreateSettings {
        organization_id: None,
        key: "delete_key".to_string(),
        value: "value".to_string(),
        description: None,
    };
    repo.create_settings(new_settings, DEFAULT_NAMESPACE)
        .await
        .unwrap();

    repo.delete_settings_by_key("delete_key", DEFAULT_NAMESPACE)
        .await
        .unwrap();

    let found = repo
        .get_settings_by_key("delete_key", DEFAULT_NAMESPACE)
        .await
        .unwrap();
    assert!(found.is_none());
}

#[tokio::test]
#[serial]
async fn test_get_all_settings() {
    // Setup
    let repo = setup_test_db().await;

    let s1 = CreateSettings {
        organization_id: None,
        key: "k1".to_string(),
        value: "v1".to_string(),
        description: None,
    };
    let s2 = CreateSettings {
        organization_id: None,
        key: "k2".to_string(),
        value: "v2".to_string(),
        description: None,
    };

    repo.create_settings(s1, DEFAULT_NAMESPACE).await.unwrap();
    repo.create_settings(s2, DEFAULT_NAMESPACE).await.unwrap();

    // Act
    let all = repo.get_all_settings(DEFAULT_NAMESPACE).await.unwrap();

    // Assert
    assert_eq!(all.len(), 2);
}
