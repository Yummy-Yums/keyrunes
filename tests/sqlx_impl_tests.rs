use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::repository::{NewUser, UserRepository};
use serial_test::serial;
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use std::env;
use url::Url;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

// Setup test database
async fn setup_test_db() -> PgPool {
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

    sqlx::query!("TRUNCATE TABLE users CASCADE")
        .execute(&pool)
        .await
        .expect("Failed to clean up users table");

    pool
}

#[tokio::test]
#[serial]
async fn test_insert_and_find_user() {
    // Setup
    let pool = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "john@test.com".to_string(),
        username: "johndoe".to_string(),
        password_hash: "hashed_password".to_string(),
        first_login: false,
        organization_id: 1,
    };

    // Act
    let user = repo.insert_user(new_user.clone()).await.unwrap();

    // Assert
    assert_eq!(user.email, new_user.email);
    assert_eq!(user.username, new_user.username);
    assert_eq!(user.first_login, new_user.first_login);

    // Act
    let found_by_email = repo.find_by_email("john@test.com").await.unwrap().unwrap();

    // Assert
    assert_eq!(found_by_email.email, new_user.email);
    assert_eq!(found_by_email.username, new_user.username);

    // Act
    let found_by_username = repo.find_by_username("johndoe").await.unwrap().unwrap();

    // Assert
    assert_eq!(found_by_username.email, new_user.email);
    assert_eq!(found_by_username.username, new_user.username);

    // Act
    let found_by_id = repo.find_by_id(user.user_id).await.unwrap().unwrap();

    // Assert
    assert_eq!(found_by_id.email, new_user.email);
    assert_eq!(found_by_id.username, new_user.username);
}

#[tokio::test]
#[serial]
async fn test_update_user_password() {
    // Setup
    let pool = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "password@test.com".to_string(),
        username: "passworduser".to_string(),
        password_hash: "old_hash".to_string(),
        first_login: true,
        organization_id: 1,
    };

    let user = repo.insert_user(new_user).await.unwrap();

    // Act
    repo.update_user_password(user.user_id, "new_hash")
        .await
        .unwrap();

    // Assert
    let updated_user = repo.find_by_id(user.user_id).await.unwrap().unwrap();
    assert_eq!(updated_user.password_hash, "new_hash");
}

#[tokio::test]
#[serial]
async fn test_set_first_login() {
    // Setup
    let pool = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "firstlogin@test.com".to_string(),
        username: "firstloginuser".to_string(),
        password_hash: "hash".to_string(),
        first_login: true,
        organization_id: 1,
    };

    let user = repo.insert_user(new_user).await.unwrap();

    // Act
    repo.set_first_login(user.user_id, false).await.unwrap();

    // Assert
    let updated_user = repo.find_by_id(user.user_id).await.unwrap().unwrap();
    assert!(!updated_user.first_login);
}

#[tokio::test]
#[serial]
async fn test_duplicate_email() {
    let pool = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "duplicate@test.com".to_string(),
        username: "user1".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
        organization_id: 1,
    };

    repo.insert_user(new_user.clone()).await.unwrap();

    let duplicate_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "duplicate@test.com".to_string(),
        username: "user2".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
        organization_id: 1,
    };

    let result = repo.insert_user(duplicate_user).await;
    assert!(result.is_err());
}

#[tokio::test]
#[serial]
async fn test_duplicate_username() {
    let pool = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "user1@test.com".to_string(),
        username: "duplicateusername".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
        organization_id: 1,
    };

    repo.insert_user(new_user.clone()).await.unwrap();

    let duplicate_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "user2@test.com".to_string(),
        username: "duplicateusername".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
        organization_id: 1,
    };

    let result = repo.insert_user(duplicate_user).await;
    assert!(result.is_err());
}

#[tokio::test]
#[serial]
async fn test_case_insensitive_email() {
    // Setup
    let pool = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "CaseTest@Test.com".to_string(),
        username: "caseuser".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
        organization_id: 1,
    };

    repo.insert_user(new_user.clone()).await.unwrap();

    // Act
    let found = repo.find_by_email("casetest@test.com").await.unwrap();

    // Assert
    assert!(found.is_some());
    assert_eq!(found.unwrap().username, "caseuser");
}
