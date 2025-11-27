use clap::{Parser, Subcommand};
use keyrunes::NewPasswordResetToken;
use keyrunes::PasswordResetRepository;
use keyrunes::jwt_service::JwtService;
use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::services::user_service::{RegisterRequest, UserService};
use keyrunes::sqlx_impl::{PgGroupRepository, PgPasswordResetRepository, PgSettingsRepository};
use keyrunes::user_service::{AdminChangePasswordRequest, SettingsService};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing_subscriber::filter::LevelFilter;
use tera::Tera;

#[derive(Parser)]
#[clap(name = "Keyrunes CLI")]
#[clap(about = "Use keyrunes via cli as sysadmin, or developer")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register User with username, password and email
    Register {
        #[clap(long)]
        email: String,
        #[clap(long)]
        username: String,
        #[clap(long)]
        password: String,
        #[clap(long)]
        first_login: bool,
    },
    /// Login as a user with username, password
    Login {
        // identity can be username or email
        #[clap(long)]
        identity: String, // email ou username
        #[clap(long)]
        password: String,
    },
    /// recover user by generating token
    RecoverUser {
        #[clap(long)]
        username: String,
        #[clap(long)]
        generate_token: bool,
    },
    /// set user password
    SetUserPassword {
        #[clap(long)]
        email: String,

        #[clap(long)]
        set_password: bool,

        #[clap(long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .init();

    let cli = Cli::parse();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".into());

    let pool = PgPool::connect(&database_url).await?;

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));

    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".into());

    // Load templates
    let _tera = Arc::new(Tera::new("templates/**/*").expect("Failed to load templates"));

    let jwt_service = Arc::new(JwtService::new(&jwt_secret));
    let settings_repo = Arc::new(PgSettingsRepository::new(pool.clone()));
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = Arc::new(UserService::new(
        user_repo,
        group_repo,
        password_reset_repo.clone(),
        jwt_service.clone(),
        settings_service,
        None,
    ));

    // load settings into a hashmap from db
    let base_url_settings: HashMap<String, String> = HashMap::from_iter(
        &mut service
            .settings_service
            .get_all_settings()
            .await?
            .iter()
            .map(|setting| (setting.key.clone(), setting.value.clone())),
    );

    match cli.command {
        Commands::Register {
            email,
            username,
            password,
            first_login,
        } => {
            let req = RegisterRequest {
                email,
                username,
                password,
                first_login: Some(first_login),
            };
            match service.register(req).await {
                Ok(u) => println!(
                    "Created user {} (external_id={})",
                    u.user.user_id, u.user.external_id
                ),
                Err(e) => eprintln!("Error registering user: {}", e),
            }
        }
        Commands::Login { identity, password } => match service.login(identity, password).await {
            Ok(u) => println!("Login successful! Welcome {}", u.user.username),
            Err(e) => eprintln!("Login failed: {}", e),
        },
        Commands::RecoverUser {
            username,
            generate_token: _,
        } => {
            // find user by username
            let res = service.find_user_by_username(&username).await;

            if res.is_none() {
                return Err(anyhow::anyhow!("User {} not found", &username));
            }

            let user = res.unwrap();

            let user_group = service.get_user_group_names(user.user_id).await?;

            let jwt_generated_token = jwt_service
                .generate_token(
                    user.user_id,
                    user.username.as_str(),
                    user.email.as_str(),
                    user_group,
                )
                .map_err(|err| tracing::error!("Error generating token: {}", err));

            let expires_at = chrono::Utc::now() + chrono::Duration::seconds(3600);

            let new_password_token = NewPasswordResetToken {
                user_id: user.user_id,
                token: jwt_generated_token.unwrap(),
                expires_at,
            };

            let password_reset_token = service
                .password_reset_repo
                .create_reset_token(new_password_token)
                .await?;

            let base_url = base_url_settings.get("BASE_URL").unwrap();

            tracing::info!("Generated reset url for user {} below", username);
            tracing::info!(
                "reset url {}?token={}",
                base_url,
                password_reset_token.token
            );
        }
        Commands::SetUserPassword {
            email,
            set_password: _set_password,
            password,
        } => {
            let user = service.find_user_by_email(&email).await;

            if user.is_none() {
                return Err(anyhow::anyhow!("User with email {} not found", &email));
            }

            let user = user.unwrap();
            let change_password_request = AdminChangePasswordRequest {
                user_id: user.user_id,
                new_password: password.to_string(),
            };

            service.update_password(change_password_request).await?;

            tracing::info!("Updated password successfully for {}", user.username);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrunes::repository::{
        CreateSettings, Group, NewPasswordResetToken, PasswordResetRepository, PasswordResetToken,
        Settings, SettingsRepository, User, UserRepository,
    };
    use keyrunes::services::user_service::{SettingsService, UserService};
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    type Store<T> = Arc<Mutex<Vec<T>>>;
    type UserStore = Store<User>;

    const USERNAME: &str = "test";
    const EMAIL: &str = "test@gmail.com";
    const PASSWORD: &str = "password";

    // Mock repositories for unit tests
    struct MockUserRepo {
        users: UserStore,
    }

    impl MockUserRepo {
        fn new() -> Self {
            let users = Arc::new(Mutex::new(Vec::new()));
            // Seed with test user
            users.lock().unwrap().push(User {
                user_id: 1,
                external_id: Uuid::new_v4(),
                email: EMAIL.to_string(),
                username: USERNAME.to_string(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$test$test".to_string(),
                first_login: false,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            });
            Self { users }
        }
    }

    #[async_trait::async_trait]
    impl UserRepository for MockUserRepo {
        async fn insert_user(&self, _user: keyrunes::NewUser) -> anyhow::Result<User> {
            unimplemented!()
        }
        async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<User>> {
            Ok(self
                .users
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.email == email)
                .cloned())
        }
        async fn find_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
            Ok(self
                .users
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.username == username)
                .cloned())
        }
        async fn find_by_id(&self, _id: i64) -> anyhow::Result<Option<User>> {
            unimplemented!()
        }
        async fn update_user_password(&self, user_id: i64, password_hash: &str) -> anyhow::Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.password_hash = password_hash.to_string();
            }
            Ok(())
        }
        async fn set_first_login(&self, _user_id: i64, _first_login: bool) -> anyhow::Result<()> {
            Ok(())
        }
        async fn get_user_groups(&self, _user_id: i64) -> anyhow::Result<Vec<Group>> {
            Ok(vec![])
        }
        async fn get_user_policies(
            &self,
            _user_id: i64,
        ) -> anyhow::Result<Vec<keyrunes::repository::Policy>> {
            Ok(vec![])
        }
        async fn get_user_all_policies(
            &self,
            _user_id: i64,
        ) -> anyhow::Result<Vec<keyrunes::repository::Policy>> {
            Ok(vec![])
        }
    }

    struct MockGroupRepo;

    #[async_trait::async_trait]
    impl keyrunes::repository::GroupRepository for MockGroupRepo {
        async fn insert_group(&self, _group: keyrunes::NewGroup) -> anyhow::Result<Group> {
            unimplemented!()
        }
        async fn find_by_name(&self, _name: &str) -> anyhow::Result<Option<Group>> {
            Ok(None)
        }
        async fn find_by_id(&self, _id: i64) -> anyhow::Result<Option<Group>> {
            unimplemented!()
        }
        async fn list_groups(&self) -> anyhow::Result<Vec<Group>> {
            Ok(vec![])
        }
        async fn assign_user_to_group(
            &self,
            _user_id: i64,
            _group_id: i64,
            _assigned_by: Option<i64>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn remove_user_from_group(
            &self,
            _user_id: i64,
            _group_id: i64,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_group_policies(&self, _group_id: i64) -> anyhow::Result<Vec<keyrunes::repository::Policy>> {
            Ok(vec![])
        }
    }

    struct MockPasswordResetRepo;

    #[async_trait::async_trait]
    impl PasswordResetRepository for MockPasswordResetRepo {
        async fn create_reset_token(
            &self,
            token: NewPasswordResetToken,
        ) -> anyhow::Result<PasswordResetToken> {
            Ok(PasswordResetToken {
                token_id: 1,
                user_id: token.user_id,
                token: token.token,
                expires_at: token.expires_at,
                used_at: None,
                created_at: chrono::Utc::now(),
            })
        }
        async fn find_valid_token(&self, _token: &str) -> anyhow::Result<Option<PasswordResetToken>> {
            Ok(None)
        }
        async fn mark_token_used(&self, _token_id: i64) -> anyhow::Result<()> {
            Ok(())
        }
        async fn cleanup_expired_tokens(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct MockSettingsRepo;

    #[async_trait::async_trait]
    impl SettingsRepository for MockSettingsRepo {
        async fn create_settings(
            &self,
            _settings: CreateSettings,
        ) -> anyhow::Result<Option<CreateSettings>> {
            Ok(None)
        }
        async fn get_settings_by_key(&self, key: &str) -> anyhow::Result<Option<Settings>> {
            if key == "BASE_URL" {
                Ok(Some(Settings {
                    settings_id: 1,
                    key: "BASE_URL".to_string(),
                    value: "http://127.0.0.1:3000".to_string(),
                    description: Some("Base URL".to_string()),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                }))
            } else {
                Ok(None)
            }
        }
        async fn get_all_settings(&self) -> anyhow::Result<Vec<Settings>> {
            Ok(vec![Settings {
                settings_id: 1,
                key: "BASE_URL".to_string(),
                value: "http://127.0.0.1:3000".to_string(),
                description: Some("Base URL".to_string()),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }])
        }
        async fn update_settings_by_key(&self, _key: &str, _value: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete_settings_by_key(&self, _key: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    // Unit tests with mocks - these run without external dependencies
    #[tokio::test]
    async fn test_update_password_with_valid_email() {
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new("test_secret"));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));

        let service = UserService::new(
            user_repo.clone(),
            group_repo,
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        // Test finding user and updating password
        let user = service.find_user_by_email(&EMAIL.to_string()).await;
        assert!(user.is_some());

        let user = user.unwrap();
        let request = AdminChangePasswordRequest {
            user_id: user.user_id,
            new_password: "NewPassword123".to_string(),
        };

        let result = service.update_password(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_password_with_invalid_email() {
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new("test_secret"));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));

        let service = UserService::new(
            user_repo,
            group_repo,
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        // Test with non-existent email
        let user = service.find_user_by_email(&"nonexistent@example.com".to_string()).await;
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_recover_user_with_valid_username() {
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new("test_secret"));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));

        let service = UserService::new(
            user_repo,
            group_repo,
            password_reset_repo,
            jwt_service.clone(),
            settings_service.clone(),
            None,
        );

        // Test finding user by username
        let user = service.find_user_by_username(&USERNAME.to_string()).await;
        assert!(user.is_some());

        let user = user.unwrap();
        assert_eq!(user.username, USERNAME);

        // Test generating token
        let groups = service.get_user_group_names(user.user_id).await.unwrap();
        let token = jwt_service
            .generate_token(user.user_id, &user.username, &user.email, groups)
            .unwrap();
        assert!(!token.is_empty());

        // Test creating reset token
        let new_token = NewPasswordResetToken {
            user_id: user.user_id,
            token: token.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
        };

        let result = service
            .password_reset_repo
            .create_reset_token(new_token)
            .await;
        assert!(result.is_ok());

        // Test getting base URL from settings
        let settings = settings_service.get_all_settings().await.unwrap();
        assert!(!settings.is_empty());
        assert_eq!(settings[0].key, "BASE_URL");
    }

    #[tokio::test]
    async fn test_recover_user_with_invalid_username() {
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new("test_secret"));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));

        let service = UserService::new(
            user_repo,
            group_repo,
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        // Test with non-existent username
        let user = service.find_user_by_username(&"nonexistent".to_string()).await;
        assert!(user.is_none());
    }

    // Integration tests - require CLI binary and database
    #[test]
    #[ignore] // Requires CLI binary and database setup
    fn test_admin_changes_user_password_successfully() {
        let output = Command::new("./target/debug/cli")
            .args(&[
                "set-user-password",
                "--email",
                EMAIL,
                "--set-password",
                "true",
                "--password",
                PASSWORD,
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(stdout.contains("Updated password successfully"));
    }

    #[test]
    #[ignore] // Requires CLI binary and database setup
    fn test_admin_changes_user_password_unsuccessfully() {
        let output = Command::new("./target/debug/cli")
            .args(&[
                "set-user-password",
                "--email",
                &EMAIL[9..],
                "--set-password",
                "true",
                "--password",
                PASSWORD,
            ])
            .output()
            .expect("Failed to execute command");

        assert!(!output.status.success());

        let stderr = String::from_utf8(output.stderr).unwrap();

        let err = &EMAIL[9..];

        assert!(stderr.contains(format!("Error: User with email {} not found", err).as_str()));
    }

    #[test]
    #[ignore] // Requires CLI binary and database setup
    fn test_recover_user_with_url_successfully() {
        let output = Command::new("./target/debug/cli")
            .args(&["recover-user", "--username", &USERNAME, "--generate-token", "true"])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(stdout.contains("http://127.0.0.1:3000?token=e"));
    }

    #[test]
    #[ignore] // Requires CLI binary and database setup
    fn test_recover_user_with_url_unsuccessfully() {
        let output = Command::new("./target/debug/cli")
            .args(&[
                "recover-user",
                "--username",
                &USERNAME[3..],
                "--generate-token",
                "true",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(!output.status.success());

        let stderr = String::from_utf8(output.stderr).unwrap();

        let err = &USERNAME[3..];

        assert!(stderr.contains(format!("Error: User {} not found", err).as_str()));
    }
}
