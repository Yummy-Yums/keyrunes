mod common;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use common::factories::UserFactory;
use keyrunes::domain::user::{Email, Password};
use keyrunes::group_service::{CreateGroupRequest, GroupService};
use keyrunes::repository::{Group, NewUser, Policy, User, UserRepository};
use keyrunes::services::user_service::{RegisterRequest, UserService};
use keyrunes::user_service::{CreateUserRequest, SettingsService};
use keyrunes::{CreateSettings, Settings, UserGroup};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

type Store<T> = Arc<Mutex<Vec<T>>>;
type GroupStore = Store<Group>;
type UserGroupStore = Store<UserGroup>;
type SettingsStore = Store<Settings>;
type UserServiceType =
    UserService<MockRepo, MockGroupRepository, MockPasswordResetRepository, MockSettingsRepository>;

fn create_stores() -> (GroupStore, UserGroupStore) {
    let group_store = Arc::new(Mutex::new(Vec::new()));
    let user_group_store = Arc::new(Mutex::new(Vec::new()));

    group_store.lock().unwrap().push(Group {
        group_id: 0,
        external_id: Uuid::new_v4(),
        organization_id: 1,
        name: "superadmin".to_string(),
        description: Some("Admin group".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    group_store.lock().unwrap().push(Group {
        group_id: 1,
        external_id: Uuid::new_v4(),
        organization_id: 1,
        name: "users".to_string(),
        description: Some("User group".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    (group_store, user_group_store)
}

struct MockRepo {
    users: Mutex<Vec<User>>,
    group_store: GroupStore,
    user_group_store: UserGroupStore,
}

impl MockRepo {
    fn new(group_store: GroupStore, user_group_store: UserGroupStore) -> Self {
        Self {
            users: Mutex::new(Vec::new()),
            group_store,
            user_group_store,
        }
    }
}

#[async_trait]
impl UserRepository for MockRepo {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().cloned().find(|u| u.email == email))
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().cloned().find(|u| u.username == username))
    }

    async fn find_by_id(&self, user_id: i64) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().cloned().find(|u| u.user_id == user_id))
    }

    async fn insert_user(&self, new_user: NewUser) -> Result<User> {
        let mut users = self.users.lock().unwrap();
        let user = User {
            user_id: (users.len() + 1) as i64,
            external_id: new_user.external_id,
            organization_id: new_user.organization_id,
            email: new_user.email,
            username: new_user.username,
            password_hash: new_user.password_hash,
            first_login: new_user.first_login,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        users.push(user.clone());
        Ok(user)
    }

    async fn update_user_password(&self, user_id: i64, new_password_hash: &str) -> Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
            user.password_hash = new_password_hash.to_string();
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn update_user_profile(&self, user_id: i64, email: &str, username: &str) -> Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
            user.email = email.to_string();
            user.username = username.to_string();
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn set_first_login(&self, user_id: i64, first_login: bool) -> Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
            user.first_login = first_login;
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>> {
        let groups = self.group_store.lock().unwrap();
        let user_groups = self.user_group_store.lock().unwrap();
        let user_groups: Vec<Group> = user_groups
            .iter()
            .filter(|ug| ug.user_id == user_id)
            .map(|ug| {
                groups
                    .iter()
                    .cloned()
                    .find(|g| ug.group_id == g.group_id)
                    .unwrap()
            })
            .collect();
        Ok(user_groups)
    }

    async fn get_user_policies(&self, _user_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }

    async fn get_user_all_policies(&self, _user_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

struct MockGroupRepository {
    group_store: Store<Group>,
    user_group_store: Store<UserGroup>,
}

impl MockGroupRepository {
    fn new(group_store: GroupStore, user_group_store: UserGroupStore) -> Self {
        Self {
            group_store,
            user_group_store,
        }
    }
}

#[async_trait]
impl keyrunes::repository::GroupRepository for MockGroupRepository {
    async fn find_by_name(&self, name: &str, _organization_id: i64) -> Result<Option<Group>> {
        let groups = self.group_store.lock().unwrap();
        let group = groups.iter().cloned().find(|g| g.name == name);
        Ok(group)
    }

    async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        let groups = self.group_store.lock().unwrap();
        let group = groups.iter().cloned().find(|g| g.group_id == group_id);
        Ok(group)
    }

    async fn insert_group(&self, new_group: keyrunes::repository::NewGroup) -> Result<Group> {
        let mut groups = self.group_store.lock().unwrap();
        let group = Group {
            group_id: groups.len() as i64,
            external_id: new_group.external_id,
            organization_id: new_group.organization_id,
            name: new_group.name,
            description: new_group.description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        groups.push(group.clone());
        Ok(group)
    }

    async fn list_groups(&self, _organization_id: i64) -> Result<Vec<Group>> {
        Ok(self.group_store.lock().unwrap().clone())
    }

    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        let mut user_groups = self.user_group_store.lock().unwrap();
        user_groups.push(UserGroup {
            user_id,
            group_id,
            assigned_by,
            assigned_at: Utc::now(),
        });
        Ok(())
    }

    async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()> {
        let mut user_groups = self.user_group_store.lock().unwrap();
        user_groups.retain(|g| !(g.user_id == user_id && g.group_id == group_id));
        Ok(())
    }

    async fn get_group_policies(&self, _group_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

struct MockSettingsRepository {
    settings_store: SettingsStore,
}

impl MockSettingsRepository {
    fn new() -> Self {
        Self {
            settings_store: Self::create_stores(),
        }
    }

    fn create_stores() -> SettingsStore {
        let settings_store: SettingsStore = Arc::new(Mutex::new(Vec::new()));

        settings_store.lock().unwrap().push(Settings {
            settings_id: 0,
            organization_id: Some(1),
            key: "test_key".to_string(),
            value: "test_value".to_string(),
            description: Some("Test settings".to_string()),
            created_at: Default::default(),
            updated_at: Default::default(),
        });

        settings_store.lock().unwrap().push(Settings {
            settings_id: 1,
            organization_id: Some(1),
            key: "test_key_1".to_string(),
            value: "test_value_1".to_string(),
            description: Some("Test settings 1".to_string()),
            created_at: Default::default(),
            updated_at: Default::default(),
        });

        settings_store
    }
}

#[async_trait]
impl keyrunes::repository::SettingsRepository for MockSettingsRepository {
    async fn create_settings(&self, settings: CreateSettings) -> Result<Option<CreateSettings>> {
        let settings_record = Settings {
            settings_id: 22,
            organization_id: Some(1),
            key: settings.key.clone(),
            value: settings.value.clone(),
            description: settings.description.clone(),
            created_at: Default::default(),
            updated_at: Default::default(),
        };

        self.settings_store.lock().unwrap().push(settings_record);

        Ok(Some(settings))
    }

    async fn get_settings_by_key(&self, key: &str) -> Result<Option<Settings>> {
        let res = self
            .settings_store
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.key == key)
            .cloned();

        Ok(res)
    }

    async fn get_setting_by_key_and_org(
        &self,
        key: &str,
        _organization_id: Option<i64>,
    ) -> Result<Option<Settings>> {
        self.get_settings_by_key(key).await
    }

    async fn get_all_settings(&self) -> Result<Vec<Settings>> {
        let res = self
            .settings_store
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();

        Ok(res)
    }

    async fn update_settings_by_key(&self, key: &str, value: &str) -> Result<()> {
        if let Some(s) = self
            .settings_store
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.key == key)
        {
            s.value = value.to_string();
        }

        Ok(())
    }

    async fn delete_settings_by_key(&self, key: &str) -> Result<()> {
        self.settings_store.lock().unwrap().retain(|s| s.key != key);

        Ok(())
    }
}

struct MockPasswordResetRepository;

#[async_trait]
impl keyrunes::repository::PasswordResetRepository for MockPasswordResetRepository {
    async fn create_reset_token(
        &self,
        _token: keyrunes::repository::NewPasswordResetToken,
    ) -> Result<keyrunes::repository::PasswordResetToken> {
        unimplemented!()
    }

    async fn find_valid_token(
        &self,
        _token: &str,
    ) -> Result<Option<keyrunes::repository::PasswordResetToken>> {
        Ok(None)
    }

    async fn mark_token_used(&self, _token_id: i64) -> Result<()> {
        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> Result<()> {
        Ok(())
    }
}

fn helper_service() -> UserServiceType {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));

    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = UserService::new(
        user_repo,
        group_repo,
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    service
}

#[tokio::test]
async fn test_settings_functionality() {
    let service = helper_service();

    let test_key = String::from("settings test key");
    let _test_key_update = String::from("settings test key updated");
    let test_value = String::from("settings test value");
    let test_value_update = String::from("settings test value updated");
    let test_description = String::from("settings test description");

    let settings_inserted = service
        .settings_service
        .insert_settings(
            test_key.clone(),
            test_value.clone(),
            test_description.clone(),
        )
        .await;

    assert!(settings_inserted.is_ok());

    let result_settings = service
        .settings_service
        .find_settings_by_key(test_key.as_str())
        .await;

    assert!(result_settings.is_ok());

    let result_settings = result_settings.unwrap();
    assert!(result_settings.key == test_key);
    assert!(result_settings.value == test_value.clone());
    assert!(result_settings.description.unwrap() == test_description);

    let result = service
        .settings_service
        .update_settings(test_key.clone(), test_value_update.clone())
        .await;

    assert!(result.is_ok());

    let updated_result_settings = service
        .settings_service
        .find_settings_by_key(test_key.as_str())
        .await;
    assert!(updated_result_settings.is_ok());

    let updated_result_settings = updated_result_settings.unwrap();

    assert!(updated_result_settings.key == test_key);
    assert!(updated_result_settings.value == test_value_update);

    let deleted_settings = service
        .settings_service
        .delete_settings(test_key.clone())
        .await;

    assert!(deleted_settings.is_ok());

    let result = service
        .settings_service
        .find_settings_by_key(test_key.as_str())
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_register_and_login() {
    // Setup
    let service = helper_service();
    let user_data = UserFactory::build();

    let req = RegisterRequest {
        email: user_data.email.clone(),
        username: user_data.username.clone(),
        password: "Password123".to_string(),
        first_login: Some(false),
        organization_id: None,
    };

    // Act
    let auth_response = service.register(req.clone()).await.unwrap();

    // Assert
    assert_eq!(auth_response.user.email, user_data.email);
    assert_eq!(auth_response.user.username, user_data.username);
    assert!(!auth_response.token.is_empty());

    // Act
    let login_response = service
        .login(user_data.email.clone(), "Password123".to_string())
        .await
        .unwrap();

    // Assert
    assert_eq!(login_response.user.username, user_data.username);
    assert!(!login_response.token.is_empty());

    // Act
    let login_response2 = service
        .login(user_data.username.clone(), "Password123".to_string())
        .await
        .unwrap();

    // Assert
    assert_eq!(login_response2.user.email, user_data.email);

    // Act
    let err = service
        .login(user_data.username, "wrongpass".to_string())
        .await
        .unwrap_err();

    // Assert
    assert_eq!(err.to_string(), "invalid credentials");
}

#[tokio::test]
async fn test_duplicate_registration() {
    // Setup
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));
    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = UserService::new(
        user_repo.clone(),
        group_repo,
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    let user_data = UserFactory::build();
    let req = RegisterRequest {
        email: user_data.email.clone(),
        username: user_data.username.clone(),
        password: "Password123".to_string(),
        first_login: Some(false),
        organization_id: None,
    };

    // Act
    service.register(req.clone()).await.unwrap();
    let result = service.register(req).await;

    // Assert
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("email already registered")
    );
}

#[tokio::test]
async fn test_password_validation() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));
    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = UserService::new(
        user_repo,
        group_repo,
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    // Setup
    let req = RegisterRequest {
        email: "short@example.com".to_string(),
        username: "shortpass".to_string(),
        password: "short".to_string(),
        first_login: Some(false),
        organization_id: None,
    };

    let result = service.register(req).await;

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "password too short");
}

#[tokio::test]
async fn test_email_validation() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));
    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = UserService::new(
        user_repo,
        group_repo,
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    // Setup
    let req = RegisterRequest {
        email: "invalid-email".to_string(),
        username: "testuser".to_string(),
        password: "Password123".to_string(),
        first_login: Some(false),
        organization_id: None,
    };

    let result = service.register(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid email");
}

#[tokio::test]
async fn test_change_password() {
    // Setup
    let service = helper_service();
    let user_data = UserFactory::build();

    let req = RegisterRequest {
        email: user_data.email.clone(),
        username: user_data.username.clone(),
        password: "OldPassword123".to_string(),
        first_login: Some(true),
        organization_id: None,
    };

    let auth_response = service.register(req).await.unwrap();
    let user_id = auth_response.user.user_id;

    // Act
    let change_req = keyrunes::services::user_service::ChangePasswordRequest {
        current_password: "OldPassword123".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    service.change_password(user_id, change_req).await.unwrap();

    // Assert
    let login_result = service
        .login(user_data.email.clone(), "NewPassword456".to_string())
        .await;
    assert!(login_result.is_ok());

    // Act
    let old_login_result = service
        .login(user_data.email, "OldPassword123".to_string())
        .await;

    // Assert
    assert!(old_login_result.is_err());
}

#[tokio::test]
async fn admin_create_user_with_groups() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));

    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let service = UserService::new(
        user_repo,
        group_repo.clone(),
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    let group_service = GroupService::new(group_repo.clone());

    // Setup
    let superadmin = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("admin@example.com").unwrap(),
                username: "admin".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec!["superadmin".to_string()]),
                first_login: false,
                organization_id: 1,
            },
            None,
        )
        .await
        .unwrap();

    // Act
    let test_group = group_service
        .create_group(CreateGroupRequest {
            organization_id: 1,
            name: "test".to_string(),
            description: Some("Test Group".to_string()),
        })
        .await
        .unwrap();

    // Assert
    assert_eq!(group_store.lock().unwrap().len(), 3);

    // Act
    let test_user = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("testuser@example.com").unwrap(),
                username: "testuser".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec!["users".to_string(), test_group.name]),
                first_login: false,
                organization_id: 1,
            },
            Some(superadmin.user_id),
        )
        .await;

    // Assert
    assert!(test_user.is_ok());
    let test_user = test_user.unwrap();
    assert_eq!(test_user.email, "testuser@example.com");
    assert_eq!(test_user.username, "testuser");
    assert_eq!(test_user.groups, &["users", "test"]);

    // Act
    let test_user = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("testuser2@example.com").unwrap(),
                username: "testuser2".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec!["users".to_string(), "invalid".to_string()]),
                first_login: false,
                organization_id: 1,
            },
            Some(superadmin.user_id),
        )
        .await;

    // Assert
    assert!(test_user.is_err());
    assert_eq!(
        test_user.err().unwrap().to_string(),
        "invalid group specified: `invalid`"
    )
}
