mod common;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use common::factories::GroupFactory;
use keyrunes::constants::DEFAULT_NAMESPACE;
use keyrunes::group_service::{CreateGroupRequest, GroupService};
use keyrunes::repository::{Group, GroupRepository, NewGroup, Policy};
use std::sync::{Arc, Mutex};

struct MockGroupRepository {
    groups: Mutex<Vec<Group>>,
    user_groups: Mutex<Vec<(i64, i64, Option<i64>)>>,
}

impl MockGroupRepository {
    fn new() -> Self {
        let groups = Mutex::new(vec![
            GroupFactory::create_group(
                1,
                "superadmin".to_string(),
                Some("Superadmin group".to_string()),
                1,
            ),
            GroupFactory::create_group(
                2,
                "users".to_string(),
                Some("Regular users".to_string()),
                1,
            ),
        ]);

        Self {
            groups,
            user_groups: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl GroupRepository for MockGroupRepository {
    async fn insert_group(&self, new_group: NewGroup, _namespace: &str) -> Result<Group> {
        let mut groups = self.groups.lock().unwrap();
        let group = Group {
            group_id: (groups.len() + 1) as i64,
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

    async fn find_by_name(
        &self,
        name: &str,
        _organization_id: i64,
        _namespace: &str,
    ) -> Result<Option<Group>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups.iter().find(|g| g.name == name).cloned())
    }

    async fn find_by_id(&self, group_id: i64, _namespace: &str) -> Result<Option<Group>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups.iter().find(|g| g.group_id == group_id).cloned())
    }

    async fn list_groups(&self, _organization_id: i64, _namespace: &str) -> Result<Vec<Group>> {
        Ok(self.groups.lock().unwrap().clone())
    }

    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
        _namespace: &str,
    ) -> Result<()> {
        let mut user_groups = self.user_groups.lock().unwrap();

        if user_groups
            .iter()
            .any(|(uid, gid, _)| *uid == user_id && *gid == group_id)
        {
            return Err(anyhow::anyhow!("User already assigned to this group"));
        }

        user_groups.push((user_id, group_id, assigned_by));
        Ok(())
    }

    async fn remove_user_from_group(
        &self,
        user_id: i64,
        group_id: i64,
        _namespace: &str,
    ) -> Result<()> {
        let mut user_groups = self.user_groups.lock().unwrap();
        user_groups.retain(|(uid, gid, _)| !(*uid == user_id && *gid == group_id));
        Ok(())
    }

    async fn get_group_policies(&self, _group_id: i64, _namespace: &str) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn test_create_group_success() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let req = CreateGroupRequest {
        organization_id: 1,
        name: "developers".to_string(),
        description: Some("Development team".to_string()),
    };

    // Act
    let result = service.create_group(req, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_ok());

    let group = result.unwrap();
    assert_eq!(group.name, "developers");
    assert_eq!(group.description, Some("Development team".to_string()));
}

#[tokio::test]
async fn test_create_group_duplicate_name() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let req = CreateGroupRequest {
        organization_id: 1,
        name: "superadmin".to_string(),
        description: Some("Duplicate".to_string()),
    };

    // Act
    let result = service.create_group(req, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "group name already exists");
}

#[tokio::test]
async fn test_list_groups() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    // Act
    let result = service.list_groups(1, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_ok());

    let groups = result.unwrap();
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().any(|g| g.name == "superadmin"));
    assert!(groups.iter().any(|g| g.name == "users"));
}

#[tokio::test]
async fn test_get_group_by_name() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    // Act
    let result = service
        .get_group_by_name("superadmin", 1, DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(result.is_ok());

    let group = result.unwrap();
    assert!(group.is_some());
    assert_eq!(group.unwrap().name, "superadmin");
}

#[tokio::test]
async fn test_get_group_by_name_not_found() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    // Act
    let result = service
        .get_group_by_name("nonexistent", 1, DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_group_by_id() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    // Act
    let result = service.get_group_by_id(1, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_ok());

    let group = result.unwrap();
    assert!(group.is_some());
    assert_eq!(group.unwrap().group_id, 1);
}

#[tokio::test]
async fn test_assign_user_to_group_success() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    // Act
    let result = service
        .assign_user_to_group(100, 1, Some(1), DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(result.is_ok());

    let user_groups = repo.user_groups.lock().unwrap();
    assert!(
        user_groups
            .iter()
            .any(|(uid, gid, _)| *uid == 100 && *gid == 1)
    );
}

#[tokio::test]
async fn test_assign_user_to_group_nonexistent_group() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    // Act
    let result = service
        .assign_user_to_group(100, 999, Some(1), DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "group not found");
}

#[tokio::test]
async fn test_assign_user_to_group_duplicate() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let result1 = service
        .assign_user_to_group(100, 1, Some(1), DEFAULT_NAMESPACE)
        .await;
    assert!(result1.is_ok());

    // Act
    let result2 = service
        .assign_user_to_group(100, 1, Some(1), DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(result2.is_err());
    assert_eq!(
        result2.unwrap_err().to_string(),
        "User already assigned to this group"
    );
}

#[tokio::test]
async fn test_remove_user_from_group() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    service
        .assign_user_to_group(100, 1, Some(1), DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Act
    let result = service
        .remove_user_from_group(100, 1, DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(result.is_ok());

    let user_groups = repo.user_groups.lock().unwrap();
    assert_eq!(user_groups.len(), 0);
}

#[tokio::test]
async fn test_create_multiple_groups() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let groups = vec![
        ("developers", "Dev team"),
        ("qa", "QA team"),
        ("support", "Support team"),
    ];

    // Act
    for (name, desc) in groups {
        let req = CreateGroupRequest {
            organization_id: 1,
            name: name.to_string(),
            description: Some(desc.to_string()),
        };
        let result = service.create_group(req, DEFAULT_NAMESPACE).await;
        assert!(result.is_ok(), "Failed to create group: {}", name);
    }

    // Assert
    let all_groups = service.list_groups(1, DEFAULT_NAMESPACE).await.unwrap();
    assert_eq!(all_groups.len(), 5);
}

#[tokio::test]
async fn test_assign_multiple_users_to_group() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    // Act
    for user_id in 100..105 {
        let result = service
            .assign_user_to_group(user_id, 1, Some(1), DEFAULT_NAMESPACE)
            .await;
        assert!(result.is_ok());
    }

    // Assert
    let user_groups = repo.user_groups.lock().unwrap();
    assert_eq!(user_groups.len(), 5);
}

#[tokio::test]
async fn test_assign_user_to_multiple_groups() {
    // Setup
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    // Act
    let result1 = service
        .assign_user_to_group(100, 1, Some(1), DEFAULT_NAMESPACE)
        .await;
    let result2 = service
        .assign_user_to_group(100, 2, Some(1), DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    let user_groups = repo.user_groups.lock().unwrap();
    assert_eq!(user_groups.len(), 2);
    assert!(
        user_groups
            .iter()
            .any(|(uid, gid, _)| *uid == 100 && *gid == 1)
    );
    assert!(
        user_groups
            .iter()
            .any(|(uid, gid, _)| *uid == 100 && *gid == 2)
    );
}
