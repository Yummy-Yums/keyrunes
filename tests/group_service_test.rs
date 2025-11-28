use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use keyrunes::group_service::{CreateGroupRequest, GroupService};
use keyrunes::repository::{Group, GroupRepository, NewGroup, Policy};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

struct MockGroupRepository {
    groups: Mutex<Vec<Group>>,
    user_groups: Mutex<Vec<(i64, i64, Option<i64>)>>, // (user_id, group_id, assigned_by)
}

impl MockGroupRepository {
    fn new() -> Self {
        let groups = Mutex::new(vec![
            Group {
                group_id: 1,
                external_id: Uuid::new_v4(),
                name: "superadmin".to_string(),
                description: Some("Superadmin group".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Group {
                group_id: 2,
                external_id: Uuid::new_v4(),
                name: "users".to_string(),
                description: Some("Regular users".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ]);

        Self {
            groups,
            user_groups: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl GroupRepository for MockGroupRepository {
    async fn insert_group(&self, new_group: NewGroup) -> Result<Group> {
        let mut groups = self.groups.lock().unwrap();
        let group = Group {
            group_id: (groups.len() + 1) as i64,
            external_id: new_group.external_id,
            name: new_group.name,
            description: new_group.description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        groups.push(group.clone());
        Ok(group)
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<Group>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups.iter().find(|g| g.name == name).cloned())
    }

    async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups.iter().find(|g| g.group_id == group_id).cloned())
    }

    async fn list_groups(&self) -> Result<Vec<Group>> {
        Ok(self.groups.lock().unwrap().clone())
    }

    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        let mut user_groups = self.user_groups.lock().unwrap();

        if user_groups.iter().any(|(uid, gid, _)| *uid == user_id && *gid == group_id) {
            return Err(anyhow::anyhow!("User already assigned to this group"));
        }

        user_groups.push((user_id, group_id, assigned_by));
        Ok(())
    }

    async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()> {
        let mut user_groups = self.user_groups.lock().unwrap();
        user_groups.retain(|(uid, gid, _)| !(*uid == user_id && *gid == group_id));
        Ok(())
    }

    async fn get_group_policies(&self, _group_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn test_create_group_success() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let req = CreateGroupRequest {
        name: "developers".to_string(),
        description: Some("Development team".to_string()),
    };

    let result = service.create_group(req).await;
    assert!(result.is_ok());

    let group = result.unwrap();
    assert_eq!(group.name, "developers");
    assert_eq!(group.description, Some("Development team".to_string()));
}

#[tokio::test]
async fn test_create_group_duplicate_name() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let req = CreateGroupRequest {
        name: "superadmin".to_string(), // Already exists in mock
        description: Some("Duplicate".to_string()),
    };

    let result = service.create_group(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "group name already exists");
}

#[tokio::test]
async fn test_list_groups() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let result = service.list_groups().await;
    assert!(result.is_ok());

    let groups = result.unwrap();
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().any(|g| g.name == "superadmin"));
    assert!(groups.iter().any(|g| g.name == "users"));
}

#[tokio::test]
async fn test_get_group_by_name() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let result = service.get_group_by_name("superadmin").await;
    assert!(result.is_ok());

    let group = result.unwrap();
    assert!(group.is_some());
    assert_eq!(group.unwrap().name, "superadmin");
}

#[tokio::test]
async fn test_get_group_by_name_not_found() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let result = service.get_group_by_name("nonexistent").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_group_by_id() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let result = service.get_group_by_id(1).await;
    assert!(result.is_ok());

    let group = result.unwrap();
    assert!(group.is_some());
    assert_eq!(group.unwrap().group_id, 1);
}

#[tokio::test]
async fn test_assign_user_to_group_success() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    let result = service.assign_user_to_group(100, 1, Some(1)).await;
    assert!(result.is_ok());

    let user_groups = repo.user_groups.lock().unwrap();
    assert!(user_groups.iter().any(|(uid, gid, _)| *uid == 100 && *gid == 1));
}

#[tokio::test]
async fn test_assign_user_to_group_nonexistent_group() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let result = service.assign_user_to_group(100, 999, Some(1)).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "group not found");
}

#[tokio::test]
async fn test_assign_user_to_group_duplicate() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let result1 = service.assign_user_to_group(100, 1, Some(1)).await;
    assert!(result1.is_ok());

    let result2 = service.assign_user_to_group(100, 1, Some(1)).await;
    assert!(result2.is_err());
    assert_eq!(result2.unwrap_err().to_string(), "User already assigned to this group");
}

#[tokio::test]
async fn test_remove_user_from_group() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    service.assign_user_to_group(100, 1, Some(1)).await.unwrap();

    {
        let user_groups = repo.user_groups.lock().unwrap();
        assert_eq!(user_groups.len(), 1);
    }

    let result = service.remove_user_from_group(100, 1).await;
    assert!(result.is_ok());

    let user_groups = repo.user_groups.lock().unwrap();
    assert_eq!(user_groups.len(), 0);
}

#[tokio::test]
async fn test_create_multiple_groups() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo);

    let groups = vec![
        ("developers", "Dev team"),
        ("qa", "QA team"),
        ("support", "Support team"),
    ];

    for (name, desc) in groups {
        let req = CreateGroupRequest {
            name: name.to_string(),
            description: Some(desc.to_string()),
        };
        let result = service.create_group(req).await;
        assert!(result.is_ok(), "Failed to create group: {}", name);
    }

    let all_groups = service.list_groups().await.unwrap();
    assert_eq!(all_groups.len(), 5); // 2 default + 3 new
}

#[tokio::test]
async fn test_assign_multiple_users_to_group() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    for user_id in 100..105 {
        let result = service.assign_user_to_group(user_id, 1, Some(1)).await;
        assert!(result.is_ok());
    }

    let user_groups = repo.user_groups.lock().unwrap();
    assert_eq!(user_groups.len(), 5);
}

#[tokio::test]
async fn test_assign_user_to_multiple_groups() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());

    let result1 = service.assign_user_to_group(100, 1, Some(1)).await;
    let result2 = service.assign_user_to_group(100, 2, Some(1)).await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    let user_groups = repo.user_groups.lock().unwrap();
    assert_eq!(user_groups.len(), 2);
    assert!(user_groups.iter().any(|(uid, gid, _)| *uid == 100 && *gid == 1));
    assert!(user_groups.iter().any(|(uid, gid, _)| *uid == 100 && *gid == 2));
}
