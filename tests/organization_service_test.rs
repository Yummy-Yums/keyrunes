mod common;

use anyhow::Result;
use async_trait::async_trait;
use common::factories::OrgFactory;
use keyrunes::domain::organization::NewOrganization;
use keyrunes::repository::{Organization, OrganizationRepository};
use keyrunes::services::organization_service::{CreateOrganizationRequest, OrganizationService};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

struct MockOrganizationRepository {
    organizations: Mutex<Vec<Organization>>,
}

impl MockOrganizationRepository {
    fn new() -> Self {
        Self {
            organizations: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl OrganizationRepository for MockOrganizationRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Organization>> {
        let orgs = self.organizations.lock().unwrap();
        Ok(orgs.iter().find(|o| o.name == name).cloned())
    }

    async fn find_by_id(&self, organization_id: i64) -> Result<Option<Organization>> {
        let orgs = self.organizations.lock().unwrap();
        Ok(orgs
            .iter()
            .find(|o| o.organization_id == organization_id)
            .cloned())
    }

    async fn insert_organization(&self, new_org: NewOrganization) -> Result<Organization> {
        let mut orgs = self.organizations.lock().unwrap();
        let org = Organization {
            organization_id: (orgs.len() + 1) as i64,
            external_id: Uuid::new_v4(),
            name: new_org.name,
            description: new_org.description,
            secret_key: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        orgs.push(org.clone());
        Ok(org)
    }

    async fn list_organizations(&self) -> Result<Vec<Organization>> {
        let orgs = self.organizations.lock().unwrap();
        Ok(orgs.clone())
    }

    async fn find_by_secret_key(&self, secret_key: Uuid) -> Result<Option<Organization>> {
        let orgs = self.organizations.lock().unwrap();
        Ok(orgs.iter().find(|o| o.secret_key == secret_key).cloned())
    }

    async fn rotate_secret_key(&self, organization_id: i64) -> Result<Uuid> {
        let mut orgs = self.organizations.lock().unwrap();
        if let Some(org) = orgs
            .iter_mut()
            .find(|o| o.organization_id == organization_id)
        {
            org.secret_key = Uuid::new_v4();
            Ok(org.secret_key)
        } else {
            Err(anyhow::anyhow!("organization not found"))
        }
    }
}

#[tokio::test]
async fn test_create_organization() {
    // Setup
    let repo = Arc::new(MockOrganizationRepository::new());
    let service = OrganizationService::new(repo);
    let org_data = OrgFactory::build();

    let req = CreateOrganizationRequest {
        name: org_data.name.clone(),
        description: org_data.description.clone(),
    };

    // Act
    let org = service.create_organization(req).await.unwrap();

    // Assert
    assert_eq!(org.name, org_data.name);
    assert_eq!(org.description, org_data.description);
    assert_eq!(org.organization_id, 1);
}

#[tokio::test]
async fn test_create_duplicate_organization() {
    // Setup
    let repo = Arc::new(MockOrganizationRepository::new());
    let service = OrganizationService::new(repo);
    let org_data = OrgFactory::build();

    let req = CreateOrganizationRequest {
        name: org_data.name.clone(),
        description: org_data.description.clone(),
    };

    service.create_organization(req.clone()).await.unwrap();

    // Act
    let result = service.create_organization(req).await;

    // Assert
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "organization already exists"
    );
}

#[tokio::test]
async fn test_list_organizations() {
    // Setup
    let repo = Arc::new(MockOrganizationRepository::new());
    let service = OrganizationService::new(repo);
    let org1 = OrgFactory::build();
    let org2 = OrgFactory::build();

    service
        .create_organization(CreateOrganizationRequest {
            name: org1.name.clone(),
            description: None,
        })
        .await
        .unwrap();

    service
        .create_organization(CreateOrganizationRequest {
            name: org2.name.clone(),
            description: None,
        })
        .await
        .unwrap();

    // Act
    let orgs = service.list_organizations().await.unwrap();

    // Assert
    assert_eq!(orgs.len(), 2);
    assert!(orgs.iter().any(|o| o.name == org1.name));
    assert!(orgs.iter().any(|o| o.name == org2.name));
}

#[tokio::test]
async fn test_get_organization_by_id() {
    // Setup
    let repo = Arc::new(MockOrganizationRepository::new());
    let service = OrganizationService::new(repo);

    let org = service
        .create_organization(CreateOrganizationRequest {
            name: "Found Org".to_string(),
            description: None,
        })
        .await
        .unwrap();

    // Act
    let found = service
        .get_organization_by_id(org.organization_id)
        .await
        .unwrap();

    // Assert
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "Found Org");

    // Act
    let not_found = service.get_organization_by_id(999).await.unwrap();

    // Assert
    assert!(not_found.is_none());
}
