use crate::domain::organization::NewOrganization;
use crate::repository::{Organization, OrganizationRepository};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateOrganizationRequest {
    pub name: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub description: Option<String>,
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    Ok(s.and_then(|s| if s.trim().is_empty() { None } else { Some(s) }))
}

#[derive(Debug, Clone)]
pub struct OrganizationService<O: OrganizationRepository> {
    pub repo: Arc<O>,
}

impl<O: OrganizationRepository> OrganizationService<O> {
    pub fn new(repo: Arc<O>) -> Self {
        Self { repo }
    }

    pub async fn create_organization(
        &self,
        req: CreateOrganizationRequest,
    ) -> Result<Organization> {
        if self.repo.find_by_name(&req.name).await?.is_some() {
            return Err(anyhow!("organization already exists"));
        }

        let new_org = NewOrganization {
            name: req.name,
            description: req.description,
        };

        self.repo.insert_organization(new_org).await
    }

    pub async fn list_organizations(&self) -> Result<Vec<Organization>> {
        self.repo.list_organizations().await
    }

    pub async fn get_organization_by_id(
        &self,
        organization_id: i64,
    ) -> Result<Option<Organization>> {
        self.repo.find_by_id(organization_id).await
    }

    pub async fn get_organization_by_secret_key(
        &self,
        secret_key: Uuid,
    ) -> Result<Option<Organization>> {
        self.repo.find_by_secret_key(secret_key).await
    }

    pub async fn rotate_org_key(&self, organization_id: i64) -> Result<Uuid> {
        self.repo.rotate_secret_key(organization_id).await
    }
}
