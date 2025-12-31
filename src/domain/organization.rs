use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub organization_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub secret_key: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrganization {
    pub name: String,
    pub description: Option<String>,
}
