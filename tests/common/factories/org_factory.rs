use chrono::Utc;
use fake::{Fake, faker::company::en::CompanyName};
use keyrunes::repository::Organization;
use uuid::Uuid;

#[allow(dead_code)]
pub struct OrgFactory;

#[allow(dead_code)]
impl OrgFactory {
    pub fn build() -> Organization {
        Organization {
            organization_id: (1..1000).fake(),
            external_id: Uuid::new_v4(),
            name: CompanyName().fake(),
            description: Some("Test Organization Description".to_string()),
            secret_key: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn build_with_name(name: &str) -> Organization {
        let mut org = Self::build();
        org.name = name.to_string();
        org
    }
}
