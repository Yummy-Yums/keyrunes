use chrono::Utc;
use fake::{
    Fake,
    faker::company::en::{Bs, Buzzword, CompanyName},
};
use keyrunes::domain::organization::{NewOrganization, Organization};
use uuid::Uuid;

pub struct OrganizationFactory {
    org: Organization,
}

#[allow(dead_code)]
impl OrganizationFactory {
    pub fn create_organization(id: i64, name: String, namespace: String) -> Organization {
        Self::new()
            .organization_id(id)
            .name(&name)
            .namespace(&namespace)
            .finish()
    }

    pub fn new() -> Self {
        let name: String = CompanyName().fake();
        let namespace = Self::generate_namespace(&name);

        Self {
            org: Organization {
                organization_id: (1..1000).fake(),
                external_id: Uuid::new_v4(),
                name: name.clone(),
                description: Some(format!(
                    "{} - {}",
                    Buzzword().fake::<String>(),
                    Bs().fake::<String>()
                )),
                secret_key: Uuid::new_v4(),
                namespace,
                base_url: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        }
    }

    fn generate_namespace(name: &str) -> String {
        let clean = name
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '_')
            .collect::<String>()
            .replace(' ', "_");

        let suffix: u32 = (1000..9999).fake();
        format!("{}_{}", clean.chars().take(20).collect::<String>(), suffix)
    }

    pub fn build() -> Organization {
        Self::new().finish()
    }

    pub fn name(mut self, name: &str) -> Self {
        self.org.name = name.to_string();
        self.org.namespace = Self::generate_namespace(name);
        self
    }

    pub fn namespace(mut self, namespace: &str) -> Self {
        self.org.namespace = namespace.to_string();
        self
    }

    pub fn description(mut self, description: &str) -> Self {
        self.org.description = Some(description.to_string());
        self
    }

    pub fn organization_id(mut self, id: i64) -> Self {
        self.org.organization_id = id;
        self
    }

    pub fn base_url(mut self, url: Option<String>) -> Self {
        self.org.base_url = url;
        self
    }

    pub fn build_new() -> NewOrganization {
        let name: String = CompanyName().fake();
        NewOrganization {
            name: name.clone(),
            description: Some(format!(
                "{} - {}",
                Buzzword().fake::<String>(),
                Bs().fake::<String>()
            )),
            namespace: Self::generate_namespace(&name),
            base_url: None,
        }
    }

    pub fn build_new_with_name(name: &str) -> NewOrganization {
        NewOrganization {
            name: name.to_string(),
            description: Some(Bs().fake()),
            namespace: Self::generate_namespace(name),
            base_url: None,
        }
    }

    pub fn finish(self) -> Organization {
        self.org
    }
}

impl Default for OrganizationFactory {
    fn default() -> Self {
        Self::new()
    }
}
