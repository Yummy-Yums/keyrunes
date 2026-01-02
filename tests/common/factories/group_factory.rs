use chrono::Utc;
use fake::{
    Fake,
    faker::{
        company::en::{Buzzword, Profession},
        lorem::en::Words,
    },
};
use keyrunes::repository::Group;
use uuid::Uuid;

pub struct GroupFactory {
    group: Group,
}

#[allow(dead_code)]
impl GroupFactory {
    pub fn create_group(
        id: i64,
        name: String,
        description: Option<String>,
        organization_id: i64,
    ) -> Group {
        Self::new()
            .group_id(id)
            .name(&name)
            .description(&description.unwrap_or_default())
            .organization_id(organization_id)
            .finish()
    }

    pub fn new() -> Self {
        let role: String = Profession().fake();
        let words: Vec<String> = Words(1..3).fake();
        let name = format!(
            "{}_{}",
            role.to_lowercase().replace(' ', "_"),
            words.join("_")
        );

        Self {
            group: Group {
                group_id: (1..1000).fake(),
                organization_id: (1..100).fake(),
                external_id: Uuid::new_v4(),
                name: name.chars().take(50).collect(),
                description: Some(Buzzword().fake()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        }
    }

    pub fn build() -> Group {
        Self::new().finish()
    }

    pub fn build_with_org(organization_id: i64) -> Group {
        Self::new().organization_id(organization_id).finish()
    }

    pub fn build_with_name(name: &str) -> Group {
        Self::new().name(name).finish()
    }

    pub fn group_id(mut self, id: i64) -> Self {
        self.group.group_id = id;
        self
    }

    pub fn organization_id(mut self, org_id: i64) -> Self {
        self.group.organization_id = org_id;
        self
    }

    pub fn name(mut self, name: &str) -> Self {
        self.group.name = name.to_string();
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.group.description = Some(desc.to_string());
        self
    }

    pub fn finish(self) -> Group {
        self.group
    }
}

impl Default for GroupFactory {
    fn default() -> Self {
        Self::new()
    }
}
