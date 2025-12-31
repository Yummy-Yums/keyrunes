use chrono::Utc;
use fake::{
    Fake,
    faker::internet::en::{SafeEmail, Username},
};
use keyrunes::repository::User;
use uuid::Uuid;

pub struct UserFactory;

#[allow(dead_code)]
impl UserFactory {
    pub fn build() -> User {
        User {
            user_id: (1..1000).fake(),
            external_id: Uuid::new_v4(),
            organization_id: (1..100).fake(),
            email: SafeEmail().fake(),
            username: Username().fake(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$VEVTVA$dmVyeXNlY3JldA".to_string(),
            first_login: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn build_with_org(organization_id: i64) -> User {
        let mut user = Self::build();
        user.organization_id = organization_id;
        user
    }

    pub fn build_with_email(email: &str) -> User {
        let mut user = Self::build();
        user.email = email.to_string();
        user
    }
}
