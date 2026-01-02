/// Default namespace for public/default tenant
pub const DEFAULT_NAMESPACE: &str = "public";

/// Default organization ID
pub const DEFAULT_ORGANIZATION_ID: i64 = 1;

/// Default admin credentials (used in tests and initial setup)
pub const DEFAULT_ADMIN_EMAIL: &str = "admin@example.com";
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";

/// Default group names
pub const SUPERADMIN_GROUP: &str = "superadmin";
pub const ADMIN_GROUP: &str = "admin";
pub const USERS_GROUP: &str = "users";

/// Password validation
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// JWT token  
pub const DEFAULT_JWT_SECRET: &str = "0123456789ABCDEF0123456789ABCDEF";
