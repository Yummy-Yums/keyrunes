use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::auth::login_api,
        crate::api::auth::register_api,
        crate::api::auth::refresh_token_api,
        crate::api::auth::me_api,
        crate::api::auth::forgot_password_api,
        crate::api::auth::reset_password_api,
        
        crate::api::organization::get_org_key,
        crate::api::organization::rotate_org_key,

        crate::api::health::health_check,
    ),
    components(
        schemas(
            crate::api::auth::LoginApi,
            crate::api::auth::RegisterApi,
            crate::services::user_service::AuthResponse,
            crate::api::auth::RefreshTokenRequest,
            crate::api::auth::RefreshTokenResponse,
            crate::api::auth::ForgotPasswordApi,
            crate::api::auth::ForgotPasswordResponse,
            crate::api::auth::ResetPasswordApi,
            crate::api::auth::MessageResponse,
            crate::api::organization::OrgKeyResponse,
            crate::services::user_service::UserResponse,
            crate::api::health::HealthResponse,
            crate::api::health::DatabaseHealth,
            crate::api::health::ServicesHealth,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "organization", description = "Organization management endpoints"),
        (name = "health", description = "Health check endpoint")
    )
)]
pub struct ApiDoc;

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::Modify;

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
             components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(
                    utoipa::openapi::security::ApiKey::Header(
                        utoipa::openapi::security::ApiKeyValue::new("X-Organization-Key"),
                    ),
                ),
            );
        }
    }
}
