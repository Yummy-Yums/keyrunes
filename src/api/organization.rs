use crate::handler::auth::AuthenticatedUser;
use crate::handler::errors::ErrorResponse;
use crate::repository::UserRepository;
use crate::repository::sqlx_impl::{
    PgGroupRepository, PgOrganizationRepository, PgPasswordResetRepository, PgSettingsRepository,
    PgUserRepository,
};
use crate::services::organization_service::CreateOrganizationRequest;
use crate::services::organization_service::OrganizationService;
use crate::services::user_service::UserService;
use axum::{
    Extension,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

type OrgService = OrganizationService<PgOrganizationRepository>;
type UserSvc = UserService<
    PgUserRepository,
    PgGroupRepository,
    PgPasswordResetRepository,
    PgSettingsRepository,
>;

#[derive(Serialize, ToSchema)]
pub struct OrgKeyResponse {
    pub organization_id: i64,
    pub secret_key: String,
}

/// GET /api/org/secret
#[utoipa::path(
    get,
    path = "/api/org/secret",
    responses(
        (status = 200, description = "Get Organization Secret", body = OrgKeyResponse),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Organization not found")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "organization"
)]
pub async fn get_org_key(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserSvc>>,
    Extension(org_service): Extension<Arc<OrgService>>,
) -> impl IntoResponse {
    if !user
        .groups
        .iter()
        .any(|g| g == "admin" || g == "superadmin")
    {
        return ErrorResponse::forbidden("Insufficient permissions to view Organization Secret")
            .into_response();
    }

    let full_user = match user_service.user_repo.find_by_id(user.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return ErrorResponse::unauthorized("User not found").into_response(),
        Err(_) => {
            return ErrorResponse::internal_server_error("Failed to fetch user").into_response();
        }
    };

    let org_id = full_user.organization_id;

    match org_service.get_organization_by_id(org_id).await {
        Ok(Some(org)) => Json(OrgKeyResponse {
            organization_id: org.organization_id,
            secret_key: org.secret_key.to_string(),
        })
        .into_response(),
        Ok(None) => ErrorResponse::not_found("Organization not found").into_response(),
        Err(e) => {
            tracing::error!("Failed to fetch organization: {:?}", e);
            ErrorResponse::internal_server_error("Database error").into_response()
        }
    }
}

/// POST /api/org/secret/rotate
#[utoipa::path(
    post,
    path = "/api/org/secret/rotate",
    responses(
        (status = 200, description = "Rotate Organization Secret", body = OrgKeyResponse),
        (status = 403, description = "Insufficient permissions")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "organization"
)]
pub async fn rotate_org_key(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserSvc>>,
    Extension(org_service): Extension<Arc<OrgService>>,
) -> impl IntoResponse {
    if !user
        .groups
        .iter()
        .any(|g| g == "admin" || g == "superadmin")
    {
        return ErrorResponse::forbidden("Insufficient permissions to rotate Organization Secret")
            .into_response();
    }

    let full_user = match user_service.user_repo.find_by_id(user.user_id).await {
        Ok(Some(u)) => u,
        _ => return ErrorResponse::unauthorized("User not found").into_response(),
    };

    let org_id = full_user.organization_id;

    match org_service.rotate_org_key(org_id).await {
        Ok(new_key) => Json(OrgKeyResponse {
            organization_id: org_id,
            secret_key: new_key.to_string(),
        })
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to rotate org key: {:?}", e);
            ErrorResponse::internal_server_error("Failed to rotate key").into_response()
        }
    }
}

/// POST /api/organizations
pub async fn create_organization(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> impl IntoResponse {
    tracing::info!(
        "Create org request: name={}, description={:?}",
        payload.name,
        payload.description
    );

    if !admin.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let org_repo = Arc::new(PgOrganizationRepository::new(pool));
    let org_service = OrganizationService::new(org_repo);

    match org_service.create_organization(payload).await {
        Ok(org) => (StatusCode::CREATED, Json(org)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// GET /api/organizations
pub async fn list_organizations(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    if !admin.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let org_repo = Arc::new(PgOrganizationRepository::new(pool));
    let org_service = OrganizationService::new(org_repo);

    match org_service.list_organizations().await {
        Ok(orgs) => (StatusCode::OK, Json(orgs)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /api/organizations/{id}/rotate-key
pub async fn admin_rotate_org_key(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path(organization_id): Path<i64>,
) -> impl IntoResponse {
    if !admin.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let org_repo = Arc::new(PgOrganizationRepository::new(pool));
    let org_service = OrganizationService::new(org_repo);

    match org_service.rotate_org_key(organization_id).await {
        Ok(new_key) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "organization_id": organization_id,
                "secret_key": new_key,
                "message": "Key rotated successfully"
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
