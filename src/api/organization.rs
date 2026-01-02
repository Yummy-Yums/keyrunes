use crate::constants::SUPERADMIN_GROUP;
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

type OrgService = OrganizationService<PgOrganizationRepository, PgGroupRepository>;
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
        .any(|g| g == "admin" || g == SUPERADMIN_GROUP)
    {
        return ErrorResponse::forbidden("Insufficient permissions to view Organization Secret")
            .into_response();
    }

    let full_user = match user_service
        .user_repo
        .find_by_id(user.user_id, &user.namespace)
        .await
    {
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
        .any(|g| g == "admin" || g == SUPERADMIN_GROUP)
    {
        return ErrorResponse::forbidden("Insufficient permissions to rotate Organization Secret")
            .into_response();
    }

    let full_user = match user_service
        .user_repo
        .find_by_id(user.user_id, &user.namespace)
        .await
    {
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

    if let Err(e) = validate_global_superadmin_access(&admin) {
        return e.into_response();
    }

    let org_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let org_service = OrganizationService::new(org_repo, group_repo);

    match org_service.create_organization(payload).await {
        Ok(org) => (StatusCode::CREATED, Json(org)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// GET /api/organizations
pub async fn list_organizations(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Extension(user_service): Extension<Arc<UserSvc>>,
) -> impl IntoResponse {
    let org_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let org_service = OrganizationService::new(org_repo, group_repo);

    if user.groups.contains(&SUPERADMIN_GROUP.to_string())
        && user.namespace == crate::constants::DEFAULT_NAMESPACE
    {
        match org_service.list_organizations().await {
            Ok(orgs) => (StatusCode::OK, Json(orgs)).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    } else if user.groups.contains(&"admin".to_string())
        || user.groups.contains(&SUPERADMIN_GROUP.to_string())
    {
        match user_service
            .user_repo
            .find_by_id(user.user_id, &user.namespace)
            .await
        {
            Ok(Some(full_user)) => {
                match org_service
                    .get_organization_by_id(full_user.organization_id)
                    .await
                {
                    Ok(Some(org)) => (StatusCode::OK, Json(vec![org])).into_response(),
                    Ok(None) => (StatusCode::NOT_FOUND, "Organization not found").into_response(),
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
                }
            }
            _ => (StatusCode::UNAUTHORIZED, "User not found").into_response(),
        }
    } else {
        (StatusCode::FORBIDDEN, "Insufficient permissions").into_response()
    }
}

/// POST /api/organizations/{id}/rotate-key
pub async fn admin_rotate_org_key(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path(organization_id): Path<i64>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let org_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let org_service = OrganizationService::new(org_repo, group_repo);

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

fn validate_global_superadmin_access(
    user: &AuthenticatedUser,
) -> Result<(), (StatusCode, &'static str)> {
    if !user.groups.contains(&SUPERADMIN_GROUP.to_string())
        || user.namespace != crate::constants::DEFAULT_NAMESPACE
    {
        return Err((StatusCode::FORBIDDEN, "Global Superadmin access required"));
    }
    Ok(())
}

/// DELETE /api/admin/organizations/{id}
pub async fn delete_organization(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path(organization_id): Path<i64>,
) -> impl IntoResponse {
    if let Err(e) = validate_global_superadmin_access(&admin) {
        return e.into_response();
    }

    let org_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let org_service = OrganizationService::new(org_repo, group_repo);

    match org_service.delete_organization(organization_id).await {
        Ok(_) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_NAMESPACE;

    fn create_user(groups: Vec<&str>, namespace: &str) -> AuthenticatedUser {
        AuthenticatedUser {
            user_id: 1,
            email: "test@example.com".to_string(),
            username: "test".to_string(),
            groups: groups.iter().map(|&s| s.to_string()).collect(),
            namespace: namespace.to_string(),
            organization_id: 1,
        }
    }

    #[test]
    fn test_global_superadmin_allowed() {
        // Setup
        let user = create_user(vec!["superadmin"], DEFAULT_NAMESPACE);

        // Act
        let result = validate_global_superadmin_access(&user);

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_tenant_superadmin_forbidden() {
        // Setup
        let user = create_user(vec!["superadmin"], "tenant_ns");

        // Act
        let result = validate_global_superadmin_access(&user);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_regular_admin_public_ns_forbidden() {
        // Setup
        let user = create_user(vec!["admin"], DEFAULT_NAMESPACE);

        // Act
        let result = validate_global_superadmin_access(&user);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_regular_user_forbidden() {
        // Setup
        let user = create_user(vec!["users"], "tenant_ns");

        // Act
        let result = validate_global_superadmin_access(&user);

        // Assert
        assert!(result.is_err());
    }
}
