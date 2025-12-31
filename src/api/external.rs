use crate::handler::auth::ApiAuthContext;
use crate::repository::UserRepository;
use crate::repository::sqlx_impl::{PgPolicyRepository, PgUserRepository};
use crate::services::policy_service::PolicyService;
use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct CheckPermissionRequest {
    pub user_id: i64,
    pub resource: String,
    pub action: String,
}

#[derive(Serialize)]
pub struct PermissionResponse {
    pub allowed: bool,
    pub user_id: i64,
    pub resource: String,
    pub action: String,
}

pub async fn check_permission(
    Extension(auth_context): Extension<ApiAuthContext>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CheckPermissionRequest>,
) -> impl IntoResponse {
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let policy_repo = Arc::new(PgPolicyRepository::new(pool.clone()));
    let policy_service = PolicyService::new(policy_repo);

    let user = match user_repo.find_by_id(payload.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    match auth_context {
        ApiAuthContext::Organization(org) => {
            if user.organization_id != org.organization_id {
                return (
                    StatusCode::FORBIDDEN,
                    "User does not belong to this organization",
                )
                    .into_response();
            }
        }
        ApiAuthContext::Superadmin(_) => {}
    }

    let user_policies = match user_repo.get_user_all_policies(payload.user_id).await {
        Ok(policies) => policies,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let has_permission = policy_service
        .evaluate_permission(&user_policies, &payload.resource, &payload.action)
        .await;

    (
        StatusCode::OK,
        Json(PermissionResponse {
            allowed: has_permission,
            user_id: payload.user_id,
            resource: payload.resource,
            action: payload.action,
        }),
    )
        .into_response()
}
