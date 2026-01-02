use crate::handler::auth::AuthenticatedUser;
use crate::services::user_service::{ChangePasswordRequest, UpdateProfileRequest, UserService};
use axum::{Extension, Json, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use crate::repository::sqlx_impl::{
    PgGroupRepository, PgPasswordResetRepository, PgSettingsRepository, PgUserRepository,
};

type UserServiceType = UserService<
    PgUserRepository,
    PgGroupRepository,
    PgPasswordResetRepository,
    PgSettingsRepository,
>;

/// PATCH /api/user/profile
pub async fn update_profile(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<UpdateProfileRequest>,
) -> impl IntoResponse {
    match user_service
        .update_profile(user.user_id, payload, &user.namespace)
        .await
    {
        Ok(updated_user) => (StatusCode::OK, Json(updated_user)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /api/user/password/change
pub async fn change_password(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    match user_service
        .change_password(user.user_id, payload, &user.namespace)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "Password changed successfully"})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}
