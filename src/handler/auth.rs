use axum::{
    body::Body,
    extract::{Extension, Request},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::handler::errors::ErrorResponse;
use crate::repository::sqlx_impl::PgOrganizationRepository;
use crate::services::jwt_service::{Claims, JwtService};
use crate::services::organization_service::OrganizationService;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_id: i64,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
}

impl From<Claims> for AuthenticatedUser {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub.parse().unwrap_or(0),
            email: claims.email,
            username: claims.username,
            groups: claims.groups,
        }
    }
}

/// Middleware that requires JWT authentication
pub async fn require_auth(
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return ErrorResponse::unauthorized("Missing authorization header").into_response();
        }
    };

    match jwt_service.verify_token(&token) {
        Ok(claims) => {
            let user = AuthenticatedUser::from(claims);
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(_) => ErrorResponse::unauthorized("Invalid or expired token").into_response(),
    }
}

/// Middleware that optionally extracts user from JWT if present
#[allow(dead_code)]
pub async fn optional_auth(
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(token) = extract_bearer_token(&headers)
        && let Ok(claims) = jwt_service.verify_token(&token)
    {
        let user = AuthenticatedUser::from(claims);
        request.extensions_mut().insert(user);
    }

    next.run(request).await
}

/// Middleware that requires specific groups
#[allow(dead_code)]
pub fn require_groups(
    required_groups: Vec<String>,
) -> impl Clone
+ Fn(
    Extension<AuthenticatedUser>,
    Request<Body>,
    Next,
) -> Pin<Box<dyn Future<Output = Response> + Send>> {
    let required_groups: Vec<Arc<String>> = required_groups.into_iter().map(Arc::new).collect();

    move |Extension(user): Extension<AuthenticatedUser>, request: Request<Body>, next: Next| {
        let required_groups = required_groups.clone();

        Box::pin(async move {
            let has_required_group = required_groups
                .iter()
                .any(|group| user.groups.iter().any(|ug| ug == &**group));

            if has_required_group {
                next.run(request).await
            } else {
                ErrorResponse::forbidden("Insufficient permissions - required group not found")
                    .into_response()
            }
        })
    }
}

/// Middleware that requires superadmin group
pub async fn require_superadmin(
    Extension(user): Extension<AuthenticatedUser>,
    request: Request,
    next: Next,
) -> Response {
    if user.groups.contains(&"superadmin".to_string()) {
        next.run(request).await
    } else {
        ErrorResponse::forbidden("Superadmin access required").into_response()
    }
}

use crate::domain::organization::Organization;

#[derive(Clone)]
pub enum ApiAuthContext {
    Organization(Organization),
    Superadmin(AuthenticatedUser),
}

/// Middleware that requires X-Organization-Key header OR superadmin permissions
pub async fn require_org_key_or_superadmin(
    Extension(org_service): Extension<Arc<OrganizationService<PgOrganizationRepository>>>,
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(key) = headers.get("X-Organization-Key") {
        let api_key = match key.to_str() {
            Ok(k) => k,
            Err(_) => return ErrorResponse::unauthorized("Invalid API Key format").into_response(),
        };

        let secret_key = match Uuid::parse_str(api_key) {
            Ok(uuid) => uuid,
            Err(_) => {
                return ErrorResponse::unauthorized("Invalid API Key format (must be UUID)")
                    .into_response();
            }
        };

        return match org_service.get_organization_by_secret_key(secret_key).await {
            Ok(Some(org)) => {
                request
                    .extensions_mut()
                    .insert(ApiAuthContext::Organization(org));
                next.run(request).await
            }
            Ok(None) => ErrorResponse::unauthorized("Invalid API Key").into_response(),
            Err(e) => {
                tracing::error!("Database error extracting org key: {:?}", e);
                ErrorResponse::internal_server_error("Internal server error").into_response()
            }
        };
    }

    if let Some(token) = extract_bearer_token(&headers)
        && let Ok(claims) = jwt_service.verify_token(&token)
    {
        let user = AuthenticatedUser::from(claims);
        if user.groups.contains(&"superadmin".to_string()) {
            request
                .extensions_mut()
                .insert(ApiAuthContext::Superadmin(user));
            return next.run(request).await;
        }
    }

    ErrorResponse::unauthorized("Missing X-Organization-Key header or valid Superadmin token")
        .into_response()
}

/// Extract Bearer token from Authorization header or cookies
///
/// FIXED: Safe cookie parsing using strip_prefix instead of direct indexing
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth_header) = headers.get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && auth_str.starts_with("Bearer ")
        && auth_str.len() > 7
    {
        return Some(auth_str[7..].to_string());
    }

    if let Some(cookie_header) = headers.get("cookie")
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();

            if let Some(token_value) = cookie.strip_prefix("jwt_token=")
                && !token_value.is_empty()
            {
                return Some(token_value.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_bearer_token_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer test123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("jwt_token=test123; other=value"),
        );

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_from_cookie_only() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token=abc123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_empty_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token="));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Basic abc123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_bearer_too_short() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer "));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_authenticated_user_from_claims() {
        let claims = Claims {
            sub: "123".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            groups: vec!["users".to_string(), "admin".to_string()],
            exp: 1234567890,
            iat: 1234567890,
            iss: "keyrunes".to_string(),
        };

        let user = AuthenticatedUser::from(claims);
        assert_eq!(user.user_id, 123);
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.username, "testuser");
        assert_eq!(user.groups, vec!["users", "admin"]);
    }
}
