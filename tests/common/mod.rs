pub mod factories;

use axum::{Router, body::Body, http::Request};
use serde_json::json;
use tower::util::ServiceExt;

#[allow(dead_code)]
pub async fn create_test_app() -> Router {
    todo!("Implement test app creation")
}

#[allow(dead_code)]
pub async fn create_admin_user(app: &Router) {
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "org_admin@test.com",
                        "username": "org_admin_test",
                        "password": "testpass123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
}

#[allow(dead_code)]
pub async fn create_regular_user(app: &Router) {
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "regular@test.com",
                        "username": "regular_user",
                        "password": "testpass123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
}

#[allow(dead_code)]
pub async fn login_user(app: &Router, email: &str, password: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    body["token"].as_str().unwrap().to_string()
}
