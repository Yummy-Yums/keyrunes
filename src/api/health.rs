use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use password_hash::rand_core::OsRng;
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::time::SystemTime;

use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub database: DatabaseHealth,
    pub services: ServicesHealth,
}

#[derive(Serialize, ToSchema)]
pub struct DatabaseHealth {
    pub status: String,
    pub response_time_ms: Option<u64>,
    pub active_connections: Option<i32>,
}

#[derive(Serialize, ToSchema)]
pub struct ServicesHealth {
    pub jwt_service: String,
    pub password_hashing: String,
}

static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

pub fn init_health_check() {
    START_TIME.set(SystemTime::now()).ok();
}

#[utoipa::path(
    get,
    path = "/api/health",
    responses(
        (status = 200, description = "System is healthy", body = HealthResponse),
        (status = 503, description = "System is unhealthy", body = HealthResponse)
    ),
    tag = "health"
)]
pub async fn health_check(Extension(pool): Extension<PgPool>) -> impl IntoResponse {
    let start_time = START_TIME.get().copied().unwrap_or_else(SystemTime::now);
    let uptime = SystemTime::now()
        .duration_since(start_time)
        .unwrap_or_default()
        .as_secs();

    let db_health = check_database_health(&pool).await;

    let services_health = check_services_health();

    let overall_status = if db_health.status == "healthy"
        && services_health.jwt_service == "healthy"
        && services_health.password_hashing == "healthy"
    {
        "healthy"
    } else {
        "unhealthy"
    };

    let response = HealthResponse {
        status: overall_status.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        database: db_health,
        services: services_health,
    };

    let status_code = if overall_status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

pub async fn readiness_check(Extension(pool): Extension<PgPool>) -> impl IntoResponse {
    let db_result = sqlx::query("SELECT 1 as health_check")
        .fetch_one(&pool)
        .await;

    match db_result {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ready",
                "timestamp": Utc::now().to_rfc3339()
            })),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "timestamp": Utc::now().to_rfc3339(),
                "error": "database_connection_failed"
            })),
        ),
    }
}

pub async fn liveness_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "alive",
            "timestamp": Utc::now().to_rfc3339(),
            "version": env!("CARGO_PKG_VERSION")
        })),
    )
}

async fn check_database_health(pool: &PgPool) -> DatabaseHealth {
    let start = SystemTime::now();

    let query_result = sqlx::query("SELECT 1 as health_check, count(*) as connection_count FROM pg_stat_activity WHERE state = 'active'")
        .fetch_one(pool)
        .await;

    let response_time = SystemTime::now()
        .duration_since(start)
        .unwrap_or_default()
        .as_millis() as u64;

    match query_result {
        Ok(row) => {
            let connection_count: i64 = row.try_get("connection_count").unwrap_or(0);
            DatabaseHealth {
                status: "healthy".to_string(),
                response_time_ms: Some(response_time),
                active_connections: Some(connection_count as i32),
            }
        }
        Err(_) => DatabaseHealth {
            status: "unhealthy".to_string(),
            response_time_ms: Some(response_time),
            active_connections: None,
        },
    }
}

fn check_services_health() -> ServicesHealth {
    let jwt_status = match test_jwt_service() {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };

    let password_status = match test_password_hashing() {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };

    ServicesHealth {
        jwt_service: jwt_status.to_string(),
        password_hashing: password_status.to_string(),
    }
}

pub fn test_jwt_service() -> Result<(), Box<dyn std::error::Error>> {
    use crate::services::jwt_service::JwtService;

    let jwt_service = JwtService::new("0123456789ABCDEF0123456789ABCDEF");
    let token = jwt_service.generate_token(1, "test@example.com", "test", vec![])?;
    jwt_service.verify_token(&token)?;
    Ok(())
}

pub fn test_password_hashing() -> Result<(), Box<dyn std::error::Error>> {
    use argon2::{Argon2, password_hash::PasswordHasher};
    use password_hash::{PasswordHash, PasswordVerifier, SaltString};
    use std::io;

    let password = "test_password";

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Box::new(io::Error::other(format!("password hash error: {}", e))))?;

    let binding = hash.to_string();
    let parsed_hash = PasswordHash::new(&binding).map_err(|e| {
        Box::new(io::Error::other(format!(
            "password hash parse error: {}",
            e
        )))
    })?;

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|e| Box::new(io::Error::other(format!("password verify error: {}", e))))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_service_health() {
        let result = test_jwt_service();
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_hashing_health() {
        let result = test_password_hashing();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_services_health() {
        let health = check_services_health();
        assert_eq!(health.jwt_service, "healthy");
        assert_eq!(health.password_hashing, "healthy");
    }

    #[test]
    fn test_health_response_serialization() {
        let health = HealthResponse {
            status: "healthy".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            version: "0.1.0".to_string(),
            uptime_seconds: 3600,
            database: DatabaseHealth {
                status: "healthy".to_string(),
                response_time_ms: Some(10),
                active_connections: Some(5),
            },
            services: ServicesHealth {
                jwt_service: "healthy".to_string(),
                password_hashing: "healthy".to_string(),
            },
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("0.1.0"));
    }
}
