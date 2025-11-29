use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use josekit::jws::HS256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
}

#[derive(Clone)]
pub struct JwtService {
    secret: Vec<u8>,
    issuer: String,
}

impl JwtService {
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
            issuer: "keyrunes".to_string(),
        }
    }

    pub fn generate_token(
        &self,
        user_id: i64,
        email: &str,
        username: &str,
        groups: Vec<String>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(1);

        let mut payload = JwtPayload::new();
        payload.set_claim("sub", Some(Value::String(user_id.to_string())))?;
        payload.set_claim("email", Some(Value::String(email.to_string())))?;
        payload.set_claim("username", Some(Value::String(username.to_string())))?;
        payload.set_claim("groups", Some(serde_json::to_value(&groups)?))?;
        payload.set_claim("exp", Some(Value::Number(exp.timestamp().into())))?;
        payload.set_claim("iat", Some(Value::Number(now.timestamp().into())))?;
        payload.set_claim("iss", Some(Value::String(self.issuer.clone())))?;

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let signer = HS256.signer_from_bytes(&self.secret)?;
        let token = jwt::encode_with_signer(&payload, &header, &signer)?;

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let verifier = HS256.verifier_from_bytes(&self.secret)?;
        let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
            .map_err(|e| anyhow!("Failed to decode JWT: {}", e))?;

        let sub = payload
            .claim("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'sub' claim"))?
            .to_string();
        let email = payload
            .claim("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'email' claim"))?
            .to_string();
        let username = payload
            .claim("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'username' claim"))?
            .to_string();
        let groups = payload
            .claim("groups")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("Missing or invalid 'groups' claim"))?;
        let exp = payload
            .claim("exp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("Missing or invalid 'exp' claim"))?;
        let iat = payload
            .claim("iat")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("Missing or invalid 'iat' claim"))?;
        let iss = payload
            .claim("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'iss' claim"))?
            .to_string();

        Ok(Claims {
            sub,
            email,
            username,
            groups,
            exp,
            iat,
            iss,
        })
    }

    pub fn refresh_token(&self, token: &str) -> Result<String> {
        let claims = self.verify_token(token)?;
        self.generate_token(
            claims.sub.parse()?,
            &claims.email,
            &claims.username,
            claims.groups,
        )
    }

    pub fn extract_user_id(&self, token: &str) -> Result<i64> {
        let claims = self.verify_token(token)?;
        claims
            .sub
            .parse()
            .map_err(|e| anyhow!("Invalid user ID in token: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_jwt_token_generation_and_verification() {
        let service = JwtService::new("0123456789ABCDEF0123456789ABCDEF");
        let groups = vec!["users".to_string(), "admin".to_string()];

        let token = service
            .generate_token(1, "test@example.com", "testuser", groups.clone())
            .unwrap();
        let claims = service.verify_token(&token).unwrap();

        assert_eq!(claims.sub, "1");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.groups, groups);
        assert_eq!(claims.iss, "keyrunes");
    }

    #[test]
    fn test_refresh_token() {
        let service = JwtService::new("0123456789ABCDEF0123456789ABCDEF");
        let groups = vec!["users".to_string()];

        let original_token = service
            .generate_token(1, "test@example.com", "testuser", groups.clone())
            .unwrap();

        thread::sleep(StdDuration::from_secs(1));

        let refreshed_token = service.refresh_token(&original_token).unwrap();

        let original_claims = service.verify_token(&original_token).unwrap();
        let refreshed_claims = service.verify_token(&refreshed_token).unwrap();

        assert_eq!(original_claims.sub, refreshed_claims.sub);
        assert_eq!(original_claims.email, refreshed_claims.email);
        assert!(refreshed_claims.exp > original_claims.exp);
    }

    #[test]
    fn test_extract_user_id() {
        let service = JwtService::new("0123456789ABCDEF0123456789ABCDEF");
        let groups = vec!["users".to_string()];

        let token = service
            .generate_token(42, "test@example.com", "testuser", groups)
            .unwrap();
        let user_id = service.extract_user_id(&token).unwrap();

        assert_eq!(user_id, 42);
    }
}
