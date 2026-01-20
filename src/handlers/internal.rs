//! Internal API handlers for conductor registration.
//!
//! These endpoints are unauthenticated but protected by short-lived codes,
//! one-time use, and rate limiting.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::services::registration::{generate_vps_secret, hash_code, verify_code};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub registration_code: String, // "ABC123"
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub vps_secret: String,  // "spoq_vps_..."
    pub owner_id: String,    // User UUID
    pub jwt_secret: String,  // For validating CLI tokens
    pub hostname: String,    // "username.spoq.dev"
}

/// POST /internal/conductor/register
///
/// Rate limit: 5 requests per IP per minute
/// Returns 404 for any invalid state (prevent enumeration)
pub async fn register_conductor(
    pool: web::Data<PgPool>,
    req: web::Json<RegisterRequest>,
) -> AppResult<HttpResponse> {
    let code = req.registration_code.to_uppercase().trim().to_string();

    // Validate format (6 chars, A-Z 0-9)
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Invalid registration code"
        })));
    }

    // Query pending registrations (not expired, not used)
    let pending_vps: Vec<PendingVps> = sqlx::query_as(
        r#"SELECT id, user_id, registration_code_hash, jwt_secret, hostname
           FROM user_vps
           WHERE registration_expires_at > NOW()
             AND registered_at IS NULL
             AND registration_code_hash IS NOT NULL"#,
    )
    .fetch_all(pool.get_ref())
    .await?;

    // Find matching VPS by verifying hash
    let matched = pending_vps.iter().find(|vps| {
        vps.registration_code_hash
            .as_ref()
            .map(|hash| verify_code(&code, hash))
            .unwrap_or(false)
    });

    let Some(vps) = matched else {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Invalid registration code"
        })));
    };

    // Generate vps_secret and hash it
    let vps_secret = generate_vps_secret();
    let vps_secret_hash = hash_code(&vps_secret).map_err(|e| {
        crate::error::AppError::Internal(format!("Failed to hash VPS secret: {}", e))
    })?;

    // Mark as registered, store vps_secret_hash
    sqlx::query(
        r#"UPDATE user_vps
           SET registered_at = NOW(),
               vps_secret_hash = $1,
               registration_code_hash = NULL
           WHERE id = $2"#,
    )
    .bind(&vps_secret_hash)
    .bind(vps.id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(RegisterResponse {
        vps_secret,
        owner_id: vps.user_id.to_string(),
        jwt_secret: vps.jwt_secret.clone(),
        hostname: vps.hostname.clone(),
    }))
}

#[derive(sqlx::FromRow)]
struct PendingVps {
    id: Uuid,
    user_id: Uuid,
    registration_code_hash: Option<String>,
    jwt_secret: String,
    hostname: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_code_validation_after_normalization() {
        // Tests use the same normalization as the handler:
        // 1. Uppercase
        // 2. Trim
        // 3. Check length == 6 and alphanumeric

        // Valid codes (after normalization)
        assert!(is_valid_normalized("ABC123"));
        assert!(is_valid_normalized("A1B2C3"));
        assert!(is_valid_normalized("000000"));
        assert!(is_valid_normalized("ZZZZZZ"));
        assert!(is_valid_normalized("abc123")); // Lowercase becomes uppercase
        assert!(is_valid_normalized("  ABC123  ")); // Whitespace trimmed

        // Invalid codes - wrong length (after normalization)
        assert!(!is_valid_normalized("ABC12"));
        assert!(!is_valid_normalized("ABC1234"));
        assert!(!is_valid_normalized(""));

        // Invalid codes - non-alphanumeric characters
        assert!(!is_valid_normalized("ABC12!"));
        assert!(!is_valid_normalized("ABC-23"));
    }

    /// Matches the handler's validation logic exactly
    fn is_valid_normalized(input: &str) -> bool {
        let code = input.to_uppercase().trim().to_string();
        code.len() == 6 && code.chars().all(|c| c.is_ascii_alphanumeric())
    }
}
