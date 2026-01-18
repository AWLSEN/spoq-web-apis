//! Token service for generating, hashing, and validating authentication tokens.
//!
//! This module provides:
//! - Refresh token generation with `spoq_` prefix
//! - Token hashing using Argon2id
//! - JWT access token creation and validation

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims structure for access tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject - the user ID as a string
    pub sub: String,
    /// Expiration time as Unix timestamp
    pub exp: i64,
    /// Issued at time as Unix timestamp
    pub iat: i64,
}

/// Generates a cryptographically secure refresh token with `spoq_` prefix.
///
/// The token format is: `spoq_<43 base64url characters>`
/// - Uses 32 bytes of cryptographically secure random data
/// - Encoded with URL-safe base64 (no padding)
///
/// # Returns
///
/// A string in the format `spoq_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::token::generate_refresh_token;
///
/// let token = generate_refresh_token();
/// assert!(token.starts_with("spoq_"));
/// assert_eq!(token.len(), 48); // 5 (prefix) + 43 (base64)
/// ```
pub fn generate_refresh_token() -> String {
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let encoded = URL_SAFE_NO_PAD.encode(random_bytes);
    format!("spoq_{}", encoded)
}

/// Hashes a token using Argon2id with secure defaults.
///
/// # Arguments
///
/// * `token` - The raw token string to hash
///
/// # Returns
///
/// A Result containing the PHC string format hash, or an error if hashing fails
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::token::{generate_refresh_token, hash_token};
///
/// let token = generate_refresh_token();
/// let hash = hash_token(&token).expect("Failed to hash token");
/// assert!(hash.starts_with("$argon2id$"));
/// ```
pub fn hash_token(token: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(token.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verifies a token against a stored hash.
///
/// # Arguments
///
/// * `token` - The raw token to verify
/// * `hash` - The PHC string format hash to verify against
///
/// # Returns
///
/// `true` if the token matches the hash, `false` otherwise
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::token::{generate_refresh_token, hash_token, verify_token};
///
/// let token = generate_refresh_token();
/// let hash = hash_token(&token).expect("Failed to hash token");
/// assert!(verify_token(&token, &hash));
/// assert!(!verify_token("wrong_token", &hash));
/// ```
pub fn verify_token(token: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Creates a JWT access token for a user.
///
/// # Arguments
///
/// * `user_id` - The UUID of the user
/// * `secret` - The secret key used to sign the JWT
/// * `expiry_secs` - Number of seconds until the token expires
///
/// # Returns
///
/// A Result containing the JWT string, or an error if encoding fails
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::token::create_access_token;
/// use uuid::Uuid;
///
/// let user_id = Uuid::new_v4();
/// let token = create_access_token(user_id, "my_secret", 3600).expect("Failed to create token");
/// assert!(!token.is_empty());
/// ```
pub fn create_access_token(
    user_id: Uuid,
    secret: &str,
    expiry_secs: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        exp: now + expiry_secs,
        iat: now,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Decodes and validates a JWT access token.
///
/// # Arguments
///
/// * `token` - The JWT string to decode
/// * `secret` - The secret key used to verify the JWT signature
///
/// # Returns
///
/// A Result containing the Claims if valid, or an error if decoding/validation fails
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::token::{create_access_token, decode_access_token};
/// use uuid::Uuid;
///
/// let user_id = Uuid::new_v4();
/// let token = create_access_token(user_id, "my_secret", 3600).expect("Failed to create token");
/// let claims = decode_access_token(&token, "my_secret").expect("Failed to decode token");
/// assert_eq!(claims.sub, user_id.to_string());
/// ```
pub fn decode_access_token(
    token: &str,
    secret: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_refresh_token_format() {
        let token = generate_refresh_token();
        assert!(token.starts_with("spoq_"));
        // 5 chars for "spoq_" + 43 chars for base64url encoded 32 bytes
        assert_eq!(token.len(), 48);
    }

    #[test]
    fn test_generate_refresh_token_uniqueness() {
        let token1 = generate_refresh_token();
        let token2 = generate_refresh_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_hash_token_produces_argon2id_hash() {
        let token = generate_refresh_token();
        let hash = hash_token(&token).expect("Failed to hash token");
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_hash_token_produces_unique_hashes() {
        let token = generate_refresh_token();
        let hash1 = hash_token(&token).expect("Failed to hash token");
        let hash2 = hash_token(&token).expect("Failed to hash token");
        // Same token should produce different hashes due to random salt
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_token_correct_token() {
        let token = generate_refresh_token();
        let hash = hash_token(&token).expect("Failed to hash token");
        assert!(verify_token(&token, &hash));
    }

    #[test]
    fn test_verify_token_wrong_token() {
        let token = generate_refresh_token();
        let hash = hash_token(&token).expect("Failed to hash token");
        assert!(!verify_token("wrong_token", &hash));
    }

    #[test]
    fn test_verify_token_invalid_hash() {
        let token = generate_refresh_token();
        assert!(!verify_token(&token, "invalid_hash_format"));
    }

    #[test]
    fn test_create_access_token() {
        let user_id = Uuid::new_v4();
        let secret = "test_secret_key_12345";
        let expiry_secs = 3600;

        let token = create_access_token(user_id, secret, expiry_secs)
            .expect("Failed to create access token");
        assert!(!token.is_empty());
        // JWT has three parts separated by dots
        assert_eq!(token.matches('.').count(), 2);
    }

    #[test]
    fn test_decode_access_token_valid() {
        let user_id = Uuid::new_v4();
        let secret = "test_secret_key_12345";
        let expiry_secs = 3600;

        let token = create_access_token(user_id, secret, expiry_secs)
            .expect("Failed to create access token");
        let claims =
            decode_access_token(&token, secret).expect("Failed to decode access token");

        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_decode_access_token_wrong_secret() {
        let user_id = Uuid::new_v4();
        let secret = "correct_secret";
        let expiry_secs = 3600;

        let token = create_access_token(user_id, secret, expiry_secs)
            .expect("Failed to create access token");
        let result = decode_access_token(&token, "wrong_secret");

        assert!(result.is_err());
    }

    #[test]
    fn test_decode_access_token_expired() {
        let user_id = Uuid::new_v4();
        let secret = "test_secret";
        // Create a token that has already expired (well past any tolerance)
        let expiry_secs = -120; // 2 minutes in the past

        let token = create_access_token(user_id, secret, expiry_secs)
            .expect("Failed to create access token");
        let result = decode_access_token(&token, secret);

        assert!(result.is_err(), "Expected expired token to fail validation");
    }

    #[test]
    fn test_claims_serialization() {
        let claims = Claims {
            sub: "user-123".to_string(),
            exp: 1700000000,
            iat: 1699996400,
        };

        let json = serde_json::to_string(&claims).expect("Failed to serialize claims");
        assert!(json.contains("\"sub\":\"user-123\""));
        assert!(json.contains("\"exp\":1700000000"));
        assert!(json.contains("\"iat\":1699996400"));
    }
}
