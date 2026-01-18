//! Refresh token model for JWT authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Represents a refresh token stored in the database.
///
/// Refresh tokens are used to obtain new access tokens without
/// requiring the user to re-authenticate. They are stored as
/// hashed values for security.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    /// Unique identifier for the refresh token (UUID v4)
    pub id: Uuid,

    /// Reference to the user who owns this token
    pub user_id: Uuid,

    /// Hashed value of the actual refresh token
    /// The raw token is never stored, only its hash
    pub token_hash: String,

    /// Timestamp when this token expires
    pub expires_at: DateTime<Utc>,

    /// Timestamp when this token was revoked (None if still valid)
    pub revoked_at: Option<DateTime<Utc>>,

    /// Timestamp when this token was created
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    /// Creates a new RefreshToken instance (for testing or manual construction).
    ///
    /// Note: In production, refresh tokens are typically created via database INSERT
    /// with default values for id and created_at.
    #[allow(dead_code)]
    pub fn new(user_id: Uuid, token_hash: String, expires_at: DateTime<Utc>) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            token_hash,
            expires_at,
            revoked_at: None,
            created_at: Utc::now(),
        }
    }

    /// Checks if the token has expired.
    #[allow(dead_code)]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Checks if the token has been revoked.
    #[allow(dead_code)]
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Checks if the token is valid (not expired and not revoked).
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_revoked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_refresh_token_new() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);
        let token = RefreshToken::new(user_id, "hashed_token_value".to_string(), expires_at);

        assert_eq!(token.user_id, user_id);
        assert_eq!(token.token_hash, "hashed_token_value");
        assert!(token.revoked_at.is_none());
    }

    #[test]
    fn test_is_expired_false() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);
        let token = RefreshToken::new(user_id, "hash".to_string(), expires_at);

        assert!(!token.is_expired());
    }

    #[test]
    fn test_is_expired_true() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() - Duration::days(1);
        let token = RefreshToken::new(user_id, "hash".to_string(), expires_at);

        assert!(token.is_expired());
    }

    #[test]
    fn test_is_revoked_false() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);
        let token = RefreshToken::new(user_id, "hash".to_string(), expires_at);

        assert!(!token.is_revoked());
    }

    #[test]
    fn test_is_revoked_true() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);
        let mut token = RefreshToken::new(user_id, "hash".to_string(), expires_at);
        token.revoked_at = Some(Utc::now());

        assert!(token.is_revoked());
    }

    #[test]
    fn test_is_valid_true() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);
        let token = RefreshToken::new(user_id, "hash".to_string(), expires_at);

        assert!(token.is_valid());
    }

    #[test]
    fn test_is_valid_false_expired() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() - Duration::days(1);
        let token = RefreshToken::new(user_id, "hash".to_string(), expires_at);

        assert!(!token.is_valid());
    }

    #[test]
    fn test_is_valid_false_revoked() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);
        let mut token = RefreshToken::new(user_id, "hash".to_string(), expires_at);
        token.revoked_at = Some(Utc::now());

        assert!(!token.is_valid());
    }

    #[test]
    fn test_token_serialization() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);
        let token = RefreshToken::new(user_id, "hash".to_string(), expires_at);

        let json = serde_json::to_string(&token).expect("Failed to serialize token");
        assert!(json.contains(&format!("\"user_id\":\"{}\"", user_id)));
        assert!(json.contains("\"token_hash\":\"hash\""));
    }
}
