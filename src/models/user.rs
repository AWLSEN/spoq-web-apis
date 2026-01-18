//! User model for GitHub OAuth authenticated users.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Represents a user authenticated via GitHub OAuth.
///
/// Users are created when they first authenticate with GitHub
/// and are identified by their unique GitHub ID.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    /// Unique identifier for the user (UUID v4)
    pub id: Uuid,

    /// GitHub's unique user ID
    pub github_id: i64,

    /// GitHub username
    pub username: String,

    /// User's email address (optional, may not be public on GitHub)
    pub email: Option<String>,

    /// URL to the user's GitHub avatar
    pub avatar_url: Option<String>,

    /// Timestamp when the user record was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when the user record was last updated
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Creates a new User instance (for testing or manual construction).
    ///
    /// Note: In production, users are typically created via database INSERT
    /// with default values for id, created_at, and updated_at.
    #[allow(dead_code)]
    pub fn new(
        github_id: i64,
        username: String,
        email: Option<String>,
        avatar_url: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            github_id,
            username,
            email,
            avatar_url,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_new() {
        let user = User::new(
            12345,
            "testuser".to_string(),
            Some("test@example.com".to_string()),
            Some("https://avatars.githubusercontent.com/u/12345".to_string()),
        );

        assert_eq!(user.github_id, 12345);
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, Some("test@example.com".to_string()));
        assert!(user.avatar_url.is_some());
    }

    #[test]
    fn test_user_new_minimal() {
        let user = User::new(67890, "minimaluser".to_string(), None, None);

        assert_eq!(user.github_id, 67890);
        assert_eq!(user.username, "minimaluser");
        assert!(user.email.is_none());
        assert!(user.avatar_url.is_none());
    }

    #[test]
    fn test_user_serialization() {
        let user = User::new(
            12345,
            "testuser".to_string(),
            Some("test@example.com".to_string()),
            None,
        );

        let json = serde_json::to_string(&user).expect("Failed to serialize user");
        assert!(json.contains("\"github_id\":12345"));
        assert!(json.contains("\"username\":\"testuser\""));
        assert!(json.contains("\"email\":\"test@example.com\""));
    }

    #[test]
    fn test_user_deserialization() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "id": "{}",
                "github_id": 12345,
                "username": "testuser",
                "email": "test@example.com",
                "avatar_url": null,
                "created_at": "{}",
                "updated_at": "{}"
            }}"#,
            id,
            now.to_rfc3339(),
            now.to_rfc3339()
        );

        let user: User = serde_json::from_str(&json).expect("Failed to deserialize user");
        assert_eq!(user.id, id);
        assert_eq!(user.github_id, 12345);
        assert_eq!(user.username, "testuser");
    }
}
