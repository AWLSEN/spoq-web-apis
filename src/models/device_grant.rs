//! Device grant model for device authorization flow.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of a device authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeviceGrantStatus {
    /// Authorization request is pending user approval
    Pending,
    /// User has approved the authorization request
    Approved,
    /// User has denied the authorization request
    Denied,
}

impl DeviceGrantStatus {
    /// Returns the string representation of the status.
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceGrantStatus::Pending => "pending",
            DeviceGrantStatus::Approved => "approved",
            DeviceGrantStatus::Denied => "denied",
        }
    }
}

impl std::fmt::Display for DeviceGrantStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents a device authorization grant in the OAuth device flow.
///
/// Device grants allow CLI applications to authenticate users without
/// requiring a web browser redirect. Users approve the request via a
/// web portal using a user-friendly word code.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DeviceGrant {
    /// Unique identifier for the device grant (UUID v4)
    pub id: Uuid,

    /// Machine-readable device code used by the CLI to poll for authorization
    pub device_code: String,

    /// Human-readable word code displayed to the user for approval
    pub word_code: String,

    /// Hostname of the device requesting authorization
    pub hostname: String,

    /// User ID of the user who approved the grant (null if pending/denied)
    pub user_id: Option<Uuid>,

    /// Current status of the authorization request
    pub status: DeviceGrantStatus,

    /// Timestamp when the grant expires
    pub expires_at: DateTime<Utc>,

    /// Timestamp when the grant was created
    pub created_at: DateTime<Utc>,
}

impl DeviceGrant {
    /// Creates a new device grant for testing or manual construction.
    ///
    /// In production, grants are typically created via database INSERT
    /// with default values for id and created_at.
    #[allow(dead_code)]
    pub fn new(
        device_code: String,
        word_code: String,
        hostname: String,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            device_code,
            word_code,
            hostname,
            user_id: None,
            status: DeviceGrantStatus::Pending,
            expires_at,
            created_at: Utc::now(),
        }
    }

    /// Checks if the device grant has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Checks if the device grant is pending approval.
    pub fn is_pending(&self) -> bool {
        self.status == DeviceGrantStatus::Pending
    }

    /// Checks if the device grant has been approved.
    pub fn is_approved(&self) -> bool {
        self.status == DeviceGrantStatus::Approved
    }

    /// Checks if the device grant has been denied.
    pub fn is_denied(&self) -> bool {
        self.status == DeviceGrantStatus::Denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_device_grant_new() {
        let expires_at = Utc::now() + Duration::minutes(15);
        let grant = DeviceGrant::new(
            "DEVICE_123456".to_string(),
            "happy-cat-blue".to_string(),
            "my-laptop".to_string(),
            expires_at,
        );

        assert_eq!(grant.device_code, "DEVICE_123456");
        assert_eq!(grant.word_code, "happy-cat-blue");
        assert_eq!(grant.hostname, "my-laptop");
        assert!(grant.user_id.is_none());
        assert_eq!(grant.status, DeviceGrantStatus::Pending);
        assert_eq!(grant.expires_at, expires_at);
    }

    #[test]
    fn test_device_grant_is_expired() {
        let past = Utc::now() - Duration::minutes(5);
        let future = Utc::now() + Duration::minutes(15);

        let expired_grant = DeviceGrant::new(
            "DEVICE_EXPIRED".to_string(),
            "sad-dog-red".to_string(),
            "old-device".to_string(),
            past,
        );

        let valid_grant = DeviceGrant::new(
            "DEVICE_VALID".to_string(),
            "happy-bird-green".to_string(),
            "new-device".to_string(),
            future,
        );

        assert!(expired_grant.is_expired());
        assert!(!valid_grant.is_expired());
    }

    #[test]
    fn test_device_grant_status_checks() {
        let expires_at = Utc::now() + Duration::minutes(15);
        let grant = DeviceGrant::new(
            "DEVICE_123".to_string(),
            "test-word-code".to_string(),
            "test-host".to_string(),
            expires_at,
        );

        assert!(grant.is_pending());
        assert!(!grant.is_approved());
        assert!(!grant.is_denied());
    }

    #[test]
    fn test_device_grant_status_display() {
        assert_eq!(DeviceGrantStatus::Pending.to_string(), "pending");
        assert_eq!(DeviceGrantStatus::Approved.to_string(), "approved");
        assert_eq!(DeviceGrantStatus::Denied.to_string(), "denied");
    }

    #[test]
    fn test_device_grant_status_as_str() {
        assert_eq!(DeviceGrantStatus::Pending.as_str(), "pending");
        assert_eq!(DeviceGrantStatus::Approved.as_str(), "approved");
        assert_eq!(DeviceGrantStatus::Denied.as_str(), "denied");
    }

    #[test]
    fn test_device_grant_serialization() {
        let expires_at = Utc::now() + Duration::minutes(15);
        let grant = DeviceGrant::new(
            "DEVICE_SERIAL".to_string(),
            "serial-test-code".to_string(),
            "serial-host".to_string(),
            expires_at,
        );

        let json = serde_json::to_string(&grant).expect("Failed to serialize grant");
        assert!(json.contains("\"device_code\":\"DEVICE_SERIAL\""));
        assert!(json.contains("\"word_code\":\"serial-test-code\""));
        assert!(json.contains("\"hostname\":\"serial-host\""));
        assert!(json.contains("\"status\":\"pending\""));
    }

    #[test]
    fn test_device_grant_deserialization() {
        let now = Utc::now();
        let expires = now + Duration::minutes(15);
        let id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "id": "{}",
                "device_code": "DEVICE_DESER",
                "word_code": "deser-test-code",
                "hostname": "deser-host",
                "user_id": null,
                "status": "pending",
                "expires_at": "{}",
                "created_at": "{}"
            }}"#,
            id,
            expires.to_rfc3339(),
            now.to_rfc3339()
        );

        let grant: DeviceGrant =
            serde_json::from_str(&json).expect("Failed to deserialize grant");
        assert_eq!(grant.id, id);
        assert_eq!(grant.device_code, "DEVICE_DESER");
        assert_eq!(grant.word_code, "deser-test-code");
        assert_eq!(grant.hostname, "deser-host");
        assert!(grant.user_id.is_none());
        assert_eq!(grant.status, DeviceGrantStatus::Pending);
    }
}
