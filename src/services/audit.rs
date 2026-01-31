//! Audit logging service for tracking security-relevant operations.
//!
//! This service provides methods for logging VPS operations, authentication events,
//! and other security-relevant actions to the audit_logs table.
//!
//! # Security
//! - All request data is sanitized before logging (passwords, tokens removed)
//! - User IDs are extracted from authenticated context
//! - IP addresses are captured for forensic analysis

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Sensitive field names that should be sanitized from logs
const SENSITIVE_FIELDS: &[&str] = &[
    "password",
    "ssh_password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "api_secret",
    "authorization",
    "credential",
    "private_key",
];

/// Audit log action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    // VPS actions
    VpsProvision,
    VpsConfirm,
    VpsStart,
    VpsStop,
    VpsRestart,
    VpsResetPassword,

    // BYOVPS actions
    ByovpsProvision,
    ByovpsReplace,

    // Auth actions
    AuthFailed,
    AuthRateLimited,

    // Operation polling
    OperationPoll,
}

impl AuditAction {
    /// Get the string representation for storage
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VpsProvision => "vps.provision",
            Self::VpsConfirm => "vps.confirm",
            Self::VpsStart => "vps.start",
            Self::VpsStop => "vps.stop",
            Self::VpsRestart => "vps.restart",
            Self::VpsResetPassword => "vps.reset_password",
            Self::ByovpsProvision => "byovps.provision",
            Self::ByovpsReplace => "byovps.replace",
            Self::AuthFailed => "auth.failed",
            Self::AuthRateLimited => "auth.rate_limited",
            Self::OperationPoll => "operation.poll",
        }
    }
}

/// Resource types for audit logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    Vps,
    Byovps,
    User,
    Operation,
}

impl ResourceType {
    /// Get the string representation for storage
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vps => "vps",
            Self::Byovps => "byovps",
            Self::User => "user",
            Self::Operation => "operation",
        }
    }
}

/// Audit log entry for creating a new log
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    pub resource_type: ResourceType,
    pub resource_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_data: Option<Value>,
    pub response_status: Option<i32>,
    pub error_message: Option<String>,
}

impl AuditLogEntry {
    /// Create a new audit log entry builder
    pub fn new(action: AuditAction, resource_type: ResourceType) -> Self {
        Self {
            user_id: None,
            action,
            resource_type,
            resource_id: None,
            ip_address: None,
            user_agent: None,
            request_data: None,
            response_status: None,
            error_message: None,
        }
    }

    /// Set the user ID
    pub fn user_id(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set the resource ID
    pub fn resource_id(mut self, resource_id: Uuid) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    /// Set the IP address
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set the user agent
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Set request data (will be sanitized)
    pub fn request_data<T: Serialize>(mut self, data: &T) -> Self {
        if let Ok(value) = serde_json::to_value(data) {
            self.request_data = Some(sanitize_json(&value));
        }
        self
    }

    /// Set response status
    pub fn response_status(mut self, status: u16) -> Self {
        self.response_status = Some(status as i32);
        self
    }

    /// Set error message
    pub fn error_message(mut self, msg: impl Into<String>) -> Self {
        self.error_message = Some(msg.into());
        self
    }
}

/// Stored audit log record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_data: Option<Value>,
    pub response_status: Option<i32>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Audit service for logging operations
#[derive(Clone)]
pub struct AuditService {
    pool: PgPool,
}

impl AuditService {
    /// Create a new audit service
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log an audit entry
    pub async fn log(&self, entry: AuditLogEntry) -> Result<Uuid, sqlx::Error> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO audit_logs (
                user_id, action, resource_type, resource_id,
                ip_address, user_agent, request_data,
                response_status, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(entry.user_id)
        .bind(entry.action.as_str())
        .bind(entry.resource_type.as_str())
        .bind(entry.resource_id)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .bind(&entry.request_data)
        .bind(entry.response_status)
        .bind(&entry.error_message)
        .fetch_one(&self.pool)
        .await?;

        tracing::debug!(
            audit_id = %id,
            action = entry.action.as_str(),
            resource_type = entry.resource_type.as_str(),
            "Audit log created"
        );

        Ok(id)
    }

    /// Log an audit entry without blocking (fire and forget)
    /// Errors are logged but not propagated
    pub fn log_async(&self, entry: AuditLogEntry) {
        let service = self.clone();
        tokio::spawn(async move {
            if let Err(e) = service.log(entry).await {
                tracing::warn!(error = %e, "Failed to write audit log");
            }
        });
    }

    /// Get audit logs for a user
    pub async fn get_user_logs(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditLog>, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT id, user_id, action, resource_type, resource_id,
                   ip_address, user_agent, request_data, response_status,
                   error_message, created_at
            FROM audit_logs
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Get audit logs by action type
    pub async fn get_logs_by_action(
        &self,
        action: AuditAction,
        limit: i64,
    ) -> Result<Vec<AuditLog>, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT id, user_id, action, resource_type, resource_id,
                   ip_address, user_agent, request_data, response_status,
                   error_message, created_at
            FROM audit_logs
            WHERE action = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(action.as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }
}

/// Sanitize a JSON value by removing sensitive fields
pub fn sanitize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::new();
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if SENSITIVE_FIELDS.iter().any(|&s| key_lower.contains(s)) {
                    // Replace sensitive values with "[REDACTED]"
                    sanitized.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    // Recursively sanitize nested objects
                    sanitized.insert(key.clone(), sanitize_json(val));
                }
            }
            Value::Object(sanitized)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(sanitize_json).collect())
        }
        _ => value.clone(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sanitize_password() {
        let input = json!({
            "vps_ip": "192.168.1.1",
            "ssh_password": "secret123",
            "username": "root"
        });

        let sanitized = sanitize_json(&input);

        assert_eq!(sanitized["vps_ip"], "192.168.1.1");
        assert_eq!(sanitized["ssh_password"], "[REDACTED]");
        assert_eq!(sanitized["username"], "root");
    }

    #[test]
    fn test_sanitize_nested_object() {
        let input = json!({
            "user": {
                "name": "test",
                "password": "secret"
            },
            "config": {
                "api_key": "key123"
            }
        });

        let sanitized = sanitize_json(&input);

        assert_eq!(sanitized["user"]["name"], "test");
        assert_eq!(sanitized["user"]["password"], "[REDACTED]");
        assert_eq!(sanitized["config"]["api_key"], "[REDACTED]");
    }

    #[test]
    fn test_sanitize_array() {
        let input = json!([
            { "token": "abc123" },
            { "data": "safe" }
        ]);

        let sanitized = sanitize_json(&input);

        assert_eq!(sanitized[0]["token"], "[REDACTED]");
        assert_eq!(sanitized[1]["data"], "safe");
    }

    #[test]
    fn test_sanitize_case_insensitive() {
        let input = json!({
            "PASSWORD": "secret",
            "Password": "secret",
            "password": "secret"
        });

        let sanitized = sanitize_json(&input);

        assert_eq!(sanitized["PASSWORD"], "[REDACTED]");
        assert_eq!(sanitized["Password"], "[REDACTED]");
        assert_eq!(sanitized["password"], "[REDACTED]");
    }

    #[test]
    fn test_action_as_str() {
        assert_eq!(AuditAction::VpsProvision.as_str(), "vps.provision");
        assert_eq!(AuditAction::ByovpsReplace.as_str(), "byovps.replace");
        assert_eq!(AuditAction::AuthFailed.as_str(), "auth.failed");
    }

    #[test]
    fn test_resource_type_as_str() {
        assert_eq!(ResourceType::Vps.as_str(), "vps");
        assert_eq!(ResourceType::Byovps.as_str(), "byovps");
        assert_eq!(ResourceType::User.as_str(), "user");
    }

    #[test]
    fn test_audit_entry_builder() {
        let entry = AuditLogEntry::new(AuditAction::VpsProvision, ResourceType::Vps)
            .user_id(Uuid::nil())
            .ip_address("127.0.0.1")
            .response_status(200);

        assert_eq!(entry.user_id, Some(Uuid::nil()));
        assert_eq!(entry.ip_address, Some("127.0.0.1".to_string()));
        assert_eq!(entry.response_status, Some(200));
    }
}
