//! User VPS model - represents a VPS instance provisioned for a user.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// VPS provisioning status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VpsStatus {
    /// Initial state, payment processing
    Pending,
    /// VPS being created on the provider
    Provisioning,
    /// VM running, waiting for Conductor to register
    Registering,
    /// Post-install script running, Conductor registered but health check not passing
    Configuring,
    /// Fully operational
    Ready,
    /// Provisioning failed
    Failed,
    /// VPS powered off (grace period)
    Stopped,
    /// VPS deleted
    Terminated,
}

impl VpsStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VpsStatus::Pending => "pending",
            VpsStatus::Provisioning => "provisioning",
            VpsStatus::Registering => "registering",
            VpsStatus::Configuring => "configuring",
            VpsStatus::Ready => "ready",
            VpsStatus::Failed => "failed",
            VpsStatus::Stopped => "stopped",
            VpsStatus::Terminated => "terminated",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "pending" => VpsStatus::Pending,
            "provisioning" => VpsStatus::Provisioning,
            "registering" => VpsStatus::Registering,
            "configuring" => VpsStatus::Configuring,
            "ready" => VpsStatus::Ready,
            "failed" => VpsStatus::Failed,
            "stopped" => VpsStatus::Stopped,
            "terminated" => VpsStatus::Terminated,
            _ => VpsStatus::Pending,
        }
    }
}

/// VPS provider
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VpsProvider {
    Hostinger,
    Contabo,
}

impl VpsProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            VpsProvider::Hostinger => "hostinger",
            VpsProvider::Contabo => "contabo",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "hostinger" => VpsProvider::Hostinger,
            "contabo" => VpsProvider::Contabo,
            _ => VpsProvider::Hostinger,
        }
    }
}

/// User VPS instance from database
#[derive(Debug, Clone, FromRow)]
pub struct UserVps {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_instance_id: Option<i64>,
    pub provider_order_id: Option<String>,
    pub plan_id: String,
    pub template_id: i32,
    pub data_center_id: i32,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub status: String,
    pub ssh_username: String,
    pub ssh_password_hash: String,
    pub jwt_secret: String,
    pub dns_record_id: Option<String>,
    pub device_type: String,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub registration_code_hash: Option<String>,
    pub registration_expires_at: Option<DateTime<Utc>>,
    pub vps_secret_hash: Option<String>,
    pub registered_at: Option<DateTime<Utc>>,
    pub conductor_verified_at: Option<DateTime<Utc>>,
}

impl UserVps {
    pub fn status_enum(&self) -> VpsStatus {
        VpsStatus::from_str(&self.status)
    }

    pub fn provider_enum(&self) -> VpsProvider {
        VpsProvider::from_str(&self.provider)
    }

    pub fn is_ready(&self) -> bool {
        self.status == "ready"
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.status.as_str(),
            "pending" | "provisioning" | "registering" | "configuring" | "ready"
        )
    }

    pub fn has_dns_record(&self) -> bool {
        self.dns_record_id.is_some()
    }
}

/// Request to provision a new VPS
#[derive(Debug, Deserialize)]
pub struct ProvisionVpsRequest {
    /// SSH password for mobile access (min 12 chars)
    pub ssh_password: String,
    /// Optional: Override default plan
    pub plan_id: Option<String>,
    /// Optional: Override default data center
    pub data_center_id: Option<i32>,
}

/// Response for VPS status
#[derive(Debug, Serialize)]
pub struct VpsStatusResponse {
    pub id: Uuid,
    pub hostname: String,
    pub status: String,
    pub ip_address: Option<String>,
    pub ssh_username: String,
    pub provider: String,
    pub plan_id: String,
    pub data_center_id: i32,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    /// Conductor status: "pending" | "registered" | "healthy"
    pub conductor_status: Option<String>,
}

impl From<UserVps> for VpsStatusResponse {
    fn from(vps: UserVps) -> Self {
        // Determine conductor status based on VPS state
        let conductor_status = if vps.conductor_verified_at.is_some() {
            Some("healthy".to_string())
        } else if vps.registered_at.is_some() {
            Some("registered".to_string())
        } else if matches!(
            vps.status.as_str(),
            "registering" | "configuring" | "ready"
        ) {
            Some("pending".to_string())
        } else {
            None
        };

        Self {
            id: vps.id,
            hostname: vps.hostname,
            status: vps.status,
            ip_address: vps.ip_address,
            ssh_username: vps.ssh_username,
            provider: vps.provider,
            plan_id: vps.plan_id,
            data_center_id: vps.data_center_id,
            created_at: vps.created_at,
            ready_at: vps.ready_at,
            conductor_status,
        }
    }
}

/// VPS plan info for listing available plans
#[derive(Debug, Serialize)]
pub struct VpsPlan {
    pub id: String,
    pub name: String,
    pub vcpu: i32,
    pub ram_gb: i32,
    pub disk_gb: i32,
    pub bandwidth_tb: i32,
    pub monthly_price_cents: i64,
    pub first_month_price_cents: i64,
    /// Stripe price ID for subscription checkout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripe_price_id: Option<String>,
}

/// Data center info
#[derive(Debug, Serialize)]
pub struct VpsDataCenter {
    pub id: i32,
    pub name: String,
    pub city: String,
    pub country: String,
    pub continent: String,
}

/// Pre-check status response for CLI setup flow (Step 1: PRE-CHECK)
///
/// This is a simplified response specifically for the CLI to determine
/// if the user has a VPS and whether to skip to CREDS-SYNC or start provisioning.
#[derive(Debug, Serialize)]
pub struct VpsPrecheckResponse {
    /// Whether the user has a VPS provisioned
    pub has_vps: bool,
    /// VPS ID if exists
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vps_id: Option<Uuid>,
    /// VPS URL (hostname) if exists and ready for connections
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vps_url: Option<String>,
    /// Whether the conductor health check passes (null if no VPS or not applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthy: Option<bool>,
    /// Simplified status: "provisioning" | "ready" | "stopped" | "error" | null
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<VpsPrecheckStatus>,
}

/// Simplified VPS status for pre-check
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VpsPrecheckStatus {
    /// VPS is being provisioned, installed, registered, or configured
    Provisioning,
    /// VPS is fully ready and healthy
    Ready,
    /// VPS is stopped
    Stopped,
    /// VPS provisioning failed or is in an error state
    Error,
}

impl VpsPrecheckStatus {
    /// Convert from database status string to pre-check status
    pub fn from_db_status(status: &str) -> Self {
        match status {
            "ready" => VpsPrecheckStatus::Ready,
            "stopped" => VpsPrecheckStatus::Stopped,
            "failed" | "terminated" => VpsPrecheckStatus::Error,
            // pending, provisioning, registering, configuring all map to provisioning
            _ => VpsPrecheckStatus::Provisioning,
        }
    }
}

impl VpsPrecheckResponse {
    /// Create a response indicating no VPS exists
    pub fn no_vps() -> Self {
        Self {
            has_vps: false,
            vps_id: None,
            vps_url: None,
            healthy: None,
            status: None,
        }
    }

    /// Create a response from a UserVps record
    pub fn from_vps(vps: &UserVps, healthy: Option<bool>) -> Self {
        let status = VpsPrecheckStatus::from_db_status(&vps.status);

        // Only provide vps_url if the VPS is ready or at least registered
        let vps_url = if vps.status == "ready" || vps.registered_at.is_some() {
            Some(format!("https://{}", vps.hostname))
        } else {
            None
        };

        Self {
            has_vps: true,
            vps_id: Some(vps.id),
            vps_url,
            healthy,
            status: Some(status),
        }
    }
}

/// Response for VPS provision endpoint when VPS creation is initiated
///
/// This response is returned when provisioning starts successfully.
/// The CLI uses this data for health polling and later confirmation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionPendingResponse {
    /// VPS hostname (e.g., "username.spoq.dev")
    pub hostname: String,
    /// IP address if immediately available, otherwise None
    pub ip_address: Option<String>,
    /// Provider-specific instance ID (Hostinger VM ID)
    pub provider_instance_id: i64,
    /// Provider-specific order ID if applicable (Hostinger subscription ID)
    pub provider_order_id: Option<String>,
    /// Plan ID (e.g., "hostingercom-vps-kvm1-usd-1m")
    pub plan_id: String,
    /// Template ID used for provisioning (e.g., 1007 for Ubuntu 22.04)
    pub template_id: i32,
    /// Data center ID where VPS is provisioned (e.g., 9 for Phoenix)
    pub data_center_id: i32,
    /// JWT secret for conductor authentication
    pub jwt_secret: String,
    /// SSH password for server access (plaintext)
    pub ssh_password: String,
    /// Status message for the user
    pub message: String,
}
