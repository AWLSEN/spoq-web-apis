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
    /// Post-install script running
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
            "pending" | "provisioning" | "configuring" | "ready"
        )
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
}

impl From<UserVps> for VpsStatusResponse {
    fn from(vps: UserVps) -> Self {
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
