//! Hostinger VPS API client.
//!
//! This module provides a client for interacting with the Hostinger VPS API
//! to provision and manage VPS instances for users.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const HOSTINGER_API_BASE: &str = "https://developers.hostinger.com";

/// Default VPS template (Ubuntu 22.04 LTS)
pub const DEFAULT_TEMPLATE_ID: i32 = 1007;

/// Default data center (Phoenix, USA)
pub const DEFAULT_DATACENTER_ID: i32 = 9;

/// Default plan (KVM 1 monthly)
pub const DEFAULT_PLAN_ID: &str = "hostingercom-vps-kvm1-usd-1m";

#[derive(Debug, Error)]
pub enum HostingerError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("API error: {message} (status: {status})")]
    Api { status: u16, message: String },

    #[error("VPS not found: {0}")]
    NotFound(String),

    #[error("Invalid response from Hostinger API")]
    InvalidResponse,
}

/// Hostinger API client
#[derive(Clone)]
pub struct HostingerClient {
    client: Client,
    api_key: String,
}

// Request types

#[derive(Debug, Serialize)]
pub struct CreateVpsRequest {
    pub item_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_id: Option<i64>,
    pub setup: VpsSetup,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coupons: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct VpsSetup {
    pub template_id: i32,
    pub data_center_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_install_script_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_backups: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
}

#[derive(Debug, Serialize)]
pub struct PublicKey {
    pub name: String,
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct CreatePostInstallScriptRequest {
    pub name: String,
    pub content: String,
}

// Response types

#[derive(Debug, Deserialize)]
pub struct CreateVpsResponse {
    pub order: Option<OrderInfo>,
    pub virtual_machine: Option<VirtualMachineInfo>,
}

#[derive(Debug, Deserialize)]
pub struct OrderInfo {
    pub id: Option<i64>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VirtualMachineInfo {
    pub id: i64,
    pub state: String,
    pub hostname: Option<String>,
    pub subscription_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VirtualMachine {
    pub id: i64,
    pub state: String,
    pub hostname: String,
    #[serde(default)]
    pub ipv4: Vec<IpAddress>,
    #[serde(default)]
    pub ipv6: Vec<IpAddress>,
    pub plan: Option<String>,
    pub template: Option<TemplateInfo>,
    pub data_center: Option<DataCenterInfo>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpAddress {
    pub id: Option<i64>,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TemplateInfo {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DataCenterInfo {
    pub id: i32,
    pub name: String,
    pub location: String,
    pub city: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostInstallScript {
    pub id: i64,
    pub name: String,
    pub content: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DataCenter {
    pub id: i32,
    pub name: String,
    pub location: String,
    pub city: String,
    pub continent: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogItem {
    pub id: String,
    pub name: String,
    pub category: String,
    pub metadata: Option<CatalogMetadata>,
    pub prices: Vec<CatalogPrice>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogMetadata {
    pub cpus: Option<String>,
    pub memory: Option<String>,
    pub bandwidth: Option<String>,
    pub disk_space: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogPrice {
    pub id: String,
    pub name: String,
    pub currency: String,
    pub price: i64,
    pub first_period_price: i64,
    pub period: i32,
    pub period_unit: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VpsAction {
    pub id: i64,
    pub name: String,
    pub state: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    message: Option<String>,
    error: Option<String>,
}

impl HostingerClient {
    /// Create a new Hostinger API client
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    /// Make a GET request to the Hostinger API
    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, HostingerError> {
        let url = format!("{}{}", HOSTINGER_API_BASE, path);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let error_body: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
                message: Some("Unknown error".to_string()),
                error: None,
            });
            return Err(HostingerError::Api {
                status,
                message: error_body
                    .message
                    .or(error_body.error)
                    .unwrap_or_else(|| "Unknown error".to_string()),
            });
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse Hostinger response: {}", e);
            HostingerError::InvalidResponse
        })
    }

    /// Make a POST request to the Hostinger API
    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, HostingerError> {
        let url = format!("{}{}", HOSTINGER_API_BASE, path);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let error_body: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
                message: Some("Unknown error".to_string()),
                error: None,
            });
            return Err(HostingerError::Api {
                status,
                message: error_body
                    .message
                    .or(error_body.error)
                    .unwrap_or_else(|| "Unknown error".to_string()),
            });
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse Hostinger response: {}", e);
            HostingerError::InvalidResponse
        })
    }

    /// Make a POST request without a response body
    async fn post_no_response<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(), HostingerError> {
        let url = format!("{}{}", HOSTINGER_API_BASE, path);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let error_body: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
                message: Some("Unknown error".to_string()),
                error: None,
            });
            return Err(HostingerError::Api {
                status,
                message: error_body
                    .message
                    .or(error_body.error)
                    .unwrap_or_else(|| "Unknown error".to_string()),
            });
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // VPS Management
    // -------------------------------------------------------------------------

    /// Create a new VPS instance
    pub async fn create_vps(&self, req: CreateVpsRequest) -> Result<CreateVpsResponse, HostingerError> {
        tracing::info!("Creating VPS with plan: {}", req.item_id);
        self.post("/api/vps/v1/virtual-machines", &req).await
    }

    /// Get a VPS instance by ID
    pub async fn get_vps(&self, vm_id: i64) -> Result<VirtualMachine, HostingerError> {
        self.get(&format!("/api/vps/v1/virtual-machines/{}", vm_id))
            .await
    }

    /// List all VPS instances
    pub async fn list_vps(&self) -> Result<Vec<VirtualMachine>, HostingerError> {
        self.get("/api/vps/v1/virtual-machines").await
    }

    /// Start a VPS instance
    pub async fn start_vps(&self, vm_id: i64) -> Result<(), HostingerError> {
        self.post_no_response(
            &format!("/api/vps/v1/virtual-machines/{}/start", vm_id),
            &serde_json::json!({}),
        )
        .await
    }

    /// Stop a VPS instance
    pub async fn stop_vps(&self, vm_id: i64) -> Result<(), HostingerError> {
        self.post_no_response(
            &format!("/api/vps/v1/virtual-machines/{}/stop", vm_id),
            &serde_json::json!({}),
        )
        .await
    }

    /// Restart a VPS instance
    pub async fn restart_vps(&self, vm_id: i64) -> Result<(), HostingerError> {
        self.post_no_response(
            &format!("/api/vps/v1/virtual-machines/{}/restart", vm_id),
            &serde_json::json!({}),
        )
        .await
    }

    /// Reset root password (safe - does NOT delete data)
    pub async fn reset_password(&self, vm_id: i64, new_password: &str) -> Result<(), HostingerError> {
        let url = format!(
            "{}/api/vps/v1/virtual-machines/{}/root-password",
            HOSTINGER_API_BASE, vm_id
        );
        let response = self
            .client
            .put(&url)
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({ "password": new_password }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_body: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
                message: Some("Unknown error".to_string()),
                error: None,
            });
            return Err(HostingerError::Api {
                status,
                message: error_body
                    .message
                    .or(error_body.error)
                    .unwrap_or_else(|| "Unknown error".to_string()),
            });
        }

        Ok(())
    }

    /// Get VPS actions (for tracking provisioning status)
    pub async fn get_vps_actions(&self, vm_id: i64) -> Result<Vec<VpsAction>, HostingerError> {
        self.get(&format!("/api/vps/v1/virtual-machines/{}/actions", vm_id))
            .await
    }

    // -------------------------------------------------------------------------
    // Post-Install Scripts
    // -------------------------------------------------------------------------

    /// Create a post-install script
    pub async fn create_post_install_script(
        &self,
        name: &str,
        content: &str,
    ) -> Result<PostInstallScript, HostingerError> {
        tracing::info!("Creating post-install script: {}", name);
        self.post(
            "/api/vps/v1/post-install-scripts",
            &CreatePostInstallScriptRequest {
                name: name.to_string(),
                content: content.to_string(),
            },
        )
        .await
    }

    /// List post-install scripts
    pub async fn list_post_install_scripts(&self) -> Result<Vec<PostInstallScript>, HostingerError> {
        self.get("/api/vps/v1/post-install-scripts").await
    }

    /// Delete a post-install script
    pub async fn delete_post_install_script(&self, script_id: i64) -> Result<(), HostingerError> {
        let url = format!(
            "{}/api/vps/v1/post-install-scripts/{}",
            HOSTINGER_API_BASE, script_id
        );
        let response = self
            .client
            .delete(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_body: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
                message: Some("Unknown error".to_string()),
                error: None,
            });
            return Err(HostingerError::Api {
                status,
                message: error_body
                    .message
                    .or(error_body.error)
                    .unwrap_or_else(|| "Unknown error".to_string()),
            });
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Catalog & Reference Data
    // -------------------------------------------------------------------------

    /// Get all available templates (OS images)
    pub async fn list_templates(&self) -> Result<Vec<Template>, HostingerError> {
        self.get("/api/vps/v1/templates").await
    }

    /// Get all available data centers
    pub async fn list_data_centers(&self) -> Result<Vec<DataCenter>, HostingerError> {
        self.get("/api/vps/v1/data-centers").await
    }

    /// Get the billing catalog (plans and pricing)
    pub async fn get_catalog(&self) -> Result<Vec<CatalogItem>, HostingerError> {
        self.get("/api/billing/v1/catalog").await
    }

    /// Get VPS plans from the catalog
    pub async fn get_vps_plans(&self) -> Result<Vec<CatalogItem>, HostingerError> {
        let catalog = self.get_catalog().await?;
        Ok(catalog
            .into_iter()
            .filter(|item| item.category == "VPS" && !item.id.contains("minecraft"))
            .collect())
    }
}

/// Generate the post-install script content for VPS provisioning
///
/// # Arguments
/// * `ssh_password` - Password for the spoq user
/// * `registration_code` - 6-character code for Conductor self-registration
/// * `api_url` - API URL for Conductor to call during registration
/// * `hostname` - The hostname for this VPS (e.g., "username.spoq.dev")
/// * `conductor_url` - URL to download the Conductor binary
pub fn generate_post_install_script(
    ssh_password: &str,
    registration_code: &str,
    api_url: &str,
    hostname: &str,
    conductor_url: &str,
) -> String {
    format!(
        r#"#!/bin/bash
# Spoq VPS Provisioning Script
# Executed automatically by Hostinger after VPS creation
# Output logged to /var/log/spoq-setup.log

set -e
exec > /var/log/spoq-setup.log 2>&1

# Variables
SSH_PASSWORD="{ssh_password}"
REGISTRATION_CODE="{registration_code}"
API_URL="{api_url}"
HOSTNAME="{hostname}"
CONDUCTOR_URL="{conductor_url}"

echo "=== Spoq VPS Provisioning ==="

# 1. System updates
apt-get update && apt-get upgrade -y

# 2. Install dependencies
apt-get install -y curl jq ca-certificates

# 3. Set system hostname
hostnamectl set-hostname "$HOSTNAME"
# Update /etc/hosts to resolve new hostname
echo "127.0.1.1 $HOSTNAME" >> /etc/hosts

# 4. Create spoq user (idempotent - only if doesn't exist)
if ! id spoq >/dev/null 2>&1; then
    useradd -m -s /bin/bash spoq
fi
echo "spoq:$SSH_PASSWORD" | chpasswd
usermod -aG sudo spoq
echo "spoq ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/spoq
chmod 440 /etc/sudoers.d/spoq

# 5. Download and install Conductor
curl -sSL "$CONDUCTOR_URL" -o /usr/local/bin/conductor
chmod +x /usr/local/bin/conductor

# 6. Write registration code (Conductor will self-register on first boot)
mkdir -p /etc/spoq
echo "$REGISTRATION_CODE" > /etc/spoq/registration
chmod 600 /etc/spoq/registration

# 7. Create minimal Conductor config (Conductor populates [auth] after registration)
mkdir -p /etc/conductor
cat > /etc/conductor/config.toml << EOF
[server]
host = "0.0.0.0"
port = 8080

[registration]
api_url = "$API_URL"
# Conductor reads /etc/spoq/registration on first boot
# and calls $API_URL/internal/conductor/register
EOF

# 8. Create VPS marker file
cat > /etc/spoq/vps.marker << EOF
{{
  "vps": true,
  "conductor": "http://localhost:8080",
  "version": "1.0"
}}
EOF

# 9. Create Conductor systemd service
cat > /etc/systemd/system/conductor.service << 'SERVICEEOF'
[Unit]
Description=Spoq Conductor - AI Backend Service
After=network.target

[Service]
Type=simple
User=spoq
Group=spoq
ExecStart=/usr/local/bin/conductor --config /etc/conductor/config.toml
Restart=always
RestartSec=5
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable conductor
systemctl start conductor

# 10. Download and install Spoq CLI
curl -fsSL https://download.spoq.dev/cli | bash

# 11. Setup welcome message
cat > /home/spoq/.bashrc << 'BASHRC'
export PATH="/usr/local/bin:$PATH"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Welcome to Spoq!                       ║"
echo "║                                                           ║"
echo "║  Commands:                                                ║"
echo "║    spoq ask \"your question\"  - Ask AI anything            ║"
echo "║    spoq run                  - Run a task                 ║"
echo "║    spoq help                 - Show all commands          ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
BASHRC
chown spoq:spoq /home/spoq/.bashrc

# 12. Configure firewall
ufw allow 22    # SSH
ufw allow 80    # HTTP (for Let's Encrypt verification)
ufw allow 443   # HTTPS
ufw --force enable

# 13. Install Caddy
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy

# 14. Configure Caddy
cat > /etc/caddy/Caddyfile << EOF
$HOSTNAME {{
    reverse_proxy localhost:8080
}}
EOF

systemctl enable caddy
systemctl restart caddy

echo "=== Provisioning Complete ==="
echo "Conductor: $(systemctl is-active conductor)"
echo "Caddy: $(systemctl is-active caddy)"
"#,
        ssh_password = ssh_password,
        registration_code = registration_code,
        api_url = api_url,
        hostname = hostname,
        conductor_url = conductor_url,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_post_install_script() {
        let script = generate_post_install_script(
            "TestPassword123!",
            "ABC123",  // registration_code
            "https://api.spoq.dev",  // api_url
            "test.spoq.dev",
            "https://spoq.dev/releases/conductor",
            "https://spoq.dev/releases/spoq-cli",
        );

        assert!(script.contains("TestPassword123!"));
        assert!(script.contains("ABC123"));  // registration code
        assert!(script.contains("https://api.spoq.dev"));  // api_url
        assert!(script.contains("test.spoq.dev"));
        assert!(script.contains("/etc/spoq/registration"));  // registration file
        assert!(script.contains("[registration]"));  // registration section in config
        assert!(script.contains("systemctl enable conductor"));
        assert!(script.contains("systemctl enable caddy"));
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_TEMPLATE_ID, 1007);
        assert_eq!(DEFAULT_DATACENTER_ID, 9);
        assert_eq!(DEFAULT_PLAN_ID, "hostingercom-vps-kvm1-usd-1m");
    }
}
