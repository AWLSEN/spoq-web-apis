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
/// Note: SSH password is set by Hostinger API, not needed in script
pub fn generate_post_install_script(
    owner_id: &str,
    jwt_secret: &str,
    hostname: &str,
) -> String {
    format!(
        r#"#!/bin/bash
# Spoq VPS Provisioning Script
# Executed automatically by Hostinger after VPS creation
# Log: /var/log/spoq-setup.log

set -e
exec > /var/log/spoq-setup.log 2>&1

# Variables injected during provisioning
OWNER_ID="{owner_id}"
JWT_SECRET="{jwt_secret}"
HOSTNAME="{hostname}"

echo "=== Spoq VPS Provisioning ==="
echo "Date: $(date)"
echo "Hostname: $HOSTNAME"
echo "Owner ID: $OWNER_ID"

# 1. System updates
echo "[1/10] Updating system..."
apt-get update && apt-get upgrade -y

# 2. Install dependencies
echo "[2/10] Installing dependencies..."
apt-get install -y curl jq ca-certificates debian-keyring debian-archive-keyring apt-transport-https

# 3. Configure firewall
echo "[3/10] Configuring firewall..."
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP (Let's Encrypt)
ufw allow 443/tcp  # HTTPS
ufw allow 8080/tcp # Conductor direct (for testing)
ufw --force enable

# 4. Install Caddy
echo "[4/10] Installing Caddy..."
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy

# 5. Configure Caddy
echo "[5/10] Configuring Caddy..."
cat > /etc/caddy/Caddyfile << EOF
$HOSTNAME {{
    reverse_proxy localhost:8080
}}
EOF
systemctl enable caddy
systemctl restart caddy || true  # May fail if DNS not ready

# 6. Create Conductor systemd service (env vars for config)
echo "[6/10] Setting up Conductor service..."
cat > /etc/systemd/system/conductor.service << SERVICEEOF
[Unit]
Description=Spoq Conductor - AI Backend Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/conductor
Restart=always
RestartSec=5
Environment="RUST_LOG=info"
Environment="CONDUCTOR_AUTH__JWT_SECRET=$JWT_SECRET"
Environment="CONDUCTOR_AUTH__OWNER_ID=$OWNER_ID"

[Install]
WantedBy=multi-user.target
SERVICEEOF
systemctl daemon-reload
systemctl enable conductor

# 7. Download and install Conductor
echo "[7/10] Installing Conductor..."
curl -fsSL https://download.spoq.dev/conductor | bash
systemctl start conductor

# 8. Download and install Spoq CLI
echo "[8/10] Installing Spoq CLI..."
curl -fsSL https://download.spoq.dev/cli | bash

# 9. Create VPS marker file
echo "[9/10] Creating VPS marker..."
mkdir -p /etc/spoq
cat > /etc/spoq/vps.marker << EOF
{{
  "vps": true,
  "conductor": "http://localhost:8080",
  "hostname": "$HOSTNAME",
  "version": "1.0"
}}
EOF

# 10. Setup welcome message
echo "[10/10] Setting up welcome message..."
cat >> /root/.bashrc << 'BASHRC'

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Welcome to Spoq!                       ║"
echo "║                                                           ║"
echo "║  Your VPS: HOSTNAME_PLACEHOLDER                           ║"
echo "║                                                           ║"
echo "║  Services:                                                ║"
echo "║    Conductor: systemctl status conductor                  ║"
echo "║    Caddy:     systemctl status caddy                      ║"
echo "║                                                           ║"
echo "║  Logs:                                                    ║"
echo "║    Setup:     cat /var/log/spoq-setup.log                 ║"
echo "║    Conductor: journalctl -u conductor -f                  ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
BASHRC
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/" /root/.bashrc

echo "=== Spoq VPS Provisioning Complete ==="
echo "Finished: $(date)"
echo "Caddy: $(systemctl is-active caddy || echo 'waiting for DNS')"
echo "Conductor: enabled (waiting for binary)"
"#,
        owner_id = owner_id,
        jwt_secret = jwt_secret,
        hostname = hostname,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_post_install_script() {
        let script = generate_post_install_script(
            "user-uuid-123",
            "jwt-secret-456",
            "test.spoq.dev",
        );

        assert!(script.contains("user-uuid-123"));
        assert!(script.contains("jwt-secret-456"));
        assert!(script.contains("test.spoq.dev"));
        assert!(script.contains("CONDUCTOR_AUTH__JWT_SECRET"));
        assert!(script.contains("CONDUCTOR_AUTH__OWNER_ID"));
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
