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

    /// Delete/Cancel a VPS instance
    pub async fn delete_vps(&self, vm_id: i64) -> Result<(), HostingerError> {
        let url = format!(
            "{}/api/vps/v1/virtual-machines/{}",
            HOSTINGER_API_BASE, vm_id
        );
        let response = self
            .client
            .delete(&url)
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

        Ok(())
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

/// Parameters for generating the post-install script
#[derive(Debug, Clone)]
pub struct PostInstallParams<'a> {
    /// Password for the root user
    pub ssh_password: &'a str,
    /// The hostname for this VPS (e.g., "username.spoq.dev")
    pub hostname: &'a str,
    /// URL to download the Conductor binary
    pub conductor_url: &'a str,
    /// JWT secret for Conductor authentication
    pub jwt_secret: &'a str,
    /// User UUID who owns this VPS
    pub owner_id: &'a str,
    /// Cloudflare Tunnel ID
    pub tunnel_id: &'a str,
    /// Cloudflare Tunnel token (JWT for cloudflared authentication)
    pub tunnel_token: &'a str,
}

/// Generate the post-install script content for VPS provisioning
///
/// # Arguments
/// * `params` - PostInstallParams containing all configuration values
pub fn generate_post_install_script(params: &PostInstallParams) -> String {
    let PostInstallParams {
        ssh_password,
        hostname,
        conductor_url,
        jwt_secret,
        owner_id,
        tunnel_id,
        tunnel_token,
    } = params;

    format!(
        r#"#!/bin/bash
# Spoq VPS Provisioning Script
# Executed automatically by Hostinger after VPS creation
# Output logged to /var/log/spoq-setup.log

set -e
exec > /var/log/spoq-setup.log 2>&1

# Variables
SSH_PASSWORD="{ssh_password}"
HOSTNAME="{hostname}"
CONDUCTOR_URL="{conductor_url}"
JWT_SECRET="{jwt_secret}"
OWNER_ID="{owner_id}"
TUNNEL_ID="{tunnel_id}"
TUNNEL_TOKEN="{tunnel_token}"

echo "=== Spoq VPS Provisioning ==="

# 1. System updates
apt-get update && apt-get upgrade -y

# 2. Install dependencies
apt-get install -y curl jq ca-certificates

# 2a. Install GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
apt-get update && apt-get install -y gh

# 2b. Install Node.js (required for Codex CLI)
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# 2c. Install Codex CLI via npm (stable)
echo "Installing Codex CLI via npm..."
npm install -g @openai/codex
codex --version || echo "WARNING: Codex CLI installation may have failed"

# 2d. Install Claude Code CLI via curl (stable channel)
echo "Installing Claude Code CLI (stable)..."
curl -fsSL https://claude.ai/install.sh | bash -s stable

# Add ~/.local/bin to PATH and create symlink
export PATH="/root/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> /root/.bashrc

# Create symlink for system-wide access
if [ -f "/root/.local/bin/claude" ]; then
    ln -sf /root/.local/bin/claude /usr/local/bin/claude
    echo "Claude CLI installed: $(claude --version)"
else
    echo "WARNING: Claude CLI installation may have failed"
fi

# 3. Set system hostname
hostnamectl set-hostname "$HOSTNAME"
# Update /etc/hosts to resolve new hostname
echo "127.0.1.1 $HOSTNAME" >> /etc/hosts

# 4. Set root password for SSH access
echo "root:$SSH_PASSWORD" | chpasswd

# 6. Download and install Conductor (auto-detects platform: x86_64 or aarch64)
echo "Preparing for Conductor installation..."

# Stop any running conductor service from previous attempts
if systemctl is-active --quiet conductor; then
    echo "Stopping existing conductor service..."
    systemctl stop conductor || true
fi

# Clean up any existing installation to ensure fresh install
if [ -d "/opt/spoq" ]; then
    echo "Removing existing /opt/spoq directory for clean install..."
    rm -rf /opt/spoq
fi

# Create directory with root ownership
echo "Creating /opt/spoq/bin directory..."
mkdir -p /opt/spoq/bin

echo "Checking disk space..."
df -h /opt

echo "Downloading conductor install script..."
if ! curl -fsSL "$CONDUCTOR_URL" | bash; then
    echo "ERROR: Conductor installation failed"
    echo "Disk space:"
    df -h
    echo "Directory permissions:"
    ls -la /opt/spoq/ || echo "/opt/spoq does not exist"
    exit 1
fi

# Set ownership to root after successful installation
echo "Setting root ownership..."
chown -R root:root /opt/spoq

# 7. Create directories
mkdir -p /etc/spoq
chown -R root:root /etc/spoq

# 8. Create Conductor config with auth (no registration needed)
mkdir -p /etc/conductor
cat > /etc/conductor/config.toml << EOF
[server]
host = "0.0.0.0"
port = 8080

[auth]
jwt_secret = "$JWT_SECRET"
owner_id = "$OWNER_ID"
EOF
chmod 600 /etc/conductor/config.toml
chown -R root:root /etc/conductor

# 9. Create VPS marker file
cat > /etc/spoq/vps.marker << EOF
{{
  "vps": true,
  "conductor": "http://localhost:8080",
  "version": "1.0"
}}
EOF

# 10. Create Conductor systemd service
cat > /etc/systemd/system/conductor.service << SERVICEEOF
[Unit]
Description=Spoq Conductor - AI Backend Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/spoq
ExecStart=/opt/spoq/bin/conductor
Restart=always
RestartSec=5
Environment="RUST_LOG=info"
Environment="CONDUCTOR_AUTH__JWT_SECRET=$JWT_SECRET"
Environment="CONDUCTOR_AUTH__OWNER_ID=$OWNER_ID"
Environment="PATH=/usr/local/bin:/usr/bin:/bin"

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable conductor
systemctl start conductor

# 11. Download and install Spoq CLI
curl -fsSL https://download.spoq.dev/cli | bash

# 12. Setup welcome message (only for interactive sessions to not break SCP)
cat > /root/.bashrc << 'BASHRC'
export PATH="/root/.local/bin:/usr/local/bin:$PATH"

# Only show banner for interactive sessions
if [[ $- == *i* ]]; then
    echo ""
    echo "  · spoq vps ·"
    echo ""
fi
BASHRC

# 13. Configure firewall (SSH only - cloudflared tunnel is outbound-only)
ufw allow 22    # SSH
ufw --force enable

# 14. Install cloudflared
echo "Installing cloudflared..."
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb -o /tmp/cloudflared.deb
else
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cloudflared.deb
fi
dpkg -i /tmp/cloudflared.deb
rm /tmp/cloudflared.deb

# 15. Configure cloudflared with token-based auth
mkdir -p /etc/cloudflared

# Store tunnel token securely
echo "$TUNNEL_TOKEN" > /etc/cloudflared/tunnel-token
chmod 600 /etc/cloudflared/tunnel-token

# Create config with ingress rules
cat > /etc/cloudflared/config.yml << CFCONFIG
ingress:
  - hostname: $HOSTNAME
    service: http://localhost:8080
  - service: http_status:404
CFCONFIG
chmod 600 /etc/cloudflared/config.yml

# 16. Create cloudflared systemd service with token auth
cat > /etc/systemd/system/cloudflared.service << CLOUDFLAREDSERVICE
[Unit]
Description=cloudflared tunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run --token $TUNNEL_TOKEN
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
CLOUDFLAREDSERVICE

# 17. Start cloudflared service
systemctl daemon-reload
systemctl enable cloudflared
systemctl start cloudflared

# Wait a few seconds for services to fully start
sleep 5

echo "=== Provisioning Complete ==="
echo "Conductor: $(systemctl is-active conductor)"
echo "Cloudflared: $(systemctl is-active cloudflared)"

# If Conductor isn't active, show the error and exit with failure
if [ "$(systemctl is-active conductor)" != "active" ]; then
    echo ""
    echo "=== Conductor Error Log ==="
    journalctl -u conductor -n 20 --no-pager || echo "Could not retrieve logs"
    exit 1
fi

# If cloudflared isn't active, show the error and exit with failure
if [ "$(systemctl is-active cloudflared)" != "active" ]; then
    echo ""
    echo "=== Cloudflared Error Log ==="
    journalctl -u cloudflared -n 20 --no-pager || echo "Could not retrieve logs"
    exit 1
fi

# Explicitly exit with success code
exit 0
"#,
        ssh_password = ssh_password,
        hostname = hostname,
        conductor_url = conductor_url,
        jwt_secret = jwt_secret,
        owner_id = owner_id,
        tunnel_id = tunnel_id,
        tunnel_token = tunnel_token,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_post_install_script() {
        let params = PostInstallParams {
            ssh_password: "TestPassword123!",
            hostname: "test.spoq.dev",
            conductor_url: "https://spoq.dev/releases/conductor",
            jwt_secret: "test-jwt-secret-at-least-32-characters-long",
            owner_id: "owner-123",
            tunnel_id: "test-tunnel-id-123",
            tunnel_token: "eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwiLCJzIjoic2VjcmV0In0=",
        };
        let script = generate_post_install_script(&params);

        // Basic parameters
        assert!(script.contains("TestPassword123!"));
        assert!(script.contains("test.spoq.dev"));
        assert!(script.contains("[auth]"));  // auth section in config
        assert!(script.contains("jwt_secret"));
        assert!(script.contains("owner_id"));
        assert!(script.contains("systemctl enable conductor"));

        // Cloudflared installation
        assert!(script.contains("cloudflared-linux-amd64.deb"));
        assert!(script.contains("dpkg -i /tmp/cloudflared.deb"));

        // Token-based tunnel auth
        assert!(script.contains("test-tunnel-id-123"));
        assert!(script.contains("tunnel-token"));
        assert!(script.contains("--token"));

        // Cloudflared config
        assert!(script.contains("/etc/cloudflared/config.yml"));
        assert!(script.contains("hostname: $HOSTNAME"));
        assert!(script.contains("service: http://localhost:8080"));
        assert!(script.contains("http_status:404"));

        // Cloudflared service (custom, not cloudflared service install)
        assert!(script.contains("systemctl enable cloudflared"));
        assert!(script.contains("systemctl start cloudflared"));

        // Should NOT contain Caddy
        assert!(!script.contains("caddy"));
        assert!(!script.contains("Caddyfile"));

        // Firewall should only allow SSH (no 80/443 for tunnel)
        assert!(script.contains("ufw allow 22"));
        assert!(!script.contains("ufw allow 80"));
        assert!(!script.contains("ufw allow 443"));
    }

    #[test]
    fn test_generate_post_install_script_tunnel_token_format() {
        let params = PostInstallParams {
            ssh_password: "pass",
            hostname: "user.spoq.dev",
            conductor_url: "https://example.com",
            jwt_secret: "secret",
            owner_id: "owner",
            tunnel_id: "abc-123-def",
            tunnel_token: "eyJ0ZXN0IjoidG9rZW4ifQ==",
        };
        let script = generate_post_install_script(&params);

        // Verify token-based auth (no credentials file)
        assert!(script.contains("tunnel run --token"));
        assert!(script.contains("tunnel-token"));
        assert!(!script.contains("credentials-file"));

        // Verify ingress config structure
        assert!(script.contains("ingress:"));
        assert!(script.contains("- hostname: $HOSTNAME"));
        assert!(script.contains("service: http://localhost:8080"));
        assert!(script.contains("- service: http_status:404"));
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_TEMPLATE_ID, 1007);
        assert_eq!(DEFAULT_DATACENTER_ID, 9);
        assert_eq!(DEFAULT_PLAN_ID, "hostingercom-vps-kvm1-usd-1m");
    }
}
