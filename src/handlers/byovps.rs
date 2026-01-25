//! BYOVPS (Bring Your Own VPS) handler for provisioning user-provided VPS instances.
//!
//! This module provides the following endpoint:
//! - `POST /api/byovps/provision` - Provision a user's own VPS with Spoq services
//!
//! Unlike the managed VPS provisioning (via Hostinger), BYOVPS allows users to connect
//! their own VPS servers. We SSH into their server and run the setup script remotely.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthenticatedUser;
use crate::services::hostinger::{generate_post_install_script, PostInstallParams};
use crate::models::UserVps;
use crate::services::cloudflare::CloudflareService;
use crate::services::ssh_installer::{SshConfig, SshInstallerService};

/// Request to provision a BYOVPS (Bring Your Own VPS)
#[derive(Debug, Deserialize)]
pub struct ProvisionByovpsRequest {
    /// IP address of the user's VPS
    pub vps_ip: String,
    /// SSH username for connecting to the VPS
    pub ssh_username: String,
    /// SSH password for connecting to the VPS
    pub ssh_password: String,
}

/// Response for BYOVPS provisioning when status is "pending"
#[derive(Debug, Serialize)]
pub struct ByovpsPendingResponse {
    /// Hostname assigned to the VPS (username.spoq.dev)
    pub hostname: String,
    /// IP address of the VPS
    pub ip_address: String,
    /// JWT secret for the VPS
    pub jwt_secret: String,
    /// SSH password for the VPS
    pub ssh_password: String,
    /// Human-readable message
    pub message: String,
}

/// Validate an IPv4 address format
fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    for part in parts {
        match part.parse::<u8>() {
            Ok(_) => continue,
            Err(_) => return false,
        }
    }

    true
}

/// Validate an IPv6 address format (basic validation)
fn is_valid_ipv6(ip: &str) -> bool {
    // Basic check: IPv6 contains colons and valid hex segments
    if !ip.contains(':') {
        return false;
    }

    // Handle compressed notation (::)
    let expanded = if ip.contains("::") {
        // Allow :: notation but don't fully expand it
        ip.to_string()
    } else {
        ip.to_string()
    };

    let parts: Vec<&str> = expanded.split(':').collect();

    // IPv6 has 8 groups (or fewer with ::)
    if parts.len() > 8 {
        return false;
    }

    for part in &parts {
        if part.is_empty() {
            // Empty parts are allowed due to :: compression
            continue;
        }
        if part.len() > 4 {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }

    true
}

/// Validate IP address (IPv4 or IPv6)
fn is_valid_ip(ip: &str) -> bool {
    is_valid_ipv4(ip) || is_valid_ipv6(ip)
}

/// Provision a BYOVPS (Bring Your Own VPS) for the authenticated user
///
/// POST /api/byovps/provision
///
/// This endpoint:
/// 1. Validates the input (IP, username, password)
/// 2. Creates a DNS A record (username.spoq.dev -> vps_ip)
/// 3. SSHs into the user's VPS
/// 4. Runs the Spoq post-install script
/// 5. Returns immediately with pending status (CLI will poll for health)
pub async fn provision_byovps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    cloudflare: Option<web::Data<CloudflareService>>,
    req: web::Json<ProvisionByovpsRequest>,
) -> AppResult<HttpResponse> {
    // Validate IP address format
    if !is_valid_ip(&req.vps_ip) {
        return Err(AppError::BadRequest(
            "Invalid VPS IP address format. Must be a valid IPv4 or IPv6 address.".to_string(),
        ));
    }

    // Validate username is not empty
    if req.ssh_username.trim().is_empty() {
        return Err(AppError::BadRequest(
            "SSH username cannot be empty".to_string(),
        ));
    }

    // Validate password is not empty
    if req.ssh_password.is_empty() {
        return Err(AppError::BadRequest(
            "SSH password cannot be empty".to_string(),
        ));
    }

    // Validate password length (for security)
    if req.ssh_password.len() < 8 {
        return Err(AppError::BadRequest(
            "SSH password must be at least 8 characters".to_string(),
        ));
    }

    // BYOVPS requires root access for proper system configuration
    if req.ssh_username != "root" {
        return Err(AppError::BadRequest(
            "BYOVPS requires SSH access as 'root' user for proper system configuration.".to_string(),
        ));
    }

    // Check if user already has an active VPS (including BYOVPS)
    let existing: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status NOT IN ('terminated', 'failed')",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    if existing.is_some() {
        return Err(AppError::BadRequest(
            "User already has an active VPS. Terminate it first before adding a new one."
                .to_string(),
        ));
    }

    // Clean up any stale failed or terminated VPS records for this user
    // This handles retries after failed provisioning attempts
    let deleted = sqlx::query(
        "DELETE FROM user_vps WHERE user_id = $1 AND status IN ('failed', 'terminated')",
    )
    .bind(user.user_id)
    .execute(pool.get_ref())
    .await?;

    if deleted.rows_affected() > 0 {
        tracing::info!(
            "Cleaned up {} stale VPS record(s) for user {}",
            deleted.rows_affected(),
            user.user_id
        );
    }

    // Get the user's username for hostname generation
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(user.user_id)
            .fetch_optional(pool.get_ref())
            .await?;

    let username = username
        .ok_or_else(|| AppError::Internal("User not found in database".to_string()))?;

    // Generate hostname: username.spoq.dev
    let hostname = format!("{}.spoq.dev", username.to_lowercase());
    let jwt_secret = config.jwt_secret.clone();

    tracing::info!(
        "BYOVPS provisioning started: hostname={}, ip={}",
        hostname,
        req.vps_ip
    );

    // Create Cloudflare Tunnel and DNS records
    let tunnel_credentials = if let Some(cf) = &cloudflare {
        let subdomain = username.to_lowercase();
        let tunnel_name = format!("spoq-{}", subdomain);

        // Create Cloudflare Tunnel
        let creds = match cf.create_tunnel(&tunnel_name).await {
            Ok(creds) => {
                tracing::info!(
                    "Cloudflare tunnel created: {} (id: {})",
                    tunnel_name,
                    creds.tunnel_id
                );

                // Create CNAME record pointing to the tunnel
                let tunnel_hostname = format!("{}.cfargotunnel.com", creds.tunnel_id);
                match cf.create_cname_record(&subdomain, &tunnel_hostname).await {
                    Ok(record) => {
                        tracing::info!(
                            "CNAME record created: {}.spoq.dev -> {} (id: {})",
                            subdomain,
                            tunnel_hostname,
                            record.id
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to create CNAME record for {}: {}",
                            hostname,
                            e
                        );
                        // Clean up the tunnel since we can't route to it
                        let _ = cf.delete_tunnel(&creds.tunnel_id).await;
                        return Err(AppError::Internal(format!(
                            "Failed to create DNS routing for tunnel: {}",
                            e
                        )));
                    }
                }

                Some(creds)
            }
            Err(e) => {
                tracing::error!("Failed to create Cloudflare tunnel: {}", e);
                return Err(AppError::Internal(format!(
                    "Failed to create Cloudflare tunnel: {}",
                    e
                )));
            }
        };

        creds
    } else {
        tracing::error!("Cloudflare not configured - cannot provision BYOVPS without tunnel");
        return Err(AppError::Internal(
            "Cloudflare tunnel configuration is required for BYOVPS".to_string(),
        ));
    };

    // Get tunnel credentials (we know it's Some at this point)
    let creds = tunnel_credentials.unwrap();

    // Generate the post-install script with tunnel configuration
    let params = PostInstallParams {
        ssh_password: &req.ssh_password,
        hostname: &hostname,
        conductor_url: "https://download.spoq.dev/conductor",
        jwt_secret: &config.jwt_secret,
        owner_id: &user.user_id.to_string(),
        tunnel_id: &creds.tunnel_id,
        tunnel_secret: &creds.tunnel_secret,
        account_id: &creds.account_tag,
    };
    let script_content = generate_post_install_script(&params);

    // SSH into the VPS and execute the script
    let ssh_config = SshConfig::new(&req.vps_ip, &req.ssh_username, &req.ssh_password)
        .with_timeout(60) // 60 seconds connection timeout
        .with_exec_timeout(600); // 10 minutes for script execution

    // Execute the install script via SSH
    let ssh_status = match SshInstallerService::connect(ssh_config) {
        Ok(ssh) => {
            tracing::info!("SSH connection established to {}", req.vps_ip);

            match ssh.execute_script(&script_content) {
                Ok(result) => {
                    tracing::info!(
                        "BYOVPS script completed on {} with exit code {}",
                        req.vps_ip,
                        result.exit_code
                    );
                    if result.exit_code == 0 {
                        "success"
                    } else {
                        "script_failed"
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to execute script on {}: {}", req.vps_ip, e);
                    "script_error"
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to SSH into {}: {}", req.vps_ip, e);
            "ssh_failed"
        }
    };

    // Build response message based on SSH result
    let message = match ssh_status {
        "success" => format!(
            "SSH script executed successfully. Conductor is starting on {}. \
             The CLI will poll https://{}/health to verify readiness.",
            req.vps_ip, hostname
        ),
        "script_failed" => format!(
            "SSH script completed with non-zero exit code on {}. \
             The CLI will poll https://{}/health to verify readiness.",
            req.vps_ip, hostname
        ),
        "script_error" => format!(
            "SSH script execution error on {}. \
             The CLI will poll https://{}/health to verify readiness.",
            req.vps_ip, hostname
        ),
        _ => format!(
            "SSH connection failed to {}. Please verify your credentials and try again.",
            req.vps_ip
        ),
    };

    tracing::info!(
        "BYOVPS provision returning immediately: hostname={}, ip={}, ssh_status={}",
        hostname,
        req.vps_ip,
        ssh_status
    );

    // Return immediately with pending status - CLI will poll for health
    let response = ByovpsPendingResponse {
        hostname,
        ip_address: req.vps_ip.clone(),
        jwt_secret,
        ssh_password: req.ssh_password.clone(),
        message,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ipv4() {
        // Valid IPv4 addresses
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("10.0.0.1"));
        assert!(is_valid_ipv4("255.255.255.255"));
        assert!(is_valid_ipv4("0.0.0.0"));
        assert!(is_valid_ipv4("1.2.3.4"));

        // Invalid IPv4 addresses
        assert!(!is_valid_ipv4(""));
        assert!(!is_valid_ipv4("192.168.1"));
        assert!(!is_valid_ipv4("192.168.1.1.1"));
        assert!(!is_valid_ipv4("256.1.1.1"));
        assert!(!is_valid_ipv4("192.168.1.abc"));
        assert!(!is_valid_ipv4("192.168.-1.1"));
        assert!(!is_valid_ipv4("::1"));
        assert!(!is_valid_ipv4("not.an.ip.address"));
    }

    #[test]
    fn test_is_valid_ipv6() {
        // Valid IPv6 addresses
        assert!(is_valid_ipv6("::1"));
        assert!(is_valid_ipv6("2001:db8::1"));
        assert!(is_valid_ipv6("fe80::1"));
        assert!(is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(is_valid_ipv6("::"));

        // Invalid IPv6 addresses
        assert!(!is_valid_ipv6("192.168.1.1"));
        assert!(!is_valid_ipv6(""));
        assert!(!is_valid_ipv6("not-an-ipv6"));
        assert!(!is_valid_ipv6("ghij:0db8:85a3:0000:0000:8a2e:0370:7334")); // Invalid hex chars
    }

    #[test]
    fn test_is_valid_ip() {
        // IPv4
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("10.0.0.1"));

        // IPv6
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));

        // Invalid
        assert!(!is_valid_ip(""));
        assert!(!is_valid_ip("invalid"));
        assert!(!is_valid_ip("192.168.1"));
    }

    #[test]
    fn test_byovps_pending_response_serialize() {
        let response = ByovpsPendingResponse {
            hostname: "testuser.spoq.dev".to_string(),
            ip_address: "192.168.1.100".to_string(),
            jwt_secret: "test-jwt-secret".to_string(),
            ssh_password: "test-password".to_string(),
            message: "VPS provisioning pending".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("testuser.spoq.dev"));
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("test-jwt-secret"));
        assert!(json.contains("VPS provisioning pending"));
    }

    #[test]
    fn test_provision_byovps_request_deserialize() {
        let json = r#"{
            "vps_ip": "192.168.1.100",
            "ssh_username": "root",
            "ssh_password": "securepassword123"
        }"#;

        let request: ProvisionByovpsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.vps_ip, "192.168.1.100");
        assert_eq!(request.ssh_username, "root");
        assert_eq!(request.ssh_password, "securepassword123");
    }
}
