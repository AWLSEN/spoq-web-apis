//! BYOVPS (Bring Your Own VPS) handler for provisioning user-provided VPS instances.
//!
//! This module provides the following endpoint:
//! - `POST /api/byovps/provision` - Provision a user's own VPS with Spoq services
//!
//! Unlike the managed VPS provisioning (via Hostinger), BYOVPS allows users to connect
//! their own VPS servers. We SSH into their server and run the setup script remotely.

use actix_web::{web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthenticatedUser;
use crate::services::hostinger::generate_post_install_script;
use crate::services::registration;
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

/// JWT credentials for the VPS
#[derive(Debug, Serialize)]
pub struct JwtCredentials {
    /// JWT token for the VPS to authenticate with central server
    pub jwt_token: String,
    /// Token expiration timestamp
    pub expires_at: String,
}

/// Install script status and output
#[derive(Debug, Serialize)]
pub struct InstallScript {
    /// Status: "success" or "failed"
    pub status: String,
    /// Output from the script (stdout/stderr, truncated)
    pub output: Option<String>,
}

/// Response for BYOVPS provisioning
#[derive(Debug, Serialize)]
pub struct ProvisionByovpsResponse {
    /// Internal VPS record ID
    pub id: Uuid,
    /// Hostname assigned to the VPS (username.spoq.dev)
    pub hostname: String,
    /// Current status of the provisioning
    pub status: String,
    /// Human-readable message
    pub message: String,
    /// JWT credentials for VPS authentication
    pub credentials: JwtCredentials,
    /// Install script execution details
    pub install_script: InstallScript,
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
/// 5. Saves the VPS record to the database
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

    // Hash the SSH password for storage
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let ssh_password_hash = argon2
        .hash_password(req.ssh_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?
        .to_string();

    // Create VPS record in pending state
    let vps_id = Uuid::new_v4();
    let jwt_secret = config.jwt_secret.clone();

    sqlx::query(
        r#"
        INSERT INTO user_vps (
            id, user_id, provider, plan_id, template_id, data_center_id,
            hostname, ip_address, status, ssh_username, ssh_password_hash,
            jwt_secret, device_type
        ) VALUES ($1, $2, 'byovps', 'user-provided', 0, 0, $3, $4, 'provisioning', $5, $6, $7, 'byovps')
        "#,
    )
    .bind(vps_id)
    .bind(user.user_id)
    .bind(&hostname)
    .bind(&req.vps_ip)
    .bind(&req.ssh_username)
    .bind(&ssh_password_hash)
    .bind(&jwt_secret)
    .execute(pool.get_ref())
    .await?;

    tracing::info!(
        "BYOVPS provisioning started: id={}, hostname={}, ip={}",
        vps_id,
        hostname,
        req.vps_ip
    );

    // Create DNS A record if Cloudflare is configured
    if let Some(cf) = &cloudflare {
        let subdomain = username.to_lowercase();
        match cf.update_dns_record(&subdomain, &req.vps_ip).await {
            Ok(record) => {
                tracing::info!(
                    "DNS record created/updated: {}.spoq.dev -> {} (id: {})",
                    subdomain,
                    req.vps_ip,
                    record.id
                );

                // Update VPS with DNS record ID
                sqlx::query("UPDATE user_vps SET dns_record_id = $1 WHERE id = $2")
                    .bind(&record.id)
                    .bind(vps_id)
                    .execute(pool.get_ref())
                    .await?;
            }
            Err(e) => {
                tracing::error!("Failed to create DNS record for {}: {}", hostname, e);
                // Continue anyway - DNS is not critical for BYOVPS
            }
        }
    } else {
        tracing::warn!(
            "Cloudflare not configured - skipping DNS record creation for {}",
            hostname
        );
    }

    // Generate registration code for Conductor self-registration
    let registration_code = registration::generate_registration_code();
    let registration_code_hash = registration::hash_code(&registration_code)
        .map_err(|e| AppError::Internal(format!("Failed to hash registration code: {}", e)))?;
    let registration_expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);

    // Update VPS record with registration info
    sqlx::query(
        r#"UPDATE user_vps
           SET registration_code_hash = $1,
               registration_expires_at = $2
           WHERE id = $3"#,
    )
    .bind(&registration_code_hash)
    .bind(registration_expires_at)
    .bind(vps_id)
    .execute(pool.get_ref())
    .await?;

    // Generate the post-install script
    let script_content = generate_post_install_script(
        &req.ssh_password,
        &registration_code,
        "https://spoq-api-production.up.railway.app",
        &hostname,
        "https://download.spoq.dev/conductor",
        &config.jwt_secret,
        &user.user_id.to_string(),
    );

    // SSH into the VPS and execute the script
    let ssh_config = SshConfig::new(&req.vps_ip, &req.ssh_username, &req.ssh_password)
        .with_timeout(60) // 60 seconds connection timeout
        .with_exec_timeout(600); // 10 minutes for script execution

    let (script_success, script_output, final_status) = match SshInstallerService::connect(ssh_config) {
        Ok(ssh) => {
            tracing::info!("SSH connection established to {}", req.vps_ip);

            match ssh.execute_script(&script_content) {
                Ok(result) => {
                    let success = result.is_success();
                    let mut output = if !result.stdout.is_empty() {
                        // Truncate output to last 2000 chars for response
                        let stdout = &result.stdout;
                        if stdout.len() > 2000 {
                            Some(format!("...{}", &stdout[stdout.len() - 2000..]))
                        } else {
                            Some(stdout.clone())
                        }
                    } else if !result.stderr.is_empty() {
                        Some(result.stderr.clone())
                    } else {
                        None
                    };

                    // If output is empty or script failed, try to read the log file
                    if !success || output.is_none() {
                        tracing::info!("Attempting to read /var/log/spoq-setup.log from {}", req.vps_ip);
                        match ssh.execute_command("tail -100 /var/log/spoq-setup.log 2>/dev/null || echo 'Log file not found'") {
                            Ok(log_result) if !log_result.stdout.is_empty() => {
                                let log_output = log_result.stdout.trim();
                                if !log_output.is_empty() && log_output != "Log file not found" {
                                    output = Some(format!(
                                        "Script exit code: {}\n\n=== Last 100 lines of /var/log/spoq-setup.log ===\n{}",
                                        result.exit_code,
                                        log_output
                                    ));
                                    tracing::info!("Successfully retrieved setup log from {}", req.vps_ip);
                                } else if output.is_none() {
                                    output = Some(format!("Script failed with exit code {} (no output captured)", result.exit_code));
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to read log file from {}: {}", req.vps_ip, e);
                                if output.is_none() {
                                    output = Some(format!("Script failed with exit code {} (log file inaccessible)", result.exit_code));
                                }
                            }
                            _ => {
                                if output.is_none() {
                                    output = Some(format!("Script failed with exit code {} (no log output)", result.exit_code));
                                }
                            }
                        }
                    }

                    if success {
                        tracing::info!(
                            "BYOVPS script executed successfully on {}",
                            req.vps_ip
                        );
                        (true, output, "ready")
                    } else {
                        tracing::error!(
                            "BYOVPS script failed on {} with exit code {}",
                            req.vps_ip,
                            result.exit_code
                        );
                        (false, output, "failed")
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to execute script on {}: {}", req.vps_ip, e);
                    (false, Some(format!("Script execution error: {}", e)), "failed")
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to SSH into {}: {}", req.vps_ip, e);
            (
                false,
                Some(format!("SSH connection failed: {}", e)),
                "failed",
            )
        }
    };

    // Update VPS status based on script result
    let now = chrono::Utc::now();
    if final_status == "ready" {
        sqlx::query(
            "UPDATE user_vps SET status = $1, ready_at = $2, updated_at = $2 WHERE id = $3",
        )
        .bind(final_status)
        .bind(now)
        .bind(vps_id)
        .execute(pool.get_ref())
        .await?;
    } else {
        // If provisioning failed, DELETE the record instead of saving "failed" status
        // This allows users to retry without being blocked by a stale failed record
        tracing::info!(
            "Deleting failed BYOVPS record {} for user {} (will allow retry)",
            vps_id,
            user.user_id
        );
        sqlx::query("DELETE FROM user_vps WHERE id = $1")
            .bind(vps_id)
            .execute(pool.get_ref())
            .await?;
    }

    // Generate JWT token for the VPS (valid for 10 years)
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::{Deserialize as JwtDeserialize, Serialize as JwtSerialize};

    #[derive(Debug, JwtSerialize, JwtDeserialize)]
    struct Claims {
        sub: String,  // VPS ID
        owner_id: String,  // User ID
        hostname: String,
        exp: usize,
    }

    let now = chrono::Utc::now().timestamp() as usize;
    let expiry = now + (10 * 365 * 24 * 60 * 60); // 10 years

    let claims = Claims {
        sub: vps_id.to_string(),
        owner_id: user.user_id.to_string(),
        hostname: hostname.clone(),
        exp: expiry,
    };

    let jwt_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to generate JWT: {}", e)))?;

    let expires_at = chrono::DateTime::from_timestamp(expiry as i64, 0)
        .unwrap_or_else(|| chrono::Utc::now())
        .to_rfc3339();

    // Build the response message
    let message = if script_success {
        format!(
            "BYOVPS provisioned successfully. Your VPS is accessible at {}",
            hostname
        )
    } else {
        "BYOVPS provisioning failed. Check the script output for details.".to_string()
    };

    let response = ProvisionByovpsResponse {
        id: vps_id,
        hostname,
        status: final_status.to_string(),
        message,
        credentials: JwtCredentials {
            jwt_token,
            expires_at,
        },
        install_script: InstallScript {
            status: if script_success { "success".to_string() } else { "failed".to_string() },
            output: script_output,
        },
    };

    // Always return 200 OK - the install_script.status indicates success/failure
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

    #[test]
    fn test_provision_byovps_response_serialize() {
        let response = ProvisionByovpsResponse {
            id: Uuid::nil(),
            hostname: "testuser.spoq.dev".to_string(),
            status: "ready".to_string(),
            message: "BYOVPS provisioned successfully".to_string(),
            credentials: JwtCredentials {
                jwt_token: "test.jwt.token".to_string(),
                expires_at: "2024-12-31T23:59:59Z".to_string(),
            },
            install_script: InstallScript {
                status: "success".to_string(),
                output: Some("Setup complete".to_string()),
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("testuser.spoq.dev"));
        assert!(json.contains("ready"));
        assert!(json.contains("success"));
    }

    #[test]
    fn test_provision_byovps_response_without_output() {
        let response = ProvisionByovpsResponse {
            id: Uuid::new_v4(),
            hostname: "user.spoq.dev".to_string(),
            status: "failed".to_string(),
            message: "SSH connection failed".to_string(),
            credentials: JwtCredentials {
                jwt_token: "test.jwt.token".to_string(),
                expires_at: "2024-12-31T23:59:59Z".to_string(),
            },
            install_script: InstallScript {
                status: "failed".to_string(),
                output: None,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("failed"));
        assert!(json.contains("\"status\":\"failed\""));
    }
}
