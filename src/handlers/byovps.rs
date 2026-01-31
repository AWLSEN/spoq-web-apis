//! BYOVPS (Bring Your Own VPS) handler for provisioning user-provided VPS instances.
//!
//! This module provides the following endpoints:
//! - `POST /api/byovps/provision` - Provision a user's own VPS with Spoq services
//! - `POST /api/byovps/replace` - Replace existing VPS (async, returns operation ID)
//! - `GET /api/byovps/operations/{id}` - Get operation status
//!
//! Unlike the managed VPS provisioning (via Hostinger), BYOVPS allows users to connect
//! their own VPS servers. We SSH into their server and run the setup script remotely.
//!
//! The replace endpoint uses async provisioning to avoid Cloudflare timeouts:
//! 1. Validates input and creates Cloudflare tunnel (fast, ~5s)
//! 2. Returns operation ID immediately
//! 3. SSH script execution runs in background
//! 4. Background worker auto-confirms VPS when healthy

use actix_web::{web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::middleware::audit::RequestContext;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::UserVps;
use crate::services::audit::{AuditAction, AuditLogEntry, AuditService, ResourceType};
use crate::services::cloudflare::CloudflareService;
use crate::services::hostinger::{generate_post_install_script, PostInstallParams};
use crate::services::operations::{OperationResult, OperationStatus, OperationStore};
use crate::services::ssh_installer::{SshConfig, SshInstallerService};

/// Request to provision a BYOVPS (Bring Your Own VPS)
#[derive(Debug, Deserialize, Serialize)]
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

/// Response for async BYOVPS operations (replace)
#[derive(Debug, Serialize)]
pub struct ByovpsAsyncResponse {
    /// Operation ID for polling status
    pub operation_id: Uuid,
    /// Hostname that will be assigned (username.spoq.dev)
    pub hostname: String,
    /// IP address of the VPS
    pub ip_address: String,
    /// Human-readable message
    pub message: String,
}

/// Parameters for background provisioning worker
#[derive(Clone)]
struct ProvisioningParams {
    operation_id: Uuid,
    user_id: Uuid,
    vps_ip: String,
    ssh_username: String,
    ssh_password: String,
    hostname: String,
    jwt_secret: String,
    tunnel_id: String,
    tunnel_token: String,
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

    // Health check at the IP directly (not hostname, which may still point to an old VPS via tunnel).
    // Use direct HTTP to port 8000 since the machine won't have a TLS cert yet.
    let health_url = format!("http://{}:8000/health", req.vps_ip);
    tracing::info!("Checking if VPS is already healthy at {}", health_url);

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    if let Ok(response) = http_client.get(&health_url).send().await {
        if response.status().is_success() {
            tracing::info!(
                "VPS already healthy at {} - skipping provisioning",
                health_url
            );

            // Return success so CLI can call /api/vps/confirm
            let response = ByovpsPendingResponse {
                hostname,
                ip_address: req.vps_ip.clone(),
                jwt_secret,
                ssh_password: req.ssh_password.clone(),
                message: "VPS is already healthy. Confirming setup.".to_string(),
            };

            return Ok(HttpResponse::Ok().json(response));
        }
    }

    tracing::info!(
        "BYOVPS provisioning started: hostname={}, ip={}",
        hostname,
        req.vps_ip
    );

    // Get or create Cloudflare Tunnel and DNS records
    let tunnel_credentials = if let Some(cf) = &cloudflare {
        let subdomain = username.to_lowercase();
        let tunnel_name = format!("spoq-{}", subdomain);

        // Get existing tunnel or create new one
        let creds = match cf.get_or_create_tunnel(&tunnel_name).await {
            Ok(creds) => {
                tracing::info!(
                    "Cloudflare tunnel ready: {} (id: {})",
                    tunnel_name,
                    creds.tunnel_id
                );

                // Ensure CNAME record exists (create if not, ignore if already exists)
                let tunnel_hostname = format!("{}.cfargotunnel.com", creds.tunnel_id);
                match cf.find_cname_record(&subdomain).await {
                    Ok(existing) => {
                        tracing::info!(
                            "CNAME record already exists: {}.spoq.dev -> {} (id: {})",
                            subdomain,
                            existing.content,
                            existing.id
                        );
                    }
                    Err(_) => {
                        // CNAME doesn't exist, create it
                        match cf.create_cname_record(&subdomain, &creds.tunnel_id).await {
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
                                return Err(AppError::Internal(format!(
                                    "Failed to create DNS routing for tunnel: {}",
                                    e
                                )));
                            }
                        }
                    }
                }

                Some(creds)
            }
            Err(e) => {
                tracing::error!("Failed to get/create Cloudflare tunnel: {}", e);
                return Err(AppError::Internal(format!(
                    "Failed to setup Cloudflare tunnel: {}",
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
        tunnel_token: &creds.token,
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

    // Return error for SSH failures — conductor was never installed
    match ssh_status {
        "ssh_failed" => {
            tracing::error!(
                "BYOVPS provision failed: SSH connection to {} failed. Conductor was NOT installed.",
                req.vps_ip
            );
            return Err(AppError::BadRequest(format!(
                "SSH connection failed to {}. Ensure the IP is reachable from the internet, \
                 port 22 is open, and credentials are correct. \
                 Private/Tailscale IPs are not reachable from our servers.",
                req.vps_ip
            )));
        }
        "script_error" => {
            tracing::error!(
                "BYOVPS provision failed: script execution error on {}",
                req.vps_ip
            );
            return Err(AppError::Internal(format!(
                "Setup script failed to execute on {}. Check server logs for details.",
                req.vps_ip
            )));
        }
        "script_failed" => {
            tracing::warn!(
                "BYOVPS provision: script exited non-zero on {} — conductor may still start",
                req.vps_ip
            );
            // Non-zero exit is not fatal — conductor might still be starting.
            // Fall through to return success and let TUI health-check.
        }
        _ => {
            // "success" — normal path
        }
    }

    let message = if ssh_status == "success" {
        format!(
            "SSH script executed successfully. Conductor is starting on {}.",
            req.vps_ip
        )
    } else {
        format!(
            "Setup script completed with warnings on {}. Conductor may still start.",
            req.vps_ip
        )
    };

    tracing::info!(
        "BYOVPS provision returning: hostname={}, ip={}, ssh_status={}",
        hostname,
        req.vps_ip,
        ssh_status
    );

    let response = ByovpsPendingResponse {
        hostname,
        ip_address: req.vps_ip.clone(),
        jwt_secret,
        ssh_password: req.ssh_password.clone(),
        message,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get the status of an async BYOVPS operation
///
/// GET /api/byovps/operations/{id}
///
/// Returns the current status of an async provisioning operation.
/// Poll this endpoint until status is "completed" or "failed".
pub async fn get_operation(
    user: AuthenticatedUser,
    ops: web::Data<OperationStore>,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let operation_id = path.into_inner();

    match ops.get(operation_id, user.user_id) {
        Some(op) => Ok(HttpResponse::Ok().json(op)),
        None => Err(AppError::NotFound(format!(
            "Operation {} not found",
            operation_id
        ))),
    }
}

/// Background worker that executes SSH provisioning and auto-confirms VPS
async fn run_provisioning_worker(
    params: ProvisioningParams,
    ops: Arc<OperationStore>,
    pool: Arc<PgPool>,
    _config: Arc<Config>,
) {
    let op_id = params.operation_id;

    // Step 1: Mark as running
    ops.set_status(op_id, OperationStatus::Running, "Connecting to VPS...");
    ops.complete_step(op_id, 0);

    // Step 2: SSH and execute script
    ops.set_progress(op_id, 20, "Establishing SSH connection...");

    let ssh_config = SshConfig::new(&params.vps_ip, &params.ssh_username, &params.ssh_password)
        .with_timeout(60)
        .with_exec_timeout(600);

    let script_params = PostInstallParams {
        ssh_password: &params.ssh_password,
        hostname: &params.hostname,
        conductor_url: "https://download.spoq.dev/conductor",
        jwt_secret: &params.jwt_secret,
        owner_id: &params.user_id.to_string(),
        tunnel_id: &params.tunnel_id,
        tunnel_token: &params.tunnel_token,
    };
    let script_content = generate_post_install_script(&script_params);

    let ssh_result = match SshInstallerService::connect(ssh_config) {
        Ok(ssh) => {
            ops.set_progress(op_id, 30, "Running setup script...");
            ops.complete_step(op_id, 1);

            match ssh.execute_script(&script_content) {
                Ok(result) => {
                    tracing::info!(
                        "BYOVPS script completed on {} with exit code {}",
                        params.vps_ip,
                        result.exit_code
                    );
                    if result.exit_code == 0 {
                        Ok("success")
                    } else {
                        Ok("script_failed") // Non-fatal, conductor may still start
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to execute script on {}: {}", params.vps_ip, e);
                    Err(format!("Script execution failed: {}", e))
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to SSH into {}: {}", params.vps_ip, e);
            Err(format!(
                "SSH connection failed to {}. Ensure the IP is reachable from the internet, \
                 port 22 is open, and credentials are correct.",
                params.vps_ip
            ))
        }
    };

    if let Err(error) = ssh_result {
        ops.set_error(op_id, &error);
        return;
    }

    ops.complete_step(op_id, 2);
    ops.set_progress(op_id, 60, "Waiting for conductor to start...");

    // Step 3: Wait for health check
    // Use the hostname (through Cloudflare tunnel) since conductor only listens on localhost
    let health_url = format!("https://{}/health", params.hostname);
    tracing::info!("Polling health at {} (via tunnel)", health_url);
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let mut attempts = 0;
    let max_attempts = 30; // 30 * 5s = 2.5 minutes
    let healthy = loop {
        attempts += 1;
        if attempts > max_attempts {
            break false;
        }

        ops.set_progress(
            op_id,
            60 + (attempts * 30 / max_attempts) as u8,
            &format!("Waiting for conductor... (attempt {}/{})", attempts, max_attempts),
        );

        if let Ok(response) = http_client.get(&health_url).send().await {
            if response.status().is_success() {
                tracing::info!("Conductor healthy at {}", health_url);
                break true;
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    };

    if !healthy {
        ops.set_error(
            op_id,
            &format!(
                "Conductor failed to start within timeout. Check VPS logs at {}",
                params.vps_ip
            ),
        );
        return;
    }

    ops.complete_step(op_id, 3);
    ops.set_progress(op_id, 95, "Creating VPS record...");

    // Step 4: Auto-confirm VPS (create database record)
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let ssh_password_hash = match argon2.hash_password(params.ssh_password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            ops.set_error(op_id, &format!("Failed to hash password: {}", e));
            return;
        }
    };

    // Clean up any terminated/failed records for this user before inserting
    // (same logic as confirm_vps endpoint)
    if let Err(e) = sqlx::query(
        "DELETE FROM user_vps WHERE user_id = $1 AND status IN ('failed', 'terminated')",
    )
    .bind(params.user_id)
    .execute(pool.as_ref())
    .await
    {
        tracing::warn!("Failed to clean up old VPS records: {}", e);
        // Continue anyway - the INSERT might still work
    }

    let vps_id = Uuid::new_v4();
    let result = sqlx::query(
        r#"
        INSERT INTO user_vps (
            id, user_id, provider, provider_instance_id, provider_order_id,
            plan_id, template_id, data_center_id, hostname, ip_address,
            status, ssh_username, ssh_password_hash, jwt_secret,
            device_type, ready_at, conductor_verified_at
        ) VALUES (
            $1, $2, 'byovps', 0, NULL,
            'byovps-custom', 0, 0, $3, $4,
            'ready', 'root', $5, $6,
            'byovps', NOW(), NOW()
        )
        "#,
    )
    .bind(vps_id)
    .bind(params.user_id)
    .bind(&params.hostname)
    .bind(&params.vps_ip)
    .bind(&ssh_password_hash)
    .bind(&params.jwt_secret)
    .execute(pool.as_ref())
    .await;

    match result {
        Ok(_) => {
            tracing::info!(
                "VPS auto-confirmed: id={}, hostname={}, ip={}",
                vps_id,
                params.hostname,
                params.vps_ip
            );

            ops.complete_step(op_id, 4);
            ops.set_result(
                op_id,
                OperationResult {
                    hostname: params.hostname,
                    ip_address: params.vps_ip,
                    jwt_secret: params.jwt_secret,
                    ssh_password: params.ssh_password,
                    vps_id: Some(vps_id),
                },
            );
        }
        Err(e) => {
            tracing::error!("Failed to create VPS record: {}", e);
            ops.set_error(op_id, &format!("Failed to create VPS record: {}", e));
        }
    }
}

/// Replace an existing BYOVPS with a new one for the authenticated user
///
/// POST /api/byovps/replace
///
/// This endpoint is ASYNC to avoid Cloudflare timeouts:
/// 1. Validates the input (IP, username, password) - synchronous
/// 2. Terminates any existing active VPS - synchronous
/// 3. Sets up Cloudflare tunnel/DNS - synchronous
/// 4. Returns operation_id immediately
/// 5. SSH provisioning runs in background
/// 6. Background worker auto-confirms VPS when healthy
///
/// Poll GET /api/byovps/operations/{id} for status.
pub async fn replace_byovps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    cloudflare: Option<web::Data<CloudflareService>>,
    ops: web::Data<OperationStore>,
    audit: web::Data<AuditService>,
    req_ctx: RequestContext,
    req: web::Json<ProvisionByovpsRequest>,
) -> AppResult<HttpResponse> {
    // Helper to log audit on error
    let log_error = |msg: &str| {
        audit.log_async(
            AuditLogEntry::new(AuditAction::ByovpsReplace, ResourceType::Byovps)
                .user_id(user.user_id)
                .ip_address(req_ctx.ip_address.clone().unwrap_or_default())
                .user_agent(req_ctx.user_agent.clone().unwrap_or_default())
                .request_data(&*req)
                .response_status(400)
                .error_message(msg),
        );
    };

    // Validate IP address format
    if !is_valid_ip(&req.vps_ip) {
        let msg = "Invalid VPS IP address format. Must be a valid IPv4 or IPv6 address.";
        log_error(msg);
        return Err(AppError::BadRequest(msg.to_string()));
    }

    // Validate username is not empty
    if req.ssh_username.trim().is_empty() {
        let msg = "SSH username cannot be empty";
        log_error(msg);
        return Err(AppError::BadRequest(msg.to_string()));
    }

    // Validate password is not empty
    if req.ssh_password.is_empty() {
        let msg = "SSH password cannot be empty";
        log_error(msg);
        return Err(AppError::BadRequest(msg.to_string()));
    }

    // Validate password length (for security)
    if req.ssh_password.len() < 8 {
        let msg = "SSH password must be at least 8 characters";
        log_error(msg);
        return Err(AppError::BadRequest(msg.to_string()));
    }

    // BYOVPS requires root access for proper system configuration
    if req.ssh_username != "root" {
        let msg = "BYOVPS requires SSH access as 'root' user for proper system configuration.";
        log_error(msg);
        return Err(AppError::BadRequest(msg.to_string()));
    }

    // Check if user has an existing active VPS - if so, terminate it first
    let existing: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status NOT IN ('terminated', 'failed')",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    if let Some(old_vps) = existing {
        tracing::info!(
            "Terminating existing VPS for user {} before replacement: hostname={}, id={}",
            user.user_id,
            &old_vps.hostname,
            old_vps.id
        );

        // Clean up old Cloudflare tunnel if it exists
        if let (Some(cf), Some(tunnel_id)) = (&cloudflare, &old_vps.tunnel_id) {
            // Get username for tunnel name
            let username: Option<String> =
                sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
                    .bind(user.user_id)
                    .fetch_optional(pool.get_ref())
                    .await?;

            if let Some(username) = username {
                let subdomain = username.to_lowercase();

                // Delete CNAME record if exists
                if let Ok(record) = cf.find_cname_record(&subdomain).await {
                    if let Err(e) = cf.delete_dns_record(&record.id).await {
                        tracing::warn!("Failed to delete old CNAME record: {}", e);
                    } else {
                        tracing::info!("Deleted old CNAME record for {}", subdomain);
                    }
                }

                // Delete the tunnel
                if let Err(e) = cf.delete_tunnel(tunnel_id).await {
                    tracing::warn!("Failed to delete old Cloudflare tunnel: {}", e);
                } else {
                    tracing::info!("Deleted old Cloudflare tunnel: {}", tunnel_id);
                }
            }
        }

        // Mark old VPS as terminated
        sqlx::query("UPDATE user_vps SET status = 'terminated', updated_at = NOW() WHERE id = $1")
            .bind(old_vps.id)
            .execute(pool.get_ref())
            .await?;

        tracing::info!("Old VPS marked as terminated: id={}", old_vps.id);
    }

    // Note: terminated/failed records are cleaned up by confirm_vps, not here.
    // This avoids a window where no record exists if the TUI crashes between
    // replace and confirm.

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

    // Health check at the NEW IP (not hostname, which still points to the old VPS via tunnel).
    // Use direct HTTP to port 8000 since the new machine won't have a TLS cert yet.
    let health_url = format!("http://{}:8000/health", req.vps_ip);
    tracing::info!("Checking if new VPS is already healthy at {}", health_url);

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    if let Ok(response) = http_client.get(&health_url).send().await {
        if response.status().is_success() {
            tracing::info!(
                "New VPS already healthy at {} - skipping provisioning",
                health_url
            );

            let response = ByovpsPendingResponse {
                hostname,
                ip_address: req.vps_ip.clone(),
                jwt_secret,
                ssh_password: req.ssh_password.clone(),
                message: "VPS is already healthy. Confirming setup.".to_string(),
            };

            return Ok(HttpResponse::Ok().json(response));
        }
    }

    tracing::info!(
        "BYOVPS replacement started: hostname={}, ip={}",
        hostname,
        req.vps_ip
    );

    // Get or create Cloudflare Tunnel and DNS records
    let tunnel_credentials = if let Some(cf) = &cloudflare {
        let subdomain = username.to_lowercase();
        let tunnel_name = format!("spoq-{}", subdomain);

        // Get existing tunnel or create new one
        let creds = match cf.get_or_create_tunnel(&tunnel_name).await {
            Ok(creds) => {
                tracing::info!(
                    "Cloudflare tunnel ready: {} (id: {})",
                    tunnel_name,
                    creds.tunnel_id
                );

                // Ensure CNAME record exists
                let tunnel_hostname = format!("{}.cfargotunnel.com", creds.tunnel_id);
                match cf.find_cname_record(&subdomain).await {
                    Ok(existing) => {
                        tracing::info!(
                            "CNAME record already exists: {}.spoq.dev -> {} (id: {})",
                            subdomain,
                            existing.content,
                            existing.id
                        );
                    }
                    Err(_) => {
                        match cf.create_cname_record(&subdomain, &creds.tunnel_id).await {
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
                                return Err(AppError::Internal(format!(
                                    "Failed to create DNS routing for tunnel: {}",
                                    e
                                )));
                            }
                        }
                    }
                }

                Some(creds)
            }
            Err(e) => {
                tracing::error!("Failed to get/create Cloudflare tunnel: {}", e);
                return Err(AppError::Internal(format!(
                    "Failed to setup Cloudflare tunnel: {}",
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

    // Create async operation for tracking
    let operation_id = ops.create(
        user.user_id,
        "replace",
        vec![
            "Validate input",
            "Connect via SSH",
            "Execute setup script",
            "Wait for conductor",
            "Create VPS record",
        ],
    );

    // Mark first step complete (validation done above)
    ops.complete_step(operation_id, 0);

    // Prepare parameters for background worker
    let worker_params = ProvisioningParams {
        operation_id,
        user_id: user.user_id,
        vps_ip: req.vps_ip.clone(),
        ssh_username: req.ssh_username.clone(),
        ssh_password: req.ssh_password.clone(),
        hostname: hostname.clone(),
        jwt_secret: jwt_secret.clone(),
        tunnel_id: creds.tunnel_id.clone(),
        tunnel_token: creds.token.clone(),
    };

    // Clone Arc references for the background task
    let ops_clone = Arc::new(ops.get_ref().clone());
    let pool_clone = Arc::new(pool.get_ref().clone());
    let config_clone = Arc::new(config.get_ref().clone());

    // Spawn background worker - this does the slow SSH work
    tokio::spawn(async move {
        run_provisioning_worker(worker_params, ops_clone, pool_clone, config_clone).await;
    });

    tracing::info!(
        "BYOVPS replace queued: operation_id={}, hostname={}, ip={}",
        operation_id,
        hostname,
        req.vps_ip
    );

    // Audit log: operation accepted
    audit.log_async(
        AuditLogEntry::new(AuditAction::ByovpsReplace, ResourceType::Byovps)
            .user_id(user.user_id)
            .resource_id(operation_id)
            .ip_address(req_ctx.ip_address.unwrap_or_default())
            .user_agent(req_ctx.user_agent.unwrap_or_default())
            .request_data(&*req)
            .response_status(202),
    );

    // Return immediately with operation ID
    let response = ByovpsAsyncResponse {
        operation_id,
        hostname,
        ip_address: req.vps_ip.clone(),
        message: "Provisioning started. Poll /api/byovps/operations/{id} for status.".to_string(),
    };

    Ok(HttpResponse::Accepted().json(response))
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
