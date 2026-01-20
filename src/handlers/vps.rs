//! VPS management handlers for provisioning and managing user VPS instances.
//!
//! This module provides the following endpoints:
//! - `GET /api/vps/plans` - List available VPS plans
//! - `GET /api/vps/datacenters` - List available data centers
//! - `POST /api/vps/provision` - Provision a new VPS for the user
//! - `GET /api/vps/status` - Get VPS status for the authenticated user
//! - `POST /api/vps/start` - Start user's VPS
//! - `POST /api/vps/stop` - Stop user's VPS
//! - `POST /api/vps/restart` - Restart user's VPS

use actix_web::{web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::Utc;
use reqwest::Client;
use serde::Serialize;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthenticatedUser;
use crate::models::{ProvisionVpsRequest, UserVps, VpsDataCenter, VpsPlan, VpsStatusResponse};
use crate::services::cloudflare::CloudflareService;
use crate::services::hostinger::{generate_post_install_script, CreateVpsRequest, HostingerClient, VpsSetup};
use crate::services::registration;

/// Response for listing VPS plans
#[derive(Debug, Serialize)]
pub struct VpsPlansResponse {
    pub plans: Vec<VpsPlan>,
}

/// Response for listing data centers
#[derive(Debug, Serialize)]
pub struct DataCentersResponse {
    pub data_centers: Vec<VpsDataCenter>,
}

/// Response for VPS provisioning
#[derive(Debug, Serialize)]
pub struct ProvisionResponse {
    pub id: Uuid,
    pub hostname: String,
    pub status: String,
    pub message: String,
}

/// Generic success response
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Plan & Datacenter listing (public endpoints)
// ---------------------------------------------------------------------------

/// List available VPS plans
///
/// GET /api/vps/plans
pub async fn list_plans(hostinger: web::Data<HostingerClient>) -> AppResult<HttpResponse> {
    let catalog_items = hostinger.get_vps_plans().await?;

    let plans: Vec<VpsPlan> = catalog_items
        .into_iter()
        .filter_map(|item| {
            let metadata = item.metadata?;
            let monthly_price = item
                .prices
                .iter()
                .find(|p| p.period_unit == "month" && p.period == 1)?;

            Some(VpsPlan {
                id: monthly_price.id.clone(),
                name: item.name,
                vcpu: metadata.cpus?.parse().unwrap_or(0),
                ram_gb: metadata.memory?.parse::<i32>().unwrap_or(0) / 1024,
                disk_gb: metadata.disk_space?.parse::<i32>().unwrap_or(0) / 1024,
                bandwidth_tb: metadata.bandwidth?.parse::<i32>().unwrap_or(0) / 1024000,
                monthly_price_cents: monthly_price.price,
                first_month_price_cents: monthly_price.first_period_price,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(VpsPlansResponse { plans }))
}

/// List available data centers
///
/// GET /api/vps/datacenters
pub async fn list_datacenters(hostinger: web::Data<HostingerClient>) -> AppResult<HttpResponse> {
    let dcs = hostinger.list_data_centers().await?;

    let data_centers: Vec<VpsDataCenter> = dcs
        .into_iter()
        .map(|dc| VpsDataCenter {
            id: dc.id,
            name: dc.name,
            city: dc.city,
            country: dc.location.to_uppercase(),
            continent: dc.continent,
        })
        .collect();

    Ok(HttpResponse::Ok().json(DataCentersResponse { data_centers }))
}

// ---------------------------------------------------------------------------
// VPS provisioning (authenticated)
// ---------------------------------------------------------------------------

/// Provision a new VPS for the authenticated user
///
/// POST /api/vps/provision
pub async fn provision_vps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
    config: web::Data<Config>,
    cloudflare: Option<web::Data<CloudflareService>>,
    req: web::Json<ProvisionVpsRequest>,
) -> AppResult<HttpResponse> {
    // Validate password
    if req.ssh_password.len() < 12 {
        return Err(AppError::BadRequest(
            "SSH password must be at least 12 characters".to_string(),
        ));
    }

    // Check if user already has a VPS
    let existing: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status NOT IN ('terminated', 'failed')",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    if let Some(vps) = existing {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "User already has an active VPS",
            "vps": VpsStatusResponse::from(vps)
        })));
    }

    // Get the user's username for hostname
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(user.user_id)
            .fetch_optional(pool.get_ref())
            .await?;

    let username = username
        .ok_or_else(|| AppError::Internal("User not found".to_string()))?;

    // Generate hostname
    let hostname = format!("{}.spoq.dev", username.to_lowercase());

    // Hash the SSH password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let ssh_password_hash = argon2
        .hash_password(req.ssh_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?
        .to_string();

    // Get plan and datacenter settings
    let plan_id = req.plan_id.clone().unwrap_or_else(|| config.default_vps_plan.clone());
    let data_center_id = req.data_center_id.unwrap_or(config.default_vps_datacenter);
    let template_id = config.default_vps_template;

    // Create VPS record in pending state
    let vps_id = Uuid::new_v4();
    let jwt_secret = config.jwt_secret.clone();

    sqlx::query(
        r#"
        INSERT INTO user_vps (
            id, user_id, provider, plan_id, template_id, data_center_id,
            hostname, status, ssh_username, ssh_password_hash, jwt_secret
        ) VALUES ($1, $2, 'hostinger', $3, $4, $5, $6, 'pending', 'spoq', $7, $8)
        "#,
    )
    .bind(vps_id)
    .bind(user.user_id)
    .bind(&plan_id)
    .bind(template_id)
    .bind(data_center_id)
    .bind(&hostname)
    .bind(&ssh_password_hash)
    .bind(&jwt_secret)
    .execute(pool.get_ref())
    .await?;

    // Generate registration code for Conductor self-registration
    let registration_code = registration::generate_registration_code();
    let registration_code_hash = registration::hash_code(&registration_code)
        .map_err(|e| AppError::Internal(format!("Failed to hash registration code: {}", e)))?;
    let registration_expires_at = Utc::now() + chrono::Duration::minutes(15);

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

    // Generate post-install script with registration code
    let script_content = generate_post_install_script(
        &req.ssh_password,
        &registration_code,
        "https://spoq-api-production.up.railway.app",
        &hostname,
        "https://spoq.dev/releases/conductor",
    );

    // Create post-install script on Hostinger
    let script = hostinger
        .create_post_install_script(
            &format!("spoq-setup-{}", vps_id),
            &script_content,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create post-install script: {}", e);
            AppError::Internal(format!("Failed to create post-install script: {}", e))
        })?;

    let script_id = script.id;

    // Update status to provisioning
    sqlx::query("UPDATE user_vps SET status = 'provisioning' WHERE id = $1")
        .bind(vps_id)
        .execute(pool.get_ref())
        .await?;

    // Create VPS via Hostinger API
    let create_req = CreateVpsRequest {
        item_id: plan_id.clone(),
        payment_method_id: None, // Use default payment method
        setup: VpsSetup {
            template_id,
            data_center_id,
            hostname: Some(hostname.clone()),
            password: Some(req.ssh_password.clone()),
            post_install_script_id: Some(script_id),
            enable_backups: Some(true),
            public_key: None,
        },
        coupons: None,
    };

    match hostinger.create_vps(create_req).await {
        Ok(response) => {
            // Success: schedule cleanup of post-install script after 30 minutes
            let hostinger_clone = hostinger.get_ref().clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30 * 60)).await;
                if let Err(e) = hostinger_clone.delete_post_install_script(script_id).await {
                    tracing::warn!("Failed to delete post-install script {}: {}", script_id, e);
                }
            });

            // Extract VM info from nested response
            let (provider_instance_id, provider_order_id) = if let Some(vm) = response.virtual_machine {
                (Some(vm.id), vm.subscription_id)
            } else {
                (None, None)
            };

            sqlx::query(
                r#"
                UPDATE user_vps
                SET provider_instance_id = $1, provider_order_id = $2, status = 'provisioning'
                WHERE id = $3
                "#,
            )
            .bind(provider_instance_id)
            .bind(&provider_order_id)
            .bind(vps_id)
            .execute(pool.get_ref())
            .await?;

            tracing::info!(
                "VPS provisioning started: id={}, hostname={}, provider_id={:?}",
                vps_id, hostname, provider_instance_id
            );

            Ok(HttpResponse::Accepted().json(ProvisionResponse {
                id: vps_id,
                hostname,
                status: "provisioning".to_string(),
                message: "VPS provisioning started. Check status for updates.".to_string(),
            }))
        }
        Err(e) => {
            // Failure: delete script immediately to avoid orphans
            if let Err(del_err) = hostinger.delete_post_install_script(script_id).await {
                tracing::warn!("Failed to delete post-install script {} after VPS creation failure: {}", script_id, del_err);
            }

            // Mark as failed
            sqlx::query("UPDATE user_vps SET status = 'failed' WHERE id = $1")
                .bind(vps_id)
                .execute(pool.get_ref())
                .await?;

            tracing::error!("Failed to provision VPS: {}", e);
            Err(AppError::Internal(format!(
                "Failed to provision VPS: {}",
                e
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// VPS status (authenticated)
// ---------------------------------------------------------------------------

/// Get VPS status for the authenticated user
///
/// GET /api/vps/status
pub async fn get_vps_status(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
    cloudflare: Option<web::Data<CloudflareService>>,
) -> AppResult<HttpResponse> {
    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status != 'terminated' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    match vps {
        Some(mut vps) => {
            // If provider_instance_id is missing, try to find and link the VPS on Hostinger
            if vps.provider_instance_id.is_none() && vps.status == "provisioning" {
                tracing::info!("VPS {} missing provider_instance_id, searching Hostinger...", vps.id);
                if let Ok(vms) = hostinger.list_vps().await {
                    // Search for VM matching our hostname
                    for vm in vms {
                        if vm.hostname == vps.hostname || vm.hostname.contains(&vps.hostname.replace(".spoq.dev", "")) {
                            tracing::info!("Found matching VPS on Hostinger: {} ({})", vm.id, vm.hostname);
                            let ip_address = vm.ipv4.first().map(|ip| ip.address.clone());

                            sqlx::query(
                                r#"
                                UPDATE user_vps
                                SET provider_instance_id = $1, ip_address = $2
                                WHERE id = $3
                                "#,
                            )
                            .bind(vm.id)
                            .bind(&ip_address)
                            .bind(vps.id)
                            .execute(pool.get_ref())
                            .await?;

                            // Create DNS A record if Cloudflare is configured and we have an IP
                            if let (Some(cf), Some(ref ip)) = (&cloudflare, &ip_address) {
                                let subdomain = vps.hostname.replace(".spoq.dev", "");
                                match cf.update_dns_record(&subdomain, ip).await {
                                    Ok(record) => {
                                        tracing::info!(
                                            "DNS record created/updated: {}.spoq.dev -> {} (id: {})",
                                            subdomain,
                                            ip,
                                            record.id
                                        );

                                        // Update VPS with DNS record ID
                                        sqlx::query("UPDATE user_vps SET dns_record_id = $1 WHERE id = $2")
                                            .bind(&record.id)
                                            .bind(vps.id)
                                            .execute(pool.get_ref())
                                            .await?;
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to create DNS record for {}: {}", vps.hostname, e);
                                        // Continue anyway - DNS is not critical
                                    }
                                }
                            }

                            // Reload VPS data
                            vps = sqlx::query_as("SELECT * FROM user_vps WHERE id = $1")
                                .bind(vps.id)
                                .fetch_one(pool.get_ref())
                                .await?;
                            break;
                        }
                    }
                }
            }

            // Determine status based on Hostinger VM state and registration status
            let computed_status = if let Some(vm_id) = vps.provider_instance_id {
                match hostinger.get_vps(vm_id).await {
                    Ok(vm) => {
                        // Update IP if available
                        let ip_address = vm.ipv4.first().map(|ip| ip.address.clone());
                        if ip_address.is_some() && vps.ip_address.is_none() {
                            sqlx::query("UPDATE user_vps SET ip_address = $1 WHERE id = $2")
                                .bind(&ip_address)
                                .bind(vps.id)
                                .execute(pool.get_ref())
                                .await?;
                            vps.ip_address = ip_address.clone();

                            // Create DNS A record if Cloudflare is configured
                            if let (Some(cf), Some(ref ip)) = (&cloudflare, &ip_address) {
                                let subdomain = vps.hostname.replace(".spoq.dev", "");
                                match cf.update_dns_record(&subdomain, ip).await {
                                    Ok(record) => {
                                        tracing::info!(
                                            "DNS record created/updated: {}.spoq.dev -> {} (id: {})",
                                            subdomain,
                                            ip,
                                            record.id
                                        );

                                        // Update VPS with DNS record ID
                                        sqlx::query("UPDATE user_vps SET dns_record_id = $1 WHERE id = $2")
                                            .bind(&record.id)
                                            .bind(vps.id)
                                            .execute(pool.get_ref())
                                            .await?;
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to create DNS record for {}: {}", vps.hostname, e);
                                        // Continue anyway - DNS is not critical
                                    }
                                }
                            }
                        }

                        match vm.state.as_str() {
                            "installing" | "starting" | "stopping" => "provisioning".to_string(),
                            "running" => {
                                if vps.registered_at.is_none() {
                                    // Waiting for Conductor to call /register
                                    "registering".to_string()
                                } else if vps.conductor_verified_at.is_none() {
                                    // Registered but not verified - do health check
                                    let http_client = Client::builder()
                                        .timeout(Duration::from_secs(5))
                                        .build()
                                        .map_err(|e| AppError::Internal(format!("Failed to create HTTP client: {}", e)))?;

                                    let health_url = format!("https://{}/health", vps.hostname);
                                    match http_client.get(&health_url).send().await {
                                        Ok(resp) if resp.status().is_success() => {
                                            // Update conductor_verified_at
                                            sqlx::query(
                                                "UPDATE user_vps SET conductor_verified_at = NOW(), status = 'ready', ready_at = COALESCE(ready_at, NOW()) WHERE id = $1"
                                            )
                                            .bind(vps.id)
                                            .execute(pool.get_ref())
                                            .await?;
                                            "ready".to_string()
                                        }
                                        _ => "configuring".to_string(), // Health check failed, still starting
                                    }
                                } else {
                                    "ready".to_string() // Already verified
                                }
                            }
                            "stopped" => "stopped".to_string(),
                            _ => "provisioning".to_string(),
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch VPS status from Hostinger: {}", e);
                        vps.status.clone()
                    }
                }
            } else {
                vps.status.clone()
            };

            // Update status in DB if changed
            if computed_status != vps.status {
                sqlx::query("UPDATE user_vps SET status = $1 WHERE id = $2")
                    .bind(&computed_status)
                    .bind(vps.id)
                    .execute(pool.get_ref())
                    .await?;
                vps.status = computed_status;
            }

            Ok(HttpResponse::Ok().json(VpsStatusResponse::from(vps)))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "No VPS found for user",
            "message": "Use POST /api/vps/provision to create a VPS"
        }))),
    }
}

// ---------------------------------------------------------------------------
// VPS control (authenticated)
// ---------------------------------------------------------------------------

/// Start the user's VPS
///
/// POST /api/vps/start
pub async fn start_vps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
) -> AppResult<HttpResponse> {
    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status != 'terminated' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let vps = vps.ok_or_else(|| AppError::NotFound("No VPS found for user".to_string()))?;

    let vm_id = vps
        .provider_instance_id
        .ok_or_else(|| AppError::BadRequest("VPS not yet provisioned".to_string()))?;

    hostinger.start_vps(vm_id).await?;

    // Update status
    sqlx::query("UPDATE user_vps SET status = 'provisioning' WHERE id = $1")
        .bind(vps.id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(SuccessResponse {
        success: true,
        message: "VPS start initiated".to_string(),
    }))
}

/// Stop the user's VPS
///
/// POST /api/vps/stop
pub async fn stop_vps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
) -> AppResult<HttpResponse> {
    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status != 'terminated' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let vps = vps.ok_or_else(|| AppError::NotFound("No VPS found for user".to_string()))?;

    let vm_id = vps
        .provider_instance_id
        .ok_or_else(|| AppError::BadRequest("VPS not yet provisioned".to_string()))?;

    hostinger.stop_vps(vm_id).await?;

    // Update status
    sqlx::query("UPDATE user_vps SET status = 'stopped' WHERE id = $1")
        .bind(vps.id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(SuccessResponse {
        success: true,
        message: "VPS stop initiated".to_string(),
    }))
}

/// Restart the user's VPS
///
/// POST /api/vps/restart
pub async fn restart_vps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
) -> AppResult<HttpResponse> {
    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status != 'terminated' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let vps = vps.ok_or_else(|| AppError::NotFound("No VPS found for user".to_string()))?;

    let vm_id = vps
        .provider_instance_id
        .ok_or_else(|| AppError::BadRequest("VPS not yet provisioned".to_string()))?;

    hostinger.restart_vps(vm_id).await?;

    // Update status
    sqlx::query("UPDATE user_vps SET status = 'provisioning' WHERE id = $1")
        .bind(vps.id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(SuccessResponse {
        success: true,
        message: "VPS restart initiated".to_string(),
    }))
}

/// Request for password reset
#[derive(Debug, serde::Deserialize)]
pub struct ResetPasswordRequest {
    /// New password (min 12 chars)
    pub new_password: String,
}

/// Reset the root password for the user's VPS
/// This is SAFE - does NOT delete any data
///
/// POST /api/vps/reset-password
pub async fn reset_password(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
    req: web::Json<ResetPasswordRequest>,
) -> AppResult<HttpResponse> {
    // Validate password length
    if req.new_password.len() < 12 {
        return Err(AppError::BadRequest(
            "Password must be at least 12 characters".to_string(),
        ));
    }

    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status != 'terminated' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let vps = vps.ok_or_else(|| AppError::NotFound("No VPS found for user".to_string()))?;

    let vm_id = vps
        .provider_instance_id
        .ok_or_else(|| AppError::BadRequest("VPS not yet provisioned".to_string()))?;

    // Reset password via Hostinger API (safe, no data loss)
    hostinger.reset_password(vm_id, &req.new_password).await?;

    tracing::info!("Password reset for VPS {} (user {})", vps.id, user.user_id);

    Ok(HttpResponse::Ok().json(SuccessResponse {
        success: true,
        message: "Password reset successful. Use the new password for SSH.".to_string(),
    }))
}
