//! VPS management handlers for provisioning and managing user VPS instances.
//!
//! This module provides the following endpoints:
//! - `GET /api/vps/plans` - List available VPS plans
//! - `GET /api/vps/datacenters` - List available data centers
//! - `POST /api/vps/provision` - Provision a new VPS for the user
//! - `POST /api/vps/confirm` - Confirm VPS provisioning and create database record
//! - `GET /api/vps/status` - Get VPS status for the authenticated user
//! - `POST /api/vps/start` - Start user's VPS
//! - `POST /api/vps/stop` - Stop user's VPS
//! - `POST /api/vps/restart` - Restart user's VPS

use actix_web::{web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthenticatedUser;
use crate::models::{
    ProvisionPendingResponse, ProvisionVpsRequest, UserVps, VpsDataCenter, VpsPlan,
    VpsPrecheckResponse, VpsStatusResponse,
};
use crate::services::cloudflare::CloudflareService;
use crate::services::hostinger::{generate_post_install_script, CreateVpsRequest, HostingerClient, VpsSetup};

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

/// Generic success response
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

/// Request to confirm VPS provisioning and create database record
///
/// This endpoint is called by the CLI after Hostinger provisioning completes,
/// or after BYOVPS setup completes. It creates the VPS record in the database
/// with status='ready'.
#[derive(Debug, Deserialize)]
pub struct ConfirmVpsRequest {
    /// VPS hostname (e.g., "username.spoq.dev")
    pub hostname: String,
    /// IPv4 address of the VPS
    pub ip_address: String,
    /// Provider type: "hostinger" (default) or "byovps"
    /// If not provided, defaults to "hostinger" for backwards compatibility
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Hostinger VM ID (optional for BYOVPS, uses 0)
    /// For backwards compatibility, accepts either i64 or null
    pub provider_instance_id: Option<i64>,
    /// Hostinger order/subscription ID (optional)
    pub provider_order_id: Option<String>,
    /// Hostinger plan ID (e.g., "hostingercom-vps-kvm1-usd-1m")
    pub plan_id: String,
    /// OS template ID (e.g., 1007 for Ubuntu 22.04)
    pub template_id: i32,
    /// Data center ID (e.g., 9 for Phoenix)
    pub data_center_id: i32,
    /// JWT secret for conductor authentication
    pub jwt_secret: String,
    /// SSH password (plaintext - will be hashed before storage)
    pub ssh_password: String,
}

/// Default provider value for backwards compatibility
fn default_provider() -> String {
    "hostinger".to_string()
}

/// Response for VPS confirmation
#[derive(Debug, Serialize)]
pub struct ConfirmVpsResponse {
    pub id: Uuid,
    pub hostname: String,
    pub status: String,
    pub ip_address: String,
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
                stripe_price_id: None, // TODO: Map Hostinger plans to Stripe price IDs
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(VpsPlansResponse { plans }))
}

/// List available subscription plans with Stripe pricing
///
/// GET /api/vps/subscription-plans
///
/// Returns pre-defined subscription plans with Stripe price IDs for checkout.
/// These are the user-facing plans, separate from Hostinger infrastructure pricing.
pub async fn list_subscription_plans() -> AppResult<HttpResponse> {
    // Pre-defined subscription plans with Stripe price IDs (PRODUCTION)
    // Pricing: Hostinger cost + ~$1-5 markup for adoption-first strategy
    let plans = vec![
        VpsPlan {
            id: "price_1St9pyL9gUL3LpD6V4numKPq".to_string(),
            name: "Starter".to_string(),
            vcpu: 1,
            ram_gb: 4,
            disk_gb: 50,
            bandwidth_tb: 4,
            monthly_price_cents: 1500, // $15/month (Hostinger: $13.99)
            first_month_price_cents: 1500,
            stripe_price_id: Some("price_1St9pyL9gUL3LpD6V4numKPq".to_string()),
        },
        VpsPlan {
            id: "price_1St9pzL9gUL3LpD6JmDKcHiS".to_string(),
            name: "Basic".to_string(),
            vcpu: 2,
            ram_gb: 8,
            disk_gb: 100,
            bandwidth_tb: 4,
            monthly_price_cents: 1900, // $19/month (Hostinger: $17.99)
            first_month_price_cents: 1900,
            stripe_price_id: Some("price_1St9pzL9gUL3LpD6JmDKcHiS".to_string()),
        },
        VpsPlan {
            id: "price_1St9q0L9gUL3LpD6j98aTcSL".to_string(),
            name: "Pro".to_string(),
            vcpu: 4,
            ram_gb: 16,
            disk_gb: 200,
            bandwidth_tb: 8,
            monthly_price_cents: 3200, // $32/month (Hostinger: $29.99)
            first_month_price_cents: 3200,
            stripe_price_id: Some("price_1St9q0L9gUL3LpD6j98aTcSL".to_string()),
        },
        VpsPlan {
            id: "price_1St9q1L9gUL3LpD6fsbZvrdw".to_string(),
            name: "Enterprise".to_string(),
            vcpu: 8,
            ram_gb: 32,
            disk_gb: 400,
            bandwidth_tb: 16,
            monthly_price_cents: 6500, // $65/month (Hostinger: $59.99)
            first_month_price_cents: 6500,
            stripe_price_id: Some("price_1St9q1L9gUL3LpD6fsbZvrdw".to_string()),
        },
    ];

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
// VPS confirmation (authenticated) - Creates DB record after provisioning
// ---------------------------------------------------------------------------

/// Confirm VPS provisioning and create database record
///
/// This endpoint is called by the CLI after Hostinger provisioning completes,
/// or after BYOVPS setup completes. It creates the VPS record in the database
/// with status='ready'. This is the ONLY place where user_vps records are created.
///
/// POST /api/vps/confirm
pub async fn confirm_vps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    req: web::Json<ConfirmVpsRequest>,
) -> AppResult<HttpResponse> {
    // Validate SSH password length
    if req.ssh_password.len() < 12 {
        return Err(AppError::BadRequest(
            "SSH password must be at least 12 characters".to_string(),
        ));
    }

    // Validate provider field
    let provider = req.provider.to_lowercase();
    let is_byovps = provider == "byovps";

    if provider != "hostinger" && provider != "byovps" {
        return Err(AppError::BadRequest(
            format!("Invalid provider '{}'. Must be 'hostinger' or 'byovps'", req.provider),
        ));
    }

    // Validate hostname format (only for Hostinger - BYOVPS can have any hostname)
    if !is_byovps && !req.hostname.ends_with(".spoq.dev") {
        return Err(AppError::BadRequest(
            "Hostname must end with .spoq.dev for Hostinger VPS".to_string(),
        ));
    }

    // For Hostinger, provider_instance_id is required (for backwards compatibility, also accept it directly)
    // For BYOVPS, we use 0 as a placeholder
    let provider_instance_id = if is_byovps {
        0i64
    } else {
        req.provider_instance_id.ok_or_else(|| {
            AppError::BadRequest("provider_instance_id is required for Hostinger VPS".to_string())
        })?
    };

    // Set device_type based on provider
    let device_type = if is_byovps { "byovps" } else { "vps" };

    // Check if user already has a VPS (excluding terminated/failed)
    let existing: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status NOT IN ('terminated', 'failed')",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    if let Some(vps) = existing {
        return Err(AppError::Conflict(format!(
            "User already has an active VPS: {} (status: {})",
            vps.hostname, vps.status
        )));
    }

    // Clean up any stale failed or terminated VPS records for this user
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

    // Hash the SSH password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let ssh_password_hash = argon2
        .hash_password(req.ssh_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?
        .to_string();

    // Create VPS record with status='ready'
    let vps_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO user_vps (
            id, user_id, provider, provider_instance_id, provider_order_id,
            plan_id, template_id, data_center_id, hostname, ip_address,
            status, ssh_username, ssh_password_hash, jwt_secret,
            device_type, ready_at, conductor_verified_at
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            'ready', 'root', $11, $12,
            $13, NOW(), NOW()
        )
        "#,
    )
    .bind(vps_id)
    .bind(user.user_id)
    .bind(&provider)
    .bind(provider_instance_id)
    .bind(&req.provider_order_id)
    .bind(&req.plan_id)
    .bind(req.template_id)
    .bind(req.data_center_id)
    .bind(&req.hostname)
    .bind(&req.ip_address)
    .bind(&ssh_password_hash)
    .bind(&req.jwt_secret)
    .bind(device_type)
    .execute(pool.get_ref())
    .await?;

    tracing::info!(
        "VPS confirmed: id={}, hostname={}, ip={}, provider={}, device_type={}",
        vps_id, req.hostname, req.ip_address, provider, device_type
    );

    Ok(HttpResponse::Created().json(ConfirmVpsResponse {
        id: vps_id,
        hostname: req.hostname.clone(),
        status: "ready".to_string(),
        ip_address: req.ip_address.clone(),
        message: "VPS record created successfully".to_string(),
    }))
}

// ---------------------------------------------------------------------------
// VPS provisioning (authenticated)
// ---------------------------------------------------------------------------

/// Provision a new VPS for the authenticated user
///
/// This endpoint initiates VPS provisioning via Hostinger API.
/// It does NOT create a database record - that happens when the CLI
/// calls `/api/vps/confirm` after health check passes.
///
/// POST /api/vps/provision
pub async fn provision_vps(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
    config: web::Data<Config>,
    _cloudflare: Option<web::Data<CloudflareService>>,
    req: web::Json<ProvisionVpsRequest>,
) -> AppResult<HttpResponse> {
    // Validate password
    if req.ssh_password.len() < 12 {
        return Err(AppError::BadRequest(
            "SSH password must be at least 12 characters".to_string(),
        ));
    }

    // Check subscription status for managed VPS provisioning
    let user_subscription: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT subscription_id, subscription_status FROM users WHERE id = $1"
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let (_user_subscription_id, user_subscription_status) = user_subscription
        .ok_or_else(|| AppError::Internal("User not found".to_string()))?;

    // Verify active subscription for managed VPS
    let subscription_status = user_subscription_status.as_deref().unwrap_or("inactive");
    if subscription_status != "active" {
        return Err(AppError::Forbidden(
            "Active subscription required for managed VPS provisioning. Please complete your subscription payment.".to_string()
        ));
    }

    // Check if user already has a VPS (in DB)
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

    // Get plan and datacenter settings
    let plan_id = req.plan_id.clone().unwrap_or_else(|| config.default_vps_plan.clone());
    let data_center_id = req.data_center_id.unwrap_or(config.default_vps_datacenter);
    let template_id = config.default_vps_template;

    // Generate a unique ID for the post-install script name
    let script_uuid = Uuid::new_v4();
    let jwt_secret = config.jwt_secret.clone();

    // Generate post-install script (config written directly, no registration needed)
    let script_content = generate_post_install_script(
        &req.ssh_password,
        &hostname,
        "https://download.spoq.dev/conductor",
        &jwt_secret,
        &user.user_id.to_string(),
    );

    // Create post-install script on Hostinger
    let script = hostinger
        .create_post_install_script(
            &format!("spoq-setup-{}", script_uuid),
            &script_content,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create post-install script: {}", e);
            AppError::Internal(format!("Failed to create post-install script: {}", e))
        })?;

    let script_id = script.id;

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
            // Note: VirtualMachineInfo from CreateVpsResponse doesn't include IP address yet
            // The CLI will need to poll for IP address separately
            let (provider_instance_id, provider_order_id) = if let Some(vm) = response.virtual_machine {
                (vm.id, vm.subscription_id)
            } else {
                return Err(AppError::Internal(
                    "Hostinger API returned success but no virtual machine data".to_string(),
                ));
            };

            tracing::info!(
                "VPS provisioning started: hostname={}, provider_id={}",
                hostname, provider_instance_id
            );

            // Return pending response with all data CLI needs for health polling and confirmation
            // Note: ip_address is None initially - CLI will get it from health check polling
            Ok(HttpResponse::Accepted().json(ProvisionPendingResponse {
                hostname,
                ip_address: None, // Not available yet from CreateVpsResponse
                provider_instance_id,
                provider_order_id,
                plan_id,
                template_id,
                data_center_id,
                jwt_secret,
                ssh_password: req.ssh_password.clone(),
                message: "VPS provisioning started. Poll health endpoint until ready, then call /api/vps/confirm.".to_string(),
            }))
        }
        Err(e) => {
            // Failure: delete script immediately to avoid orphans
            if let Err(del_err) = hostinger.delete_post_install_script(script_id).await {
                tracing::warn!("Failed to delete post-install script {} after VPS creation failure: {}", script_id, del_err);
            }

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

                                // Create wildcard DNS record for subdomains (*.username.spoq.dev)
                                match cf.update_wildcard_dns_record(&subdomain, ip).await {
                                    Ok(record) => {
                                        tracing::info!(
                                            "Wildcard DNS record created/updated: *.{}.spoq.dev -> {} (id: {})",
                                            subdomain,
                                            ip,
                                            record.id
                                        );
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to create wildcard DNS record for *.{}.spoq.dev: {}", subdomain, e);
                                        // Continue anyway - wildcard DNS is not critical
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

                                // Create wildcard DNS record for subdomains (*.username.spoq.dev)
                                match cf.update_wildcard_dns_record(&subdomain, ip).await {
                                    Ok(record) => {
                                        tracing::info!(
                                            "Wildcard DNS record created/updated: *.{}.spoq.dev -> {} (id: {})",
                                            subdomain,
                                            ip,
                                            record.id
                                        );
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to create wildcard DNS record for *.{}.spoq.dev: {}", subdomain, e);
                                        // Continue anyway - wildcard DNS is not critical
                                    }
                                }
                            }
                        }

                        // Map Hostinger VM state to VPS status
                        // Note: Health check is now handled by CLI directly
                        // VPS is only saved to DB after CLI calls /api/vps/confirm
                        match vm.state.as_str() {
                            "installing" | "starting" | "stopping" => "provisioning".to_string(),
                            "running" => vps.status.clone(), // Return DB status (should be 'ready' if confirmed)
                            "stopped" => "stopped".to_string(),
                            _ => vps.status.clone(), // Return DB status for unknown states
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
// VPS pre-check (authenticated) - for CLI setup flow Step 1
// ---------------------------------------------------------------------------

/// Pre-check VPS status for the CLI setup flow
///
/// This is a lightweight endpoint specifically for Step 1 (PRE-CHECK) of the
/// CLI setup flow. It returns a simplified response indicating:
/// - Whether the user has a VPS
/// - The VPS connection URL (if ready)
/// - Whether the conductor is healthy
/// - A simplified status enum
///
/// GET /api/vps/precheck
pub async fn get_vps_precheck(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
) -> AppResult<HttpResponse> {
    // Query for user's VPS, excluding terminated ones
    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status NOT IN ('terminated') ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    match vps {
        Some(vps) => {
            // Determine health status based on conductor_verified_at or health check
            let healthy = if vps.status == "failed" {
                Some(false)
            } else if vps.conductor_verified_at.is_some() {
                Some(true)
            } else {
                // Not yet verified - do a quick health check
                let http_client = Client::builder()
                    .timeout(Duration::from_secs(3))
                    .build()
                    .map_err(|e| {
                        AppError::Internal(format!("Failed to create HTTP client: {}", e))
                    })?;

                let health_url = format!("https://{}/health", vps.hostname);
                match http_client.get(&health_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        // Health check passed - mark as ready
                        sqlx::query(
                            "UPDATE user_vps SET conductor_verified_at = NOW(), status = 'ready', ready_at = COALESCE(ready_at, NOW()) WHERE id = $1"
                        )
                        .bind(vps.id)
                        .execute(pool.get_ref())
                        .await?;
                        Some(true)
                    }
                    _ => Some(false),
                }
            };

            Ok(HttpResponse::Ok().json(VpsPrecheckResponse::from_vps(&vps, healthy)))
        }
        None => {
            // No VPS found for user
            Ok(HttpResponse::Ok().json(VpsPrecheckResponse::no_vps()))
        }
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
