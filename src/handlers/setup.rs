//! Setup handlers for web-based local conductor installation.
//!
//! Provides endpoints for:
//! - `POST /api/setup/token` — Generate a short-lived setup token
//! - `GET /api/setup/credentials` — Exchange setup token for tunnel credentials
//! - `GET /api/setup/status` — Check if local conductor tunnel is healthy

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthenticatedUser;
use crate::models::UserVps;
use crate::services::cloudflare::CloudflareService;
use crate::services::token::{create_setup_token, decode_setup_token};

use super::auth::AppState;

/// Response for setup token creation
#[derive(Debug, Serialize)]
pub struct SetupTokenResponse {
    pub setup_token: String,
}

/// Query parameters for credentials endpoint
#[derive(Debug, Deserialize)]
pub struct CredentialsQuery {
    pub token: String,
    pub platform: Option<String>,
}

/// Response for setup credentials
#[derive(Debug, Serialize)]
pub struct SetupCredentialsResponse {
    pub tunnel_id: String,
    pub tunnel_token: String,
    pub hostname: String,
    pub conductor_url: String,
}

/// Response for setup status check
#[derive(Debug, Serialize)]
pub struct SetupStatusResponse {
    pub ready: bool,
    pub hostname: Option<String>,
}

/// Generate a short-lived setup token for local conductor installation.
///
/// POST /api/setup/token
///
/// Requires authentication via Bearer token. Returns a 5-minute setup token
/// that the user passes to the setup shell script.
pub async fn create_setup_token_handler(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    app_state: web::Data<AppState>,
) -> AppResult<HttpResponse> {
    // Look up username
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(user.user_id)
            .fetch_optional(pool.get_ref())
            .await?;

    let username = username
        .ok_or_else(|| AppError::Internal("User not found".to_string()))?;

    let token = create_setup_token(user.user_id, &username, &app_state.config.jwt_secret)
        .map_err(|e| AppError::Internal(format!("Failed to create setup token: {}", e)))?;

    tracing::info!("Setup token created for user {} ({})", user.user_id, username);

    Ok(HttpResponse::Ok().json(SetupTokenResponse {
        setup_token: token,
    }))
}

/// Exchange a setup token for tunnel credentials.
///
/// GET /api/setup/credentials?token=<setup_token>&platform=<platform>
///
/// This endpoint does NOT use Bearer auth — it validates the setup token
/// from the query parameter instead. This allows the shell script to call
/// it directly without needing a full auth flow.
pub async fn get_setup_credentials(
    query: web::Query<CredentialsQuery>,
    pool: web::Data<PgPool>,
    app_state: web::Data<AppState>,
    cloudflare: Option<web::Data<CloudflareService>>,
) -> AppResult<HttpResponse> {
    let cf = cloudflare.ok_or_else(|| {
        AppError::Internal("Cloudflare service not configured".to_string())
    })?;

    // Validate setup token
    let claims = decode_setup_token(&query.token, &app_state.config.jwt_secret)
        .map_err(|e| AppError::Unauthorized(format!("Invalid setup token: {}", e)))?;

    let user_id: uuid::Uuid = claims.sub.parse()
        .map_err(|_| AppError::Unauthorized("Invalid user ID in token".to_string()))?;

    // Look up user's VPS record
    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status NOT IN ('terminated') ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let hostname = if let Some(ref vps) = vps {
        vps.hostname.clone()
    } else {
        format!("{}.spoq.dev", claims.username.to_lowercase())
    };

    // Get or create tunnel
    let subdomain = hostname.strip_suffix(".spoq.dev").unwrap_or(&hostname);
    let tunnel_name = format!("spoq-{}", subdomain.to_lowercase());

    let creds = cf.get_or_create_tunnel(&tunnel_name).await.map_err(|e| {
        AppError::Internal(format!("Failed to get tunnel credentials: {}", e))
    })?;

    // Update tunnel ingress to point to localhost:8000 (local conductor)
    if let Err(e) = cf.update_tunnel_ingress(&creds.tunnel_id, &hostname, "http://localhost:8000").await {
        tracing::warn!("Failed to update tunnel ingress (continuing): {}", e);
    }

    // Store tunnel_id in DB if we have a VPS record
    if let Some(ref vps) = vps {
        if vps.tunnel_id.is_none() || vps.tunnel_id.as_deref() != Some(&creds.tunnel_id) {
            let _ = sqlx::query("UPDATE user_vps SET tunnel_id = $1 WHERE id = $2 AND user_id = $3")
                .bind(&creds.tunnel_id)
                .bind(vps.id)
                .bind(user_id)
                .execute(pool.get_ref())
                .await;
        }
    } else {
        // Create a minimal VPS record for local mode so we can track the tunnel
        let vps_id = uuid::Uuid::new_v4();
        let _ = sqlx::query(
            r#"
            INSERT INTO user_vps (
                id, user_id, provider, hostname, ip_address,
                status, plan_id, template_id, data_center_id,
                ssh_username, ssh_password_hash, jwt_secret,
                device_type, tunnel_id
            ) VALUES (
                $1, $2, 'local', $3, '127.0.0.1',
                'ready', 'local', 0, 0,
                '', '', '',
                'local', $4
            )
            "#,
        )
        .bind(vps_id)
        .bind(user_id)
        .bind(&hostname)
        .bind(&creds.tunnel_id)
        .execute(pool.get_ref())
        .await;
    }

    // Determine conductor download URL based on platform
    let platform = query.platform.as_deref().unwrap_or("unknown");
    let conductor_url = format!("https://download.spoq.dev/conductor/download/{}", platform);

    tracing::info!(
        "Setup credentials issued for user {} (tunnel: {}, hostname: {})",
        user_id, creds.tunnel_id, hostname
    );

    Ok(HttpResponse::Ok().json(SetupCredentialsResponse {
        tunnel_id: creds.tunnel_id,
        tunnel_token: creds.token,
        hostname,
        conductor_url,
    }))
}

/// Check if the user's local conductor tunnel is healthy.
///
/// GET /api/setup/status
///
/// Requires authentication. Checks the tunnel health by making an HTTP
/// request to the user's hostname.
pub async fn get_setup_status(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
) -> AppResult<HttpResponse> {
    let vps: Option<UserVps> = sqlx::query_as(
        "SELECT * FROM user_vps WHERE user_id = $1 AND status NOT IN ('terminated') ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let vps = match vps {
        Some(v) => v,
        None => {
            return Ok(HttpResponse::Ok().json(SetupStatusResponse {
                ready: false,
                hostname: None,
            }));
        }
    };

    let hostname = vps.hostname.clone();

    // Check tunnel health
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to create HTTP client: {}", e)))?;

    let health_url = format!("https://{}/health", hostname);
    let ready = match http_client.get(&health_url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    };

    Ok(HttpResponse::Ok().json(SetupStatusResponse {
        ready,
        hostname: Some(hostname),
    }))
}
