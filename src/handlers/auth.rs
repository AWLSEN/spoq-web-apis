//! Authentication handlers for GitHub OAuth flow and device authorization.
//!
//! This module provides the following endpoints:
//! - `GET /auth/github` - Initiates GitHub OAuth flow (supports return_to for device verification)
//! - `GET /auth/github/callback` - Handles OAuth callback from GitHub (for device flow login)
//! - `POST /auth/refresh` - Refreshes access token using refresh token
//! - `POST /auth/revoke` - Revokes a refresh token
//! - `POST /auth/device` - Initiates device authorization flow (for CLI)
//! - `GET /auth/verify` - Device verification page (browser)
//! - `POST /auth/authorize` - Approves/denies device authorization (browser)
//! - `POST /auth/device/token` - CLI polls for token after authorization

use actix_web::{cookie::Cookie, http::header, web, HttpRequest, HttpResponse};
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::Duration as TimeDuration;
use uuid::Uuid;

use crate::config::Config;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::device_grant::DeviceGrantStatus;
use crate::services::device::{
    approve_device_grant, create_device_grant, decode_verification_param, deny_device_grant,
    get_device_grant_by_device_code, get_device_grant_by_word_code,
};
use crate::services::github::{exchange_code, get_authorize_url, get_user, GitHubOAuthConfig};
use crate::services::token::{
    create_access_token, generate_refresh_token, hash_token, verify_token,
};
use crate::services::user::find_or_create_from_github;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub pool: PgPool,
    /// Application configuration
    pub config: Config,
    /// HTTP client for external API calls
    pub http_client: reqwest::Client,
}

/// Query parameters for the OAuth callback.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// Authorization code from GitHub
    pub code: String,
    /// State parameter for CSRF protection
    pub state: String,
}

/// Request body for refresh token endpoint.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// The refresh token to use
    pub refresh_token: String,
}

/// Response from the refresh endpoint.
#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    /// New access token
    pub access_token: String,
}

/// Request body for revoke endpoint.
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// The refresh token to revoke
    pub refresh_token: String,
}

/// Query parameters for GitHub redirect with optional return_to.
#[derive(Debug, Deserialize)]
pub struct GitHubRedirectQuery {
    /// Optional return_to parameter for device verification flow
    pub return_to: Option<String>,
}

/// Request body for device initiation endpoint.
#[derive(Debug, Deserialize)]
pub struct DeviceInitRequest {
    /// The hostname/device name from the CLI
    pub hostname: String,
}

/// Response from device initiation endpoint.
#[derive(Debug, Serialize)]
pub struct DeviceInitResponse {
    /// The device code for CLI polling
    pub device_code: String,
    /// The verification URL for the user to visit
    pub verification_uri: String,
    /// Seconds until the grant expires
    pub expires_in: i64,
    /// Recommended polling interval in seconds
    pub interval: i64,
}

/// Query parameters for verification page.
#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    /// Base64-encoded verification data
    pub d: String,
}

/// Form data for device authorization.
#[derive(Debug, Deserialize)]
pub struct AuthorizeForm {
    /// The word code being authorized
    pub word_code: String,
    /// Whether the request is approved (true) or denied (false)
    pub approved: String,
}

/// Request body for device token polling.
#[derive(Debug, Deserialize)]
pub struct DeviceTokenRequest {
    /// The device code from initiation
    pub device_code: String,
    /// Must be "device_code"
    pub grant_type: String,
}

/// Response from device token endpoint.
#[derive(Debug, Serialize)]
pub struct DeviceTokenResponse {
    /// The access token (if approved)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// The refresh token (if approved)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Token type (always "Bearer" if approved)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Error code (if not approved)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Name of the cookie used to store OAuth state.
const OAUTH_STATE_COOKIE: &str = "oauth_state";
/// Name of the cookie used to store return URL.
const RETURN_TO_COOKIE: &str = "return_to";
/// Name of the cookie used to store user session.
const SESSION_COOKIE: &str = "spoq_session";
/// Device grant expiry in seconds (5 minutes).
const DEVICE_GRANT_EXPIRY_SECS: i64 = 300;
/// Recommended polling interval in seconds.
const DEVICE_POLL_INTERVAL_SECS: i64 = 5;

/// Generates a random hex-encoded state string for CSRF protection.
fn generate_state() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Initiates the GitHub OAuth flow by redirecting to GitHub's authorization page.
///
/// # Process
/// 1. Generates a random state string for CSRF protection
/// 2. Stores the state in an httponly cookie
/// 3. If return_to is provided, stores it in a cookie for post-auth redirect
/// 4. Redirects the user to GitHub's authorization URL
///
/// # Query Parameters
///
/// * `return_to` - Optional URL to redirect to after authentication (for device flow)
///
/// # Returns
///
/// A redirect response to GitHub's OAuth authorization page
pub async fn github_redirect(
    query: web::Query<GitHubRedirectQuery>,
    data: web::Data<AppState>,
) -> HttpResponse {
    let state = generate_state();

    let github_config = GitHubOAuthConfig {
        client_id: data.config.github_client_id.clone(),
        client_secret: data.config.github_client_secret.clone(),
        redirect_uri: data.config.github_redirect_uri.clone(),
    };

    let authorize_url = get_authorize_url(&github_config, &state);

    // In production (when redirect_uri contains https), set secure flag
    let is_production = data.config.github_redirect_uri.starts_with("https://");

    let state_cookie = Cookie::build(OAUTH_STATE_COOKIE, state)
        .path("/")
        .http_only(true)
        .secure(is_production)
        .max_age(TimeDuration::minutes(10))
        .finish();

    let mut response_builder = HttpResponse::Found();
    response_builder.append_header((header::SET_COOKIE, state_cookie.to_string()));

    // If return_to is provided, store it in a cookie for post-auth redirect
    if let Some(return_to) = &query.return_to {
        let return_to_cookie = Cookie::build(RETURN_TO_COOKIE, return_to.clone())
            .path("/")
            .http_only(true)
            .secure(is_production)
            .max_age(TimeDuration::minutes(10))
            .finish();
        response_builder.append_header((header::SET_COOKIE, return_to_cookie.to_string()));
    }

    response_builder
        .append_header((header::LOCATION, authorize_url))
        .finish()
}

/// Handles the OAuth callback from GitHub for device flow authentication.
///
/// # Process
/// 1. Validates the state parameter against the cookie (CSRF protection)
/// 2. Exchanges the authorization code for a GitHub access token
/// 3. Fetches the user's GitHub profile
/// 4. Creates or updates the user in the database
/// 5. Creates a session cookie and redirects to the verification page
///
/// This callback is used exclusively for the device flow. When a user clicks
/// "Login with GitHub" on the device verification page, they are redirected
/// here after GitHub authentication. The callback then redirects back to the
/// verification page with a session cookie set, allowing the user to approve
/// or deny the device authorization.
///
/// # Arguments
///
/// * `query` - Query parameters containing `code` and `state`
/// * `req` - The HTTP request (for reading cookies)
/// * `data` - Application state
///
/// # Returns
///
/// A redirect to the device verification page (from return_to cookie),
/// or an error if the return_to cookie is missing.
pub async fn github_callback(
    query: web::Query<CallbackQuery>,
    req: HttpRequest,
    data: web::Data<AppState>,
) -> HttpResponse {
    // Verify state matches cookie (CSRF protection)
    let cookie_state = req
        .cookie(OAUTH_STATE_COOKIE)
        .map(|c| c.value().to_string());

    match cookie_state {
        Some(expected_state) if expected_state == query.state => {
            // State matches, proceed
        }
        Some(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid state parameter"}));
        }
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Missing state cookie"}));
        }
    }

    // Get return_to cookie (required for device flow)
    let return_to = match req.cookie(RETURN_TO_COOKIE) {
        Some(cookie) => cookie.value().to_string(),
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Missing return_to cookie. Please use the device flow to authenticate."}));
        }
    };

    let github_config = GitHubOAuthConfig {
        client_id: data.config.github_client_id.clone(),
        client_secret: data.config.github_client_secret.clone(),
        redirect_uri: data.config.github_redirect_uri.clone(),
    };

    // Exchange code for GitHub access token
    let github_access_token = match exchange_code(&data.http_client, &github_config, &query.code).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to exchange code: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to authenticate with GitHub"}));
        }
    };

    // Fetch GitHub user profile
    let github_user = match get_user(&data.http_client, &github_access_token).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to fetch GitHub user: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to fetch user profile"}));
        }
    };

    // Find or create user in database
    let user = match find_or_create_from_github(&data.pool, &github_user).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to create/update user: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to save user"}));
        }
    };

    // In production, set secure flag
    let is_production = data.config.github_redirect_uri.starts_with("https://");

    // Clear the state cookie
    let clear_state_cookie = Cookie::build(OAUTH_STATE_COOKIE, "")
        .path("/")
        .max_age(TimeDuration::seconds(0))
        .finish();

    // Create session cookie with user ID
    let session_cookie = Cookie::build(SESSION_COOKIE, user.id.to_string())
        .path("/")
        .http_only(true)
        .secure(is_production)
        .max_age(TimeDuration::minutes(30))
        .finish();

    // Clear return_to cookie
    let clear_return_to_cookie = Cookie::build(RETURN_TO_COOKIE, "")
        .path("/")
        .max_age(TimeDuration::seconds(0))
        .finish();

    HttpResponse::Found()
        .append_header((header::SET_COOKIE, clear_state_cookie.to_string()))
        .append_header((header::SET_COOKIE, clear_return_to_cookie.to_string()))
        .append_header((header::SET_COOKIE, session_cookie.to_string()))
        .append_header((header::LOCATION, return_to))
        .finish()
}

/// Refreshes an access token using a valid refresh token.
///
/// # Process
/// 1. Looks up all non-revoked, non-expired tokens for comparison
/// 2. Verifies the provided token against stored hashes
/// 3. Generates a new access token if valid
///
/// # Arguments
///
/// * `body` - JSON body containing the refresh token
/// * `data` - Application state
///
/// # Returns
///
/// A JSON response with a new access token, or an error
pub async fn refresh_token(
    body: web::Json<RefreshRequest>,
    data: web::Data<AppState>,
) -> HttpResponse {
    // Find all valid (non-expired, non-revoked) refresh tokens
    let rows = match sqlx::query(
        r#"
        SELECT id, user_id, token_hash
        FROM refresh_tokens
        WHERE expires_at > NOW()
          AND revoked_at IS NULL
        "#,
    )
    .fetch_all(&data.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Database error while fetching tokens: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    // Find matching token by verifying hash
    let mut matched_user_id: Option<Uuid> = None;

    for row in rows {
        let token_hash: String = row.get("token_hash");
        if verify_token(&body.refresh_token, &token_hash) {
            matched_user_id = Some(row.get("user_id"));
            break;
        }
    }

    let user_id = match matched_user_id {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Invalid or expired refresh token"}));
        }
    };

    // Generate new access token
    let access_token = match create_access_token(
        user_id,
        &data.config.jwt_secret,
        data.config.jwt_access_token_expiry_secs,
    ) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to create access token: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to generate access token"}));
        }
    };

    HttpResponse::Ok().json(RefreshResponse { access_token })
}

/// Revokes a refresh token.
///
/// Requires a valid JWT access token in the Authorization header.
///
/// # Process
/// 1. Verifies the user is authenticated (via middleware)
/// 2. Finds the refresh token by comparing hashes
/// 3. Marks the token as revoked
///
/// # Arguments
///
/// * `user` - The authenticated user (from middleware)
/// * `body` - JSON body containing the refresh token to revoke
/// * `data` - Application state
///
/// # Returns
///
/// A 200 OK response on success, or an error
pub async fn revoke_token(
    user: AuthenticatedUser,
    body: web::Json<RevokeRequest>,
    data: web::Data<AppState>,
) -> HttpResponse {
    // Find all tokens belonging to this user
    let rows = match sqlx::query(
        r#"
        SELECT id, token_hash
        FROM refresh_tokens
        WHERE user_id = $1
          AND revoked_at IS NULL
        "#,
    )
    .bind(user.user_id)
    .fetch_all(&data.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Database error while fetching tokens: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Internal server error"}));
        }
    };

    // Find matching token by verifying hash
    let mut matched_token_id: Option<Uuid> = None;

    for row in rows {
        let token_hash: String = row.get("token_hash");
        if verify_token(&body.refresh_token, &token_hash) {
            matched_token_id = Some(row.get("id"));
            break;
        }
    }

    let token_id = match matched_token_id {
        Some(id) => id,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Token not found"}));
        }
    };

    // Mark token as revoked
    if let Err(e) = sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(token_id)
    .execute(&data.pool)
    .await
    {
        tracing::error!("Failed to revoke token: {:?}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "Failed to revoke token"}));
    }

    HttpResponse::Ok().json(serde_json::json!({"message": "Token revoked successfully"}))
}

/// Initiates a device authorization flow for CLI authentication.
///
/// # Process
/// 1. Creates a new device grant with device code and word code
/// 2. Returns device code and verification URL for the CLI to display
///
/// # Request Body
///
/// * `hostname` - The name of the device requesting authorization
///
/// # Returns
///
/// JSON response with device_code, verification_uri, expires_in, and interval
pub async fn device_init(
    body: web::Json<DeviceInitRequest>,
    data: web::Data<AppState>,
) -> HttpResponse {
    // Build verification base URL from the redirect URI
    // e.g., https://api.spoq.dev/auth/github/callback -> https://api.spoq.dev/auth/verify
    let verification_base_url = data
        .config
        .github_redirect_uri
        .replace("/github/callback", "/verify");

    let grant = match create_device_grant(
        &data.pool,
        &body.hostname,
        &verification_base_url,
        DEVICE_GRANT_EXPIRY_SECS,
    )
    .await
    {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Failed to create device grant: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to create device authorization"}));
        }
    };

    HttpResponse::Ok().json(DeviceInitResponse {
        device_code: grant.device_code,
        verification_uri: grant.verification_url,
        expires_in: DEVICE_GRANT_EXPIRY_SECS,
        interval: DEVICE_POLL_INTERVAL_SECS,
    })
}

/// Displays the device verification page.
///
/// # Process
/// 1. Decodes the base64 verification data from the `d` parameter
/// 2. Looks up the device grant by word code
/// 3. Checks if user is logged in (via session cookie)
/// 4. Displays appropriate state: pending, not_logged_in, success, denied, or error
///
/// # Query Parameters
///
/// * `d` - Base64-encoded verification data containing word_code and hostname
///
/// # Returns
///
/// HTML page with the verification form or status
pub async fn device_verify(
    query: web::Query<VerifyQuery>,
    req: HttpRequest,
    data: web::Data<AppState>,
) -> HttpResponse {
    // Decode the verification parameter
    let verification_data = match decode_verification_param(&query.d) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Failed to decode verification param: {:?}", e);
            return render_verify_page("error", "", "", "Invalid verification link");
        }
    };

    // Look up the device grant
    let grant = match get_device_grant_by_word_code(&data.pool, &verification_data.word_code).await
    {
        Ok(Some(g)) => g,
        Ok(None) => {
            return render_verify_page(
                "error",
                "",
                "",
                "Authorization request not found or expired",
            );
        }
        Err(e) => {
            tracing::error!("Database error looking up device grant: {:?}", e);
            return render_verify_page("error", "", "", "An error occurred. Please try again.");
        }
    };

    // Check if expired
    if grant.is_expired() {
        return render_verify_page("error", "", "", "This authorization request has expired");
    }

    // Check the grant status
    match grant.status {
        DeviceGrantStatus::Approved => {
            render_verify_page("success", &grant.word_code, &grant.hostname, "")
        }
        DeviceGrantStatus::Denied => {
            render_verify_page("denied", &grant.word_code, &grant.hostname, "")
        }
        DeviceGrantStatus::Pending => {
            // Check if user is logged in
            if req.cookie(SESSION_COOKIE).is_some() {
                render_verify_page_with_d("pending", &grant.word_code, &grant.hostname, "", &query.d)
            } else {
                render_verify_page_with_d("not_logged_in", &grant.word_code, &grant.hostname, "", &query.d)
            }
        }
    }
}

/// Renders the device verification HTML page.
fn render_verify_page(state: &str, word_code: &str, hostname: &str, error_message: &str) -> HttpResponse {
    render_verify_page_with_d(state, word_code, hostname, error_message, "")
}

/// Renders the device verification HTML page with the original d parameter.
fn render_verify_page_with_d(state: &str, word_code: &str, hostname: &str, error_message: &str, d_param: &str) -> HttpResponse {
    let template = include_str!("../templates/device_verify.html");

    // Build the login URL with return_to parameter
    let login_url = if !d_param.is_empty() {
        let return_to = format!("/auth/verify?d={}", d_param);
        format!("/auth/github?return_to={}", urlencoding::encode(&return_to))
    } else {
        "/auth/github".to_string()
    };

    // Simple template rendering - replace placeholders
    // The template uses handlebars-like syntax, but we'll do simple replacements
    let html = template
        .replace("{{WORD_CODE}}", word_code)
        .replace("{{HOSTNAME}}", hostname)
        .replace("{{ERROR_MESSAGE}}", error_message)
        .replace("{{LOGIN_URL}}", &login_url)
        // Handle state visibility - show/hide sections based on state
        .replace(
            "{{#if (eq STATE 'pending')}}{{else}}hidden{{/if}}",
            if state == "pending" { "" } else { "hidden" },
        )
        .replace(
            "{{#if (eq STATE 'not_logged_in')}}{{else}}hidden{{/if}}",
            if state == "not_logged_in" { "" } else { "hidden" },
        )
        .replace(
            "{{#if (eq STATE 'success')}}{{else}}hidden{{/if}}",
            if state == "success" { "" } else { "hidden" },
        )
        .replace(
            "{{#if (eq STATE 'denied')}}{{else}}hidden{{/if}}",
            if state == "denied" { "" } else { "hidden" },
        )
        .replace(
            "{{#if (eq STATE 'error')}}{{else}}hidden{{/if}}",
            if state == "error" { "" } else { "hidden" },
        );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

/// Handles device authorization approval/denial from the browser.
///
/// # Process
/// 1. Checks if user is logged in (via session cookie)
/// 2. If not logged in, redirects to GitHub OAuth with return_to
/// 3. Updates the device grant status based on approval
/// 4. Returns success/denied page
///
/// # Form Data
///
/// * `word_code` - The word code being authorized
/// * `approved` - "true" to approve, "false" to deny
///
/// # Returns
///
/// HTML page showing success or denial status
pub async fn device_authorize(
    form: web::Form<AuthorizeForm>,
    req: HttpRequest,
    data: web::Data<AppState>,
) -> HttpResponse {
    // Check if user is logged in
    let user_id = match req.cookie(SESSION_COOKIE) {
        Some(cookie) => match Uuid::parse_str(cookie.value()) {
            Ok(id) => id,
            Err(_) => {
                // Invalid session, redirect to GitHub login
                return redirect_to_github_login(&form.word_code, &data);
            }
        },
        None => {
            // Not logged in, redirect to GitHub login
            return redirect_to_github_login(&form.word_code, &data);
        }
    };

    // Verify the grant exists and is pending
    let grant = match get_device_grant_by_word_code(&data.pool, &form.word_code).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return render_verify_page(
                "error",
                "",
                "",
                "Authorization request not found",
            );
        }
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            return render_verify_page("error", "", "", "An error occurred");
        }
    };

    if grant.is_expired() {
        return render_verify_page("error", "", "", "This authorization request has expired");
    }

    if !grant.is_pending() {
        // Already processed
        return match grant.status {
            DeviceGrantStatus::Approved => {
                render_verify_page("success", &grant.word_code, &grant.hostname, "")
            }
            DeviceGrantStatus::Denied => {
                render_verify_page("denied", &grant.word_code, &grant.hostname, "")
            }
            _ => render_verify_page("error", "", "", "Invalid grant status"),
        };
    }

    // Process approval/denial
    let is_approved = form.approved == "true";

    if is_approved {
        match approve_device_grant(&data.pool, &form.word_code, user_id).await {
            Ok(true) => render_verify_page("success", &grant.word_code, &grant.hostname, ""),
            Ok(false) => render_verify_page(
                "error",
                "",
                "",
                "Failed to approve - grant may have expired",
            ),
            Err(e) => {
                tracing::error!("Failed to approve grant: {:?}", e);
                render_verify_page("error", "", "", "An error occurred")
            }
        }
    } else {
        match deny_device_grant(&data.pool, &form.word_code).await {
            Ok(_) => render_verify_page("denied", &grant.word_code, &grant.hostname, ""),
            Err(e) => {
                tracing::error!("Failed to deny grant: {:?}", e);
                render_verify_page("error", "", "", "An error occurred")
            }
        }
    }
}

/// Redirects to GitHub login with return_to for device flow.
fn redirect_to_github_login(word_code: &str, data: &web::Data<AppState>) -> HttpResponse {
    // Build verification URL for return_to
    let verification_base_url = data
        .config
        .github_redirect_uri
        .replace("/github/callback", "/verify");

    // Create a minimal verification data for return URL
    let verification_data = crate::services::device::VerificationData {
        word_code: word_code.to_string(),
        hostname: String::new(), // Hostname not needed for return URL
    };
    let json = serde_json::to_string(&verification_data).unwrap_or_default();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
    let return_to = format!("{}?d={}", verification_base_url, encoded);

    // Redirect to GitHub with return_to
    let redirect_url = format!("/auth/github?return_to={}", urlencoding::encode(&return_to));

    HttpResponse::Found()
        .append_header((header::LOCATION, redirect_url))
        .finish()
}

/// CLI polls this endpoint to check authorization status and get tokens.
///
/// # Process
/// 1. Validates the grant_type is "device_code"
/// 2. Looks up the device grant by device code
/// 3. Returns appropriate response based on status:
///    - pending: {"error": "authorization_pending"}
///    - denied: {"error": "access_denied"}
///    - expired: {"error": "expired_token"}
///    - approved: Generate and return access_token + refresh_token
///
/// # Request Body
///
/// * `device_code` - The device code from initiation
/// * `grant_type` - Must be "device_code"
///
/// # Returns
///
/// JSON response with tokens or error
pub async fn device_token(
    body: web::Json<DeviceTokenRequest>,
    data: web::Data<AppState>,
) -> HttpResponse {
    // Validate grant_type
    if body.grant_type != "device_code" {
        return HttpResponse::BadRequest().json(DeviceTokenResponse {
            access_token: None,
            refresh_token: None,
            token_type: None,
            error: Some("unsupported_grant_type".to_string()),
        });
    }

    // Look up the device grant
    let grant = match get_device_grant_by_device_code(&data.pool, &body.device_code).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return HttpResponse::BadRequest().json(DeviceTokenResponse {
                access_token: None,
                refresh_token: None,
                token_type: None,
                error: Some("invalid_grant".to_string()),
            });
        }
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            return HttpResponse::InternalServerError().json(DeviceTokenResponse {
                access_token: None,
                refresh_token: None,
                token_type: None,
                error: Some("server_error".to_string()),
            });
        }
    };

    // Check if expired
    if grant.is_expired() {
        return HttpResponse::BadRequest().json(DeviceTokenResponse {
            access_token: None,
            refresh_token: None,
            token_type: None,
            error: Some("expired_token".to_string()),
        });
    }

    // Check status
    match grant.status {
        DeviceGrantStatus::Pending => HttpResponse::BadRequest().json(DeviceTokenResponse {
            access_token: None,
            refresh_token: None,
            token_type: None,
            error: Some("authorization_pending".to_string()),
        }),
        DeviceGrantStatus::Denied => HttpResponse::BadRequest().json(DeviceTokenResponse {
            access_token: None,
            refresh_token: None,
            token_type: None,
            error: Some("access_denied".to_string()),
        }),
        DeviceGrantStatus::Approved => {
            // Get user ID from the grant
            let user_id = match grant.user_id {
                Some(id) => id,
                None => {
                    tracing::error!("Approved grant without user_id: {:?}", grant.id);
                    return HttpResponse::InternalServerError().json(DeviceTokenResponse {
                        access_token: None,
                        refresh_token: None,
                        token_type: None,
                        error: Some("server_error".to_string()),
                    });
                }
            };

            // Generate refresh token
            let refresh_token = generate_refresh_token();
            let token_hash = match hash_token(&refresh_token) {
                Ok(hash) => hash,
                Err(e) => {
                    tracing::error!("Failed to hash token: {:?}", e);
                    return HttpResponse::InternalServerError().json(DeviceTokenResponse {
                        access_token: None,
                        refresh_token: None,
                        token_type: None,
                        error: Some("server_error".to_string()),
                    });
                }
            };

            // Calculate expiration
            let expires_at = Utc::now() + Duration::days(data.config.jwt_refresh_token_expiry_days);

            // Store refresh token hash in database
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(user_id)
            .bind(&token_hash)
            .bind(expires_at)
            .execute(&data.pool)
            .await
            {
                tracing::error!("Failed to store refresh token: {:?}", e);
                return HttpResponse::InternalServerError().json(DeviceTokenResponse {
                    access_token: None,
                    refresh_token: None,
                    token_type: None,
                    error: Some("server_error".to_string()),
                });
            }

            // Generate JWT access token
            let access_token = match create_access_token(
                user_id,
                &data.config.jwt_secret,
                data.config.jwt_access_token_expiry_secs,
            ) {
                Ok(token) => token,
                Err(e) => {
                    tracing::error!("Failed to create access token: {:?}", e);
                    return HttpResponse::InternalServerError().json(DeviceTokenResponse {
                        access_token: None,
                        refresh_token: None,
                        token_type: None,
                        error: Some("server_error".to_string()),
                    });
                }
            };

            HttpResponse::Ok().json(DeviceTokenResponse {
                access_token: Some(access_token),
                refresh_token: Some(refresh_token),
                token_type: Some("Bearer".to_string()),
                error: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_state_length() {
        let state = generate_state();
        // 16 bytes hex encoded = 32 characters
        assert_eq!(state.len(), 32);
    }

    #[test]
    fn test_generate_state_uniqueness() {
        let state1 = generate_state();
        let state2 = generate_state();
        assert_ne!(state1, state2);
    }

    #[test]
    fn test_generate_state_is_hex() {
        let state = generate_state();
        assert!(state.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_refresh_request_deserialization() {
        let json = r#"{"refresh_token": "spoq_abc123"}"#;
        let req: RefreshRequest = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(req.refresh_token, "spoq_abc123");
    }

    #[test]
    fn test_refresh_response_serialization() {
        let resp = RefreshResponse {
            access_token: "jwt_token_here".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("Failed to serialize");
        assert!(json.contains("\"access_token\":\"jwt_token_here\""));
    }

    #[test]
    fn test_revoke_request_deserialization() {
        let json = r#"{"refresh_token": "spoq_xyz789"}"#;
        let req: RevokeRequest = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(req.refresh_token, "spoq_xyz789");
    }

    #[test]
    fn test_callback_query_deserialization() {
        let json = r#"{"code": "github_code", "state": "random_state"}"#;
        let query: CallbackQuery = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(query.code, "github_code");
        assert_eq!(query.state, "random_state");
    }

    #[test]
    fn test_device_init_request_deserialization() {
        let json = r#"{"hostname": "my-macbook"}"#;
        let req: DeviceInitRequest = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(req.hostname, "my-macbook");
    }

    #[test]
    fn test_device_init_response_serialization() {
        let resp = DeviceInitResponse {
            device_code: "abc123".to_string(),
            verification_uri: "https://example.com/verify?d=xyz".to_string(),
            expires_in: 300,
            interval: 5,
        };
        let json = serde_json::to_string(&resp).expect("Failed to serialize");
        assert!(json.contains("\"device_code\":\"abc123\""));
        assert!(json.contains("\"verification_uri\""));
        assert!(json.contains("\"expires_in\":300"));
        assert!(json.contains("\"interval\":5"));
    }

    #[test]
    fn test_device_token_request_deserialization() {
        let json = r#"{"device_code": "abc123", "grant_type": "device_code"}"#;
        let req: DeviceTokenRequest = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(req.device_code, "abc123");
        assert_eq!(req.grant_type, "device_code");
    }

    #[test]
    fn test_device_token_response_success_serialization() {
        let resp = DeviceTokenResponse {
            access_token: Some("jwt_token".to_string()),
            refresh_token: Some("spoq_refresh".to_string()),
            token_type: Some("Bearer".to_string()),
            error: None,
        };
        let json = serde_json::to_string(&resp).expect("Failed to serialize");
        assert!(json.contains("\"access_token\":\"jwt_token\""));
        assert!(json.contains("\"refresh_token\":\"spoq_refresh\""));
        assert!(json.contains("\"token_type\":\"Bearer\""));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_device_token_response_error_serialization() {
        let resp = DeviceTokenResponse {
            access_token: None,
            refresh_token: None,
            token_type: None,
            error: Some("authorization_pending".to_string()),
        };
        let json = serde_json::to_string(&resp).expect("Failed to serialize");
        assert!(json.contains("\"error\":\"authorization_pending\""));
        assert!(!json.contains("access_token"));
        assert!(!json.contains("refresh_token"));
        assert!(!json.contains("token_type"));
    }

    #[test]
    fn test_authorize_form_deserialization() {
        let form_data = "word_code=swift-bright-tiger&approved=true";
        let form: AuthorizeForm =
            serde_urlencoded::from_str(form_data).expect("Failed to deserialize");
        assert_eq!(form.word_code, "swift-bright-tiger");
        assert_eq!(form.approved, "true");
    }
}
