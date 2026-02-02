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

/// Serve the setup shell script.
///
/// GET /api/setup/script
///
/// Returns the POSIX shell script that installs conductor + cloudflared
/// and connects the tunnel. No authentication required — the script
/// authenticates via the setup token passed as an argument.
pub async fn get_setup_script(
    app_state: web::Data<AppState>,
) -> HttpResponse {
    // Use the server's own URL as the API base for the script
    let api_url = std::env::var("PUBLIC_API_URL")
        .unwrap_or_else(|_| format!("http://{}", app_state.config.server_addr()));

    let script = generate_setup_script(&api_url);

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(script)
}

/// Generate the setup shell script with the given API URL baked in.
fn generate_setup_script(api_url: &str) -> String {
    format!(r##"#!/bin/sh
# spoq local conductor setup
# Usage: curl -fsSL {api_url}/api/setup/script | sh -s -- <setup-token>
set -e

SETUP_TOKEN="$1"
API_URL="{api_url}"
SPOQ_DIR="$HOME/.spoq"

# --- Colors ---
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

info()    {{ printf "%b==>%b %s\n" "$BLUE" "$NC" "$1"; }}
success() {{ printf "%b==>%b %s\n" "$GREEN" "$NC" "$1"; }}
warn()    {{ printf "%bWarning:%b %s\n" "$YELLOW" "$NC" "$1"; }}
error()   {{ printf "%bError:%b %s\n" "$RED" "$NC" "$1" >&2; exit 1; }}

# --- Validation ---
if [ -z "$SETUP_TOKEN" ]; then
    error "Missing setup token. Usage: curl -fsSL .../setup | sh -s -- <token>"
fi

if ! command -v curl >/dev/null 2>&1; then
    error "curl is required but not installed."
fi

# --- Platform detection ---
detect_platform() {{
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)  os="linux" ;;
        Darwin) os="darwin" ;;
        *) error "Unsupported OS: $os" ;;
    esac
    case "$arch" in
        x86_64|amd64)   arch="x86_64" ;;
        aarch64|arm64)  arch="aarch64" ;;
        *) error "Unsupported architecture: $arch" ;;
    esac
    PLATFORM="${{os}}-${{arch}}"
    info "Platform: $PLATFORM"
}}

# --- JSON parsing (no jq dependency) ---
parse_json() {{
    key="$1"; json="$2"
    if command -v python3 >/dev/null 2>&1; then
        echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)['$key'])"
    elif command -v python >/dev/null 2>&1; then
        echo "$json" | python -c "import sys,json; print(json.load(sys.stdin)['$key'])"
    else
        echo "$json" | grep -o "\"$key\":\"[^\"]*\"" | head -1 | sed "s/\"$key\":\"//;s/\"//"
    fi
}}

# --- Process management ---
stop_process() {{
    pid_file="$1"; name="$2"
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            info "Stopping existing $name (pid: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 2
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$pid_file"
    fi
}}

# --- Main ---
main() {{
    info "Setting up local conductor..."
    detect_platform

    # Create directories
    mkdir -p "$SPOQ_DIR/bin" "$SPOQ_DIR/logs"
    chmod 700 "$SPOQ_DIR"

    # Stop existing processes
    stop_process "$SPOQ_DIR/conductor.pid" "conductor"
    stop_process "$SPOQ_DIR/cloudflared.pid" "cloudflared"

    # Fetch credentials from API
    info "Fetching tunnel credentials..."
    CREDS=$(curl -fsSL "$API_URL/api/setup/credentials?token=$SETUP_TOKEN&platform=$PLATFORM") || \
        error "Failed to fetch credentials. Token may have expired — generate a new one from the website."

    TUNNEL_TOKEN=$(parse_json "tunnel_token" "$CREDS")
    HOSTNAME=$(parse_json "hostname" "$CREDS")
    CONDUCTOR_URL=$(parse_json "conductor_url" "$CREDS")

    if [ -z "$TUNNEL_TOKEN" ] || [ -z "$HOSTNAME" ]; then
        error "Failed to parse credentials response."
    fi

    info "Tunnel hostname: $HOSTNAME"

    # Download conductor
    if [ ! -x "$SPOQ_DIR/bin/conductor" ]; then
        info "Downloading conductor..."
        curl -fsSL "$CONDUCTOR_URL" -o "$SPOQ_DIR/bin/conductor.tmp" || \
            error "Failed to download conductor"
        mv "$SPOQ_DIR/bin/conductor.tmp" "$SPOQ_DIR/bin/conductor"
        chmod 755 "$SPOQ_DIR/bin/conductor"
        success "Conductor downloaded"
    else
        info "Conductor already installed"
    fi

    # Download cloudflared
    if [ ! -x "$SPOQ_DIR/bin/cloudflared" ]; then
        info "Downloading cloudflared..."
        os=$(uname -s)
        arch=$(uname -m)
        case "$os-$arch" in
            Darwin-arm64|Darwin-aarch64)
                CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz"
                IS_TGZ=1 ;;
            Darwin-x86_64)
                CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz"
                IS_TGZ=1 ;;
            Linux-x86_64|Linux-amd64)
                CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
                IS_TGZ=0 ;;
            Linux-aarch64|Linux-arm64)
                CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
                IS_TGZ=0 ;;
            *) error "Unsupported platform for cloudflared: $os-$arch" ;;
        esac

        if [ "$IS_TGZ" = "1" ]; then
            curl -fsSL "$CF_URL" -o "$SPOQ_DIR/bin/cloudflared.tgz" || \
                error "Failed to download cloudflared"
            tar -xzf "$SPOQ_DIR/bin/cloudflared.tgz" -C "$SPOQ_DIR/bin/" cloudflared
            rm -f "$SPOQ_DIR/bin/cloudflared.tgz"
        else
            curl -fsSL "$CF_URL" -o "$SPOQ_DIR/bin/cloudflared.tmp" || \
                error "Failed to download cloudflared"
            mv "$SPOQ_DIR/bin/cloudflared.tmp" "$SPOQ_DIR/bin/cloudflared"
        fi
        chmod 755 "$SPOQ_DIR/bin/cloudflared"
        success "Cloudflared downloaded"
    else
        info "Cloudflared already installed"
    fi

    # Start conductor
    info "Starting conductor..."
    nohup "$SPOQ_DIR/bin/conductor" > "$SPOQ_DIR/logs/conductor.log" 2>&1 &
    CONDUCTOR_PID=$!
    echo "$CONDUCTOR_PID" > "$SPOQ_DIR/conductor.pid"
    chmod 600 "$SPOQ_DIR/conductor.pid"

    # Wait for conductor health
    info "Waiting for conductor to start..."
    RETRIES=0
    while [ $RETRIES -lt 10 ]; do
        if curl -fsSo /dev/null "http://localhost:8000/health" 2>/dev/null; then
            success "Conductor is running"
            break
        fi
        RETRIES=$((RETRIES + 1))
        sleep 2
    done
    if [ $RETRIES -ge 10 ]; then
        error "Conductor failed to start. Check $SPOQ_DIR/logs/conductor.log"
    fi

    # Start cloudflared
    info "Starting tunnel..."
    nohup "$SPOQ_DIR/bin/cloudflared" tunnel --no-autoupdate run --token "$TUNNEL_TOKEN" \
        > "$SPOQ_DIR/logs/cloudflared.log" 2>&1 &
    CF_PID=$!
    echo "$CF_PID" > "$SPOQ_DIR/cloudflared.pid"
    chmod 600 "$SPOQ_DIR/cloudflared.pid"

    # Wait for tunnel to be ready
    info "Waiting for tunnel to connect..."
    RETRIES=0
    while [ $RETRIES -lt 15 ]; do
        if curl -fsSo /dev/null "https://$HOSTNAME/health" 2>/dev/null; then
            break
        fi
        RETRIES=$((RETRIES + 1))
        sleep 2
    done

    if [ $RETRIES -ge 15 ]; then
        warn "Tunnel not ready yet — it may take a moment to propagate."
        warn "You can check status at: https://$HOSTNAME/health"
    else
        success "Tunnel connected!"
    fi

    echo ""
    success "Local conductor ready!"
    echo ""
    info "Conductor: http://localhost:8000"
    info "Tunnel:    https://$HOSTNAME"
    info "Logs:      $SPOQ_DIR/logs/"
    echo ""
    info "Return to the website — it will detect the connection automatically."
}}

main
"##, api_url = api_url)
}

