# Device Expansion: Implementation Guide

> **Status:** Future Feature - Ready for Implementation
> **Estimated Effort:** 1-2 weeks for MVP
> **Dependencies:** Conductor source code access, Cloudflare Tunnel API

---

## Table of Contents

1. [Conductor Changes Required](#conductor-changes-required)
2. [Platform Binary Matrix](#platform-binary-matrix)
3. [Backend/API Changes](#backendapi-changes)
4. [Implementation Phases](#implementation-phases)
5. [Testing Strategy](#testing-strategy)

---

## Conductor Changes Required

### Current State Analysis

**What Conductor Currently Does:**
- Reads config from `/etc/conductor/config.toml`
- Reads registration code from `/etc/spoq/registration`
- Listens on port 8080 (configurable in config.toml)
- Self-registers with API on first boot
- Runs as systemd service on VPS

**Hardcoded Assumptions:**
```rust
// Current (assumed):
const CONFIG_PATH: &str = "/etc/conductor/config.toml";
const REGISTRATION_PATH: &str = "/etc/spoq/registration";
```

### Required Changes

#### 1. Add Environment Variable Support

**Priority:** HIGH
**Effort:** 1-2 hours
**Files:** `src/config.rs` or similar

Add support for custom paths via environment variables:

```rust
// New: Check environment variables first, fallback to default
fn get_config_path() -> PathBuf {
    if let Ok(path) = std::env::var("SPOQ_CONFIG_DIR") {
        PathBuf::from(path).join("conductor.toml")
    } else if let Ok(home) = std::env::var("HOME") {
        // Check user home directory (macOS/Linux local devices)
        let user_config = PathBuf::from(home)
            .join(".spoq")
            .join("config")
            .join("conductor.toml");

        if user_config.exists() {
            user_config
        } else {
            // Fallback to system path (VPS)
            PathBuf::from("/etc/conductor/config.toml")
        }
    } else {
        PathBuf::from("/etc/conductor/config.toml")
    }
}

fn get_registration_path() -> PathBuf {
    if let Ok(path) = std::env::var("SPOQ_REGISTRATION_FILE") {
        PathBuf::from(path)
    } else if let Ok(home) = std::env::var("HOME") {
        let user_reg = PathBuf::from(home)
            .join(".spoq")
            .join("registration");

        if user_reg.exists() {
            user_reg
        } else {
            PathBuf::from("/etc/spoq/registration")
        }
    } else {
        PathBuf::from("/etc/spoq/registration")
    }
}
```

**Why:** Allows Conductor to run from user directories on Mac/Linux desktops without root privileges.

#### 2. Support CLI --config Flag

**Priority:** MEDIUM
**Effort:** 30 minutes
**Files:** `src/main.rs`

Currently the systemd service uses:
```bash
ExecStart=/opt/spoq/bin/conductor --config /etc/conductor/config.toml
```

But Conductor rejects this with:
```
error: unexpected argument '--config' found
```

**Add CLI argument support:**

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "conductor")]
#[command(about = "Spoq Conductor - AI Backend Service")]
struct Cli {
    /// Path to config file
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override server port
    #[arg(long)]
    port: Option<u16>,

    /// Override server host
    #[arg(long)]
    host: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_path = cli.config
        .unwrap_or_else(|| get_config_path());

    let config = load_config(&config_path)?;

    // Override with CLI args if provided
    let config = if let Some(port) = cli.port {
        config.with_port(port)
    } else {
        config
    };

    // ... rest of startup
}
```

**Why:**
- Fixes current systemd service failure
- Provides flexibility for different deployment scenarios
- Standard practice for Rust CLI apps

#### 3. Add XDG Base Directory Support (Linux)

**Priority:** MEDIUM
**Effort:** 1 hour
**Files:** `src/config.rs`

Follow XDG Base Directory specification for Linux:

```rust
use dirs;

fn get_xdg_config_path() -> Option<PathBuf> {
    // Check XDG_CONFIG_HOME first
    if let Ok(xdg_home) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg_home).join("spoq").join("conductor.toml"));
    }

    // Fallback to ~/.config/spoq/conductor.toml
    if let Some(home) = dirs::home_dir() {
        Some(home.join(".config").join("spoq").join("conductor.toml"))
    } else {
        None
    }
}

fn get_config_path() -> PathBuf {
    // 1. CLI flag (--config)
    // 2. Environment variable (SPOQ_CONFIG_DIR)
    // 3. XDG Base Directory (~/.config/spoq/conductor.toml)
    // 4. macOS Application Support (~/Library/Application Support/Spoq/conductor.toml)
    // 5. System default (/etc/conductor/config.toml)

    if cfg!(target_os = "macos") {
        if let Some(home) = dirs::home_dir() {
            let mac_path = home
                .join("Library")
                .join("Application Support")
                .join("Spoq")
                .join("conductor.toml");
            if mac_path.exists() {
                return mac_path;
            }
        }
    }

    if let Some(xdg_path) = get_xdg_config_path() {
        if xdg_path.exists() {
            return xdg_path;
        }
    }

    // Fallback to system path
    PathBuf::from("/etc/conductor/config.toml")
}
```

**Why:** Standard for Linux desktop applications.

#### 4. Optional: Add Config Auto-Detection

**Priority:** LOW (nice to have)
**Effort:** 1 hour
**Files:** `src/config.rs`

Auto-detect deployment type and adjust defaults:

```rust
#[derive(Debug, Clone, Copy)]
enum DeploymentType {
    VPS,        // Traditional VPS with systemd
    Desktop,    // Local desktop/laptop
    Development, // Development mode
}

fn detect_deployment_type() -> DeploymentType {
    // Check for VPS marker
    if Path::new("/etc/spoq/vps.marker").exists() {
        return DeploymentType::VPS;
    }

    // Check for desktop marker
    if let Some(home) = dirs::home_dir() {
        if home.join(".spoq/device.marker").exists() {
            return DeploymentType::Desktop;
        }
    }

    // Check if running as systemd service
    if std::env::var("INVOCATION_ID").is_ok() {
        return DeploymentType::VPS;
    }

    DeploymentType::Desktop
}

fn apply_deployment_defaults(config: &mut Config, deployment: DeploymentType) {
    match deployment {
        DeploymentType::VPS => {
            // Bind to 0.0.0.0 (accessible from Caddy)
            config.server.host = "0.0.0.0";
        }
        DeploymentType::Desktop => {
            // Bind to localhost only (tunnel handles external access)
            config.server.host = "127.0.0.1";
        }
        DeploymentType::Development => {
            // Development settings
            config.server.host = "127.0.0.1";
            config.log_level = "debug";
        }
    }
}
```

**Why:** Reduces configuration burden - Conductor "just works" in different environments.

---

## Platform Binary Matrix

### Required Binaries

| Platform | Architecture | Rust Target | OS | Priority |
|----------|-------------|-------------|-----|----------|
| **macOS Intel** | x86_64 | `x86_64-apple-darwin` | macOS 10.15+ | HIGH |
| **macOS Apple Silicon** | ARM64 | `aarch64-apple-darwin` | macOS 11+ | HIGH |
| **Linux (VPS)** | x86_64 | `x86_64-unknown-linux-gnu` | Ubuntu 20.04+ | ✅ EXISTS |
| **Linux (Desktop)** | x86_64 | `x86_64-unknown-linux-gnu` | Ubuntu 20.04+ | ✅ EXISTS |
| **Raspberry Pi** | ARM64 | `aarch64-unknown-linux-gnu` | Raspbian/Ubuntu | MEDIUM |
| **Raspberry Pi** | ARMv7 | `armv7-unknown-linux-gnueabihf` | Older Pi models | LOW |
| **Windows (WSL2)** | x86_64 | `x86_64-unknown-linux-gnu` | WSL2 | LOW |

### Build Configuration

**Cargo.toml:**
```toml
[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Link-time optimization
codegen-units = 1   # Better optimization
strip = true        # Strip symbols (smaller binary)
panic = "abort"     # Smaller binary
```

**Build Commands:**
```bash
# macOS Intel
cargo build --release --target x86_64-apple-darwin

# macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin

# Linux x86_64 (VPS/Desktop)
cargo build --release --target x86_64-unknown-linux-gnu

# Raspberry Pi (64-bit)
cargo build --release --target aarch64-unknown-linux-gnu

# Raspberry Pi (32-bit, older models)
cargo build --release --target armv7-unknown-linux-gnueabihf
```

### Cross-Compilation Setup

**Install targets:**
```bash
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf
```

**Use cross for Linux targets (from macOS):**
```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu
cross build --release --target aarch64-unknown-linux-gnu
```

### Binary Hosting

Update download service to serve platform-specific binaries:

```
https://download.spoq.dev/conductor/download/
  ├── darwin-x86_64        (macOS Intel)
  ├── darwin-arm64         (macOS Apple Silicon)
  ├── linux-x86_64         (VPS/Desktop, exists)
  ├── linux-arm64          (Raspberry Pi 4/5)
  └── linux-armv7          (Raspberry Pi 2/3)
```

**Detection logic (in install script):**
```bash
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case "$OS" in
    darwin)
        case "$ARCH" in
            x86_64)  PLATFORM="darwin-x86_64" ;;
            arm64)   PLATFORM="darwin-arm64" ;;
            *)       echo "Unsupported Mac architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    linux)
        case "$ARCH" in
            x86_64)  PLATFORM="linux-x86_64" ;;
            aarch64) PLATFORM="linux-arm64" ;;
            armv7l)  PLATFORM="linux-armv7" ;;
            *)       echo "Unsupported Linux architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

DOWNLOAD_URL="https://download.spoq.dev/conductor/download/$PLATFORM"
```

---

## Backend/API Changes

### 1. New Database Columns

**Migration: `add_device_support.sql`**

```sql
-- Add device type tracking
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT 'vps';
-- Values: 'vps', 'mac', 'linux_desktop', 'raspberry_pi'

-- Add tunnel info for local devices
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS tunnel_id TEXT;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS tunnel_credentials JSONB;

-- Add platform detection
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS platform TEXT;
-- Values: 'darwin-x86_64', 'darwin-arm64', 'linux-x86_64', 'linux-arm64'

-- Index for tunnel lookups
CREATE INDEX IF NOT EXISTS idx_user_vps_tunnel ON user_vps(tunnel_id) WHERE tunnel_id IS NOT NULL;

-- Consider renaming table
-- ALTER TABLE user_vps RENAME TO user_devices;
```

### 2. New Service: Cloudflare Tunnel

**File: `src/services/cloudflare_tunnel.rs`**

```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};
use base64;

pub struct CloudflareTunnelService {
    client: Client,
    account_id: String,
    api_token: String,
    zone_id: String,
}

#[derive(Serialize)]
struct CreateTunnelRequest {
    name: String,
    tunnel_secret: String,  // Base64 encoded 32 bytes
}

#[derive(Deserialize)]
pub struct TunnelResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct TunnelCredentials {
    #[serde(rename = "AccountTag")]
    pub account_tag: String,
    #[serde(rename = "TunnelID")]
    pub tunnel_id: String,
    #[serde(rename = "TunnelSecret")]
    pub tunnel_secret: String,
}

impl CloudflareTunnelService {
    pub fn new(account_id: String, api_token: String, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            account_id,
            api_token,
            zone_id,
        }
    }

    /// Create a new tunnel for a user
    pub async fn create_tunnel(&self, username: &str) -> Result<(String, TunnelCredentials)> {
        // 1. Generate random 32-byte secret
        let mut secret = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut secret);
        let tunnel_secret = base64::encode(&secret);

        // 2. Create tunnel via Cloudflare API
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel",
            self.account_id
        );

        let response = self.client
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&CreateTunnelRequest {
                name: format!("spoq-{}", username),
                tunnel_secret: tunnel_secret.clone(),
            })
            .send()
            .await?;

        let tunnel: TunnelResponse = response.json::<CloudflareApiResponse<TunnelResponse>>()
            .await?
            .result;

        // 3. Create credentials object
        let credentials = TunnelCredentials {
            account_tag: self.account_id.clone(),
            tunnel_id: tunnel.id.clone(),
            tunnel_secret,
        };

        // 4. Create CNAME record: username.spoq.dev -> tunnel_id.cfargotunnel.com
        self.create_dns_record(username, &tunnel.id).await?;

        Ok((tunnel.id, credentials))
    }

    /// Create DNS CNAME record pointing to tunnel
    async fn create_dns_record(&self, subdomain: &str, tunnel_id: &str) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        self.client
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "CNAME",
                "name": subdomain,
                "content": format!("{}.cfargotunnel.com", tunnel_id),
                "proxied": true,
                "ttl": 1  // Auto TTL
            }))
            .send()
            .await?;

        Ok(())
    }

    /// Delete tunnel when user cancels/switches
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel/{}",
            self.account_id, tunnel_id
        );

        self.client
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await?;

        Ok(())
    }
}

#[derive(Deserialize)]
struct CloudflareApiResponse<T> {
    result: T,
    success: bool,
    errors: Vec<serde_json::Value>,
}
```

### 3. New Endpoint: Device Setup

**File: `src/handlers/device.rs`**

```rust
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct DeviceSetupRequest {
    pub device_type: String,  // "mac_arm64", "mac_x86_64", "linux_arm64", etc.
}

#[derive(Serialize)]
pub struct DeviceSetupResponse {
    pub setup_script: String,
    pub tunnel_id: String,
    pub tunnel_credentials: serde_json::Value,
    pub hostname: String,
    pub registration_code: String,
}

/// POST /api/device/setup
pub async fn setup_device(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tunnel_service: web::Data<CloudflareTunnelService>,
    req: web::Json<DeviceSetupRequest>,
) -> AppResult<HttpResponse> {
    // 1. Get username
    let username: String = sqlx::query_scalar(
        "SELECT username FROM users WHERE id = $1"
    )
    .bind(user.user_id)
    .fetch_one(pool.get_ref())
    .await?;

    // 2. Create Cloudflare tunnel
    let (tunnel_id, credentials) = tunnel_service
        .create_tunnel(&username)
        .await?;

    // 3. Generate registration code
    let registration_code = registration::generate_registration_code();
    let registration_code_hash = registration::hash_code(&registration_code)?;
    let registration_expires_at = Utc::now() + chrono::Duration::minutes(15);

    // 4. Create device record in database
    let device_id = Uuid::new_v4();
    let hostname = format!("{}.spoq.dev", username);

    sqlx::query(
        r#"INSERT INTO user_vps
           (id, user_id, device_type, platform, hostname, tunnel_id, tunnel_credentials,
            registration_code_hash, registration_expires_at, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')"#
    )
    .bind(device_id)
    .bind(user.user_id)
    .bind(detect_device_type(&req.device_type))
    .bind(&req.device_type)
    .bind(&hostname)
    .bind(&tunnel_id)
    .bind(serde_json::to_value(&credentials)?)
    .bind(&registration_code_hash)
    .bind(registration_expires_at)
    .execute(pool.get_ref())
    .await?;

    // 5. Generate setup script based on platform
    let setup_script = generate_setup_script(
        &req.device_type,
        &tunnel_id,
        &credentials,
        &hostname,
        &registration_code,
    );

    Ok(HttpResponse::Ok().json(DeviceSetupResponse {
        setup_script,
        tunnel_id,
        tunnel_credentials: serde_json::to_value(&credentials)?,
        hostname,
        registration_code,
    }))
}

fn detect_device_type(platform: &str) -> &str {
    match platform {
        "mac_arm64" | "mac_x86_64" => "mac",
        "linux_arm64" if platform.contains("pi") => "raspberry_pi",
        "linux_arm64" | "linux_x86_64" => "linux_desktop",
        _ => "unknown"
    }
}
```

### 4. Update Config Service

**File: `src/config.rs`**

Add Cloudflare Tunnel credentials:

```rust
pub struct Config {
    // ... existing fields ...

    // Cloudflare Tunnel
    pub cloudflare_account_id: Option<String>,
    pub cloudflare_tunnel_token: Option<String>,  // Separate from DNS token
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // ... existing code ...

        let cloudflare_account_id = env::var("CLOUDFLARE_ACCOUNT_ID").ok();
        let cloudflare_tunnel_token = env::var("CLOUDFLARE_TUNNEL_TOKEN").ok();

        Ok(Config {
            // ... existing fields ...
            cloudflare_account_id,
            cloudflare_tunnel_token,
        })
    }
}
```

### 5. Update Main App

**File: `src/main.rs`**

```rust
use spoq_web_apis::services::cloudflare_tunnel::CloudflareTunnelService;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // ... existing setup ...

    // Create Cloudflare Tunnel service if configured
    let tunnel_service = if let (Some(account_id), Some(token), Some(zone_id)) = (
        &config.cloudflare_account_id,
        &config.cloudflare_tunnel_token,
        &config.cloudflare_zone_id,
    ) {
        tracing::info!("Cloudflare Tunnel service configured");
        Some(web::Data::new(CloudflareTunnelService::new(
            account_id.clone(),
            token.clone(),
            zone_id.clone(),
        )))
    } else {
        tracing::warn!("Cloudflare Tunnel not configured - device support disabled");
        None
    };

    HttpServer::new(move || {
        let mut app = App::new()
            // ... existing setup ...
            .app_data(pool.clone())
            .app_data(config_data.clone());

        // Add tunnel service if available
        if let Some(ref tunnel) = tunnel_service {
            app = app.app_data(tunnel.clone());
        }

        app.service(
            web::scope("/api")
                .service(
                    web::scope("/device")
                        .route("/setup", web::post().to(handlers::device::setup_device))
                        .route("/status", web::get().to(handlers::device::get_status))
                )
                // ... existing routes ...
        )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1)

**Goal:** Get Conductor working on macOS with environment variable support

**Tasks:**
1. ✅ Update Conductor to support environment variables
2. ✅ Add `--config` CLI flag support
3. ✅ Build macOS binaries (Intel + ARM)
4. ✅ Test Conductor on Mac with custom config paths
5. ✅ Update download service to serve macOS binaries

**Deliverables:**
- Conductor runs on macOS from `~/.spoq/`
- Config reads from `~/Library/Application Support/Spoq/`
- Binaries available at `download.spoq.dev/conductor/download/darwin-{x86_64,arm64}`

### Phase 2: Backend Integration (Week 1-2)

**Goal:** Backend can create tunnels and provision local devices

**Tasks:**
1. ✅ Add Cloudflare Tunnel service
2. ✅ Create `/api/device/setup` endpoint
3. ✅ Generate setup scripts for macOS
4. ✅ Database schema updates
5. ✅ Test tunnel creation and DNS

**Deliverables:**
- API can create Cloudflare Tunnels
- Returns setup script with embedded credentials
- DNS automatically points to tunnel

### Phase 3: CLI Integration (Week 2)

**Goal:** CLI can run `spoq init` and setup local device

**Tasks:**
1. ✅ Add `spoq init` command
2. ✅ Detect device type automatically
3. ✅ Download and install Conductor + cloudflared
4. ✅ Create launchd plists for macOS
5. ✅ Test end-to-end flow

**Deliverables:**
- `spoq init` works on macOS
- Services auto-start on login
- Device accessible at `https://username.spoq.dev`

### Phase 4: Additional Platforms (Week 3+)

**Goal:** Support Raspberry Pi and Linux desktops

**Tasks:**
1. ✅ Build ARM64 binaries for Raspberry Pi
2. ✅ Create systemd setup scripts
3. ✅ Test on Raspberry Pi 4/5
4. ✅ Test on Ubuntu Desktop
5. ✅ Documentation for each platform

**Deliverables:**
- Works on Raspberry Pi
- Works on Ubuntu/Debian Desktop
- Platform-specific docs

---

## Testing Strategy

### Local Testing (Development)

**Test Matrix:**

| Platform | Device | Test Status |
|----------|--------|-------------|
| macOS Intel | MacBook Pro 2019 | ⏳ Pending |
| macOS Apple Silicon | MacBook Air M2 | ⏳ Pending |
| Linux x86_64 | Ubuntu 22.04 Desktop | ⏳ Pending |
| Raspberry Pi | Pi 4 Model B (4GB) | ⏳ Pending |
| VPS | Hostinger Ubuntu 22.04 | ✅ Working |

**Test Checklist:**

```bash
# For each platform:

1. Install CLI
   ✓ curl -fsSL https://spoq.dev/install.sh | bash

2. Run init
   ✓ spoq init
   ✓ Authenticates via device flow
   ✓ Detects platform correctly
   ✓ Prompts for local device vs VPS

3. Local device setup
   ✓ Downloads correct binaries
   ✓ Creates config files
   ✓ Sets up services (launchd/systemd)
   ✓ Starts services

4. Verify connectivity
   ✓ curl https://username.spoq.dev/health
   ✓ Returns {"status":"healthy"}
   ✓ SSL certificate valid

5. Service management
   ✓ spoq service status (shows running)
   ✓ spoq service restart (restarts successfully)
   ✓ spoq service stop (stops services)
   ✓ spoq service start (starts again)
   ✓ spoq service logs (shows logs)

6. CLI commands
   ✓ spoq ask "test question" (works)
   ✓ spoq run "task" (works)

7. Persistence
   ✓ Reboot device
   ✓ Services auto-start
   ✓ Still accessible externally
```

### Integration Testing

**Test tunnel reliability:**
```bash
# Stress test
for i in {1..1000}; do
  curl -s https://alice.spoq.dev/health > /dev/null
  if [ $? -ne 0 ]; then
    echo "Request $i failed"
  fi
done
```

**Test network conditions:**
- Device sleep/wake (macOS)
- WiFi network change
- VPN connection
- Airplane mode → reconnect

**Expected:** Tunnel reconnects automatically within 10 seconds

---

## Security Considerations

### Tunnel Credentials

**Storage:**
- macOS: `~/Library/Application Support/Spoq/tunnel-credentials.json` (600 permissions)
- Linux: `~/.spoq/config/tunnel-credentials.json` (600 permissions)

**Protection:**
- File permissions: 600 (owner read/write only)
- Never logged or transmitted except to Cloudflare
- Rotatable via API

### Local Conductor Binding

**VPS (Public):**
```toml
[server]
host = "0.0.0.0"  # Accept connections from Caddy
port = 8080
```

**Local Device (Private):**
```toml
[server]
host = "127.0.0.1"  # Only localhost
port = 8080
```

**Why:** On local devices, only cloudflared should access Conductor. External access goes through tunnel.

### Tunnel Revocation

User can revoke access:
```bash
$ spoq service stop
$ spoq device remove
```

Backend deletes tunnel via API:
```rust
tunnel_service.delete_tunnel(&tunnel_id).await?;
```

DNS record removed, device no longer accessible.

---

## Environment Variables (Backend)

Add to Railway/production:

```bash
# Cloudflare Tunnel (separate from DNS)
CLOUDFLARE_ACCOUNT_ID=xxx
CLOUDFLARE_TUNNEL_TOKEN=xxx  # Needs tunnel:edit permission
CLOUDFLARE_ZONE_ID=xxx       # For spoq.dev (already have)
```

**Create Cloudflare API Token:**
1. Go to Cloudflare Dashboard
2. My Profile → API Tokens → Create Token
3. Use template: "Edit Cloudflare Tunnels"
4. Permissions:
   - Account → Cloudflare Tunnel → Edit
   - Zone → DNS → Edit (for CNAME creation)
5. Zone Resources: Include → Specific zone → spoq.dev

---

## Rollout Plan

### Beta Testing

**Week 1:** Internal testing
- Test on our own Macs
- Fix any issues

**Week 2:** Limited beta
- 10-20 trusted users
- Gather feedback
- Monitor tunnel stability

**Week 3:** Public beta
- Open to all users
- Monitor Cloudflare usage
- Gather analytics

### Success Metrics

- [ ] 95%+ tunnel uptime
- [ ] < 5 seconds reconnect time after network change
- [ ] Setup completes in < 2 minutes
- [ ] Zero manual configuration needed
- [ ] Works on all major platforms

---

## Open Questions

1. **Conductor wake-on-demand:** Should we implement logic to wake Conductor when tunnel receives requests?
2. **Multiple devices per user:** Allow alice-mac.spoq.dev and alice-pi.spoq.dev simultaneously?
3. **Free tier limits:** What happens if a user creates/deletes tunnels repeatedly? Rate limiting?
4. **Windows native support:** WSL2 works, but native Windows binary needed?
5. **Offline handling:** How long should tunnel credentials remain valid if device is offline for weeks?

---

## Resources

**Cloudflare Tunnel Documentation:**
- API: https://developers.cloudflare.com/api/operations/cloudflare-tunnel-create-a-cloudflare-tunnel
- Tunnels: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/

**Rust Cross-Compilation:**
- cross: https://github.com/cross-rs/cross
- Targets: https://doc.rust-lang.org/nightly/rustc/platform-support.html

**Platform Guides:**
- launchd: https://www.launchd.info/
- systemd: https://www.freedesktop.org/software/systemd/man/systemd.service.html

---

## Summary

**Conductor Changes:** ~4-6 hours
- Add environment variable support
- Add `--config` CLI flag
- Build multi-platform binaries
- Test on each platform

**Backend Changes:** ~1 week
- Cloudflare Tunnel service
- Device setup endpoint
- Database schema updates
- Setup script generation

**Total MVP:** 1-2 weeks for macOS support, 2-3 weeks for all platforms

**Key Insight:** Most of the work is backend/infra. Conductor needs minimal changes - just flexible config paths and multi-platform builds.
