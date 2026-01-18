# Spoq Architecture

## Overview

Spoq is a CLI tool (like Claude Code) that runs on the user's local machine and makes API calls to their personal VPS for AI orchestration.

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER'S COMPUTER                              │
│                                                                 │
│   $ spoq ask "help me with this code"                           │
│                                                                 │
│   CLI runs locally                                              │
│   Reads local files, understands context                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS API calls (JWT auth)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    USER'S PERSONAL VPS                          │
│                   (alice.spoq.dev)                              │
│                                                                 │
│   Runs Spoq backend API                                         │
│   Orchestrates AI agents                                        │
│   Stores user data, syncs files                                 │
│   Calls Claude/OpenAI/etc.                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Access Methods

| Platform | Method | Auth |
|----------|--------|------|
| Desktop/Laptop | Local CLI (`spoq`) | OAuth device flow → JWT |
| Mobile/Termius | SSH into VPS | Username + Password |

---

## User Flows

### 1. Signup Flow (Web)

```
┌──────────────────────────────────────────────────────────────────┐
│  STEP 1: Subscribe                                               │
├──────────────────────────────────────────────────────────────────┤
│  → User visits spoq.dev                                          │
│  → Clicks "Subscribe"                                            │
│  → Pays via Stripe                                               │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 2: Identity Verification                                   │
├──────────────────────────────────────────────────────────────────┤
│  → "Sign in with GitHub" (standard web OAuth)                    │
│  → Links payment to GitHub identity                              │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 3: Create SSH Password                                     │
├──────────────────────────────────────────────────────────────────┤
│  → User creates their own password (they'll remember it)         │
│  → Used for mobile/Termius SSH access                            │
│  → Requirements: 12+ chars, 1 number, 1 special                  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 4: VPS Provisioning                                        │
├──────────────────────────────────────────────────────────────────┤
│  → "Setting up your environment..."                              │
│  → Backend provisions VPS on Contabo/Hostinger                   │
│  → Configures SSH with user's password                           │
│  → Installs Spoq backend API                                     │
│  → Assigns hostname (alice.spoq.dev)                             │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 5: Show Credentials                                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  "Your environment is ready!"                                    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Desktop:                                                   │  │
│  │ curl -sSL https://spoq.dev/install.sh | bash               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Mobile (Termius):                                          │  │
│  │ Host: alice.spoq.dev                                       │  │
│  │ Username: spoq                                             │  │
│  │ Password: (what you just created)                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2. Desktop CLI Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  FIRST RUN: spoq init                                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  $ spoq init                                                     │
│                                                                  │
│  Visit this URL to authenticate:                                 │
│  https://spoq.dev/auth/verify?code=BLUE-FISH-TREE                │
│                                                                  │
│  Waiting... ✓ Authenticated!                                     │
│                                                                  │
│  Your VPS: alice.spoq.dev                                        │
│  Ready to use!                                                   │
│                                                                  │
│  Token saved to ~/.spoq/credentials                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  DAILY USE                                                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  $ spoq ask "explain this function"                              │
│                                                                  │
│  → CLI reads local files for context                             │
│  → Sends request to alice.spoq.dev/api/ask                       │
│  → Authorization: Bearer <jwt_token>                             │
│  → VPS orchestrates AI response                                  │
│  → Response displayed locally                                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3. Mobile/Termius Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  SSH ACCESS                                                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  In Termius:                                                     │
│  → Add new host                                                  │
│  → Host: alice.spoq.dev                                          │
│  → Username: spoq                                                │
│  → Password: (created during signup)                             │
│  → Save and connect                                              │
│                                                                  │
│  On VPS:                                                         │
│  $ spoq ask "help me with this"                                  │
│  (CLI is pre-installed, no auth needed - already on VPS)         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Authentication

### JWT Token Flow (Desktop CLI)

```
┌─────────────────────────────────────────────────────────────────┐
│                   CENTRAL BACKEND (spoq.dev)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   JWT_SECRET = "shared_secret_key"                              │
│                                                                 │
│   1. User completes OAuth device flow                           │
│   2. Backend signs JWT: { user_id, vps_hostname, exp }          │
│   3. Returns JWT to CLI                                         │
│   4. CLI stores in ~/.spoq/credentials                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Same secret configured during
                              │ VPS provisioning
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   USER'S VPS (alice.spoq.dev)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   JWT_SECRET = "shared_secret_key"                              │
│   OWNER_ID = "alice_user_id"                                    │
│                                                                 │
│   On each request:                                              │
│   1. Verify JWT signature                                       │
│   2. Check user_id matches OWNER_ID                             │
│   3. If valid → process request                                 │
│   4. If invalid → 403 Forbidden                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Security Layers

| Layer | Protection |
|-------|------------|
| HTTPS (TLS) | Encrypts all traffic |
| JWT Signature (HS256) | Can't forge tokens without secret |
| Token Expiration | Short-lived access tokens (1 hour) |
| Refresh Tokens | Long-lived, can be revoked |
| Owner Verification | VPS only accepts tokens from its owner |
| VPS Isolation | Each user has separate VPS |

### Future Upgrade: RS256 (Asymmetric)

```
Central Backend: PRIVATE_KEY (signs tokens)
User VPS: PUBLIC_KEY only (verifies, can't create)

Benefits:
- VPS compromise doesn't leak signing capability
- Can rotate keys centrally
```

---

## Database Schema

### users

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id TEXT UNIQUE NOT NULL,
    username TEXT,
    email TEXT,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### subscriptions

```sql
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',  -- active, cancelled, expired
    plan TEXT NOT NULL DEFAULT 'basic',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (user_id)
);
```

### user_vps

```sql
CREATE TABLE user_vps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- VPS details
    provider TEXT NOT NULL,  -- 'contabo' or 'hostinger'
    provider_instance_id TEXT,
    hostname TEXT UNIQUE NOT NULL,  -- alice.spoq.dev
    ip_address INET,
    region TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
        -- pending, provisioning, ready, failed, terminated

    -- SSH credentials
    ssh_username TEXT NOT NULL DEFAULT 'spoq',
    ssh_password_hash TEXT NOT NULL,  -- argon2 hash of user-created password

    -- JWT validation config (set during provisioning)
    jwt_secret TEXT NOT NULL,  -- same as central, for HS256

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ready_at TIMESTAMPTZ,

    UNIQUE (user_id)  -- one VPS per user
);

CREATE INDEX idx_user_vps_hostname ON user_vps(hostname);
CREATE INDEX idx_user_vps_status ON user_vps(status);
```

### device_grants (existing - for CLI OAuth)

```sql
CREATE TABLE device_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code TEXT UNIQUE NOT NULL,
    word_code TEXT UNIQUE NOT NULL,
    hostname TEXT,
    user_id UUID REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### refresh_tokens (existing)

```sql
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## API Endpoints

### Central Backend (spoq.dev)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/github` | GET | Initiate GitHub OAuth (web) |
| `/auth/github/callback` | GET | GitHub OAuth callback |
| `/auth/device` | POST | CLI initiates device flow |
| `/auth/verify` | GET | Device verification page |
| `/auth/authorize` | POST | Approve/deny device |
| `/auth/device/token` | POST | CLI polls for token |
| `/auth/refresh` | POST | Refresh access token |
| `/auth/revoke` | POST | Revoke refresh token |
| `/api/vps/provision` | POST | Trigger VPS provisioning |
| `/api/vps/status` | GET | Check VPS status |
| `/api/subscription/create` | POST | Create Stripe subscription |
| `/api/subscription/webhook` | POST | Stripe webhook handler |

### User's VPS (alice.spoq.dev)

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `/api/ask` | POST | Send query to AI | JWT |
| `/api/run` | POST | Execute command | JWT |
| `/api/sync` | POST | Sync files | JWT |
| `/api/status` | GET | VPS status | JWT |
| `/health` | GET | Health check | None |

---

## VPS Provisioning

### Provider APIs

**Contabo:**
- Docs: https://api.contabo.com/
- Create instance: `POST /v1/compute/instances`
- Auth: OAuth2 client credentials

**Hostinger:**
- Docs: https://developers.hostinger.com/
- Similar REST API

### Provisioning Steps

```
1. User completes signup (payment + OAuth + password)

2. Backend calls provider API to create VPS
   - Region selection (nearest to user)
   - Base image (Ubuntu 22.04)
   - Size (based on subscription plan)

3. Wait for VPS to be ready (poll provider API)

4. Configure VPS via SSH/cloud-init:
   a. Create user 'spoq' with sudo
   b. Set SSH password (user-provided, hashed)
   c. Install Spoq backend API
   d. Configure JWT_SECRET and OWNER_ID
   e. Set up firewall (allow 22, 443)
   f. Configure SSL certificate (Let's Encrypt)

5. Set up DNS
   - Add A record: alice.spoq.dev → VPS IP

6. Mark VPS as ready in database

7. Notify user (show credentials on web)
```

### VPS Configuration Script

```bash
#!/bin/bash
# Runs on VPS during provisioning

# Create spoq user
useradd -m -s /bin/bash spoq
echo "spoq:$SSH_PASSWORD" | chpasswd
usermod -aG sudo spoq

# Install Spoq backend
curl -sSL https://spoq.dev/install-backend.sh | bash

# Configure
cat > /etc/spoq/config.json << EOF
{
  "owner_id": "$OWNER_ID",
  "jwt_secret": "$JWT_SECRET",
  "api_port": 8080
}
EOF

# Start service
systemctl enable spoq-api
systemctl start spoq-api

# Firewall
ufw allow 22
ufw allow 443
ufw enable
```

---

## VPS Software Components

Two things must be installed on each user's VPS:

| Component | Purpose | Used By |
|-----------|---------|---------|
| **Conductor** | Backend API server (handles AI orchestration) | Desktop CLI (via HTTPS) |
| **Spoq CLI/TUI** | Terminal interface | Mobile/SSH users |

### Conductor (Backend Service)

The conductor is the backend that:
- Receives API calls from the desktop CLI
- Orchestrates AI agents
- Manages file sync
- Handles all the heavy lifting

**Access Model:**

```
┌─────────────────────────────────────────────────────────────────┐
│                           VPS                                   │
│                                                                 │
│   Conductor binds to 0.0.0.0:8080                               │
│                                                                 │
│   ┌───────────────────────────────────────────────────────────┐ │
│   │ localhost:8080                                            │ │
│   │ → SSH/mobile users (already authenticated via SSH)        │ │
│   │ → NO JWT needed - trust localhost                         │ │
│   └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│   ┌───────────────────────────────────────────────────────────┐ │
│   │ Reverse Proxy (nginx/caddy) :443 → localhost:8080         │ │
│   │ → Desktop CLI connects via https://alice.spoq.dev         │ │
│   │ → JWT REQUIRED for all requests                           │ │
│   └───────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Access From | Endpoint | Auth Required |
|-------------|----------|---------------|
| SSH user (on VPS) | `http://localhost:8080` | No - already SSH'd |
| Desktop CLI (remote) | `https://alice.spoq.dev` | Yes - JWT |

**Conductor Auth Logic:**

```rust
fn check_auth(req: &Request) -> Result<(), AuthError> {
    // Trust localhost (SSH users already authenticated)
    if req.peer_addr().ip().is_loopback() {
        return Ok(());
    }

    // Remote requests require JWT
    let token = req.header("Authorization")?;
    validate_jwt(token)?;
    Ok(())
}
```

**Installation:**

```bash
# Download conductor binary
curl -sSL https://spoq.dev/releases/conductor-linux-amd64 -o /usr/local/bin/conductor
chmod +x /usr/local/bin/conductor

# Create config directory
mkdir -p /etc/conductor

# Write config
cat > /etc/conductor/config.toml << EOF
[server]
host = "0.0.0.0"
port = 8080

[auth]
owner_id = "$OWNER_ID"
jwt_secret = "$JWT_SECRET"

[ai]
# AI provider configs
EOF
```

**Systemd Service (`/etc/systemd/system/conductor.service`):**

```ini
[Unit]
Description=Spoq Conductor - AI Backend Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=spoq
Group=spoq
WorkingDirectory=/home/spoq
ExecStart=/usr/local/bin/conductor --config /etc/conductor/config.toml
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Environment
Environment="RUST_LOG=info"
EnvironmentFile=-/etc/conductor/env

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/home/spoq/.conductor

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=conductor

[Install]
WantedBy=multi-user.target
```

**Enable and start:**

```bash
systemctl daemon-reload
systemctl enable conductor
systemctl start conductor

# Verify
systemctl status conductor
journalctl -u conductor -f  # View logs
```

### Spoq CLI/TUI

The same CLI binary works on both VPS and user's Mac. It detects where it's running and adjusts behavior.

**Environment Detection:**

```
┌─────────────────────────────────────────────────────────────────┐
│                         spoq ask "..."                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ /etc/spoq/vps.marker│
                   │      exists?        │
                   └─────────────────────┘
                      │              │
                     YES             NO
                      │              │
                      ▼              ▼
              ┌──────────────┐  ┌──────────────────────┐
              │ ON VPS       │  │ ON USER'S MAC        │
              │ localhost    │  │ Load ~/.spoq/creds   │
              │ No auth      │  │ Use JWT + hostname   │
              └──────────────┘  └──────────────────────┘
```

**CLI Config Logic:**

```rust
use std::path::Path;

struct ApiConfig {
    endpoint: String,
    auth_token: Option<String>,
}

fn get_api_config() -> Result<ApiConfig> {
    // 1. Check if we're on the VPS (marker file exists)
    if Path::new("/etc/spoq/vps.marker").exists() {
        // On VPS - use localhost, no auth needed
        return Ok(ApiConfig {
            endpoint: "http://localhost:8080".into(),
            auth_token: None,
        });
    }

    // 2. On user's local machine - need JWT
    let creds_path = dirs::home_dir()
        .unwrap()
        .join(".spoq/credentials");

    if !creds_path.exists() {
        return Err(anyhow!("Not authenticated. Run 'spoq init' first."));
    }

    let credentials: Credentials = load_json(&creds_path)?;

    // Check if token expired, refresh if needed
    if credentials.is_expired() {
        let new_token = refresh_token(&credentials.refresh_token)?;
        save_credentials(&creds_path, &new_token)?;
        return Ok(ApiConfig {
            endpoint: credentials.vps_hostname,
            auth_token: Some(new_token.access_token),
        });
    }

    Ok(ApiConfig {
        endpoint: credentials.vps_hostname,
        auth_token: Some(credentials.access_token),
    })
}
```

**File Locations:**

| File | Location | Purpose |
|------|----------|---------|
| VPS marker | `/etc/spoq/vps.marker` | Signals "we're on VPS, use localhost" |
| Credentials | `~/.spoq/credentials` | JWT tokens + hostname (Mac only) |

**VPS Marker File (`/etc/spoq/vps.marker`):**

Created during VPS provisioning:

```json
{
  "vps": true,
  "conductor": "http://localhost:8080",
  "version": "1.0"
}
```

**Credentials File (`~/.spoq/credentials`):**

Created after `spoq init` on user's Mac:

```json
{
  "vps_hostname": "https://alice.spoq.dev",
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "spoq_abc123xyz...",
  "expires_at": "2024-01-15T10:30:00Z",
  "user_id": "alice-uuid"
}
```

**Why Marker File, Not Network Probing?**

| Approach | Problem |
|----------|---------|
| Try localhost first, fallback | Adds latency (timeout wait) |
| Check both in parallel | Complexity, race conditions |
| **Check marker file** | Instant, deterministic, clean |

---

### CLI Installation (VPS vs Mac)

**On VPS (during provisioning):**

```bash
# Download CLI binary
curl -sSL https://spoq.dev/releases/spoq-linux-amd64 -o /usr/local/bin/spoq
chmod +x /usr/local/bin/spoq

# Create VPS marker file
mkdir -p /etc/spoq
cat > /etc/spoq/vps.marker << 'EOF'
{
  "vps": true,
  "conductor": "http://localhost:8080",
  "version": "1.0"
}
EOF

# Setup welcome message for SSH users
cat > /home/spoq/.bashrc << 'BASHRC'
export PATH="/usr/local/bin:$PATH"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Welcome to Spoq!                       ║"
echo "║                                                           ║"
echo "║  Commands:                                                ║"
echo "║    spoq ask \"your question\"  - Ask AI anything            ║"
echo "║    spoq run                  - Run a task                 ║"
echo "║    spoq help                 - Show all commands          ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
BASHRC

chown spoq:spoq /home/spoq/.bashrc
```

**On Mac (user runs install script):**

```bash
# install.sh - downloaded via: curl -sSL https://spoq.dev/install.sh | bash

#!/bin/bash
set -e

# Detect OS/arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in
    x86_64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
esac

# Download binary
curl -sSL "https://spoq.dev/releases/spoq-${OS}-${ARCH}" -o /usr/local/bin/spoq
chmod +x /usr/local/bin/spoq

# Create config directory
mkdir -p ~/.spoq

echo "✓ Spoq installed!"
echo ""
echo "Run 'spoq init' to authenticate."
```

### Complete VPS Provisioning Script

```bash
#!/bin/bash
# /opt/spoq/provision.sh
# Run during VPS setup

set -e

# Variables (passed from provisioning system)
SSH_PASSWORD="${SSH_PASSWORD}"
OWNER_ID="${OWNER_ID}"
JWT_SECRET="${JWT_SECRET}"
HOSTNAME="${HOSTNAME}"

echo "=== Spoq VPS Provisioning ==="

# 1. System updates
apt-get update && apt-get upgrade -y

# 2. Create spoq user
useradd -m -s /bin/bash spoq
echo "spoq:$SSH_PASSWORD" | chpasswd
usermod -aG sudo spoq

# 3. Install Conductor
echo "Installing Conductor..."
curl -sSL https://spoq.dev/releases/conductor-linux-amd64 -o /usr/local/bin/conductor
chmod +x /usr/local/bin/conductor

mkdir -p /etc/conductor
cat > /etc/conductor/config.toml << EOF
[server]
host = "0.0.0.0"
port = 8080

[auth]
owner_id = "$OWNER_ID"
jwt_secret = "$JWT_SECRET"
EOF

# 4. Install Conductor systemd service
cat > /etc/systemd/system/conductor.service << 'EOF'
[Unit]
Description=Spoq Conductor - AI Backend Service
After=network.target

[Service]
Type=simple
User=spoq
Group=spoq
ExecStart=/usr/local/bin/conductor --config /etc/conductor/config.toml
Restart=always
RestartSec=5
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable conductor
systemctl start conductor

# 5. Install Spoq CLI/TUI
echo "Installing Spoq CLI..."
curl -sSL https://spoq.dev/releases/spoq-linux-amd64 -o /usr/local/bin/spoq
chmod +x /usr/local/bin/spoq

# 6. Setup welcome message
cat > /home/spoq/.bashrc << 'BASHRC'
export PATH="/usr/local/bin:$PATH"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Welcome to Spoq!                       ║"
echo "║                                                           ║"
echo "║  Commands:                                                ║"
echo "║    spoq ask \"your question\"  - Ask AI anything            ║"
echo "║    spoq run                  - Run a task                 ║"
echo "║    spoq help                 - Show all commands          ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
BASHRC

chown spoq:spoq /home/spoq/.bashrc

# 7. Firewall
ufw allow 22    # SSH
ufw allow 443   # HTTPS (conductor API)
ufw --force enable

# 8. Install Caddy (reverse proxy + auto SSL)
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy

# 9. Configure Caddy reverse proxy
cat > /etc/caddy/Caddyfile << EOF
$HOSTNAME {
    reverse_proxy localhost:8080
}
EOF

systemctl enable caddy
systemctl restart caddy

echo "=== Provisioning Complete ==="
echo "Conductor status: $(systemctl is-active conductor)"
echo "Caddy status: $(systemctl is-active caddy)"
```

### Reverse Proxy (Caddy)

Caddy handles:
- HTTPS termination (auto Let's Encrypt)
- Proxies `https://alice.spoq.dev` → `localhost:8080`

**Caddyfile (`/etc/caddy/Caddyfile`):**

```
alice.spoq.dev {
    reverse_proxy localhost:8080
}
```

That's it. Caddy auto-provisions SSL certificates.

### Monitoring & Health Checks

```bash
# Check conductor is running
systemctl is-active conductor

# View conductor logs
journalctl -u conductor -f

# Health endpoint
curl http://localhost:8080/health

# Restart if needed
systemctl restart conductor
```

### Auto-Recovery

The systemd configuration ensures:

| Scenario | Behavior |
|----------|----------|
| VPS reboots | Conductor auto-starts |
| Conductor crashes | Restarts within 5 seconds |
| Repeated crashes | Stops after 3 attempts in 60 seconds, then retries |
| Manual stop | Stays stopped until manually started |

---

## Subscription Lifecycle

```
┌─────────────────┐
│    ACTIVE       │ ← User pays, VPS running
└────────┬────────┘
         │
         │ Payment fails / User cancels
         ▼
┌─────────────────┐
│   CANCELLED     │ ← Grace period (7 days)
└────────┬────────┘
         │
         │ Grace period ends
         ▼
┌─────────────────┐
│    EXPIRED      │ ← VPS terminated, data deleted
└─────────────────┘
```

### Webhook Handling

```
Stripe webhook: subscription.updated
  → If status = cancelled → start grace period
  → If status = active → resume VPS

Stripe webhook: subscription.deleted
  → Terminate VPS
  → Delete user data
```

---

## File Structure

```
spoq-web-apis/
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── auth.rs          # OAuth, device flow
│   │   ├── subscription.rs  # Stripe integration
│   │   └── vps.rs           # VPS provisioning
│   ├── services/
│   │   ├── mod.rs
│   │   ├── device.rs        # Device code generation
│   │   ├── github.rs        # GitHub OAuth
│   │   ├── jwt.rs           # Token generation/validation
│   │   ├── vps_provider.rs  # Contabo/Hostinger API
│   │   └── stripe.rs        # Payment processing
│   ├── middleware/
│   │   └── auth.rs          # JWT validation
│   └── models/
│       └── mod.rs
├── migrations/
│   ├── 001_users.sql
│   ├── 002_refresh_tokens.sql
│   ├── 003_device_grants.sql
│   ├── 004_subscriptions.sql
│   └── 005_user_vps.sql
├── docs/
│   └── architecture.md
├── Cargo.toml
└── Dockerfile
```

---

## Environment Variables

```bash
# GitHub OAuth
GITHUB_CLIENT_ID=xxx
GITHUB_CLIENT_SECRET=xxx
GITHUB_REDIRECT_URI=https://spoq.dev/auth/github/callback

# JWT
JWT_SECRET=xxx
JWT_ACCESS_TOKEN_EXPIRY_SECS=3600
JWT_REFRESH_TOKEN_EXPIRY_DAYS=30

# Database
DATABASE_URL=postgres://user:pass@host/db

# Stripe
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

# VPS Provider (Contabo)
CONTABO_CLIENT_ID=xxx
CONTABO_CLIENT_SECRET=xxx
CONTABO_API_USER=xxx
CONTABO_API_PASSWORD=xxx

# Or Hostinger
HOSTINGER_API_KEY=xxx

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
BASE_URL=https://spoq.dev
```

---

## Summary

| Component | Technology | Purpose |
|-----------|------------|---------|
| Central Backend | Rust/Actix | Auth, payments, VPS orchestration |
| User VPS | Ubuntu + Spoq API | AI execution environment |
| CLI | Rust | Local interface, file context |
| Database | PostgreSQL | Users, subscriptions, VPS records |
| Payments | Stripe | Subscription management |
| VPS Provider | Contabo/Hostinger | Infrastructure |
| DNS | Cloudflare/Route53 | *.spoq.dev routing |
