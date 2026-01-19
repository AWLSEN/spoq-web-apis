# Hostinger VPS Integration

## Overview

This document outlines the integration with Hostinger's VPS API for automated provisioning.

## API Base URL

```
https://developers.hostinger.com
```

## Authentication

```
Authorization: Bearer <API_KEY>
```

---

## Available VPS Plans

| Plan | vCPU | RAM | Disk | Bandwidth | Monthly Price | First Month |
|------|------|-----|------|-----------|---------------|-------------|
| **KVM 1** | 1 | 4 GB | 50 GB | 4 TB | $13.99 | $4.99 |
| **KVM 2** | 2 | 8 GB | 100 GB | 8 TB | $17.99 | $6.99 |
| **KVM 4** | 4 | 16 GB | 200 GB | 16 TB | $29.99 | $9.99 |
| **KVM 8** | 8 | 32 GB | 400 GB | 32 TB | $59.99 | $19.99 |

**Recommendation for MVP:** Start with **KVM 1** ($13.99/mo) - sufficient for single-user AI orchestration.

### Catalog Item IDs

```
hostingercom-vps-kvm1-usd-1m   # KVM 1 monthly
hostingercom-vps-kvm2-usd-1m   # KVM 2 monthly
hostingercom-vps-kvm4-usd-1m   # KVM 4 monthly
hostingercom-vps-kvm8-usd-1m   # KVM 8 monthly
```

---

## Data Centers

| ID | Code | City | Country | Continent |
|----|------|------|---------|-----------|
| 11 | bnk | Vilnius | Lithuania | Europe |
| 9 | phx | Phoenix | USA | North America |
| 13 | mum | Mumbai | India | Asia |
| 14 | asc | São Paulo | Brazil | South America |
| 15 | int | Paris | France | Europe |
| 17 | bos | Boston | USA | North America |
| 18 | fast | Manchester | UK | Europe |
| 19 | fra | Frankfurt | Germany | Europe |
| 20 | dci | Jakarta | Indonesia | Asia |
| 21 | kul | Kuala Lumpur | Malaysia | Asia |

**Recommendation:** Default to nearest location based on user's signup IP.

---

## OS Templates

| ID | Name | Recommendation |
|----|------|----------------|
| 1007 | **Ubuntu 22.04 LTS** | **Recommended** - Stable, long-term support until 2027 |
| 1002 | Debian 11 | Good alternative |
| 1012 | CentOS 9 Stream | Rolling release, less stable |
| 1013 | Rocky Linux 8 | RHEL-compatible |
| 1014 | Rocky Linux 9 | RHEL-compatible |
| 1015 | AlmaLinux 8 | RHEL-compatible |
| 1016 | AlmaLinux 9 | RHEL-compatible |

**Decision:** Use **Ubuntu 22.04 LTS (ID: 1007)** for all VPS provisioning.

---

## API Endpoints

### 1. Create VPS

```
POST /api/vps/v1/virtual-machines
```

**Request Body:**

```json
{
  "item_id": "hostingercom-vps-kvm1-usd-1m",
  "payment_method_id": 40857526,
  "setup": {
    "template_id": 1007,
    "data_center_id": 9,
    "hostname": "alice.spoq.dev",
    "password": "SecurePassword123!",
    "post_install_script_id": 12345,
    "enable_backups": true,
    "public_key": {
      "name": "spoq-deploy",
      "key": "ssh-rsa AAAA..."
    }
  }
}
```

**Response:**

```json
{
  "order_id": "123456",
  "virtual_machine_id": 789012,
  "status": "processing"
}
```

### 2. Create Post-Install Script

```
POST /api/vps/v1/post-install-scripts
```

**Request Body:**

```json
{
  "name": "spoq-conductor-setup",
  "content": "#!/bin/bash\n\n# Spoq VPS provisioning script\nset -e\n..."
}
```

**Response:**

```json
{
  "id": 12345,
  "name": "spoq-conductor-setup",
  "created_at": "2024-01-15T10:00:00Z"
}
```

### 3. List VPS Instances

```
GET /api/vps/v1/virtual-machines
```

### 4. Get VPS Details

```
GET /api/vps/v1/virtual-machines/{id}
```

### 5. VPS Actions

```
POST /api/vps/v1/virtual-machines/{id}/start
POST /api/vps/v1/virtual-machines/{id}/stop
POST /api/vps/v1/virtual-machines/{id}/restart
POST /api/vps/v1/virtual-machines/{id}/recreate
```

### 6. Get VPS Status

```
GET /api/vps/v1/virtual-machines/{id}/actions
```

Returns list of actions and their status (running, completed, failed).

---

## Provisioning Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    VPS Provisioning Flow                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Create/Update Post-Install Script                            │
│    POST /api/vps/v1/post-install-scripts                        │
│    - Contains conductor install, config, systemd setup          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Purchase VPS                                                  │
│    POST /api/vps/v1/virtual-machines                            │
│    - Include post_install_script_id in setup                    │
│    - Use template_id 1007 (Ubuntu 22.04)                        │
│    - Select data_center_id based on user location               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Poll for Completion                                           │
│    GET /api/vps/v1/virtual-machines/{id}                        │
│    - Wait for state = "running"                                 │
│    - Get IP address                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Configure DNS                                                 │
│    - Add A record: {username}.spoq.dev → IP                     │
│    - Via Cloudflare API                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Verify Setup                                                  │
│    - Wait for SSL cert (Caddy auto-provisions)                  │
│    - Health check: GET https://{hostname}/health                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Mark Ready                                                    │
│    - Update user_vps.status = 'ready'                           │
│    - Show credentials to user                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Post-Install Script Template

```bash
#!/bin/bash
# Spoq VPS Provisioning Script
# Executed automatically by Hostinger after VPS creation
# Output logged to /post_install.log

set -e

# Variables injected at runtime
SSH_PASSWORD="__SSH_PASSWORD__"
OWNER_ID="__OWNER_ID__"
JWT_SECRET="__JWT_SECRET__"
HOSTNAME="__HOSTNAME__"
CONDUCTOR_URL="__CONDUCTOR_URL__"
CLI_URL="__CLI_URL__"

echo "=== Spoq VPS Provisioning ==="

# 1. System updates
apt-get update && apt-get upgrade -y

# 2. Install dependencies
apt-get install -y curl jq ca-certificates

# 3. Create spoq user
useradd -m -s /bin/bash spoq
echo "spoq:$SSH_PASSWORD" | chpasswd
usermod -aG sudo spoq
echo "spoq ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/spoq

# 4. Download and install Conductor
curl -sSL "$CONDUCTOR_URL" -o /usr/local/bin/conductor
chmod +x /usr/local/bin/conductor

# 5. Configure Conductor
mkdir -p /etc/conductor
cat > /etc/conductor/config.toml << EOF
[server]
host = "0.0.0.0"
port = 8080

[auth]
owner_id = "$OWNER_ID"
jwt_secret = "$JWT_SECRET"
EOF

# 6. Create VPS marker file
mkdir -p /etc/spoq
cat > /etc/spoq/vps.marker << EOF
{
  "vps": true,
  "conductor": "http://localhost:8080",
  "version": "1.0"
}
EOF

# 7. Create Conductor systemd service
cat > /etc/systemd/system/conductor.service << 'SERVICEEOF'
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
SERVICEEOF

systemctl daemon-reload
systemctl enable conductor
systemctl start conductor

# 8. Download and install Spoq CLI
curl -sSL "$CLI_URL" -o /usr/local/bin/spoq
chmod +x /usr/local/bin/spoq

# 9. Setup welcome message
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

# 10. Configure firewall
ufw allow 22    # SSH
ufw allow 80    # HTTP (for Let's Encrypt verification)
ufw allow 443   # HTTPS
ufw --force enable

# 11. Install Caddy
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy

# 12. Configure Caddy
cat > /etc/caddy/Caddyfile << EOF
$HOSTNAME {
    reverse_proxy localhost:8080
}
EOF

systemctl enable caddy
systemctl restart caddy

echo "=== Provisioning Complete ==="
echo "Conductor: $(systemctl is-active conductor)"
echo "Caddy: $(systemctl is-active caddy)"
```

---

## Backend Implementation

### Database Migration

```sql
-- migrations/006_hostinger.sql

-- Store Hostinger-specific VPS metadata
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS hostinger_vm_id BIGINT;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS hostinger_order_id TEXT;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS plan_id TEXT;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS data_center_id INTEGER;

CREATE INDEX IF NOT EXISTS idx_user_vps_hostinger_vm_id ON user_vps(hostinger_vm_id);
```

### Rust Service: `src/services/hostinger.rs`

```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};

const HOSTINGER_API_BASE: &str = "https://developers.hostinger.com";

pub struct HostingerClient {
    client: Client,
    api_key: String,
}

#[derive(Serialize)]
pub struct CreateVpsRequest {
    pub item_id: String,
    pub payment_method_id: Option<i64>,
    pub setup: VpsSetup,
}

#[derive(Serialize)]
pub struct VpsSetup {
    pub template_id: i32,
    pub data_center_id: i32,
    pub hostname: Option<String>,
    pub password: Option<String>,
    pub post_install_script_id: Option<i64>,
    pub enable_backups: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
}

#[derive(Serialize)]
pub struct PublicKey {
    pub name: String,
    pub key: String,
}

#[derive(Deserialize)]
pub struct CreateVpsResponse {
    pub order_id: Option<String>,
    pub virtual_machine_id: Option<i64>,
    pub status: String,
}

#[derive(Deserialize)]
pub struct VirtualMachine {
    pub id: i64,
    pub state: String,
    pub hostname: String,
    pub ipv4: Option<Vec<IpAddress>>,
    pub plan: String,
}

#[derive(Deserialize)]
pub struct IpAddress {
    pub address: String,
}

impl HostingerClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    pub async fn create_vps(&self, req: CreateVpsRequest) -> Result<CreateVpsResponse, Error> {
        let response = self.client
            .post(format!("{}/api/vps/v1/virtual-machines", HOSTINGER_API_BASE))
            .bearer_auth(&self.api_key)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    pub async fn get_vps(&self, vm_id: i64) -> Result<VirtualMachine, Error> {
        let response = self.client
            .get(format!("{}/api/vps/v1/virtual-machines/{}", HOSTINGER_API_BASE, vm_id))
            .bearer_auth(&self.api_key)
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    pub async fn list_vps(&self) -> Result<Vec<VirtualMachine>, Error> {
        let response = self.client
            .get(format!("{}/api/vps/v1/virtual-machines", HOSTINGER_API_BASE))
            .bearer_auth(&self.api_key)
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    pub async fn create_post_install_script(&self, name: &str, content: &str) -> Result<PostInstallScript, Error> {
        let response = self.client
            .post(format!("{}/api/vps/v1/post-install-scripts", HOSTINGER_API_BASE))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({
                "name": name,
                "content": content
            }))
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    pub async fn start_vps(&self, vm_id: i64) -> Result<(), Error> {
        self.client
            .post(format!("{}/api/vps/v1/virtual-machines/{}/start", HOSTINGER_API_BASE, vm_id))
            .bearer_auth(&self.api_key)
            .send()
            .await?;

        Ok(())
    }

    pub async fn stop_vps(&self, vm_id: i64) -> Result<(), Error> {
        self.client
            .post(format!("{}/api/vps/v1/virtual-machines/{}/stop", HOSTINGER_API_BASE, vm_id))
            .bearer_auth(&self.api_key)
            .send()
            .await?;

        Ok(())
    }
}
```

### API Endpoints

```rust
// src/handlers/vps.rs

#[post("/api/vps/provision")]
async fn provision_vps(
    user: AuthenticatedUser,
    db: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
    req: web::Json<ProvisionRequest>,
) -> Result<HttpResponse, Error> {
    // 1. Check user doesn't already have a VPS
    // 2. Generate credentials
    // 3. Create post-install script
    // 4. Create VPS via Hostinger API
    // 5. Store in database
    // 6. Return pending status
}

#[get("/api/vps/status")]
async fn get_vps_status(
    user: AuthenticatedUser,
    db: web::Data<PgPool>,
    hostinger: web::Data<HostingerClient>,
) -> Result<HttpResponse, Error> {
    // 1. Get user's VPS from DB
    // 2. If pending, poll Hostinger for status
    // 3. If running + no IP, fetch IP from Hostinger
    // 4. Return current status
}
```

---

## CLI Testing Commands

For testing without frontend:

```bash
# List available plans
curl -X GET "https://developers.hostinger.com/api/billing/v1/catalog" \
  -H "Authorization: Bearer $HOSTINGER_API_KEY" | jq '.[] | select(.category == "VPS")'

# List data centers
curl -X GET "https://developers.hostinger.com/api/vps/v1/data-centers" \
  -H "Authorization: Bearer $HOSTINGER_API_KEY" | jq .

# List templates
curl -X GET "https://developers.hostinger.com/api/vps/v1/templates" \
  -H "Authorization: Bearer $HOSTINGER_API_KEY" | jq .

# Create post-install script
curl -X POST "https://developers.hostinger.com/api/vps/v1/post-install-scripts" \
  -H "Authorization: Bearer $HOSTINGER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-script", "content": "#!/bin/bash\necho hello"}'

# Create VPS (TEST - will charge!)
curl -X POST "https://developers.hostinger.com/api/vps/v1/virtual-machines" \
  -H "Authorization: Bearer $HOSTINGER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "item_id": "hostingercom-vps-kvm1-usd-1m",
    "setup": {
      "template_id": 1007,
      "data_center_id": 9,
      "password": "TestPassword123!",
      "enable_backups": false
    }
  }'

# List VPS instances
curl -X GET "https://developers.hostinger.com/api/vps/v1/virtual-machines" \
  -H "Authorization: Bearer $HOSTINGER_API_KEY" | jq .

# Get specific VPS
curl -X GET "https://developers.hostinger.com/api/vps/v1/virtual-machines/{vm_id}" \
  -H "Authorization: Bearer $HOSTINGER_API_KEY" | jq .
```

---

## Implementation Checklist

1. [ ] Add Hostinger service (`src/services/hostinger.rs`)
2. [ ] Add database migration for Hostinger fields
3. [ ] Create VPS provisioning endpoint
4. [ ] Create VPS status endpoint
5. [ ] Add post-install script generation
6. [ ] Add background job for polling VPS status
7. [ ] Integrate with Cloudflare DNS API
8. [ ] Add health check verification
9. [ ] Test full provisioning flow

---

## Environment Variables

```bash
# Add to .env
HOSTINGER_API_KEY=OcjL1s8fMuG0p0b080zFmdZK48xKlKgeFZAYOArN2f7709f8

# Default VPS settings
DEFAULT_VPS_PLAN=hostingercom-vps-kvm1-usd-1m
DEFAULT_VPS_TEMPLATE=1007
DEFAULT_VPS_DATACENTER=9
```
