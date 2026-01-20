# Device Expansion: Mac, Raspberry Pi, and Beyond

> **Status:** Future Expansion (Post-MVP)
> **Prerequisite:** Core VPS architecture complete

## Overview

Extend Spoq to run on any device - not just cloud VPS. Users install the CLI, and we handle everything: tunnel creation, DNS, SSL, service management.

```
┌─────────────────────────────────────────────────────────────────┐
│                         SUPPORTED DEVICES                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ✓ Cloud VPS (Hostinger)      - Current MVP                    │
│   ✓ Mac (Intel/Apple Silicon)  - Future                         │
│   ✓ Raspberry Pi               - Future                         │
│   ✓ Linux Desktop/Server       - Future                         │
│   ✓ Windows (WSL2)             - Future                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Architecture

### The Challenge

Local devices (Mac, Pi) are typically behind NAT:
- No public IP address
- Can't receive incoming connections
- User would need to configure port forwarding (bad UX)

### The Solution: Cloudflare Tunnel

Cloudflare Tunnel creates an outbound connection from the device to Cloudflare's edge network. No inbound ports needed.

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER'S DEVICE (Mac / Pi / any)               │
│                                                                 │
│   ┌─────────────┐      ┌─────────────┐                          │
│   │ Conductor   │ ←──→ │ cloudflared │ ──── outbound ────┐      │
│   │ :8080       │      │ (tunnel)    │                   │      │
│   └─────────────┘      └─────────────┘                   │      │
│                                                          │      │
│   - Runs locally                                         │      │
│   - No ports exposed                                     │      │
│   - Works behind any NAT/firewall                        │      │
│                                                          │      │
└──────────────────────────────────────────────────────────│──────┘
                                                           │
                                                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      CLOUDFLARE EDGE                            │
│                                                                 │
│   Incoming request: https://alice.spoq.dev/api/ask              │
│                              │                                  │
│                              ▼                                  │
│                     ┌───────────────┐                           │
│                     │ Tunnel Router │                           │
│                     └───────────────┘                           │
│                              │                                  │
│                              ▼                                  │
│                     Route to alice's tunnel                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                                           │
                                                           ▼
                                                    User's Device
```

### Why Cloudflare Tunnel?

| Feature | Cloudflare Tunnel | ngrok | Tailscale |
|---------|-------------------|-------|-----------|
| Free tier | ✓ (unlimited) | Limited | ✓ |
| Custom domain | ✓ (spoq.dev) | Paid | No |
| Auto SSL | ✓ | ✓ | ✓ |
| We control DNS | ✓ | ✗ | ✗ |
| No client install for users | ✓ | ✓ | ✗ |
| Enterprise-grade | ✓ | ✓ | ✓ |

---

## User Experience

### Same Flow Everywhere

```bash
# Install (same command for all platforms)
$ curl -fsSL https://spoq.dev/install.sh | bash

# Initialize
$ spoq init

  Authenticating...
  Visit: https://spoq.dev/auth/verify?code=BLUE-FISH

  ✓ Authenticated as @alice

  Where do you want to run Spoq?

  ○ This device (Mac)           ← Detected automatically
  ○ Cloud VPS ($X/mo)

  Setting up on this Mac...
  ████████████████████████████░░ 85%

  → Installing Conductor...
  → Installing tunnel service...
  → Creating secure tunnel...
  → Configuring DNS (alice.spoq.dev)...

  ✓ Ready!

  Your Spoq endpoint: https://alice.spoq.dev

  This Mac is now your Spoq server.
  Keep it running to use Spoq from anywhere.

  Start using:
    spoq ask "help me with this code"
```

### Device Selection

```
┌─────────────────────────────────────────────────────────────────┐
│  SIGNUP OPTIONS                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Where should Spoq run?                                         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ ○ This device (MacBook Pro M2)                          │    │
│  │   Free - Uses your hardware                             │    │
│  │   Must be running to use Spoq                           │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ ○ Cloud VPS - Always On                                 │    │
│  │   $X/month - We manage everything                       │    │
│  │   24/7 availability, no device needed                   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Platform Support Matrix

| Platform | Conductor | Tunnel | Service Manager | Binary |
|----------|-----------|--------|-----------------|--------|
| VPS (Ubuntu) | ✓ | Optional | systemd | linux-amd64 |
| Mac (Intel) | ✓ | cloudflared | launchd | darwin-amd64 |
| Mac (Apple Silicon) | ✓ | cloudflared | launchd | darwin-arm64 |
| Raspberry Pi | ✓ | cloudflared | systemd | linux-arm64 |
| Linux Desktop | ✓ | cloudflared | systemd | linux-amd64 |
| Windows (WSL2) | ✓ | cloudflared | systemd (WSL) | linux-amd64 |

---

## Implementation

### 1. Cloudflare Tunnel API Integration

```rust
// src/services/cloudflare_tunnel.rs

use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct CloudflareTunnelService {
    client: Client,
    account_id: String,
    api_token: String,
}

#[derive(Serialize)]
struct CreateTunnelRequest {
    name: String,
    tunnel_secret: String,  // Base64 encoded 32-byte secret
}

#[derive(Deserialize)]
struct TunnelResponse {
    id: String,
    name: String,
    credentials_file: CredentialsFile,
}

#[derive(Deserialize, Serialize)]
struct CredentialsFile {
    #[serde(rename = "AccountTag")]
    account_tag: String,
    #[serde(rename = "TunnelID")]
    tunnel_id: String,
    #[serde(rename = "TunnelSecret")]
    tunnel_secret: String,
}

impl CloudflareTunnelService {
    /// Create a new tunnel for a user
    pub async fn create_tunnel(&self, username: &str) -> Result<TunnelInfo> {
        // 1. Generate tunnel secret
        let secret = generate_tunnel_secret();

        // 2. Create tunnel via API
        let response = self.client
            .post(format!(
                "https://api.cloudflare.com/client/v4/accounts/{}/tunnels",
                self.account_id
            ))
            .bearer_auth(&self.api_token)
            .json(&CreateTunnelRequest {
                name: format!("spoq-{}", username),
                tunnel_secret: base64::encode(&secret),
            })
            .send()
            .await?;

        let tunnel: TunnelResponse = response.json().await?;

        // 3. Create DNS record pointing to tunnel
        self.create_dns_record(username, &tunnel.id).await?;

        // 4. Return credentials for device
        Ok(TunnelInfo {
            tunnel_id: tunnel.id,
            credentials: tunnel.credentials_file,
            hostname: format!("{}.spoq.dev", username),
        })
    }

    /// Create DNS CNAME record for tunnel
    async fn create_dns_record(&self, username: &str, tunnel_id: &str) -> Result<()> {
        // CNAME: alice.spoq.dev -> <tunnel_id>.cfargotunnel.com
        self.client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                self.zone_id
            ))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "CNAME",
                "name": username,
                "content": format!("{}.cfargotunnel.com", tunnel_id),
                "proxied": true
            }))
            .send()
            .await?;

        Ok(())
    }

    /// Delete tunnel when user cancels
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<()> {
        self.client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/accounts/{}/tunnels/{}",
                self.account_id, tunnel_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?;

        Ok(())
    }
}

fn generate_tunnel_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).unwrap();
    secret
}
```

### 2. Device Setup Service

```rust
// src/services/device_setup.rs

pub enum DeviceType {
    MacIntel,
    MacArm,
    LinuxAmd64,
    LinuxArm64,  // Raspberry Pi
    Vps,
}

pub struct DeviceSetupService {
    tunnel_service: CloudflareTunnelService,
}

impl DeviceSetupService {
    /// Generate setup script for device
    pub async fn generate_setup_script(
        &self,
        user_id: &str,
        username: &str,
        device_type: DeviceType,
    ) -> Result<SetupScript> {
        // 1. Create tunnel
        let tunnel_info = self.tunnel_service.create_tunnel(username).await?;

        // 2. Generate signed download URLs
        let conductor_url = generate_signed_url(&conductor_binary(device_type));
        let cloudflared_url = get_cloudflared_url(device_type);

        // 3. Generate setup script based on device type
        let script = match device_type {
            DeviceType::MacIntel | DeviceType::MacArm => {
                self.generate_mac_script(&tunnel_info, &conductor_url, &cloudflared_url)
            }
            DeviceType::LinuxAmd64 | DeviceType::LinuxArm64 => {
                self.generate_linux_script(&tunnel_info, &conductor_url, &cloudflared_url)
            }
            DeviceType::Vps => {
                // Existing VPS provisioning
                self.generate_vps_script(&tunnel_info, &conductor_url)
            }
        };

        Ok(SetupScript {
            script,
            tunnel_id: tunnel_info.tunnel_id,
            hostname: tunnel_info.hostname,
        })
    }
}
```

### 3. Mac Setup Script (launchd)

```bash
#!/bin/bash
# mac-setup.sh - Generated per user with embedded credentials

set -e

CONDUCTOR_URL="{{CONDUCTOR_URL}}"
CLOUDFLARED_URL="{{CLOUDFLARED_URL}}"
TUNNEL_CREDENTIALS='{{TUNNEL_CREDENTIALS_JSON}}'
HOSTNAME="{{HOSTNAME}}"
JWT_SECRET="{{JWT_SECRET}}"
OWNER_ID="{{OWNER_ID}}"

echo "=== Spoq Device Setup (Mac) ==="

# 1. Create directories
mkdir -p ~/.spoq/bin
mkdir -p ~/.spoq/config
mkdir -p ~/Library/LaunchAgents

# 2. Download Conductor
echo "Downloading Conductor..."
curl -sSL "$CONDUCTOR_URL" -o ~/.spoq/bin/conductor
chmod +x ~/.spoq/bin/conductor

# 3. Download cloudflared
echo "Downloading cloudflared..."
curl -sSL "$CLOUDFLARED_URL" -o ~/.spoq/bin/cloudflared
chmod +x ~/.spoq/bin/cloudflared

# 4. Write tunnel credentials
echo "$TUNNEL_CREDENTIALS" > ~/.spoq/config/tunnel-credentials.json

# 5. Write tunnel config
cat > ~/.spoq/config/tunnel-config.yml << EOF
tunnel: {{TUNNEL_ID}}
credentials-file: $HOME/.spoq/config/tunnel-credentials.json

ingress:
  - hostname: $HOSTNAME
    service: http://localhost:8080
  - service: http_status:404
EOF

# 6. Write Conductor config
cat > ~/.spoq/config/conductor.toml << EOF
[server]
host = "127.0.0.1"
port = 8080

[auth]
owner_id = "$OWNER_ID"
jwt_secret = "$JWT_SECRET"
EOF

# 7. Create launchd plist for Conductor
cat > ~/Library/LaunchAgents/dev.spoq.conductor.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.spoq.conductor</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HOME/.spoq/bin/conductor</string>
        <string>--config</string>
        <string>$HOME/.spoq/config/conductor.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.spoq/logs/conductor.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.spoq/logs/conductor.error.log</string>
</dict>
</plist>
EOF

# 8. Create launchd plist for cloudflared
cat > ~/Library/LaunchAgents/dev.spoq.tunnel.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.spoq.tunnel</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HOME/.spoq/bin/cloudflared</string>
        <string>tunnel</string>
        <string>--config</string>
        <string>$HOME/.spoq/config/tunnel-config.yml</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.spoq/logs/tunnel.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.spoq/logs/tunnel.error.log</string>
</dict>
</plist>
EOF

# 9. Create logs directory
mkdir -p ~/.spoq/logs

# 10. Load services
launchctl load ~/Library/LaunchAgents/dev.spoq.conductor.plist
launchctl load ~/Library/LaunchAgents/dev.spoq.tunnel.plist

# 11. Create device marker
cat > ~/.spoq/device.marker << EOF
{
  "type": "local",
  "conductor": "http://localhost:8080",
  "hostname": "$HOSTNAME",
  "version": "1.0"
}
EOF

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Your Spoq endpoint: https://$HOSTNAME"
echo ""
echo "Services running:"
echo "  - Conductor (AI backend)"
echo "  - Tunnel (secure connection)"
echo ""
echo "Manage services:"
echo "  spoq service status"
echo "  spoq service restart"
echo "  spoq service stop"
```

### 4. Linux/Pi Setup Script (systemd)

```bash
#!/bin/bash
# linux-setup.sh - For Raspberry Pi and Linux desktops

set -e

CONDUCTOR_URL="{{CONDUCTOR_URL}}"
CLOUDFLARED_URL="{{CLOUDFLARED_URL}}"
TUNNEL_CREDENTIALS='{{TUNNEL_CREDENTIALS_JSON}}'
HOSTNAME="{{HOSTNAME}}"
JWT_SECRET="{{JWT_SECRET}}"
OWNER_ID="{{OWNER_ID}}"

echo "=== Spoq Device Setup (Linux) ==="

# 1. Create directories
sudo mkdir -p /opt/spoq/bin
sudo mkdir -p /etc/spoq

# 2. Download binaries
echo "Downloading Conductor..."
sudo curl -sSL "$CONDUCTOR_URL" -o /opt/spoq/bin/conductor
sudo chmod +x /opt/spoq/bin/conductor

echo "Downloading cloudflared..."
sudo curl -sSL "$CLOUDFLARED_URL" -o /opt/spoq/bin/cloudflared
sudo chmod +x /opt/spoq/bin/cloudflared

# 3. Write configs
echo "$TUNNEL_CREDENTIALS" | sudo tee /etc/spoq/tunnel-credentials.json > /dev/null

sudo tee /etc/spoq/tunnel-config.yml > /dev/null << EOF
tunnel: {{TUNNEL_ID}}
credentials-file: /etc/spoq/tunnel-credentials.json

ingress:
  - hostname: $HOSTNAME
    service: http://localhost:8080
  - service: http_status:404
EOF

sudo tee /etc/spoq/conductor.toml > /dev/null << EOF
[server]
host = "127.0.0.1"
port = 8080

[auth]
owner_id = "$OWNER_ID"
jwt_secret = "$JWT_SECRET"
EOF

# 4. Create systemd services
sudo tee /etc/systemd/system/spoq-conductor.service > /dev/null << EOF
[Unit]
Description=Spoq Conductor - AI Backend
After=network.target

[Service]
Type=simple
ExecStart=/opt/spoq/bin/conductor --config /etc/spoq/conductor.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/spoq-tunnel.service > /dev/null << EOF
[Unit]
Description=Spoq Tunnel - Cloudflare Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/spoq/bin/cloudflared tunnel --config /etc/spoq/tunnel-config.yml run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 5. Create device marker
sudo tee /etc/spoq/device.marker > /dev/null << EOF
{
  "type": "local",
  "conductor": "http://localhost:8080",
  "hostname": "$HOSTNAME",
  "version": "1.0"
}
EOF

# 6. Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable spoq-conductor spoq-tunnel
sudo systemctl start spoq-conductor spoq-tunnel

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Your Spoq endpoint: https://$HOSTNAME"
echo ""
echo "Check status: systemctl status spoq-conductor spoq-tunnel"
```

### 5. CLI Device Detection

```rust
// In CLI: detect device type and adjust behavior

use std::path::Path;

#[derive(Debug, Clone)]
pub enum RuntimeEnvironment {
    /// Running on cloud VPS (managed by us)
    Vps { conductor: String },

    /// Running on local device with tunnel
    LocalDevice {
        conductor: String,
        hostname: String,
    },

    /// Running on user's Mac, connecting to remote
    RemoteClient {
        endpoint: String,
        access_token: String,
    },
}

pub fn detect_environment() -> Result<RuntimeEnvironment> {
    // 1. Check for VPS marker (cloud VPS)
    if Path::new("/etc/spoq/vps.marker").exists() {
        return Ok(RuntimeEnvironment::Vps {
            conductor: "http://localhost:8080".into(),
        });
    }

    // 2. Check for device marker (local device with tunnel)
    let device_marker = dirs::home_dir()
        .unwrap()
        .join(".spoq/device.marker");

    if device_marker.exists() {
        let marker: DeviceMarker = load_json(&device_marker)?;
        return Ok(RuntimeEnvironment::LocalDevice {
            conductor: marker.conductor,
            hostname: marker.hostname,
        });
    }

    // Also check Linux location
    if Path::new("/etc/spoq/device.marker").exists() {
        let marker: DeviceMarker = load_json("/etc/spoq/device.marker")?;
        return Ok(RuntimeEnvironment::LocalDevice {
            conductor: marker.conductor,
            hostname: marker.hostname,
        });
    }

    // 3. Check for credentials (remote client)
    let creds_path = dirs::home_dir()
        .unwrap()
        .join(".spoq/credentials");

    if creds_path.exists() {
        let creds: Credentials = load_json(&creds_path)?;
        return Ok(RuntimeEnvironment::RemoteClient {
            endpoint: creds.vps_hostname,
            access_token: creds.access_token,
        });
    }

    Err(anyhow!("Not configured. Run 'spoq init' first."))
}
```

---

## Database Schema Changes

```sql
-- Update user_vps to support multiple device types
ALTER TABLE user_vps ADD COLUMN device_type TEXT NOT NULL DEFAULT 'vps';
-- vps, mac, raspberry_pi, linux_desktop

ALTER TABLE user_vps ADD COLUMN tunnel_id TEXT;
-- Cloudflare tunnel ID (null for VPS with public IP)

-- Rename table to be more generic
ALTER TABLE user_vps RENAME TO user_devices;

-- Index for tunnel lookups
CREATE INDEX idx_user_devices_tunnel ON user_devices(tunnel_id);
```

---

## API Changes

### New Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/device/setup` | POST | Get setup script for device type |
| `/api/device/status` | GET | Check device/tunnel status |
| `/api/tunnel/create` | POST | Create Cloudflare tunnel |
| `/api/tunnel/delete` | DELETE | Delete tunnel |

### Setup Flow

```
POST /api/device/setup
{
  "device_type": "mac_arm64"  // or "linux_arm64", "linux_amd64"
}

Response:
{
  "setup_script": "#!/bin/bash\n...",
  "tunnel_id": "abc-123",
  "hostname": "alice.spoq.dev",
  "expires_at": "2024-01-15T10:00:00Z"
}
```

---

## Service Management CLI

```bash
# Check status of local services
$ spoq service status

  Conductor:  ● Running (PID 1234)
  Tunnel:     ● Running (PID 1235)
  Endpoint:   https://alice.spoq.dev
  Uptime:     2 days, 5 hours

# Restart services
$ spoq service restart

  Restarting Conductor... ✓
  Restarting Tunnel... ✓

# Stop services (going offline)
$ spoq service stop

  Stopping Conductor... ✓
  Stopping Tunnel... ✓

  ⚠ Your Spoq endpoint is now offline.
  Run 'spoq service start' to bring it back.

# View logs
$ spoq service logs
$ spoq service logs --follow
$ spoq service logs conductor
$ spoq service logs tunnel
```

---

## Pricing Considerations

| Option | Cost to Us | Price to User |
|--------|------------|---------------|
| Cloud VPS | ~$5-10/mo (Hostinger) | $X/mo |
| Local Device | ~$0 (Cloudflare free tier) | Free or reduced |

**Potential pricing model:**

```
┌─────────────────────────────────────────────────────────────────┐
│  PRICING                                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Local Device (Mac/Pi)          Cloud VPS                       │
│  ────────────────────           ────────────────────            │
│  Free                           $X/month                        │
│                                                                 │
│  ✓ Use your own hardware        ✓ Always online                 │
│  ✓ Full AI capabilities         ✓ No device needed              │
│  ✗ Must keep device running     ✓ Access from anywhere          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Migration Path

For users who start on local device but want to upgrade to VPS:

```bash
$ spoq upgrade

  You're currently running Spoq on your Mac.

  Upgrade to Cloud VPS?
  - Always online (24/7)
  - No need to keep Mac running
  - $X/month

  [Upgrade] [Cancel]

  Migrating...
  → Provisioning VPS...
  → Syncing data...
  → Updating DNS...

  ✓ Migrated to Cloud VPS!

  Your endpoint remains: https://alice.spoq.dev

  You can now close your Mac. Spoq will keep running.
```

---

## Security Considerations

| Concern | Mitigation |
|---------|------------|
| Tunnel credentials on device | Encrypted at rest, user-specific |
| Device compromise | JWT still required, can revoke tunnel |
| Cloudflare as middleman | All traffic encrypted end-to-end |
| Tunnel hijacking | Credentials tied to specific tunnel ID |

---

## Implementation Priority

1. **Phase 1:** Mac support (largest user base)
2. **Phase 2:** Raspberry Pi (enthusiast/homelab users)
3. **Phase 3:** Linux desktop
4. **Phase 4:** Windows WSL2

---

## Environment Variables (Backend)

```bash
# Cloudflare Tunnel API
CLOUDFLARE_ACCOUNT_ID=xxx
CLOUDFLARE_API_TOKEN=xxx  # With tunnel permissions
CLOUDFLARE_ZONE_ID=xxx    # For spoq.dev
```

---

## Summary

| Current (MVP) | Future (This Doc) |
|---------------|-------------------|
| VPS only | VPS + Mac + Pi + Linux |
| Public IP required | Cloudflare Tunnel (no public IP) |
| We provision hardware | User's hardware or our VPS |
| One pricing tier | Free (local) + Paid (VPS) |
