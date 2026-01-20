#!/bin/bash
# Setup Caddy reverse proxy for HTTPS on VPS
# Run this on the VPS after provisioning
#
# Usage: curl -sSL https://spoq.dev/scripts/setup-caddy.sh | bash -s -- <hostname>
# Example: curl -sSL https://spoq.dev/scripts/setup-caddy.sh | bash -s -- nidhishgajjar.spoq.dev

set -e

HOSTNAME="${1:-$(hostname -f)}"

if [[ ! "$HOSTNAME" =~ \.spoq\.dev$ ]]; then
    echo "Error: Hostname must end with .spoq.dev"
    echo "Usage: $0 <hostname.spoq.dev>"
    exit 1
fi

echo "=== Setting up Caddy for $HOSTNAME ==="

# 1. Install Caddy
echo "Installing Caddy..."
apt-get update -qq
apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null

apt-get update -qq
apt-get install -y -qq caddy

# 2. Configure Caddy
echo "Configuring Caddy..."
cat > /etc/caddy/Caddyfile << EOF
# Spoq Conductor reverse proxy
# Auto-HTTPS via Let's Encrypt

$HOSTNAME {
    reverse_proxy localhost:8080

    # Security headers
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    # Logging
    log {
        output file /var/log/caddy/access.log
        format json
    }
}
EOF

# 3. Create log directory
mkdir -p /var/log/caddy
chown caddy:caddy /var/log/caddy

# 4. Open firewall for HTTPS
echo "Configuring firewall..."
ufw allow 443/tcp
ufw allow 80/tcp  # Needed for Let's Encrypt HTTP challenge

# 5. Enable and start Caddy
echo "Starting Caddy..."
systemctl enable caddy
systemctl restart caddy

# 6. Wait for certificate
echo "Waiting for SSL certificate..."
sleep 5

# 7. Verify
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Caddy status: $(systemctl is-active caddy)"
echo ""
echo "Testing HTTPS..."
if curl -sf "https://$HOSTNAME/health" >/dev/null 2>&1; then
    echo "HTTPS is working: https://$HOSTNAME"
else
    echo "HTTPS not yet ready (certificate may still be provisioning)"
    echo "Try: curl https://$HOSTNAME/health"
fi
echo ""
echo "View logs: journalctl -u caddy -f"
echo "View access logs: tail -f /var/log/caddy/access.log"
