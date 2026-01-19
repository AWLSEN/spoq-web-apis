#!/bin/bash
# Test CLI for Spoq Authentication + VPS Provisioning Flow
# Usage: ./test-flow.sh [base_url]
#
# This script tests the complete flow from architecture.md:
# 1. Device flow authentication
# 2. VPS provisioning
# 3. VPS status check

set -e

# Configuration
BASE_URL="${1:-https://spoq-api-production.up.railway.app}"
CREDENTIALS_FILE="$HOME/.spoq/test-credentials.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Spoq Flow Test CLI                              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Base URL: ${YELLOW}$BASE_URL${NC}"
echo ""

# Helper function for API calls with auto-refresh on 401
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local auth=$4

    if [ -n "$auth" ]; then
        local response
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $auth" \
            -d "$data")

        local http_code=$(echo "$response" | tail -n1)
        local body=$(echo "$response" | sed '$d')

        # Auto-refresh on 401 Unauthorized
        if [ "$http_code" = "401" ] && [ -f "$CREDENTIALS_FILE" ]; then
            local refresh_token=$(jq -r '.refresh_token' "$CREDENTIALS_FILE")
            if [ -n "$refresh_token" ] && [ "$refresh_token" != "null" ]; then
                local refresh_result=$(curl -s -X POST "$BASE_URL/auth/refresh" \
                    -H "Content-Type: application/json" \
                    -d "{\"refresh_token\":\"$refresh_token\"}")

                local new_token=$(echo "$refresh_result" | jq -r '.access_token // empty')
                if [ -n "$new_token" ]; then
                    # Update credentials file
                    jq ".access_token = \"$new_token\"" "$CREDENTIALS_FILE" > "$CREDENTIALS_FILE.tmp" \
                        && mv "$CREDENTIALS_FILE.tmp" "$CREDENTIALS_FILE"
                    ACCESS_TOKEN="$new_token"

                    # Retry the call with new token
                    body=$(curl -s -X "$method" "$BASE_URL$endpoint" \
                        -H "Content-Type: application/json" \
                        -H "Authorization: Bearer $new_token" \
                        -d "$data")
                fi
            fi
        fi

        echo "$body"
    else
        curl -s -X "$method" "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data"
    fi
}

# Check if we have stored credentials
load_credentials() {
    if [ -f "$CREDENTIALS_FILE" ]; then
        echo -e "${GREEN}Found existing credentials${NC}"
        ACCESS_TOKEN=$(jq -r '.access_token' "$CREDENTIALS_FILE")
        REFRESH_TOKEN=$(jq -r '.refresh_token' "$CREDENTIALS_FILE")
        VPS_HOSTNAME=$(jq -r '.vps_hostname // empty' "$CREDENTIALS_FILE")
        return 0
    fi
    return 1
}

save_credentials() {
    mkdir -p "$(dirname "$CREDENTIALS_FILE")"
    echo "$1" > "$CREDENTIALS_FILE"
    echo -e "${GREEN}Credentials saved to $CREDENTIALS_FILE${NC}"
}

# ============================================================================
# Step 1: Health Check
# ============================================================================
echo -e "${YELLOW}[1/6] Health Check${NC}"
HEALTH=$(curl -s "$BASE_URL/health")
if echo "$HEALTH" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Server is healthy${NC}"
else
    echo -e "${RED}✗ Server health check failed${NC}"
    echo "$HEALTH"
    exit 1
fi
echo ""

# ============================================================================
# Step 2: List VPS Plans (Public endpoint)
# ============================================================================
echo -e "${YELLOW}[2/6] List VPS Plans${NC}"
PLANS=$(api_call GET "/api/vps/plans")
if echo "$PLANS" | jq -e '.plans' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ VPS Plans available:${NC}"
    echo "$PLANS" | jq -r '.plans[] | "  - \(.name): \(.vcpu) vCPU, \(.ram_gb)GB RAM, $\(.monthly_price_cents/100)/mo"'
else
    echo -e "${RED}✗ Failed to get VPS plans (Hostinger may not be configured)${NC}"
    echo "$PLANS"
fi
echo ""

# ============================================================================
# Step 3: List Data Centers (Public endpoint)
# ============================================================================
echo -e "${YELLOW}[3/6] List Data Centers${NC}"
DCS=$(api_call GET "/api/vps/datacenters")
if echo "$DCS" | jq -e '.data_centers' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Data Centers available:${NC}"
    echo "$DCS" | jq -r '.data_centers[] | "  - \(.city), \(.country) (\(.continent))"'
else
    echo -e "${RED}✗ Failed to get data centers${NC}"
    echo "$DCS"
fi
echo ""

# ============================================================================
# Step 4: Authentication (Device Flow)
# ============================================================================
echo -e "${YELLOW}[4/6] Authentication${NC}"

if load_credentials; then
    echo -e "Using stored access token"

    # Try to refresh if needed
    echo -e "Attempting token refresh..."
    REFRESH_RESULT=$(api_call POST "/auth/refresh" "{\"refresh_token\":\"$REFRESH_TOKEN\"}")

    if echo "$REFRESH_RESULT" | jq -e '.access_token' > /dev/null 2>&1; then
        ACCESS_TOKEN=$(echo "$REFRESH_RESULT" | jq -r '.access_token')
        echo -e "${GREEN}✓ Token refreshed${NC}"
        # Update credentials
        jq ".access_token = \"$ACCESS_TOKEN\"" "$CREDENTIALS_FILE" > "$CREDENTIALS_FILE.tmp" && mv "$CREDENTIALS_FILE.tmp" "$CREDENTIALS_FILE"
    else
        echo -e "${YELLOW}Token refresh failed, starting device flow...${NC}"
        rm -f "$CREDENTIALS_FILE"
    fi
fi

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    echo -e "Starting device authorization flow..."

    # Initialize device flow
    HOSTNAME=$(hostname)
    DEVICE_INIT=$(api_call POST "/auth/device" "{\"hostname\":\"$HOSTNAME\"}")

    if ! echo "$DEVICE_INIT" | jq -e '.device_code' > /dev/null 2>&1; then
        echo -e "${RED}✗ Failed to initialize device flow${NC}"
        echo "$DEVICE_INIT"
        exit 1
    fi

    DEVICE_CODE=$(echo "$DEVICE_INIT" | jq -r '.device_code')
    VERIFICATION_URI=$(echo "$DEVICE_INIT" | jq -r '.verification_uri')
    EXPIRES_IN=$(echo "$DEVICE_INIT" | jq -r '.expires_in')
    INTERVAL=$(echo "$DEVICE_INIT" | jq -r '.interval')

    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  Please visit this URL to authenticate:                   ║${NC}"
    echo -e "${BLUE}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}$VERIFICATION_URI${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Waiting for authorization (expires in ${EXPIRES_IN}s)..."

    # Poll for token
    ATTEMPTS=0
    MAX_ATTEMPTS=$((EXPIRES_IN / INTERVAL))

    while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
        sleep "$INTERVAL"
        ATTEMPTS=$((ATTEMPTS + 1))

        TOKEN_RESULT=$(api_call POST "/auth/device/token" "{\"device_code\":\"$DEVICE_CODE\",\"grant_type\":\"device_code\"}")

        if echo "$TOKEN_RESULT" | jq -e '.access_token' > /dev/null 2>&1; then
            ACCESS_TOKEN=$(echo "$TOKEN_RESULT" | jq -r '.access_token')
            REFRESH_TOKEN=$(echo "$TOKEN_RESULT" | jq -r '.refresh_token')
            VPS_HOSTNAME=$(echo "$TOKEN_RESULT" | jq -r '.vps_hostname // empty')

            echo -e "${GREEN}✓ Authenticated successfully!${NC}"

            # Save credentials
            save_credentials "$TOKEN_RESULT"
            break
        fi

        ERROR=$(echo "$TOKEN_RESULT" | jq -r '.error // empty')
        if [ "$ERROR" == "authorization_pending" ]; then
            echo -ne "\rPolling... ($ATTEMPTS/$MAX_ATTEMPTS)  "
        elif [ "$ERROR" == "slow_down" ]; then
            INTERVAL=$((INTERVAL + 5))
        elif [ "$ERROR" == "expired_token" ]; then
            echo -e "${RED}✗ Device code expired${NC}"
            exit 1
        elif [ "$ERROR" == "access_denied" ]; then
            echo -e "${RED}✗ Authorization denied${NC}"
            exit 1
        else
            echo -e "${RED}✗ Unexpected error: $ERROR${NC}"
            echo "$TOKEN_RESULT"
            exit 1
        fi
    done
    echo ""
fi

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    echo -e "${RED}✗ Failed to authenticate${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Authenticated with access token${NC}"
echo ""

# ============================================================================
# Step 5: Check VPS Status
# ============================================================================
echo -e "${YELLOW}[5/6] Check VPS Status${NC}"
VPS_STATUS=$(api_call GET "/api/vps/status" "" "$ACCESS_TOKEN")

if echo "$VPS_STATUS" | jq -e '.hostname' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ VPS Found:${NC}"
    echo "$VPS_STATUS" | jq '{hostname, status, ip_address, plan_id}'
    VPS_EXISTS=true
else
    echo -e "${YELLOW}No VPS found for this user${NC}"
    echo "$VPS_STATUS" | jq '.message // .error'
    VPS_EXISTS=false
fi
echo ""

# ============================================================================
# Step 6: Provision VPS (if not exists)
# ============================================================================
echo -e "${YELLOW}[6/6] VPS Provisioning${NC}"

if [ "$VPS_EXISTS" == "true" ]; then
    echo -e "${GREEN}VPS already exists, skipping provisioning${NC}"
else
    echo -e "Would you like to provision a new VPS? (y/n)"
    read -r PROVISION_CHOICE

    if [ "$PROVISION_CHOICE" == "y" ] || [ "$PROVISION_CHOICE" == "Y" ]; then
        # Show available plans
        echo ""
        echo -e "${BLUE}Available Plans:${NC}"
        PLANS=$(api_call GET "/api/vps/plans")
        echo "$PLANS" | jq -r '.plans[] | "  [\(.id | split("-") | .[2])]: \(.name) - \(.vcpu) vCPU, \(.ram_gb)GB RAM - $\(.monthly_price_cents/100)/mo"'
        echo ""
        echo -e "Enter plan (kvm1/kvm2/kvm4/kvm8) [default: kvm1]:"
        read -r PLAN_CHOICE
        PLAN_CHOICE=${PLAN_CHOICE:-kvm1}
        PLAN_ID="hostingercom-vps-${PLAN_CHOICE}-usd-1m"

        # Show available data centers
        echo ""
        echo -e "${BLUE}Available Data Centers:${NC}"
        DCS=$(api_call GET "/api/vps/datacenters")
        echo "$DCS" | jq -r '.data_centers[] | "  [\(.id)]: \(.city), \(.country)"'
        echo ""
        echo -e "Enter data center ID [default: 9 (Phoenix)]:"
        read -r DC_CHOICE
        DC_CHOICE=${DC_CHOICE:-9}

        echo ""
        echo -e "Enter SSH password (min 12 chars):"
        read -rs SSH_PASSWORD
        echo ""

        if [ ${#SSH_PASSWORD} -lt 12 ]; then
            echo -e "${RED}Password must be at least 12 characters${NC}"
            exit 1
        fi

        echo -e "Provisioning VPS with plan=$PLAN_ID, datacenter=$DC_CHOICE..."
        PROVISION_RESULT=$(api_call POST "/api/vps/provision" "{\"ssh_password\":\"$SSH_PASSWORD\",\"plan_id\":\"$PLAN_ID\",\"data_center_id\":$DC_CHOICE}" "$ACCESS_TOKEN")

        if echo "$PROVISION_RESULT" | jq -e '.id' > /dev/null 2>&1; then
            echo -e "${GREEN}✓ VPS provisioning started!${NC}"
            echo "$PROVISION_RESULT" | jq '{id, hostname, status, message}'

            # Update credentials with VPS hostname
            VPS_HOSTNAME=$(echo "$PROVISION_RESULT" | jq -r '.hostname')
            jq ".vps_hostname = \"$VPS_HOSTNAME\"" "$CREDENTIALS_FILE" > "$CREDENTIALS_FILE.tmp" && mv "$CREDENTIALS_FILE.tmp" "$CREDENTIALS_FILE"
        else
            echo -e "${RED}✗ Provisioning failed${NC}"
            echo "$PROVISION_RESULT" | jq '.'
        fi
    else
        echo -e "Skipping provisioning"
    fi
fi

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Test Complete!                                  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Credentials stored at: ${YELLOW}$CREDENTIALS_FILE${NC}"
if [ -n "$VPS_HOSTNAME" ] && [ "$VPS_HOSTNAME" != "null" ]; then
    echo -e "VPS Hostname: ${GREEN}$VPS_HOSTNAME${NC}"
fi
