#!/bin/bash
# Cleanup VPS records from database (not actual VPS infrastructure)
# This deletes records from user_vps table to allow fresh testing

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   VPS Database Records Cleanup Tool${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo -e "${RED}ERROR: DATABASE_URL environment variable not set${NC}"
    echo ""
    echo "Please set DATABASE_URL to your Railway PostgreSQL connection string:"
    echo "  export DATABASE_URL='postgresql://user:pass@host:port/dbname'"
    echo ""
    echo "Or get it from Railway:"
    echo "  railway variables | grep DATABASE_URL"
    exit 1
fi

echo -e "${YELLOW}Warning: This will DELETE VPS records from the database${NC}"
echo -e "${YELLOW}(This does NOT delete actual VPS infrastructure)${NC}"
echo ""

# List current VPS records
echo -e "${BLUE}Current VPS records:${NC}"
psql "$DATABASE_URL" -c "
SELECT
    id,
    user_id,
    provider,
    device_type,
    hostname,
    ip_address,
    status,
    created_at
FROM user_vps
ORDER BY created_at DESC;
" 2>/dev/null || {
    echo -e "${RED}Failed to connect to database${NC}"
    echo "Check your DATABASE_URL and network connection"
    exit 1
}

echo ""
echo "What would you like to do?"
echo "  1) Delete ALL VPS records"
echo "  2) Delete records for a specific user (by email)"
echo "  3) Delete records for a specific hostname"
echo "  4) Delete only 'vps' (managed Hostinger) records"
echo "  5) Delete only 'byovps' (user-provided) records"
echo "  6) Cancel"
echo ""
read -p "Enter your choice (1-6): " CHOICE

case $CHOICE in
    1)
        echo ""
        echo -e "${RED}⚠️  This will delete ALL VPS records from the database${NC}"
        read -p "Type 'DELETE ALL' to confirm: " CONFIRM
        if [ "$CONFIRM" = "DELETE ALL" ]; then
            psql "$DATABASE_URL" -c "DELETE FROM user_vps;"
            echo -e "${GREEN}✓ All VPS records deleted${NC}"
        else
            echo -e "${YELLOW}Cancelled${NC}"
        fi
        ;;
    2)
        echo ""
        read -p "Enter user email: " USER_EMAIL
        echo ""
        echo -e "${BLUE}VPS records for user: $USER_EMAIL${NC}"
        psql "$DATABASE_URL" -c "
        SELECT uv.id, uv.hostname, uv.device_type, uv.status
        FROM user_vps uv
        JOIN users u ON uv.user_id = u.id
        WHERE u.email = '$USER_EMAIL';
        "
        echo ""
        read -p "Delete these records? (yes/no): " CONFIRM
        if [ "$CONFIRM" = "yes" ]; then
            psql "$DATABASE_URL" -c "
            DELETE FROM user_vps
            WHERE user_id IN (SELECT id FROM users WHERE email = '$USER_EMAIL');
            "
            echo -e "${GREEN}✓ VPS records deleted for $USER_EMAIL${NC}"
        else
            echo -e "${YELLOW}Cancelled${NC}"
        fi
        ;;
    3)
        echo ""
        read -p "Enter hostname (e.g., alice.spoq.dev): " HOSTNAME
        echo ""
        read -p "Delete VPS record for $HOSTNAME? (yes/no): " CONFIRM
        if [ "$CONFIRM" = "yes" ]; then
            psql "$DATABASE_URL" -c "DELETE FROM user_vps WHERE hostname = '$HOSTNAME';"
            echo -e "${GREEN}✓ VPS record deleted for $HOSTNAME${NC}"
        else
            echo -e "${YELLOW}Cancelled${NC}"
        fi
        ;;
    4)
        echo ""
        echo -e "${BLUE}Managed Hostinger VPS records:${NC}"
        psql "$DATABASE_URL" -c "
        SELECT id, hostname, status, created_at
        FROM user_vps
        WHERE device_type = 'vps';
        "
        echo ""
        read -p "Delete all managed VPS records? (yes/no): " CONFIRM
        if [ "$CONFIRM" = "yes" ]; then
            psql "$DATABASE_URL" -c "DELETE FROM user_vps WHERE device_type = 'vps';"
            echo -e "${GREEN}✓ Managed VPS records deleted${NC}"
        else
            echo -e "${YELLOW}Cancelled${NC}"
        fi
        ;;
    5)
        echo ""
        echo -e "${BLUE}BYOVPS (user-provided) records:${NC}"
        psql "$DATABASE_URL" -c "
        SELECT id, hostname, ip_address, status, created_at
        FROM user_vps
        WHERE device_type = 'byovps';
        "
        echo ""
        read -p "Delete all BYOVPS records? (yes/no): " CONFIRM
        if [ "$CONFIRM" = "yes" ]; then
            psql "$DATABASE_URL" -c "DELETE FROM user_vps WHERE device_type = 'byovps';"
            echo -e "${GREEN}✓ BYOVPS records deleted${NC}"
        else
            echo -e "${YELLOW}Cancelled${NC}"
        fi
        ;;
    6)
        echo -e "${YELLOW}Cancelled${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}Remaining VPS records:${NC}"
psql "$DATABASE_URL" -c "
SELECT
    id,
    user_id,
    device_type,
    hostname,
    status,
    created_at
FROM user_vps
ORDER BY created_at DESC;
"

echo ""
echo -e "${GREEN}Done!${NC}"
