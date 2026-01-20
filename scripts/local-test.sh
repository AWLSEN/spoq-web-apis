#!/bin/bash
# Local Testing Setup for Spoq Web APIs
# This script helps set up the local development environment and run tests

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Spoq Local Testing Setup                              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if we're in the project root
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}Error: Must be run from project root directory${NC}"
    exit 1
fi

# Step 1: Check for .env file
echo -e "${YELLOW}[Step 1/5] Checking .env configuration...${NC}"
if [ -f ".env" ]; then
    echo -e "${GREEN}✓ .env file exists${NC}"
else
    echo -e "${YELLOW}Creating .env from .env.example...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file${NC}"
    echo -e "${YELLOW}⚠ Please edit .env with your configuration${NC}"
fi
echo ""

# Step 2: Check DATABASE_URL
echo -e "${YELLOW}[Step 2/5] Checking database configuration...${NC}"
if [ -f ".env" ]; then
    source .env

    if [ -z "$DATABASE_URL" ] || [ "$DATABASE_URL" == "postgres://user:pass@localhost:5432/spoq" ]; then
        echo -e "${YELLOW}DATABASE_URL not configured${NC}"
        echo -e "Default: postgres://postgres@localhost:5432/spoq"
        echo -n "Enter DATABASE_URL (press Enter for default): "
        read -r db_url
        db_url=${db_url:-postgres://postgres@localhost:5432/spoq}

        # Update .env file
        if grep -q "^DATABASE_URL=" .env; then
            sed -i.bak "s|^DATABASE_URL=.*|DATABASE_URL=$db_url|" .env && rm .env.bak
        else
            echo "DATABASE_URL=$db_url" >> .env
        fi

        DATABASE_URL="$db_url"
        echo -e "${GREEN}✓ DATABASE_URL updated${NC}"
    else
        echo -e "${GREEN}✓ DATABASE_URL configured${NC}"
    fi

    # Extract database name from URL
    DB_NAME=$(echo "$DATABASE_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')

    # Check if database exists
    if psql "$DATABASE_URL" -c '\q' 2>/dev/null; then
        echo -e "${GREEN}✓ Database '$DB_NAME' exists and is accessible${NC}"
    else
        echo -e "${YELLOW}Database '$DB_NAME' not found${NC}"
        echo -n "Create database? (y/n): "
        read -r create_db

        if [ "$create_db" == "y" ] || [ "$create_db" == "Y" ]; then
            # Extract base URL without database name
            BASE_URL=$(echo "$DATABASE_URL" | sed 's|/[^/]*$|/postgres|')

            if psql "$BASE_URL" -c "CREATE DATABASE $DB_NAME" 2>/dev/null; then
                echo -e "${GREEN}✓ Database '$DB_NAME' created${NC}"
            else
                echo -e "${RED}✗ Failed to create database. Please create manually:${NC}"
                echo -e "  createdb $DB_NAME"
                exit 1
            fi
        else
            echo -e "${YELLOW}⚠ Please create the database manually:${NC}"
            echo -e "  createdb $DB_NAME"
            exit 1
        fi
    fi
else
    echo -e "${RED}✗ .env file not found${NC}"
    exit 1
fi
echo ""

# Step 3: Check required environment variables
echo -e "${YELLOW}[Step 3/5] Checking required environment variables...${NC}"
source .env

MISSING_VARS=()

if [ -z "$GITHUB_CLIENT_ID" ] || [ "$GITHUB_CLIENT_ID" == "your_client_id" ]; then
    MISSING_VARS+=("GITHUB_CLIENT_ID")
fi

if [ -z "$GITHUB_CLIENT_SECRET" ] || [ "$GITHUB_CLIENT_SECRET" == "your_client_secret" ]; then
    MISSING_VARS+=("GITHUB_CLIENT_SECRET")
fi

if [ -z "$JWT_SECRET" ] || [ "$JWT_SECRET" == "your_jwt_secret_min_32_chars" ]; then
    MISSING_VARS+=("JWT_SECRET")
fi

if [ ${#MISSING_VARS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Missing or unconfigured variables:${NC}"
    for var in "${MISSING_VARS[@]}"; do
        echo -e "  - $var"
    done
    echo ""
    echo -e "${YELLOW}Please edit .env and set these variables${NC}"
    echo ""

    if [[ " ${MISSING_VARS[@]} " =~ " JWT_SECRET " ]]; then
        echo -e "${BLUE}Generate JWT_SECRET (32+ chars):${NC}"
        echo "  openssl rand -base64 32"
        echo ""
    fi

    if [[ " ${MISSING_VARS[@]} " =~ " GITHUB_CLIENT_ID " ]]; then
        echo -e "${BLUE}Get GitHub OAuth credentials:${NC}"
        echo "  1. Go to https://github.com/settings/developers"
        echo "  2. Create a new OAuth App"
        echo "  3. Set callback URL: http://localhost:8080/auth/github/callback"
        echo "  4. Copy Client ID and Client Secret to .env"
        echo ""
    fi

    exit 1
else
    echo -e "${GREEN}✓ All required variables configured${NC}"
fi
echo ""

# Step 4: Build the project
echo -e "${YELLOW}[Step 4/5] Building project...${NC}"
if cargo build; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo ""

# Step 5: Instructions
echo -e "${YELLOW}[Step 5/5] Setup complete!${NC}"
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Ready to test locally!                                    ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}To start the server:${NC}"
echo -e "  cargo run"
echo ""
echo -e "${BLUE}To run tests (in another terminal):${NC}"
echo -e "  ./scripts/test-flow.sh http://localhost:8080"
echo ""
echo -e "${BLUE}Health check:${NC}"
echo -e "  curl http://localhost:8080/health"
echo ""
echo -e "${YELLOW}Note: The server will run database migrations automatically on startup${NC}"
echo ""
