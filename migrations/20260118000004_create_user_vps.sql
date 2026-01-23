-- User VPS instances table
-- Stores information about VPS instances provisioned for users

CREATE TABLE user_vps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- VPS provider details
    provider TEXT NOT NULL DEFAULT 'hostinger',  -- 'hostinger' or 'contabo'
    provider_instance_id BIGINT,  -- Hostinger VM ID
    provider_order_id TEXT,  -- Hostinger order ID

    -- VPS configuration
    plan_id TEXT NOT NULL,  -- e.g., 'hostingercom-vps-kvm1-usd-1m'
    template_id INTEGER NOT NULL DEFAULT 1007,  -- OS template (1007 = Ubuntu 22.04)
    data_center_id INTEGER NOT NULL DEFAULT 9,  -- Data center (9 = Phoenix)

    -- Network details
    hostname TEXT UNIQUE NOT NULL,  -- e.g., 'alice.spoq.dev'
    ip_address TEXT,  -- IPv4 address as string

    -- Status
    status TEXT NOT NULL DEFAULT 'pending',
        -- pending: Initial state, payment processing
        -- provisioning: VPS being created
        -- configuring: Post-install script running
        -- ready: Fully operational
        -- failed: Provisioning failed
        -- stopped: VPS powered off (grace period)
        -- terminated: VPS deleted

    -- SSH credentials (for mobile access)
    ssh_username TEXT NOT NULL DEFAULT 'spoq',
    ssh_password_hash TEXT NOT NULL,  -- Argon2 hash of user-created password

    -- JWT validation config (set during provisioning)
    jwt_secret TEXT NOT NULL,  -- Same as central server for HS256

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ready_at TIMESTAMPTZ,  -- When provisioning completed
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One VPS per user constraint
    UNIQUE (user_id)
);

-- Indexes for common queries
CREATE INDEX idx_user_vps_user_id ON user_vps(user_id);
CREATE INDEX idx_user_vps_hostname ON user_vps(hostname);
CREATE INDEX idx_user_vps_status ON user_vps(status);
CREATE INDEX idx_user_vps_provider_instance_id ON user_vps(provider_instance_id);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_user_vps_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_user_vps_updated_at
    BEFORE UPDATE ON user_vps
    FOR EACH ROW
    EXECUTE FUNCTION update_user_vps_updated_at();
