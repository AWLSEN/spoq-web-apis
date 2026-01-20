-- Add registration tracking fields to user_vps
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS registration_code_hash TEXT;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS registration_expires_at TIMESTAMPTZ;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS vps_secret_hash TEXT;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS registered_at TIMESTAMPTZ;
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS conductor_verified_at TIMESTAMPTZ;

-- Index for registration lookup (query pending registrations)
CREATE INDEX IF NOT EXISTS idx_user_vps_registration_pending
ON user_vps (registration_expires_at)
WHERE registered_at IS NULL;

-- BACKFILL: Existing "ready" VPS records should be marked as registered/verified
-- Otherwise status check would incorrectly return "registering"
UPDATE user_vps
SET registered_at = created_at,
    conductor_verified_at = COALESCE(ready_at, created_at)
WHERE status = 'ready' AND registered_at IS NULL;
