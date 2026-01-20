-- Add device_type column to distinguish between VPS types
-- 'vps' = managed Hostinger VPS (default)
-- 'byovps' = user-provided VPS (bring your own)

ALTER TABLE user_vps ADD COLUMN device_type TEXT NOT NULL DEFAULT 'vps';

-- Create index for filtering by device type
CREATE INDEX idx_user_vps_device_type ON user_vps(device_type);

-- Comment explaining the field
COMMENT ON COLUMN user_vps.device_type IS 'VPS provisioning type: ''vps'' for managed Hostinger VPS, ''byovps'' for user-provided VPS';
