-- Add device type column to distinguish VPS from other devices
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT 'vps';
CREATE INDEX IF NOT EXISTS idx_user_vps_device_type ON user_vps(device_type);
