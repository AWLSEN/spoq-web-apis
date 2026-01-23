-- Change default SSH username from 'spoq' to 'root'
-- This is a non-destructive change that only affects new VPS records

ALTER TABLE user_vps ALTER COLUMN ssh_username SET DEFAULT 'root';

-- Note: Existing records keep their current ssh_username value
-- The default only applies to new inserts
