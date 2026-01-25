-- Add tunnel_id column to user_vps table
-- Stores the Cloudflare tunnel ID for secure access to the VPS

ALTER TABLE user_vps ADD COLUMN tunnel_id TEXT;
