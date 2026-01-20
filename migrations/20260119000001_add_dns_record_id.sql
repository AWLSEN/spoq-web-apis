-- Add DNS record ID for Cloudflare management
ALTER TABLE user_vps ADD COLUMN IF NOT EXISTS dns_record_id TEXT;
