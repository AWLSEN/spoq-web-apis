-- Add dns_record_id column to track Cloudflare DNS record creation
-- This allows us to know if the DNS record has been created for the VPS

ALTER TABLE user_vps ADD COLUMN dns_record_id TEXT;

-- Comment explaining the field
COMMENT ON COLUMN user_vps.dns_record_id IS 'Cloudflare DNS record ID for hostname -> IP mapping';
