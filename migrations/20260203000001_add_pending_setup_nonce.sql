-- Add pending_setup_nonce column for verifying local conductor setup
-- This prevents race conditions when switching from cloud VPS to local conductor

ALTER TABLE user_vps ADD COLUMN pending_setup_nonce TEXT;
