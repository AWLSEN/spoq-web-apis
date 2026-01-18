-- Create device_grants table for device authorization flow
CREATE TABLE device_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_code VARCHAR(64) NOT NULL UNIQUE,
    word_code VARCHAR(64) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_grants_device_code ON device_grants(device_code);
CREATE INDEX idx_device_grants_word_code ON device_grants(word_code);
CREATE INDEX idx_device_grants_expires_at ON device_grants(expires_at) WHERE status = 'pending';
