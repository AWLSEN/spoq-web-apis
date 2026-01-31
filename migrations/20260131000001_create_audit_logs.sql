-- Audit logs table for compliance tracking
-- Tracks all security-relevant actions (VPS operations, auth events, etc.)

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Who performed the action
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- What action was performed
    action TEXT NOT NULL,              -- e.g., 'vps.provision', 'vps.replace', 'auth.failed'
    resource_type TEXT NOT NULL,       -- e.g., 'vps', 'byovps', 'user'
    resource_id UUID,                  -- VPS ID, operation ID, etc. (nullable for failed actions)

    -- Request context
    ip_address TEXT,                   -- Client IP address
    user_agent TEXT,                   -- Client user agent

    -- Request/response data (sanitized - no passwords/secrets)
    request_data JSONB,                -- Sanitized request body
    response_status INTEGER,           -- HTTP status code
    error_message TEXT,                -- Error message if failed

    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- Composite index for user + time range queries
CREATE INDEX idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC);

-- Comment on table
COMMENT ON TABLE audit_logs IS 'Audit trail for security-relevant operations';
COMMENT ON COLUMN audit_logs.action IS 'Action identifier: vps.provision, vps.replace, vps.confirm, byovps.provision, byovps.replace, auth.failed, auth.rate_limited';
COMMENT ON COLUMN audit_logs.request_data IS 'Sanitized request data - NEVER contains passwords, tokens, or secrets';
