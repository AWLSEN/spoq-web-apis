-- Migration: Add Subscription Fields
-- Description: Add Stripe subscription tracking fields to users and user_vps tables, and create subscription_events table

-- Add subscription fields to users table
ALTER TABLE users
ADD COLUMN stripe_customer_id TEXT UNIQUE,
ADD COLUMN subscription_id TEXT UNIQUE,
ADD COLUMN subscription_status TEXT DEFAULT 'inactive',
ADD COLUMN subscription_plan_id TEXT,
ADD COLUMN subscription_current_period_end TIMESTAMPTZ,
ADD COLUMN subscription_cancel_at_period_end BOOLEAN DEFAULT false;

-- Add subscription fields to user_vps table
ALTER TABLE user_vps
ADD COLUMN subscription_id TEXT,
ADD COLUMN requires_subscription BOOLEAN DEFAULT false,
ADD COLUMN cancelled_at TIMESTAMPTZ,
ADD COLUMN cancellation_reason TEXT;

-- Create subscription_events table for audit trail
CREATE TABLE subscription_events (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    subscription_id TEXT,
    stripe_event_id TEXT UNIQUE,
    data JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Create indexes for performance
CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id);
CREATE INDEX idx_users_subscription ON users(subscription_id);
CREATE INDEX idx_user_vps_subscription ON user_vps(subscription_id);
CREATE INDEX idx_subscription_events_user ON subscription_events(user_id);
CREATE INDEX idx_subscription_events_stripe ON subscription_events(stripe_event_id);

-- Add comments for documentation
COMMENT ON COLUMN users.stripe_customer_id IS 'Stripe customer ID for billing';
COMMENT ON COLUMN users.subscription_id IS 'Active Stripe subscription ID';
COMMENT ON COLUMN users.subscription_status IS 'Current subscription status (active, inactive, past_due, canceled, etc.)';
COMMENT ON COLUMN users.subscription_plan_id IS 'Stripe price/plan ID';
COMMENT ON COLUMN users.subscription_current_period_end IS 'When the current subscription period ends';
COMMENT ON COLUMN users.subscription_cancel_at_period_end IS 'Whether subscription will cancel at period end';
COMMENT ON COLUMN user_vps.subscription_id IS 'Subscription ID this VPS is linked to';
COMMENT ON COLUMN user_vps.requires_subscription IS 'Whether this VPS requires an active subscription';
COMMENT ON COLUMN user_vps.cancelled_at IS 'When the VPS was cancelled';
COMMENT ON COLUMN user_vps.cancellation_reason IS 'Reason for VPS cancellation';
COMMENT ON TABLE subscription_events IS 'Audit trail of all subscription-related events from Stripe webhooks';
