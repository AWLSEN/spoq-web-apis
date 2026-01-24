//! HTTP handlers for the spoq-web-apis application.
//!
//! This module contains all the route handlers:
//! - `auth` - GitHub OAuth and device flow authentication handlers
//! - `health` - Health check endpoint
//! - `vps` - VPS provisioning and management handlers
//! - `byovps` - BYOVPS (Bring Your Own VPS) provisioning handlers
//! - `admin` - Temporary admin endpoints (NO AUTH - remove after cleanup!)
//! - `webhooks` - Stripe webhook handlers for subscription lifecycle

pub mod admin;
pub mod auth;
pub mod byovps;
pub mod health;
pub mod payment;
pub mod vps;
pub mod webhooks;

// Re-export commonly used types
pub use auth::{
    device_authorize, device_init, device_token, device_verify, github_callback, github_redirect,
    refresh_token, revoke_token, AppState, AuthorizeForm, CallbackQuery, DeviceInitRequest,
    DeviceInitResponse, DeviceTokenRequest, GitHubRedirectQuery, RefreshRequest, RefreshResponse,
    RevokeRequest, TokenResponse, VerifyQuery,
};
pub use health::{health_check, HealthResponse};
pub use vps::{
    get_vps_precheck, get_vps_status, list_datacenters, list_plans, list_subscription_plans,
    provision_vps, reset_password, restart_vps, start_vps, stop_vps, DataCentersResponse,
    ProvisionResponse, ResetPasswordRequest, SuccessResponse, VpsPlansResponse,
};
pub use byovps::{provision_byovps, ProvisionByovpsRequest, ProvisionByovpsResponse};
pub use admin::{cleanup_all_vps, cleanup_user_vps, list_all_vps};
pub use payment::{
    create_checkout_session, create_portal_session, get_session_status, payment_cancel,
    payment_success, portal_return, CheckoutSessionResponse, CreateCheckoutRequest,
    PaymentStatusResponse,
};
pub use webhooks::stripe_webhook;
