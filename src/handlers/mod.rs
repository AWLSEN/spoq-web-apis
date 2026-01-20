//! HTTP handlers for the spoq-web-apis application.
//!
//! This module contains all the route handlers:
//! - `auth` - GitHub OAuth and device flow authentication handlers
//! - `health` - Health check endpoint
//! - `internal` - Internal API for conductor registration
//! - `vps` - VPS provisioning and management handlers
//! - `byovps` - BYOVPS (Bring Your Own VPS) provisioning handlers
//! - `admin` - Temporary admin endpoints (NO AUTH - remove after cleanup!)

pub mod admin;
pub mod auth;
pub mod byovps;
pub mod health;
pub mod internal;
pub mod vps;

// Re-export commonly used types
pub use auth::{
    device_authorize, device_init, device_token, device_verify, github_callback, github_redirect,
    refresh_token, revoke_token, AppState, AuthorizeForm, CallbackQuery, DeviceInitRequest,
    DeviceInitResponse, DeviceTokenRequest, DeviceTokenResponse, GitHubRedirectQuery,
    RefreshRequest, RefreshResponse, RevokeRequest, VerifyQuery,
};
pub use health::{health_check, HealthResponse};
pub use vps::{
    get_vps_status, list_datacenters, list_plans, provision_vps, reset_password, restart_vps,
    start_vps, stop_vps, DataCentersResponse, ProvisionResponse, ResetPasswordRequest,
    SuccessResponse, VpsPlansResponse,
};
pub use byovps::{provision_byovps, ProvisionByovpsRequest, ProvisionByovpsResponse};
pub use admin::{cleanup_all_vps, cleanup_user_vps, list_all_vps};
