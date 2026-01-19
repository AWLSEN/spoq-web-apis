//! HTTP handlers for the spoq-web-apis application.
//!
//! This module contains all the route handlers:
//! - `auth` - GitHub OAuth and device flow authentication handlers
//! - `health` - Health check endpoint
//! - `vps` - VPS provisioning and management handlers

pub mod auth;
pub mod health;
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
