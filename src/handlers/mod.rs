//! HTTP handlers for the spoq-web-apis application.
//!
//! This module contains all the route handlers:
//! - `auth` - GitHub OAuth and device flow authentication handlers
//! - `health` - Health check endpoint

pub mod auth;
pub mod health;

// Re-export commonly used types
pub use auth::{
    device_authorize, device_init, device_token, device_verify, github_callback, github_redirect,
    refresh_token, revoke_token, AppState, AuthorizeForm, CallbackQuery, DeviceInitRequest,
    DeviceInitResponse, DeviceTokenRequest, DeviceTokenResponse, GitHubRedirectQuery,
    RefreshRequest, RefreshResponse, RevokeRequest, VerifyQuery,
};
pub use health::{health_check, HealthResponse};
