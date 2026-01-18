//! spoq-web-apis - GitHub OAuth authentication API
//!
//! This crate provides a complete GitHub OAuth authentication flow with JWT token management.
//!
//! # Modules
//!
//! - [`config`] - Application configuration from environment variables
//! - [`db`] - Database connection pool and migrations
//! - [`error`] - Unified error handling
//! - [`models`] - Database models (User, RefreshToken)
//! - [`services`] - Business logic (GitHub OAuth, token management, user operations)
//! - [`handlers`] - HTTP route handlers
//! - [`middleware`] - Authentication and rate limiting middleware
//!
//! # Quick Start
//!
//! ```ignore
//! use spoq_web_apis::{Config, create_pool, run_migrations, AppState};
//! use spoq_web_apis::handlers::{github_redirect, github_callback, refresh_token, revoke_token, health_check};
//! use spoq_web_apis::middleware::create_rate_limiter;
//! ```

pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod services;

// Re-export commonly used types at the crate root
pub use config::{Config, ConfigError};
pub use db::{create_pool, run_migrations};
pub use error::{AppError, AppResult};
pub use handlers::auth::AppState;
pub use models::{DeviceGrant, DeviceGrantStatus, RefreshToken, User};
pub use services::{
    Claims, DecodeError, DeviceGrantCreated, GitHubOAuthConfig, GitHubUser, GithubError,
    VerificationData,
};
