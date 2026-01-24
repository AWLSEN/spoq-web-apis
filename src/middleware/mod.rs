//! Middleware for the spoq-web-apis application.
//!
//! This module contains:
//! - `auth` - JWT authentication middleware (AuthenticatedUser extractor)
//! - `rate_limit` - Rate limiting middleware using Governor

pub mod auth;
pub mod rate_limit;

// Re-export commonly used types
pub use auth::{AuthError, AuthenticatedUser};
pub use rate_limit::{create_dev_rate_limiter, create_rate_limiter, RateLimiter, RateLimiterConfig};
