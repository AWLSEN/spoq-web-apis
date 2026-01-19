//! Services module - business logic and external service integrations.
//!
//! This module contains:
//! - `token`: Token generation, hashing, and JWT handling
//! - `github`: GitHub OAuth client for authentication
//! - `user`: User database operations
//! - `device`: Device code generation for CLI authentication
//! - `hostinger`: Hostinger VPS API client for VPS provisioning

pub mod device;
pub mod github;
pub mod hostinger;
pub mod token;
pub mod user;

// Re-export commonly used types for convenience
pub use device::{DecodeError, DeviceGrantCreated, VerificationData};
pub use github::{GitHubOAuthConfig, GitHubUser, GithubError};
pub use hostinger::{HostingerClient, HostingerError};
pub use token::Claims;
