//! Services module - business logic and external service integrations.
//!
//! This module contains:
//! - `token`: Token generation, hashing, and JWT handling
//! - `github`: GitHub OAuth client for authentication
//! - `user`: User database operations
//! - `device`: Device code generation for CLI authentication

pub mod device;
pub mod github;
pub mod token;
pub mod user;

// Re-export commonly used types for convenience
pub use device::{DecodeError, DeviceGrantCreated, VerificationData};
pub use github::{GitHubOAuthConfig, GitHubUser, GithubError};
pub use token::Claims;
