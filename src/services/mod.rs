//! Services module - business logic and external service integrations.
//!
//! This module contains:
//! - `token`: Token generation, hashing, and JWT handling
//! - `github`: GitHub OAuth client for authentication
//! - `user`: User database operations
//! - `device`: Device code generation for CLI authentication
//! - `hostinger`: Hostinger VPS API client for VPS provisioning
//! - `cloudflare`: Cloudflare DNS API client for DNS automation
//! - `ssh_installer`: SSH client for remote VPS script execution
//! - `registration`: Registration code generation and verification

pub mod cloudflare;
pub mod device;
pub mod github;
pub mod hostinger;
pub mod registration;
pub mod ssh_installer;
pub mod stripe_client;
pub mod token;
pub mod user;

// Re-export commonly used types for convenience
pub use cloudflare::{CloudflareService, CloudflareServiceError};
pub use device::{DecodeError, DeviceGrantCreated, VerificationData};
pub use github::{GitHubOAuthConfig, GitHubUser, GithubError};
pub use hostinger::{HostingerClient, HostingerError};
pub use ssh_installer::{SshConfig, SshInstallerError, SshInstallerService, ScriptExecutionResult};
pub use stripe_client::StripeClientService;
pub use token::Claims;
