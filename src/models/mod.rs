//! Data models for the spoq-web-apis application.
//!
//! This module contains the database models used throughout the application:
//! - [`User`] - Represents a GitHub-authenticated user
//! - [`RefreshToken`] - Represents a JWT refresh token
//! - [`DeviceGrant`] - Represents a device authorization grant
//! - [`UserVps`] - Represents a user's VPS instance

pub mod device_grant;
pub mod token;
pub mod user;
pub mod user_vps;

pub use device_grant::{DeviceGrant, DeviceGrantStatus};
pub use token::RefreshToken;
pub use user::User;
pub use user_vps::{
    ProvisionVpsRequest, UserVps, VpsDataCenter, VpsPlan, VpsProvider, VpsStatus,
    VpsStatusResponse,
};
