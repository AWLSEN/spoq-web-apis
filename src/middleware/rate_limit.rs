//! Rate limiting middleware using actix-governor.
//!
//! This module provides rate limiting functionality to protect the API
//! from abuse. It uses the Governor algorithm with a per-IP rate limit.

use actix_governor::{
    Governor, GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor,
};
use actix_governor::governor::middleware::NoOpMiddleware;

/// Type alias for the rate limiter configuration.
pub type RateLimiterConfig = GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>;

/// Type alias for the rate limiter.
pub type RateLimiter = Governor<PeerIpKeyExtractor, NoOpMiddleware>;

/// Creates a rate limiter configured for 10 requests per minute per IP.
///
/// The rate limiter uses a token bucket algorithm where:
/// - Each IP address has its own bucket
/// - The bucket refills at a rate of 1 token every 6 seconds (10 per minute)
/// - Burst capacity allows some flexibility for legitimate traffic
///
/// # Returns
///
/// A configured `Governor` middleware that can be applied to routes
///
/// # Example
///
/// ```ignore
/// use crate::middleware::rate_limit::create_rate_limiter;
///
/// let rate_limiter = create_rate_limiter();
///
/// HttpServer::new(move || {
///     App::new()
///         .wrap(rate_limiter.clone())
///         .route("/api/endpoint", web::get().to(handler))
/// })
/// ```
pub fn create_rate_limiter() -> RateLimiter {
    // 10 requests per minute = 1 request every 6 seconds
    let config: RateLimiterConfig = GovernorConfigBuilder::default()
        .seconds_per_request(6) // 1 request every 6 seconds = 10 per minute
        .burst_size(10) // Allow bursts up to 10 requests
        .finish()
        .expect("Failed to build rate limiter configuration");

    Governor::new(&config)
}

/// Creates a more permissive rate limiter for development/testing.
///
/// This rate limiter allows approximately 60 requests per minute per IP,
/// useful for development and testing environments.
///
/// # Returns
///
/// A configured `Governor` middleware with relaxed limits
#[allow(dead_code)]
pub fn create_dev_rate_limiter() -> RateLimiter {
    let config: RateLimiterConfig = GovernorConfigBuilder::default()
        .seconds_per_request(1) // 1 request per second
        .burst_size(60) // Allow bursts up to 60 requests
        .finish()
        .expect("Failed to build rate limiter configuration");

    Governor::new(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rate_limiter() {
        // Verify the rate limiter can be created without panicking
        let _limiter = create_rate_limiter();
    }

    #[test]
    fn test_create_dev_rate_limiter() {
        // Verify the dev rate limiter can be created without panicking
        let _limiter = create_dev_rate_limiter();
    }
}
