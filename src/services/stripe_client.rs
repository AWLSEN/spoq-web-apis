//! Stripe API client service for payment processing.
//!
//! This module provides a lightweight wrapper around the Stripe Rust SDK client.

use stripe::Client;

/// Stripe client service for managing payment operations
#[derive(Clone)]
pub struct StripeClientService {
    client: Client,
}

impl StripeClientService {
    /// Create a new Stripe client service with the provided API key
    pub fn new(api_key: String) -> Self {
        let client = Client::new(api_key);
        Self { client }
    }

    /// Get a reference to the underlying Stripe client
    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_client_creation() {
        let client = StripeClientService::new("sk_test_mock_key".to_string());
        // Just verify we can create the client without panicking
        assert!(std::mem::size_of_val(&client) > 0);
    }
}
