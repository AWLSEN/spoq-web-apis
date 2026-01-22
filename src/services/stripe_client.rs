//! Stripe API client service for payment processing.
//!
//! This module provides a wrapper around the Stripe Rust SDK for:
//! - Creating checkout sessions for subscription purchases
//! - Retrieving session details
//! - Creating customer portal sessions for subscription management

use stripe::{
    CheckoutSession, CheckoutSessionMode, Client, CreateCheckoutSession,
    CreateCheckoutSessionLineItems, CreateBillingPortalSession, BillingPortalSession,
    CustomerId,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StripeClientError {
    #[error("Stripe API error: {0}")]
    ApiError(#[from] stripe::StripeError),

    #[error("Invalid configuration: {0}")]
    ConfigError(String),
}

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

    /// Create a checkout session for subscription purchase
    ///
    /// # Arguments
    /// * `price_id` - The Stripe price ID for the subscription
    /// * `success_url` - URL to redirect to after successful payment
    /// * `cancel_url` - URL to redirect to if payment is cancelled
    /// * `customer_email` - Optional customer email to pre-fill
    ///
    /// # Returns
    /// The created checkout session with session ID and URL
    pub async fn create_checkout_session(
        &self,
        price_id: String,
        success_url: String,
        cancel_url: String,
        customer_email: Option<String>,
    ) -> Result<CheckoutSession, StripeClientError> {
        let mut params = CreateCheckoutSession::new();
        params.mode = Some(CheckoutSessionMode::Subscription);
        params.success_url = Some(&success_url);
        params.cancel_url = Some(&cancel_url);

        // Add line items (the subscription product)
        params.line_items = Some(vec![CreateCheckoutSessionLineItems {
            price: Some(price_id),
            quantity: Some(1),
            ..Default::default()
        }]);

        // Pre-fill customer email if provided
        if let Some(ref email) = customer_email {
            params.customer_email = Some(email);
        }

        let session = CheckoutSession::create(&self.client, params).await?;
        Ok(session)
    }

    /// Retrieve a checkout session by ID
    ///
    /// # Arguments
    /// * `session_id` - The Stripe session ID to retrieve
    ///
    /// # Returns
    /// The checkout session details
    pub async fn retrieve_session(
        &self,
        session_id: String,
    ) -> Result<CheckoutSession, StripeClientError> {
        let session = CheckoutSession::retrieve(&self.client, &session_id.parse().unwrap(), &[])
            .await?;
        Ok(session)
    }

    /// Create a billing portal session for subscription management
    ///
    /// # Arguments
    /// * `customer_id` - The Stripe customer ID
    /// * `return_url` - URL to redirect to when exiting the portal
    ///
    /// # Returns
    /// The billing portal session with URL
    pub async fn create_portal_session(
        &self,
        customer_id: String,
        return_url: String,
    ) -> Result<BillingPortalSession, StripeClientError> {
        let customer_id_parsed: CustomerId = customer_id.parse()
            .map_err(|_| StripeClientError::ConfigError("Invalid customer ID".to_string()))?;
        let mut params = CreateBillingPortalSession::new(customer_id_parsed);
        params.return_url = Some(&return_url);

        let session = BillingPortalSession::create(&self.client, params).await?;
        Ok(session)
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
