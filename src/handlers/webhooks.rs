//! Stripe webhook handlers for subscription lifecycle events.
//!
//! This module provides endpoints for handling Stripe webhooks:
//! - checkout.session.completed: Initial subscription creation
//! - customer.subscription.created: Subscription setup
//! - customer.subscription.updated: Subscription changes
//! - customer.subscription.deleted: Subscription cancellation (triggers VPS cancellation)
//! - invoice.payment_failed: Payment issues
//! - invoice.payment_succeeded: Successful renewals

use actix_web::{web, HttpRequest, HttpResponse};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use sqlx::PgPool;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::services::HostingerClient;

type HmacSha256 = Hmac<Sha256>;

/// Stripe event wrapper
#[derive(Debug, Deserialize)]
struct StripeEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: EventData,
}

#[derive(Debug, Deserialize)]
struct EventData {
    object: serde_json::Value,
}

/// Verify Stripe webhook signature
fn verify_signature(
    payload: &str,
    signature_header: &str,
    webhook_secret: &str,
) -> Result<(), AppError> {
    // Parse signature header (format: "t=timestamp,v1=signature")
    let mut timestamp = None;
    let mut signature = None;

    for part in signature_header.split(',') {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "t" => timestamp = Some(value),
                "v1" => signature = Some(value),
                _ => {}
            }
        }
    }

    let timestamp = timestamp.ok_or_else(|| {
        AppError::BadRequest("Missing timestamp in signature header".to_string())
    })?;
    let signature = signature
        .ok_or_else(|| AppError::BadRequest("Missing signature in header".to_string()))?;

    // Construct signed payload
    let signed_payload = format!("{}.{}", timestamp, payload);

    // Compute HMAC
    let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
        .map_err(|_| AppError::Internal("Invalid webhook secret".to_string()))?;
    mac.update(signed_payload.as_bytes());

    // Verify signature
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    if expected_signature != signature {
        return Err(AppError::BadRequest(
            "Invalid webhook signature".to_string(),
        ));
    }

    Ok(())
}

/// Log a subscription event to the database
async fn log_subscription_event(
    pool: &PgPool,
    user_id: i32,
    event_type: &str,
    subscription_id: Option<&str>,
    stripe_event_id: &str,
    data: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO subscription_events (user_id, event_type, subscription_id, stripe_event_id, data)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (stripe_event_id) DO NOTHING"
    )
    .bind(user_id)
    .bind(event_type)
    .bind(subscription_id)
    .bind(stripe_event_id)
    .bind(data)
    .execute(pool)
    .await?;

    Ok(())
}

/// Handle checkout.session.completed event
async fn handle_checkout_completed(
    pool: &PgPool,
    session: serde_json::Value,
    event_id: &str,
) -> AppResult<()> {
    // Extract fields from JSON
    let metadata = session
        .get("metadata")
        .ok_or_else(|| AppError::Internal("Missing metadata in session".to_string()))?;

    let user_id: i32 = metadata
        .get("user_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::Internal("Missing user_id in metadata".to_string()))?;

    let subscription_id = session
        .get("subscription")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing subscription in session".to_string()))?;

    let customer_id = session
        .get("customer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing customer in session".to_string()))?;

    let plan_id = metadata.get("plan_id").and_then(|v| v.as_str());

    // Update user with subscription info
    sqlx::query(
        "UPDATE users
         SET subscription_id = $1,
             subscription_status = 'active',
             stripe_customer_id = $2,
             subscription_plan_id = $3
         WHERE id = $4"
    )
    .bind(subscription_id)
    .bind(customer_id)
    .bind(plan_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    tracing::info!(
        "Checkout completed for user {}: subscription {}",
        user_id,
        subscription_id
    );

    // Log event
    log_subscription_event(
        pool,
        user_id,
        "checkout.session.completed",
        Some(subscription_id),
        event_id,
        json!({
            "subscription_id": subscription_id,
            "customer_id": customer_id,
            "plan_id": plan_id,
        }),
    )
    .await?;

    Ok(())
}

/// Handle customer.subscription.created event
async fn handle_subscription_created(
    pool: &PgPool,
    subscription: serde_json::Value,
    event_id: &str,
) -> AppResult<()> {
    let customer_id = subscription
        .get("customer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing customer in subscription".to_string()))?;

    // Find user by stripe_customer_id
    let user_id: Option<i32> = sqlx::query_scalar("SELECT id FROM users WHERE stripe_customer_id = $1")
        .bind(customer_id)
        .fetch_optional(pool)
        .await?;

    let user_id = user_id.ok_or_else(|| {
        AppError::Internal(format!("User not found for customer {}", customer_id))
    })?;

    let subscription_id = subscription
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing id in subscription".to_string()))?;

    let status = subscription
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let current_period_end = subscription
        .get("current_period_end")
        .and_then(|v| v.as_i64())
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

    let cancel_at_period_end = subscription
        .get("cancel_at_period_end")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Update user subscription info
    sqlx::query(
        "UPDATE users
         SET subscription_id = $1,
             subscription_status = $2,
             subscription_current_period_end = $3,
             subscription_cancel_at_period_end = $4
         WHERE id = $5"
    )
    .bind(subscription_id)
    .bind(status)
    .bind(current_period_end)
    .bind(cancel_at_period_end)
    .bind(user_id)
    .execute(pool)
    .await?;

    tracing::info!(
        "Subscription created for user {}: {} (status: {})",
        user_id,
        subscription_id,
        status
    );

    // Log event
    log_subscription_event(
        pool,
        user_id,
        "customer.subscription.created",
        Some(subscription_id),
        event_id,
        json!({
            "subscription_id": subscription_id,
            "status": status,
            "current_period_end": current_period_end,
            "cancel_at_period_end": cancel_at_period_end,
        }),
    )
    .await?;

    Ok(())
}

/// Handle customer.subscription.updated event
async fn handle_subscription_updated(
    pool: &PgPool,
    subscription: serde_json::Value,
    event_id: &str,
) -> AppResult<()> {
    let subscription_id = subscription
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing id in subscription".to_string()))?;

    // Find user by subscription_id
    let user_id: Option<i32> = sqlx::query_scalar("SELECT id FROM users WHERE subscription_id = $1")
        .bind(subscription_id)
        .fetch_optional(pool)
        .await?;

    let user_id = user_id.ok_or_else(|| {
        AppError::Internal(format!("User not found for subscription {}", subscription_id))
    })?;

    let status = subscription
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let current_period_end = subscription
        .get("current_period_end")
        .and_then(|v| v.as_i64())
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

    let cancel_at_period_end = subscription
        .get("cancel_at_period_end")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Update subscription info
    sqlx::query(
        "UPDATE users
         SET subscription_status = $1,
             subscription_current_period_end = $2,
             subscription_cancel_at_period_end = $3
         WHERE id = $4"
    )
    .bind(status)
    .bind(current_period_end)
    .bind(cancel_at_period_end)
    .bind(user_id)
    .execute(pool)
    .await?;

    tracing::info!(
        "Subscription updated for user {}: {} (status: {})",
        user_id,
        subscription_id,
        status
    );

    // Log event
    log_subscription_event(
        pool,
        user_id,
        "customer.subscription.updated",
        Some(subscription_id),
        event_id,
        json!({
            "subscription_id": subscription_id,
            "status": status,
            "current_period_end": current_period_end,
            "cancel_at_period_end": cancel_at_period_end,
        }),
    )
    .await?;

    Ok(())
}

/// Handle customer.subscription.deleted event
/// This will also cancel the associated VPS if it exists and requires a subscription
async fn handle_subscription_deleted(
    pool: &PgPool,
    subscription: serde_json::Value,
    event_id: &str,
    hostinger_client: Option<&HostingerClient>,
) -> AppResult<()> {
    let subscription_id = subscription
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing id in subscription".to_string()))?;

    // Find user and their VPS (if any) in a single query with JOIN
    let result: Option<(i32, Option<i64>, Option<bool>)> = sqlx::query_as(
        "SELECT u.id, v.hostinger_vps_id, v.requires_subscription
         FROM users u
         LEFT JOIN user_vps v ON u.id = v.user_id
         WHERE u.subscription_id = $1"
    )
    .bind(subscription_id)
    .fetch_optional(pool)
    .await?;

    let (user_id, vps_id, requires_subscription) = result.ok_or_else(|| {
        AppError::Internal(format!("User not found for subscription {}", subscription_id))
    })?;

    // Update user subscription status
    sqlx::query("UPDATE users SET subscription_status = 'cancelled' WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    tracing::info!(
        "Subscription deleted for user {}: {}",
        user_id,
        subscription_id
    );

    // If user has a VPS that requires subscription, cancel it
    if let (Some(hostinger_vps_id), Some(true)) = (vps_id, requires_subscription) {
        if let Some(client) = hostinger_client {
            tracing::info!(
                "Cancelling VPS {} for user {} due to subscription cancellation",
                hostinger_vps_id,
                user_id
            );

            // Attempt to delete VPS from Hostinger
            match client.delete_vps(hostinger_vps_id).await {
                Ok(_) => {
                    tracing::info!("Successfully cancelled VPS {}", hostinger_vps_id);

                    // Update user_vps record
                    sqlx::query(
                        "UPDATE user_vps
                         SET status = 'cancelled',
                             cancelled_at = NOW(),
                             cancellation_reason = 'subscription_cancelled'
                         WHERE user_id = $1"
                    )
                    .bind(user_id)
                    .execute(pool)
                    .await?;

                    // Log successful cancellation
                    log_subscription_event(
                        pool,
                        user_id,
                        "vps_cancellation_succeeded",
                        Some(subscription_id),
                        event_id,
                        json!({
                            "subscription_id": subscription_id,
                            "vps_id": hostinger_vps_id,
                        }),
                    )
                    .await?;
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to cancel VPS {} for user {}: {}",
                        hostinger_vps_id,
                        user_id,
                        e
                    );

                    // Log failure
                    log_subscription_event(
                        pool,
                        user_id,
                        "vps_cancellation_failed",
                        Some(subscription_id),
                        event_id,
                        json!({
                            "subscription_id": subscription_id,
                            "vps_id": hostinger_vps_id,
                            "error": format!("{}", e),
                        }),
                    )
                    .await?;
                }
            }
        } else {
            tracing::warn!(
                "Cannot cancel VPS {} - Hostinger client not configured",
                hostinger_vps_id
            );

            // Log that we couldn't cancel because no client
            log_subscription_event(
                pool,
                user_id,
                "vps_cancellation_failed",
                Some(subscription_id),
                event_id,
                json!({
                    "subscription_id": subscription_id,
                    "vps_id": hostinger_vps_id,
                    "error": "Hostinger client not configured",
                }),
            )
            .await?;
        }
    }

    // Log the subscription deletion event
    log_subscription_event(
        pool,
        user_id,
        "customer.subscription.deleted",
        Some(subscription_id),
        event_id,
        json!({
            "subscription_id": subscription_id,
        }),
    )
    .await?;

    Ok(())
}

/// Handle invoice.payment_failed event
async fn handle_payment_failed(
    pool: &PgPool,
    invoice: serde_json::Value,
    event_id: &str,
) -> AppResult<()> {
    let customer_id = invoice
        .get("customer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing customer in invoice".to_string()))?;

    // Find user by stripe_customer_id
    let user_id: Option<i32> = sqlx::query_scalar("SELECT id FROM users WHERE stripe_customer_id = $1")
        .bind(customer_id)
        .fetch_optional(pool)
        .await?;

    let user_id = user_id.ok_or_else(|| {
        AppError::Internal(format!("User not found for customer {}", customer_id))
    })?;

    // Update subscription status to past_due
    sqlx::query("UPDATE users SET subscription_status = 'past_due' WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    tracing::warn!("Payment failed for user {}", user_id);

    let subscription_id = invoice.get("subscription").and_then(|v| v.as_str());

    // Log event
    log_subscription_event(
        pool,
        user_id,
        "invoice.payment_failed",
        subscription_id,
        event_id,
        json!({
            "customer_id": customer_id,
            "subscription_id": subscription_id,
        }),
    )
    .await?;

    Ok(())
}

/// Handle invoice.payment_succeeded event
async fn handle_payment_succeeded(
    pool: &PgPool,
    invoice: serde_json::Value,
    event_id: &str,
) -> AppResult<()> {
    let customer_id = invoice
        .get("customer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Missing customer in invoice".to_string()))?;

    // Find user by stripe_customer_id
    let user_id: Option<i32> = sqlx::query_scalar("SELECT id FROM users WHERE stripe_customer_id = $1")
        .bind(customer_id)
        .fetch_optional(pool)
        .await?;

    let user_id = user_id.ok_or_else(|| {
        AppError::Internal(format!("User not found for customer {}", customer_id))
    })?;

    tracing::info!("Payment succeeded for user {}", user_id);

    let subscription_id = invoice.get("subscription").and_then(|v| v.as_str());

    // Log successful renewal
    log_subscription_event(
        pool,
        user_id,
        "invoice.payment_succeeded",
        subscription_id,
        event_id,
        json!({
            "customer_id": customer_id,
            "subscription_id": subscription_id,
        }),
    )
    .await?;

    Ok(())
}

/// Stripe webhook endpoint
///
/// POST /webhooks/stripe
pub async fn stripe_webhook(
    req: HttpRequest,
    payload: web::Bytes,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    hostinger_client: Option<web::Data<HostingerClient>>,
) -> AppResult<HttpResponse> {
    // Get webhook secret from config
    let webhook_secret = config
        .stripe_webhook_secret
        .as_ref()
        .ok_or_else(|| AppError::Internal("Stripe webhook secret not configured".to_string()))?;

    // Get Stripe signature from headers
    let signature = req
        .headers()
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing stripe-signature header".to_string()))?;

    // Convert payload to string
    let payload_str = std::str::from_utf8(&payload)
        .map_err(|_| AppError::BadRequest("Invalid UTF-8 in payload".to_string()))?;

    // Verify webhook signature
    verify_signature(payload_str, signature, webhook_secret)?;

    // Parse event
    let event: StripeEvent = serde_json::from_str(payload_str)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let event_id = event.id.clone();
    let event_type = event.event_type.clone();

    tracing::info!("Received Stripe webhook: {} ({})", event_type, event_id);

    // Handle different event types
    let result = match event_type.as_str() {
        "checkout.session.completed" => {
            handle_checkout_completed(&pool, event.data.object, &event_id).await
        }
        "customer.subscription.created" => {
            handle_subscription_created(&pool, event.data.object, &event_id).await
        }
        "customer.subscription.updated" => {
            handle_subscription_updated(&pool, event.data.object, &event_id).await
        }
        "customer.subscription.deleted" => {
            handle_subscription_deleted(
                &pool,
                event.data.object,
                &event_id,
                hostinger_client.as_ref().map(|c| c.as_ref()),
            )
            .await
        }
        "invoice.payment_failed" => {
            handle_payment_failed(&pool, event.data.object, &event_id).await
        }
        "invoice.payment_succeeded" => {
            handle_payment_succeeded(&pool, event.data.object, &event_id).await
        }
        _ => {
            tracing::debug!("Unhandled webhook event type: {}", event_type);
            Ok(()) // Return 200 for unhandled events
        }
    };

    // Log errors but still return 200 to Stripe
    if let Err(e) = result {
        tracing::error!("Error processing webhook {}: {}", event_id, e);
        // We still return 200 to prevent Stripe from retrying
        // The error is logged to subscription_events if it's a VPS cancellation failure
    }

    Ok(HttpResponse::Ok().json(json!({ "received": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_signature_valid() {
        let payload = r#"{"id":"evt_test","type":"test","data":{"object":{}}}"#;
        let secret = "whsec_test_secret";
        let timestamp = "1234567890";

        // Create valid signature
        let signed_payload = format!("{}.{}", timestamp, payload);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let header = format!("t={},v1={}", timestamp, signature);

        let result = verify_signature(payload, &header, secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let payload = r#"{"id":"evt_test","type":"test","data":{"object":{}}}"#;
        let secret = "whsec_test_secret";
        let timestamp = "1234567890";
        let invalid_signature = "invalid_signature";

        let header = format!("t={},v1={}", timestamp, invalid_signature);

        let result = verify_signature(payload, &header, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_module_compiles() {
        // Basic compilation test
        assert!(true);
    }
}
