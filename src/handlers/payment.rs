//! Payment checkout handlers for Stripe integration.
//!
//! This module provides endpoints for:
//! - Creating Stripe checkout sessions for VPS subscription purchases
//! - Checking payment/session status

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use stripe::{CheckoutSessionId, Customer, CreateCustomer, CustomerId};

use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthenticatedUser;
use crate::services::StripeClientService;

/// Request to create a checkout session
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateCheckoutRequest {
    /// VPS plan ID (Stripe price ID)
    pub plan_id: String,
}

/// Response for checkout session creation
#[derive(Debug, Serialize)]
pub struct CheckoutSessionResponse {
    /// URL to redirect user to for checkout
    pub checkout_url: String,
    /// Stripe session ID for status tracking
    pub session_id: String,
    /// Customer email used for checkout
    pub customer_email: String,
}

/// Response for payment status check
#[derive(Debug, Serialize)]
pub struct PaymentStatusResponse {
    /// Payment status: "paid", "pending", "expired"
    pub status: String,
    /// Stripe subscription ID if payment completed
    pub subscription_id: Option<String>,
    /// Stripe customer ID
    pub customer_id: Option<String>,
}

/// Create a Stripe checkout session for VPS subscription
///
/// POST /api/payment/create-checkout-session
pub async fn create_checkout_session(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe_client: web::Data<StripeClientService>,
    req: web::Json<CreateCheckoutRequest>,
) -> AppResult<HttpResponse> {
    // Query database for user email (not in JWT)
    let user_email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user.user_id)
        .fetch_optional(pool.get_ref())
        .await?;

    let user_email = user_email
        .ok_or_else(|| AppError::Internal("User not found".to_string()))?;

    // Validate plan_id exists in VPS plans (by checking if it's a valid Stripe price ID format)
    // Note: We can't validate against Hostinger plans here since they use different IDs
    // The plan_id should be a Stripe price ID (e.g., "price_...")
    if !req.plan_id.starts_with("price_") {
        return Err(AppError::BadRequest(
            "Invalid plan_id: must be a Stripe price ID".to_string(),
        ));
    }

    // Check if user already has active subscription
    let existing_subscription: Option<String> = sqlx::query_scalar(
        "SELECT subscription_id FROM users WHERE id = $1 AND subscription_status IN ('active', 'trialing')"
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    if existing_subscription.is_some() {
        return Err(AppError::Conflict(
            "User already has an active subscription".to_string(),
        ));
    }

    // Get or create Stripe customer
    let stripe_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT stripe_customer_id FROM users WHERE id = $1"
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?
    .flatten();

    let customer_id = if let Some(cust_id) = stripe_customer_id {
        cust_id
    } else {
        // Create new Stripe customer
        let mut create_customer = CreateCustomer::new();
        create_customer.email = Some(&user_email);
        create_customer.metadata = Some(
            vec![("user_id".to_string(), user.user_id.to_string())]
                .into_iter()
                .collect(),
        );

        let customer = Customer::create(&stripe_client.client(), create_customer)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create Stripe customer: {}", e)))?;

        let customer_id_str = customer.id.to_string();

        // Store customer ID in database
        sqlx::query("UPDATE users SET stripe_customer_id = $1 WHERE id = $2")
            .bind(&customer_id_str)
            .bind(user.user_id)
            .execute(pool.get_ref())
            .await?;

        tracing::info!("Created Stripe customer {} for user {}", customer_id_str, user.user_id);

        customer_id_str
    };

    // Create Stripe Checkout Session
    // CLI polls for payment status, these URLs are just for user feedback
    let success_url = "https://spoq.dev/payment/success?session_id={CHECKOUT_SESSION_ID}".to_string();
    let cancel_url = "https://spoq.dev/payment/cancel".to_string();

    use stripe::{CreateCheckoutSession, CheckoutSessionMode, CreateCheckoutSessionLineItems};

    let mut params = CreateCheckoutSession::new();
    params.mode = Some(CheckoutSessionMode::Subscription);
    params.success_url = Some(&success_url);
    params.cancel_url = Some(&cancel_url);

    // Set customer (prefilled)
    let customer_id_parsed: CustomerId = customer_id.parse()
        .map_err(|_| AppError::Internal("Invalid customer ID format".to_string()))?;
    params.customer = Some(customer_id_parsed);

    // Add line items
    params.line_items = Some(vec![CreateCheckoutSessionLineItems {
        price: Some(req.plan_id.clone()),
        quantity: Some(1),
        ..Default::default()
    }]);

    // Add metadata
    params.metadata = Some(
        vec![
            ("user_id".to_string(), user.user_id.to_string()),
            ("plan_id".to_string(), req.plan_id.clone()),
        ]
        .into_iter()
        .collect(),
    );

    // Add subscription metadata
    params.subscription_data = Some(stripe::CreateCheckoutSessionSubscriptionData {
        metadata: Some(
            vec![
                ("user_id".to_string(), user.user_id.to_string()),
                ("plan_id".to_string(), req.plan_id.clone()),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    });

    let session = stripe::CheckoutSession::create(&stripe_client.client(), params)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create checkout session: {}", e)))?;

    let checkout_url = session.url.ok_or_else(||
        AppError::Internal("No checkout URL in session".to_string()))?;

    Ok(HttpResponse::Ok().json(CheckoutSessionResponse {
        checkout_url,
        session_id: session.id.to_string(),
        customer_email: user_email,
    }))
}

/// Get payment/session status
///
/// GET /api/payment/session-status/:session_id
pub async fn get_session_status(
    user: AuthenticatedUser,
    stripe_client: web::Data<StripeClientService>,
    session_id: web::Path<String>,
) -> AppResult<HttpResponse> {
    // Parse session ID
    let session_id_parsed: CheckoutSessionId = session_id.parse()
        .map_err(|_| AppError::BadRequest("Invalid session ID format".to_string()))?;

    // Retrieve session from Stripe
    let session = stripe::CheckoutSession::retrieve(&stripe_client.client(), &session_id_parsed, &[])
        .await
        .map_err(|e| AppError::Internal(format!("Failed to retrieve session: {}", e)))?;

    // Verify session belongs to authenticated user
    if let Some(metadata) = &session.metadata {
        if let Some(session_user_id) = metadata.get("user_id") {
            if session_user_id != &user.user_id.to_string() {
                return Err(AppError::Forbidden(
                    "Session does not belong to authenticated user".to_string(),
                ));
            }
        } else {
            return Err(AppError::Internal("Session missing user_id metadata".to_string()));
        }
    } else {
        return Err(AppError::Internal("Session missing metadata".to_string()));
    }

    // Map Stripe status to internal status
    let status = match session.status {
        Some(stripe::CheckoutSessionStatus::Complete) => "paid",
        Some(stripe::CheckoutSessionStatus::Expired) => "expired",
        Some(stripe::CheckoutSessionStatus::Open) => "pending",
        _ => "pending",
    };

    let subscription_id = session.subscription.map(|s| s.id().to_string());
    let customer_id = session.customer.map(|c| c.id().to_string());

    Ok(HttpResponse::Ok().json(PaymentStatusResponse {
        status: status.to_string(),
        subscription_id,
        customer_id,
    }))
}

/// Payment success page - shown after successful Stripe checkout
///
/// GET /payment/success
pub async fn payment_success() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(r#"<!DOCTYPE html>
<html>
<head>
    <title>Payment Successful - SPOQ</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #0a0a0a; color: #fff; }
        .container { text-align: center; padding: 2rem; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { margin: 0 0 1rem; }
        p { color: #888; margin: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✓</div>
        <h1>Payment Successful</h1>
        <p>Return to your terminal to continue setup.</p>
    </div>
</body>
</html>"#)
}

/// Create a Stripe Customer Portal session for subscription management
///
/// POST /api/payments/portal
///
/// Returns a URL to the Stripe Customer Portal where users can:
/// - Upgrade/downgrade their plan
/// - Cancel subscription
/// - Update payment method
/// - View invoices
pub async fn create_portal_session(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe_client: web::Data<StripeClientService>,
) -> AppResult<HttpResponse> {
    // Get user's Stripe customer ID
    let stripe_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT stripe_customer_id FROM users WHERE id = $1"
    )
    .bind(user.user_id)
    .fetch_optional(pool.get_ref())
    .await?
    .flatten();

    let customer_id = stripe_customer_id.ok_or_else(|| {
        AppError::BadRequest("No subscription found. Please subscribe first.".to_string())
    })?;

    // Create portal session
    use stripe::{CreateBillingPortalSession, CustomerId};

    let customer_id_parsed: CustomerId = customer_id.parse()
        .map_err(|_| AppError::Internal("Invalid customer ID".to_string()))?;

    let mut params = CreateBillingPortalSession::new(customer_id_parsed);
    params.return_url = Some("https://spoq.dev/portal/return");

    let session = stripe::BillingPortalSession::create(&stripe_client.client(), params)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create portal session: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "portal_url": session.url
    })))
}

/// Portal return page - shown after user returns from Stripe portal
///
/// GET /portal/return
pub async fn portal_return() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(r#"<!DOCTYPE html>
<html>
<head>
    <title>Subscription Updated - SPOQ</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #0a0a0a; color: #fff; }
        .container { text-align: center; padding: 2rem; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { margin: 0 0 1rem; }
        p { color: #888; margin: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✓</div>
        <h1>Subscription Updated</h1>
        <p>Changes will take effect shortly.</p>
    </div>
</body>
</html>"#)
}

/// Payment cancelled page - shown when user cancels Stripe checkout
///
/// GET /payment/cancel
pub async fn payment_cancel() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(r#"<!DOCTYPE html>
<html>
<head>
    <title>Payment Cancelled - SPOQ</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #0a0a0a; color: #fff; }
        .container { text-align: center; padding: 2rem; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { margin: 0 0 1rem; }
        p { color: #888; margin: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✕</div>
        <h1>Payment Cancelled</h1>
        <p>Return to your terminal to try again.</p>
    </div>
</body>
</html>"#)
}
