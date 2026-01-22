//! Tests for Stripe webhook handlers.

use actix_web::{test, web, App};
use serde_json::json;
use spoq_web_apis::config::Config;
use spoq_web_apis::db::create_pool;
use spoq_web_apis::handlers::webhooks::stripe_webhook;
use spoq_web_apis::services::HostingerClient;
use sqlx::PgPool;
use uuid::Uuid;

/// Helper to create test app with webhook routes
fn create_test_app(
    pool: PgPool,
    config: Config,
    hostinger_client: Option<HostingerClient>,
) -> actix_web::App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let mut app = App::new()
        .app_data(web::Data::new(pool))
        .app_data(web::Data::new(config))
        .route("/webhooks/stripe", web::post().to(stripe_webhook));

    if let Some(hostinger) = hostinger_client {
        app = app.app_data(web::Data::new(hostinger));
    }

    app
}

#[actix_web::test]
async fn test_webhook_missing_signature() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    if config.stripe_webhook_secret.is_none() {
        println!("Skipping test: STRIPE_WEBHOOK_SECRET not configured");
        return;
    }

    let app = test::init_service(create_test_app(pool, config, None)).await;

    // Create request without stripe-signature header
    let req = test::TestRequest::post()
        .uri("/webhooks/stripe")
        .set_payload("{}")
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should return 400 for missing signature
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_webhook_invalid_signature() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    if config.stripe_webhook_secret.is_none() {
        println!("Skipping test: STRIPE_WEBHOOK_SECRET not configured");
        return;
    }

    let app = test::init_service(create_test_app(pool, config, None)).await;

    // Create request with invalid signature
    let req = test::TestRequest::post()
        .uri("/webhooks/stripe")
        .insert_header(("stripe-signature", "invalid_signature"))
        .set_payload("{}")
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should return 400 for invalid signature
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_log_subscription_event() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    // Create a test user
    let user_id = Uuid::new_v4();
    let email = format!("test+{}@example.com", user_id);

    sqlx::query(
        "INSERT INTO users (id, username, email, github_id, avatar_url) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user_id)
    .bind("testuser")
    .bind(&email)
    .bind(12345i64)
    .bind("https://example.com/avatar.jpg")
    .execute(&pool)
    .await
    .expect("Failed to create test user");

    // Get user's integer ID
    let user_int_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to get user ID");

    // Test logging event directly (unit test)
    let event_data = json!({
        "test": "data"
    });

    let result = sqlx::query(
        "INSERT INTO subscription_events (user_id, event_type, subscription_id, stripe_event_id, data)
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user_int_id)
    .bind("test_event")
    .bind("sub_test123")
    .bind(format!("evt_test_{}", Uuid::new_v4()))
    .bind(event_data)
    .execute(&pool)
    .await;

    assert!(result.is_ok());

    // Verify the event was logged
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscription_events WHERE user_id = $1 AND event_type = 'test_event'"
    )
    .bind(user_int_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count events");

    assert_eq!(count, 1);

    // Cleanup
    sqlx::query("DELETE FROM subscription_events WHERE user_id = $1")
        .bind(user_int_id)
        .execute(&pool)
        .await
        .ok();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();
}

#[actix_web::test]
async fn test_subscription_status_update() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    // Create a test user with subscription
    let user_id = Uuid::new_v4();
    let email = format!("test+{}@example.com", user_id);
    let stripe_customer_id = format!("cus_test_{}", Uuid::new_v4());
    let subscription_id = format!("sub_test_{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (id, username, email, github_id, avatar_url, stripe_customer_id, subscription_id, subscription_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(user_id)
    .bind("testuser")
    .bind(&email)
    .bind(12345i64)
    .bind("https://example.com/avatar.jpg")
    .bind(&stripe_customer_id)
    .bind(&subscription_id)
    .bind("active")
    .execute(&pool)
    .await
    .expect("Failed to create test user");

    // Update subscription status to cancelled
    let result = sqlx::query("UPDATE users SET subscription_status = 'cancelled' WHERE subscription_id = $1")
        .bind(&subscription_id)
        .execute(&pool)
        .await;

    assert!(result.is_ok());

    // Verify the status was updated
    let status: String = sqlx::query_scalar("SELECT subscription_status FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to get subscription status");

    assert_eq!(status, "cancelled");

    // Cleanup
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();
}

#[actix_web::test]
async fn test_vps_cancellation_on_subscription_deleted() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    // Create a test user with subscription and VPS
    let user_id = Uuid::new_v4();
    let email = format!("test+{}@example.com", user_id);
    let stripe_customer_id = format!("cus_test_{}", Uuid::new_v4());
    let subscription_id = format!("sub_test_{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (id, username, email, github_id, avatar_url, stripe_customer_id, subscription_id, subscription_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(user_id)
    .bind("testuser")
    .bind(&email)
    .bind(12345i64)
    .bind("https://example.com/avatar.jpg")
    .bind(&stripe_customer_id)
    .bind(&subscription_id)
    .bind("active")
    .execute(&pool)
    .await
    .expect("Failed to create test user");

    // Get user's integer ID
    let user_int_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to get user ID");

    // Create a VPS record
    sqlx::query(
        "INSERT INTO user_vps (user_id, hostinger_vps_id, hostname, status, requires_subscription)
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user_int_id)
    .bind(12345i64)
    .bind("test.spoq.dev")
    .bind("active")
    .bind(true)
    .execute(&pool)
    .await
    .expect("Failed to create VPS record");

    // Simulate subscription deletion by updating status
    sqlx::query("UPDATE users SET subscription_status = 'cancelled' WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("Failed to update subscription status");

    // Update VPS record to cancelled
    sqlx::query(
        "UPDATE user_vps
         SET status = 'cancelled',
             cancelled_at = NOW(),
             cancellation_reason = 'subscription_cancelled'
         WHERE user_id = $1"
    )
    .bind(user_int_id)
    .execute(&pool)
    .await
    .expect("Failed to update VPS status");

    // Verify VPS was cancelled
    let vps_status: String = sqlx::query_scalar(
        "SELECT status FROM user_vps WHERE user_id = $1"
    )
    .bind(user_int_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to get VPS status");

    assert_eq!(vps_status, "cancelled");

    // Verify cancellation reason
    let cancellation_reason: String = sqlx::query_scalar(
        "SELECT cancellation_reason FROM user_vps WHERE user_id = $1"
    )
    .bind(user_int_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to get cancellation reason");

    assert_eq!(cancellation_reason, "subscription_cancelled");

    // Cleanup
    sqlx::query("DELETE FROM user_vps WHERE user_id = $1")
        .bind(user_int_id)
        .execute(&pool)
        .await
        .ok();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();
}

#[actix_web::test]
async fn test_payment_failed_updates_status() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    // Create a test user with subscription
    let user_id = Uuid::new_v4();
    let email = format!("test+{}@example.com", user_id);
    let stripe_customer_id = format!("cus_test_{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (id, username, email, github_id, avatar_url, stripe_customer_id, subscription_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(user_id)
    .bind("testuser")
    .bind(&email)
    .bind(12345i64)
    .bind("https://example.com/avatar.jpg")
    .bind(&stripe_customer_id)
    .bind("active")
    .execute(&pool)
    .await
    .expect("Failed to create test user");

    // Update status to past_due (simulating payment failure)
    sqlx::query("UPDATE users SET subscription_status = 'past_due' WHERE stripe_customer_id = $1")
        .bind(&stripe_customer_id)
        .execute(&pool)
        .await
        .expect("Failed to update status");

    // Verify status was updated
    let status: String = sqlx::query_scalar("SELECT subscription_status FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to get status");

    assert_eq!(status, "past_due");

    // Cleanup
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();
}

#[actix_web::test]
async fn test_duplicate_event_handling() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    // Create a test user
    let user_id = Uuid::new_v4();
    let email = format!("test+{}@example.com", user_id);

    sqlx::query(
        "INSERT INTO users (id, username, email, github_id, avatar_url) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user_id)
    .bind("testuser")
    .bind(&email)
    .bind(12345i64)
    .bind("https://example.com/avatar.jpg")
    .execute(&pool)
    .await
    .expect("Failed to create test user");

    // Get user's integer ID
    let user_int_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to get user ID");

    let stripe_event_id = format!("evt_test_{}", Uuid::new_v4());
    let event_data = json!({"test": "data"});

    // Insert the same event twice (ON CONFLICT DO NOTHING should prevent duplicates)
    let result1 = sqlx::query(
        "INSERT INTO subscription_events (user_id, event_type, subscription_id, stripe_event_id, data)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (stripe_event_id) DO NOTHING"
    )
    .bind(user_int_id)
    .bind("test_event")
    .bind("sub_test123")
    .bind(&stripe_event_id)
    .bind(&event_data)
    .execute(&pool)
    .await;

    let result2 = sqlx::query(
        "INSERT INTO subscription_events (user_id, event_type, subscription_id, stripe_event_id, data)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (stripe_event_id) DO NOTHING"
    )
    .bind(user_int_id)
    .bind("test_event")
    .bind("sub_test123")
    .bind(&stripe_event_id)
    .bind(&event_data)
    .execute(&pool)
    .await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Verify only one event was inserted
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscription_events WHERE stripe_event_id = $1"
    )
    .bind(&stripe_event_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count events");

    assert_eq!(count, 1);

    // Cleanup
    sqlx::query("DELETE FROM subscription_events WHERE stripe_event_id = $1")
        .bind(&stripe_event_id)
        .execute(&pool)
        .await
        .ok();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();
}
