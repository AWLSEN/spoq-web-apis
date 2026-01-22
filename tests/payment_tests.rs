//! Tests for payment checkout endpoints.

use actix_web::{test, web, App};
use spoq_web_apis::config::Config;
use spoq_web_apis::db::create_pool;
use spoq_web_apis::handlers::payment::{create_checkout_session, get_session_status, CreateCheckoutRequest};
use spoq_web_apis::middleware::auth::AuthenticatedUser;
use spoq_web_apis::services::StripeClientService;
use sqlx::PgPool;
use uuid::Uuid;

/// Helper to create test app with payment routes
fn create_test_app(
    pool: PgPool,
    stripe_client: StripeClientService,
) -> actix_web::App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .app_data(web::Data::new(pool))
        .app_data(web::Data::new(stripe_client))
        .route(
            "/api/payment/create-checkout-session",
            web::post().to(create_checkout_session),
        )
        .route(
            "/api/payment/session-status/{session_id}",
            web::get().to(get_session_status),
        )
}

#[actix_web::test]
async fn test_create_checkout_session_missing_user() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    let stripe_key = match &config.stripe_secret_key {
        Some(key) => key.clone(),
        None => {
            println!("Skipping test: STRIPE_SECRET_KEY not configured");
            return;
        }
    };

    let stripe_client = StripeClientService::new(stripe_key);
    let app = test::init_service(create_test_app(pool.clone(), stripe_client)).await;

    // Create request without auth (should fail with middleware)
    let req = test::TestRequest::post()
        .uri("/api/payment/create-checkout-session")
        .set_json(CreateCheckoutRequest {
            plan_id: "price_test123".to_string(),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Without auth middleware in test, this will fail at handler level (no user)
    // In production, middleware would reject with 401
    assert!(resp.status().is_client_error());
}

#[actix_web::test]
async fn test_create_checkout_session_invalid_plan_id() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    let stripe_key = match &config.stripe_secret_key {
        Some(key) => key.clone(),
        None => {
            println!("Skipping test: STRIPE_SECRET_KEY not configured");
            return;
        }
    };

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

    let stripe_client = StripeClientService::new(stripe_key);

    // Test handler directly with invalid plan_id
    let result = create_checkout_session(
        AuthenticatedUser { user_id },
        web::Data::new(pool.clone()),
        web::Data::new(stripe_client),
        web::Json(CreateCheckoutRequest {
            plan_id: "invalid_plan".to_string(), // Not starting with "price_"
        }),
    )
    .await;

    // Cleanup
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();

    assert!(result.is_err());
}

#[actix_web::test]
async fn test_create_checkout_session_duplicate_subscription() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create pool");

    let stripe_key = match &config.stripe_secret_key {
        Some(key) => key.clone(),
        None => {
            println!("Skipping test: STRIPE_SECRET_KEY not configured");
            return;
        }
    };

    // Create a test user with active subscription
    let user_id = Uuid::new_v4();
    let email = format!("test+{}@example.com", user_id);

    sqlx::query(
        "INSERT INTO users (id, username, email, github_id, avatar_url, subscription_status) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(user_id)
    .bind("testuser")
    .bind(&email)
    .bind(12345i64)
    .bind("https://example.com/avatar.jpg")
    .bind("active")
    .execute(&pool)
    .await
    .expect("Failed to create test user");

    let stripe_client = StripeClientService::new(stripe_key);

    // Test handler directly
    let result = create_checkout_session(
        AuthenticatedUser { user_id },
        web::Data::new(pool.clone()),
        web::Data::new(stripe_client),
        web::Json(CreateCheckoutRequest {
            plan_id: "price_test123".to_string(),
        }),
    )
    .await;

    // Cleanup
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();

    assert!(result.is_err());
}

#[actix_web::test]
async fn test_get_session_status_invalid_format() {
    // Setup
    let config = Config::from_env().expect("Failed to load config");

    let stripe_key = match &config.stripe_secret_key {
        Some(key) => key.clone(),
        None => {
            println!("Skipping test: STRIPE_SECRET_KEY not configured");
            return;
        }
    };

    let user_id = Uuid::new_v4();
    let stripe_client = StripeClientService::new(stripe_key);

    // Test handler directly with invalid session ID
    let result = get_session_status(
        AuthenticatedUser { user_id },
        web::Data::new(stripe_client),
        web::Path::from("invalid_session_id".to_string()),
    )
    .await;

    assert!(result.is_err());
}
