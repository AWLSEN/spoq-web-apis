//! spoq-web-apis - Main application entry point
//!
//! This is the main entry point for the spoq-web-apis service, which provides
//! GitHub OAuth authentication with JWT token management and device flow support.

use actix_web::{middleware::Logger, web, App, HttpServer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use spoq_web_apis::config::Config;
use spoq_web_apis::db::{create_pool, run_migrations};
use spoq_web_apis::handlers::auth::AppState;
use spoq_web_apis::handlers::{
    device_authorize, device_init, device_token, device_verify, github_callback, github_redirect,
    health_check, refresh_token, revoke_token,
};
use spoq_web_apis::middleware::create_rate_limiter;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing subscriber for structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "spoq_web_apis=info,actix_web=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration from environment variables
    let config = Config::from_env().expect("Failed to load configuration");
    let server_addr = config.server_addr();

    tracing::info!("Loading configuration...");

    // Create database connection pool
    let pool = create_pool(&config.database_url)
        .await
        .expect("Failed to create database pool");

    tracing::info!("Database connection pool created");

    // Run database migrations
    run_migrations(&pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database migrations completed");

    // Create HTTP client for GitHub API calls
    let http_client = reqwest::Client::builder()
        .user_agent("spoq-web-apis")
        .build()
        .expect("Failed to create HTTP client");

    // Create shared application state
    let app_state = web::Data::new(AppState {
        pool,
        config,
        http_client,
    });

    tracing::info!("Starting server at http://{}", server_addr);

    HttpServer::new(move || {
        // Create rate limiter for each worker (Governor doesn't implement Clone)
        let rate_limiter = create_rate_limiter();

        App::new()
            .app_data(app_state.clone())
            // Request logging
            .wrap(Logger::default())
            // Distributed tracing
            .wrap(tracing_actix_web::TracingLogger::default())
            // Rate limiting
            .wrap(rate_limiter)
            // Health check endpoint
            .route("/health", web::get().to(health_check))
            // Authentication routes
            .service(
                web::scope("/auth")
                    // GitHub OAuth flow
                    .route("/github", web::get().to(github_redirect))
                    .route("/github/callback", web::get().to(github_callback))
                    // Token management
                    .route("/refresh", web::post().to(refresh_token))
                    .route("/revoke", web::post().to(revoke_token))
                    // Device flow (CLI authentication)
                    .route("/device", web::post().to(device_init))
                    .route("/verify", web::get().to(device_verify))
                    .route("/authorize", web::post().to(device_authorize))
                    .route("/device/token", web::post().to(device_token)),
            )
    })
    .bind(&server_addr)?
    .run()
    .await
}
