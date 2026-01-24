//! spoq-web-apis - Main application entry point
//!
//! This is the main entry point for the spoq-web-apis service, which provides
//! GitHub OAuth authentication with JWT token management, device flow support,
//! and VPS provisioning via Hostinger.

use actix_web::{middleware::Logger, web, App, HttpServer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use spoq_web_apis::config::Config;
use spoq_web_apis::db::{create_pool, run_migrations};
use spoq_web_apis::handlers::auth::AppState;
use spoq_web_apis::handlers::{
    device_authorize, device_init, device_token, device_verify, github_callback, github_redirect,
    health_check, refresh_token, revoke_token,
    // VPS handlers
    confirm_vps, get_vps_precheck, get_vps_status, list_datacenters, list_plans,
    list_subscription_plans, provision_vps, reset_password, restart_vps, start_vps, stop_vps,
    // BYOVPS handlers
    provision_byovps,
    // Payment handlers
    create_checkout_session, create_portal_session, get_session_status, payment_cancel,
    payment_success, portal_return,
    // Admin handlers (TEMPORARY - NO AUTH)
    cleanup_all_vps, cleanup_user_vps, list_all_vps,
    // Webhook handlers
    stripe_webhook,
};
use spoq_web_apis::middleware::create_rate_limiter;
use spoq_web_apis::services::{CloudflareService, HostingerClient, StripeClientService};

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
        pool: pool.clone(),
        config: config.clone(),
        http_client,
    });

    // Create Hostinger client if API key is configured
    let hostinger_client = config.hostinger_api_key.as_ref().map(|key| {
        tracing::info!("Hostinger API client configured");
        web::Data::new(HostingerClient::new(key.clone()))
    });

    // Create Cloudflare client if API token and zone ID are configured
    let cloudflare_client = match (&config.cloudflare_api_token, &config.cloudflare_zone_id) {
        (Some(token), Some(zone_id)) => {
            tracing::info!("Cloudflare DNS client configured");
            Some(web::Data::new(CloudflareService::new(
                token.clone(),
                zone_id.clone(),
            )))
        }
        _ => {
            tracing::warn!("Cloudflare DNS not configured - DNS records won't be created");
            None
        }
    };

    // Create Stripe client if secret key is configured
    let stripe_client = config.stripe_secret_key.as_ref().map(|key| {
        tracing::info!("Stripe payment client configured");
        web::Data::new(StripeClientService::new(key.clone()))
    });

    // Wrap pool and config for VPS handlers
    let db_pool = web::Data::new(pool);
    let app_config = web::Data::new(config);

    tracing::info!("Starting server at http://{}", server_addr);

    HttpServer::new(move || {
        // Create rate limiter for each worker (Governor doesn't implement Clone)
        let rate_limiter = create_rate_limiter();

        let mut app = App::new()
            .app_data(app_state.clone())
            .app_data(db_pool.clone())
            .app_data(app_config.clone())
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
            );

        // Add Cloudflare client if configured
        if let Some(ref cloudflare) = cloudflare_client {
            app = app.app_data(cloudflare.clone());
        }

        // Add Stripe client if configured
        if let Some(ref stripe) = stripe_client {
            app = app.app_data(stripe.clone());

            // Add payment routes if Stripe is configured
            app = app.service(
                web::scope("/api/payments")
                    .route("/create-checkout-session", web::post().to(create_checkout_session))
                    .route("/status/{session_id}", web::get().to(get_session_status))
                    .route("/portal", web::post().to(create_portal_session)),
            );

            // Add webhook routes if Stripe is configured
            app = app.service(
                web::scope("/webhooks")
                    .route("/stripe", web::post().to(stripe_webhook)),
            );
        }

        // Add BYOVPS routes (always available - doesn't require Hostinger)
        app = app.service(
            web::scope("/api/byovps")
                .route("/provision", web::post().to(provision_byovps)),
        );

        // TEMPORARY: Admin routes for database cleanup (NO AUTHENTICATION!)
        // TODO: Remove these routes after database cleanup is complete
        app = app.service(
            web::scope("/api/admin")
                .route("/cleanup-vps", web::delete().to(cleanup_all_vps))
                .route("/cleanup-vps/{email}", web::delete().to(cleanup_user_vps))
                .route("/list-vps", web::get().to(list_all_vps)),
        );

        // VPS precheck endpoint (available without Hostinger - just DB query)
        // This endpoint is used by the CLI for Step 1: PRE-CHECK
        app = app.route("/api/vps/precheck", web::get().to(get_vps_precheck));

        // VPS confirm endpoint (available without Hostinger - just DB write)
        // This endpoint is called by CLI after Hostinger provisioning completes
        app = app.route("/api/vps/confirm", web::post().to(confirm_vps));

        // Subscription plans endpoint (available without Hostinger - uses Stripe price IDs)
        app = app.route("/api/vps/subscription-plans", web::get().to(list_subscription_plans));

        // Payment result pages (static HTML, no auth required)
        app = app
            .route("/payment/success", web::get().to(payment_success))
            .route("/payment/cancel", web::get().to(payment_cancel))
            .route("/portal/return", web::get().to(portal_return));

        // Add VPS routes if Hostinger is configured
        if let Some(ref hostinger) = hostinger_client {
            app = app
                .app_data(hostinger.clone())
                .service(
                    web::scope("/api/vps")
                        // Public endpoints
                        .route("/plans", web::get().to(list_plans))
                        .route("/datacenters", web::get().to(list_datacenters))
                        // Authenticated endpoints
                        .route("/provision", web::post().to(provision_vps))
                        .route("/status", web::get().to(get_vps_status))
                        .route("/start", web::post().to(start_vps))
                        .route("/stop", web::post().to(stop_vps))
                        .route("/restart", web::post().to(restart_vps))
                        .route("/reset-password", web::post().to(reset_password)),
                );
        }

        app
    })
    .bind(&server_addr)?
    .run()
    .await
}
