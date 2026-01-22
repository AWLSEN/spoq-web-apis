use std::env;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_uri: String,
    pub jwt_secret: String,
    pub jwt_access_token_expiry_secs: i64,
    pub jwt_refresh_token_expiry_days: i64,
    pub host: String,
    pub port: u16,
    // Hostinger VPS settings
    pub hostinger_api_key: Option<String>,
    pub default_vps_plan: String,
    pub default_vps_template: i32,
    pub default_vps_datacenter: i32,
    // Base URL for the API (used for binary downloads, etc.)
    pub base_url: String,
    // Cloudflare DNS settings
    pub cloudflare_api_token: Option<String>,
    pub cloudflare_zone_id: Option<String>,
    // Stripe payment settings
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingVar(String),

    #[error("Invalid value for {var}: {message}")]
    InvalidValue { var: String, message: String },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env file if present (ok if it doesn't exist)
        // Skip loading .env in test mode to allow tests to control env vars
        if env::var("SPOQ_TEST_MODE").is_err() {
            dotenvy::dotenv().ok();
        }

        // Required variables
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingVar("DATABASE_URL".to_string()))?;

        let github_client_id = env::var("GITHUB_CLIENT_ID")
            .map_err(|_| ConfigError::MissingVar("GITHUB_CLIENT_ID".to_string()))?;

        let github_client_secret = env::var("GITHUB_CLIENT_SECRET")
            .map_err(|_| ConfigError::MissingVar("GITHUB_CLIENT_SECRET".to_string()))?;

        let github_redirect_uri = env::var("GITHUB_REDIRECT_URI")
            .map_err(|_| ConfigError::MissingVar("GITHUB_REDIRECT_URI".to_string()))?;

        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| ConfigError::MissingVar("JWT_SECRET".to_string()))?;

        // Optional variables with defaults
        let jwt_access_token_expiry_secs = env::var("JWT_ACCESS_TOKEN_EXPIRY_SECS")
            .ok()
            .map(|v| {
                v.parse::<i64>().map_err(|e| ConfigError::InvalidValue {
                    var: "JWT_ACCESS_TOKEN_EXPIRY_SECS".to_string(),
                    message: e.to_string(),
                })
            })
            .transpose()?
            .unwrap_or(900); // Default: 15 minutes

        let jwt_refresh_token_expiry_days = env::var("JWT_REFRESH_TOKEN_EXPIRY_DAYS")
            .ok()
            .map(|v| {
                v.parse::<i64>().map_err(|e| ConfigError::InvalidValue {
                    var: "JWT_REFRESH_TOKEN_EXPIRY_DAYS".to_string(),
                    message: e.to_string(),
                })
            })
            .transpose()?
            .unwrap_or(90); // Default: 90 days

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let port = env::var("PORT")
            .ok()
            .map(|v| {
                v.parse::<u16>().map_err(|e| ConfigError::InvalidValue {
                    var: "PORT".to_string(),
                    message: e.to_string(),
                })
            })
            .transpose()?
            .unwrap_or(8080); // Default: 8080

        // Hostinger settings (optional for local development)
        let hostinger_api_key = env::var("HOSTINGER_API_KEY").ok();

        let default_vps_plan = env::var("DEFAULT_VPS_PLAN")
            .unwrap_or_else(|_| "hostingercom-vps-kvm1-usd-1m".to_string());

        let default_vps_template = env::var("DEFAULT_VPS_TEMPLATE")
            .ok()
            .map(|v| {
                v.parse::<i32>().map_err(|e| ConfigError::InvalidValue {
                    var: "DEFAULT_VPS_TEMPLATE".to_string(),
                    message: e.to_string(),
                })
            })
            .transpose()?
            .unwrap_or(1007); // Default: Ubuntu 22.04 LTS

        let default_vps_datacenter = env::var("DEFAULT_VPS_DATACENTER")
            .ok()
            .map(|v| {
                v.parse::<i32>().map_err(|e| ConfigError::InvalidValue {
                    var: "DEFAULT_VPS_DATACENTER".to_string(),
                    message: e.to_string(),
                })
            })
            .transpose()?
            .unwrap_or(9); // Default: Phoenix, USA

        let base_url =
            env::var("BASE_URL").unwrap_or_else(|_| format!("http://{}:{}", host, port));

        // Cloudflare DNS settings (optional for local development)
        let cloudflare_api_token = env::var("CLOUDFLARE_API_TOKEN").ok();
        let cloudflare_zone_id = env::var("CLOUDFLARE_ZONE_ID").ok();

        // Stripe payment settings (optional for local development)
        let stripe_secret_key = env::var("STRIPE_SECRET_KEY").ok();
        let stripe_webhook_secret = env::var("STRIPE_WEBHOOK_SECRET").ok();

        Ok(Config {
            database_url,
            github_client_id,
            github_client_secret,
            github_redirect_uri,
            jwt_secret,
            jwt_access_token_expiry_secs,
            jwt_refresh_token_expiry_days,
            host,
            port,
            hostinger_api_key,
            default_vps_plan,
            default_vps_template,
            default_vps_datacenter,
            base_url,
            cloudflare_api_token,
            cloudflare_zone_id,
            stripe_secret_key,
            stripe_webhook_secret,
        })
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
