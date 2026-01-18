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
        dotenvy::dotenv().ok();

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
        })
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
