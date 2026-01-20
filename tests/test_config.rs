use spoq_web_apis::config::{Config, ConfigError};
use std::env;
use std::sync::Mutex;

// Use a mutex to serialize tests that modify environment variables
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn setup_required_env() {
    env::set_var("SPOQ_TEST_MODE", "1");
    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("GITHUB_CLIENT_ID", "test_client_id");
    env::set_var("GITHUB_CLIENT_SECRET", "test_client_secret");
    env::set_var("GITHUB_REDIRECT_URI", "http://localhost:8080/callback");
    env::set_var("JWT_SECRET", "test_jwt_secret");
}

fn cleanup_env() {
    env::remove_var("SPOQ_TEST_MODE");
    env::remove_var("DATABASE_URL");
    env::remove_var("GITHUB_CLIENT_ID");
    env::remove_var("GITHUB_CLIENT_SECRET");
    env::remove_var("GITHUB_REDIRECT_URI");
    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_ACCESS_TOKEN_EXPIRY_SECS");
    env::remove_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS");
    env::remove_var("HOST");
    env::remove_var("PORT");
}

#[test]
fn test_config_from_env_with_all_required() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();
    setup_required_env();

    let config = Config::from_env().expect("Failed to load config");

    assert_eq!(config.database_url, "postgres://localhost/test");
    assert_eq!(config.github_client_id, "test_client_id");
    assert_eq!(config.github_client_secret, "test_client_secret");
    assert_eq!(config.github_redirect_uri, "http://localhost:8080/callback");
    assert_eq!(config.jwt_secret, "test_jwt_secret");
    assert_eq!(config.jwt_access_token_expiry_secs, 900); // Default
    assert_eq!(config.jwt_refresh_token_expiry_days, 90); // Default
    assert_eq!(config.host, "0.0.0.0"); // Default
    assert_eq!(config.port, 8080); // Default

    cleanup_env();
}

#[test]
fn test_config_from_env_with_custom_values() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();

    // Set all environment variables with custom values
    env::set_var("SPOQ_TEST_MODE", "1");
    env::set_var("DATABASE_URL", "postgres://localhost/custom");
    env::set_var("GITHUB_CLIENT_ID", "custom_client_id");
    env::set_var("GITHUB_CLIENT_SECRET", "custom_client_secret");
    env::set_var("GITHUB_REDIRECT_URI", "http://custom.com/callback");
    env::set_var("JWT_SECRET", "custom_jwt_secret");
    env::set_var("JWT_ACCESS_TOKEN_EXPIRY_SECS", "1800");
    env::set_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS", "30");
    env::set_var("HOST", "127.0.0.1");
    env::set_var("PORT", "3000");

    let config = Config::from_env().expect("Failed to load config");

    assert_eq!(config.database_url, "postgres://localhost/custom");
    assert_eq!(config.github_client_id, "custom_client_id");
    assert_eq!(config.github_client_secret, "custom_client_secret");
    assert_eq!(config.github_redirect_uri, "http://custom.com/callback");
    assert_eq!(config.jwt_secret, "custom_jwt_secret");
    assert_eq!(config.jwt_access_token_expiry_secs, 1800);
    assert_eq!(config.jwt_refresh_token_expiry_days, 30);
    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.port, 3000);

    cleanup_env();
}

#[test]
fn test_config_missing_database_url() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();

    // Set all except DATABASE_URL
    env::set_var("SPOQ_TEST_MODE", "1");
    env::set_var("GITHUB_CLIENT_ID", "test_client_id");
    env::set_var("GITHUB_CLIENT_SECRET", "test_client_secret");
    env::set_var("GITHUB_REDIRECT_URI", "http://localhost:8080/callback");
    env::set_var("JWT_SECRET", "test_jwt_secret");

    let result = Config::from_env();
    assert!(result.is_err());

    match result {
        Err(ConfigError::MissingVar(var)) => {
            assert_eq!(var, "DATABASE_URL");
        }
        _ => panic!("Expected MissingVar error for DATABASE_URL"),
    }

    cleanup_env();
}

#[test]
fn test_config_missing_github_client_id() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();

    env::set_var("SPOQ_TEST_MODE", "1");
    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("GITHUB_CLIENT_SECRET", "test_client_secret");
    env::set_var("GITHUB_REDIRECT_URI", "http://localhost:8080/callback");
    env::set_var("JWT_SECRET", "test_jwt_secret");

    let result = Config::from_env();
    assert!(result.is_err());

    match result {
        Err(ConfigError::MissingVar(var)) => {
            assert_eq!(var, "GITHUB_CLIENT_ID");
        }
        _ => panic!("Expected MissingVar error for GITHUB_CLIENT_ID"),
    }

    cleanup_env();
}

#[test]
fn test_config_invalid_port() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();
    setup_required_env();

    env::set_var("PORT", "invalid_port");

    let result = Config::from_env();
    assert!(result.is_err());

    match result {
        Err(ConfigError::InvalidValue { var, .. }) => {
            assert_eq!(var, "PORT");
        }
        _ => panic!("Expected InvalidValue error for PORT"),
    }

    cleanup_env();
}

#[test]
fn test_config_invalid_jwt_expiry() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();
    setup_required_env();

    env::set_var("JWT_ACCESS_TOKEN_EXPIRY_SECS", "not_a_number");

    let result = Config::from_env();
    assert!(result.is_err());

    match result {
        Err(ConfigError::InvalidValue { var, .. }) => {
            assert_eq!(var, "JWT_ACCESS_TOKEN_EXPIRY_SECS");
        }
        _ => panic!("Expected InvalidValue error for JWT_ACCESS_TOKEN_EXPIRY_SECS"),
    }

    cleanup_env();
}

#[test]
fn test_server_addr() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();
    setup_required_env();

    env::set_var("HOST", "127.0.0.1");
    env::set_var("PORT", "9000");

    let config = Config::from_env().expect("Failed to load config");
    assert_eq!(config.server_addr(), "127.0.0.1:9000");

    cleanup_env();
}

#[test]
fn test_server_addr_default() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env();
    setup_required_env();

    let config = Config::from_env().expect("Failed to load config");
    assert_eq!(config.server_addr(), "0.0.0.0:8080");

    cleanup_env();
}
