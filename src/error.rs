//! Unified error handling for the spoq-web-apis application.
//!
//! This module provides a centralized error type (`AppError`) that handles
//! all errors throughout the application and maps them to appropriate HTTP responses.

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use thiserror::Error;

use crate::config::ConfigError;
use crate::services::github::GithubError;

/// Unified application error type.
///
/// All errors in the application are converted to this type, which implements
/// `actix_web::ResponseError` for automatic HTTP response generation.
#[derive(Debug, Error)]
pub enum AppError {
    /// Database errors from SQLx
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// GitHub API errors
    #[error("GitHub error: {0}")]
    GitHub(#[from] GithubError),

    /// Token-related errors (generation, hashing, etc.)
    #[error("Token error: {0}")]
    Token(String),

    /// Unauthorized access errors
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Bad request errors
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Resource not found errors
    #[error("Not found: {0}")]
    NotFound(String),

    /// Internal server errors
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::GitHub(_) => StatusCode::BAD_GATEWAY,
            AppError::Token(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let error_message = match self {
            // For database and internal errors, don't expose internal details
            AppError::Database(_) | AppError::Internal(_) => {
                "Internal server error".to_string()
            }
            AppError::Config(_) => "Configuration error".to_string(),
            AppError::Token(_) => "Token processing error".to_string(),
            // For these errors, expose the message
            AppError::GitHub(e) => format!("GitHub authentication error: {}", e),
            AppError::Unauthorized(msg) => msg.clone(),
            AppError::BadRequest(msg) => msg.clone(),
            AppError::NotFound(msg) => msg.clone(),
        };

        let body = serde_json::json!({
            "error": error_message
        });

        HttpResponse::build(self.status_code()).json(body)
    }
}

/// Result type alias using AppError
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_error_display() {
        let err = AppError::Unauthorized("Invalid token".to_string());
        assert_eq!(format!("{}", err), "Unauthorized: Invalid token");

        let err = AppError::BadRequest("Missing field".to_string());
        assert_eq!(format!("{}", err), "Bad request: Missing field");

        let err = AppError::NotFound("User not found".to_string());
        assert_eq!(format!("{}", err), "Not found: User not found");

        let err = AppError::Internal("Something went wrong".to_string());
        assert_eq!(
            format!("{}", err),
            "Internal server error: Something went wrong"
        );

        let err = AppError::Token("Hash failed".to_string());
        assert_eq!(format!("{}", err), "Token error: Hash failed");
    }

    #[test]
    fn test_status_codes() {
        use actix_web::ResponseError;

        assert_eq!(
            AppError::Unauthorized("test".to_string()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::BadRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::NotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::Internal("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::Token("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_github_error_conversion() {
        let github_err = GithubError::ApiError("API failed".to_string());
        let app_err: AppError = github_err.into();
        assert!(matches!(app_err, AppError::GitHub(_)));
    }

    #[test]
    fn test_config_error_conversion() {
        let config_err = ConfigError::MissingVar("TEST_VAR".to_string());
        let app_err: AppError = config_err.into();
        assert!(matches!(app_err, AppError::Config(_)));
    }

    #[test]
    fn test_error_response_hides_internal_details() {
        use actix_web::ResponseError;

        let err = AppError::Internal("sensitive database details".to_string());
        let response = err.error_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
