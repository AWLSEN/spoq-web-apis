//! Authentication middleware for JWT validation.
//!
//! This module provides:
//! - `AuthenticatedUser` extractor that validates JWT tokens
//! - Automatic extraction of user ID from valid tokens

use actix_web::{dev::Payload, http::header, web, FromRequest, HttpRequest};
use std::future::{ready, Ready};
use uuid::Uuid;

use crate::handlers::auth::AppState;
use crate::services::token::decode_access_token;

/// Represents an authenticated user extracted from a valid JWT.
///
/// This struct is used as an extractor in route handlers that require
/// authentication. It automatically validates the JWT from the
/// Authorization header and extracts the user ID.
///
/// # Example
///
/// ```ignore
/// use crate::middleware::auth::AuthenticatedUser;
///
/// async fn protected_route(user: AuthenticatedUser) -> impl Responder {
///     format!("Hello, user {}", user.user_id)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// The UUID of the authenticated user
    pub user_id: Uuid,
}

/// Error type for authentication failures.
#[derive(Debug)]
pub enum AuthError {
    /// No Authorization header present
    MissingToken,
    /// Invalid Authorization header format
    InvalidHeader,
    /// Token validation failed
    InvalidToken,
    /// User ID in token is not a valid UUID
    InvalidUserId,
    /// App state not found
    MissingAppState,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingToken => write!(f, "Missing authorization token"),
            AuthError::InvalidHeader => write!(f, "Invalid authorization header format"),
            AuthError::InvalidToken => write!(f, "Invalid or expired token"),
            AuthError::InvalidUserId => write!(f, "Invalid user ID in token"),
            AuthError::MissingAppState => write!(f, "Internal server error"),
        }
    }
}

impl actix_web::ResponseError for AuthError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AuthError::MissingToken
            | AuthError::InvalidHeader
            | AuthError::InvalidToken
            | AuthError::InvalidUserId => actix_web::http::StatusCode::UNAUTHORIZED,
            AuthError::MissingAppState => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        let body = serde_json::json!({
            "error": self.to_string()
        });
        actix_web::HttpResponse::build(self.status_code()).json(body)
    }
}

impl FromRequest for AuthenticatedUser {
    type Error = AuthError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Extract token from Authorization header
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());

        let token = match auth_header {
            Some(header) if header.starts_with("Bearer ") => &header[7..],
            Some(_) => return ready(Err(AuthError::InvalidHeader)),
            None => return ready(Err(AuthError::MissingToken)),
        };

        // Get app state to access JWT secret
        let app_state = match req.app_data::<web::Data<AppState>>() {
            Some(state) => state,
            None => return ready(Err(AuthError::MissingAppState)),
        };

        // Decode and validate JWT
        let claims = match decode_access_token(token, &app_state.config.jwt_secret) {
            Ok(claims) => claims,
            Err(_) => return ready(Err(AuthError::InvalidToken)),
        };

        // Parse user ID from claims
        let user_id = match Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => return ready(Err(AuthError::InvalidUserId)),
        };

        ready(Ok(AuthenticatedUser { user_id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_display() {
        assert_eq!(
            AuthError::MissingToken.to_string(),
            "Missing authorization token"
        );
        assert_eq!(
            AuthError::InvalidHeader.to_string(),
            "Invalid authorization header format"
        );
        assert_eq!(
            AuthError::InvalidToken.to_string(),
            "Invalid or expired token"
        );
        assert_eq!(
            AuthError::InvalidUserId.to_string(),
            "Invalid user ID in token"
        );
    }

    #[test]
    fn test_auth_error_status_codes() {
        use actix_web::http::StatusCode;
        use actix_web::ResponseError;

        assert_eq!(AuthError::MissingToken.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(AuthError::InvalidHeader.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(AuthError::InvalidToken.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(AuthError::InvalidUserId.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            AuthError::MissingAppState.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_authenticated_user_clone() {
        let user = AuthenticatedUser {
            user_id: Uuid::new_v4(),
        };
        let cloned = user.clone();
        assert_eq!(user.user_id, cloned.user_id);
    }

    #[test]
    fn test_authenticated_user_debug() {
        let user = AuthenticatedUser {
            user_id: Uuid::new_v4(),
        };
        let debug_str = format!("{:?}", user);
        assert!(debug_str.contains("AuthenticatedUser"));
        assert!(debug_str.contains(&user.user_id.to_string()));
    }
}
