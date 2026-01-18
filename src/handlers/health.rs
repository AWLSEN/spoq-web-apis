//! Health check endpoint for the API.
//!
//! Provides a simple health check endpoint that returns the status of the service.

use actix_web::{HttpResponse, Responder};
use serde::Serialize;

/// Health check response structure.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// The status of the service
    pub status: String,
}

/// Health check endpoint that returns a JSON response indicating the service is healthy.
///
/// # Returns
///
/// A JSON response with `{"status": "healthy"}`
///
/// # Example
///
/// ```ignore
/// GET /health
/// Response: {"status": "healthy"}
/// ```
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
        };
        let json = serde_json::to_string(&response).expect("Failed to serialize");
        assert!(json.contains("\"status\":\"healthy\""));
    }
}
