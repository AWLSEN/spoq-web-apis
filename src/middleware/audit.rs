//! Audit middleware for extracting request context.
//!
//! This middleware provides extractors for capturing request metadata
//! (IP address, User-Agent) that can be used with the AuditService.

use actix_web::{dev::ServiceRequest, FromRequest, HttpRequest};
use std::future::{ready, Ready};

/// Request context for audit logging
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Client IP address
    pub ip_address: Option<String>,
    /// Client User-Agent header
    pub user_agent: Option<String>,
}

impl RequestContext {
    /// Extract request context from an HTTP request
    pub fn from_request(req: &HttpRequest) -> Self {
        // Try to get real IP from common proxy headers first
        let ip_address = req
            .headers()
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .or_else(|| {
                req.headers()
                    .get("X-Real-IP")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                req.connection_info()
                    .realip_remote_addr()
                    .map(|s| s.to_string())
            });

        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| {
                // Truncate very long user agents
                if s.len() > 256 {
                    format!("{}...", &s[..253])
                } else {
                    s.to_string()
                }
            });

        Self {
            ip_address,
            user_agent,
        }
    }

    /// Extract request context from a service request
    pub fn from_service_request(req: &ServiceRequest) -> Self {
        Self::from_request(req.request())
    }
}

/// Extractor for RequestContext
///
/// Use this in handler parameters to get the request context:
/// ```ignore
/// async fn my_handler(ctx: RequestContext) -> impl Responder {
///     // ctx.ip_address and ctx.user_agent are available
/// }
/// ```
impl FromRequest for RequestContext {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready(Ok(Self::from_request(req)))
    }
}

/// Extension trait for easy audit logging from handlers
pub trait AuditExt {
    /// Get request context for audit logging
    fn audit_context(&self) -> RequestContext;
}

impl AuditExt for HttpRequest {
    fn audit_context(&self) -> RequestContext {
        RequestContext::from_request(self)
    }
}

impl AuditExt for ServiceRequest {
    fn audit_context(&self) -> RequestContext {
        RequestContext::from_service_request(self)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn test_request_context_extraction() {
        let req = test::TestRequest::default()
            .insert_header(("User-Agent", "test-client/1.0"))
            .insert_header(("X-Forwarded-For", "1.2.3.4, 5.6.7.8"))
            .to_http_request();

        let ctx = RequestContext::from_request(&req);

        assert_eq!(ctx.user_agent, Some("test-client/1.0".to_string()));
        assert_eq!(ctx.ip_address, Some("1.2.3.4".to_string()));
    }

    #[actix_web::test]
    async fn test_request_context_x_real_ip() {
        let req = test::TestRequest::default()
            .insert_header(("X-Real-IP", "10.0.0.1"))
            .to_http_request();

        let ctx = RequestContext::from_request(&req);

        assert_eq!(ctx.ip_address, Some("10.0.0.1".to_string()));
    }

    #[actix_web::test]
    async fn test_truncate_long_user_agent() {
        let long_ua = "x".repeat(300);
        let req = test::TestRequest::default()
            .insert_header(("User-Agent", long_ua.as_str()))
            .to_http_request();

        let ctx = RequestContext::from_request(&req);

        let ua = ctx.user_agent.unwrap();
        assert!(ua.len() <= 256);
        assert!(ua.ends_with("..."));
    }
}
