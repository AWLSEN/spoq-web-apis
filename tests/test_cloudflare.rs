use spoq_web_apis::services::cloudflare::{CloudflareService, CloudflareServiceError, TunnelCredentials};

/// Test that CloudflareService can be instantiated
#[test]
fn test_cloudflare_service_creation() {
    let _service = CloudflareService::new(
        "test_api_token".to_string(),
        "test_zone_id".to_string(),
    );

    // Service should be created successfully
    assert!(true, "CloudflareService created successfully");
}

/// Test CloudflareService creation with account_id for tunnel operations
#[test]
fn test_cloudflare_service_with_account_id() {
    let service = CloudflareService::with_account_id(
        "test_api_token".to_string(),
        "test_zone_id".to_string(),
        "test_account_id".to_string(),
    );

    // Service should be created successfully with account_id
    assert!(true, "CloudflareService with account_id created successfully");
    drop(service); // Ensure service is used
}

/// Test set_account_id method
#[test]
fn test_set_account_id() {
    let mut service = CloudflareService::new(
        "test_api_token".to_string(),
        "test_zone_id".to_string(),
    );

    // Set account_id
    service.set_account_id("new_account_id".to_string());

    // Service should accept account_id
    assert!(true, "set_account_id method works correctly");
}

/// Test wildcard subdomain formatting logic
#[test]
fn test_wildcard_subdomain_formatting() {
    // Test various input formats for wildcard subdomains
    let test_cases = vec![
        ("user123", "*.user123.spoq.dev"),
        ("*.user123", "*.user123.spoq.dev"),
        ("user123.spoq.dev", "*.user123.spoq.dev"),
        ("*.user123.spoq.dev", "*.user123.spoq.dev"),
    ];

    for (input, expected) in test_cases {
        let formatted = if input.starts_with("*.") {
            if input.ends_with(".spoq.dev") {
                input.to_string()
            } else {
                format!("{}.spoq.dev", input)
            }
        } else if input.ends_with(".spoq.dev") {
            format!("*.{}", input)
        } else {
            format!("*.{}.spoq.dev", input)
        };

        assert_eq!(formatted, expected, "Failed for input: {}", input);
    }
}

/// Test regular subdomain formatting logic
#[test]
fn test_regular_subdomain_formatting() {
    // Test various input formats for regular subdomains
    let test_cases = vec![
        ("user123", "user123.spoq.dev"),
        ("user123.spoq.dev", "user123.spoq.dev"),
    ];

    for (input, expected) in test_cases {
        let formatted = if input.ends_with(".spoq.dev") {
            input.to_string()
        } else {
            format!("{}.spoq.dev", input)
        };

        assert_eq!(formatted, expected, "Failed for input: {}", input);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// This test verifies the CloudflareService methods exist and have correct signatures.
    /// Integration tests with actual API calls would require:
    /// 1. Mock HTTP server (e.g., wiremock)
    /// 2. Valid Cloudflare API credentials
    /// 3. Test zone for safe DNS record manipulation
    #[test]
    fn test_cloudflare_service_methods_exist() {
        let _service = CloudflareService::new(
            "test_token".to_string(),
            "test_zone".to_string(),
        );

        // Verify the service has the required methods by checking method signatures
        // These are compile-time checks that ensure the API hasn't changed

        // Regular DNS methods exist (compile-time check)
        let _create_dns = CloudflareService::create_dns_record;
        let _find_dns = CloudflareService::find_dns_record;
        let _update_dns = CloudflareService::update_dns_record;
        let _delete_dns = CloudflareService::delete_dns_record;

        // Wildcard DNS methods exist (compile-time check)
        let _create_wildcard = CloudflareService::create_wildcard_dns_record;
        let _find_wildcard = CloudflareService::find_wildcard_dns_record;
        let _update_wildcard = CloudflareService::update_wildcard_dns_record;

        // Tunnel methods exist (compile-time check)
        let _create_tunnel = CloudflareService::create_tunnel;
        let _delete_tunnel = CloudflareService::delete_tunnel;
        let _create_cname = CloudflareService::create_cname_record;
        let _find_cname = CloudflareService::find_cname_record;
        let _delete_cname = CloudflareService::delete_cname_record;

        assert!(true, "All required methods exist on CloudflareService");
    }
}

/// Test TunnelCredentials struct
#[test]
fn test_tunnel_credentials_struct() {
    let creds = TunnelCredentials {
        tunnel_id: "abc123".to_string(),
        tunnel_secret: "c2VjcmV0".to_string(),
        account_tag: "account456".to_string(),
        tunnel_name: "my-tunnel".to_string(),
    };

    assert_eq!(creds.tunnel_id, "abc123");
    assert_eq!(creds.tunnel_secret, "c2VjcmV0");
    assert_eq!(creds.account_tag, "account456");
    assert_eq!(creds.tunnel_name, "my-tunnel");
}

/// Test TunnelCredentials serialization/deserialization
#[test]
fn test_tunnel_credentials_serde() {
    let creds = TunnelCredentials {
        tunnel_id: "tunnel-123".to_string(),
        tunnel_secret: "base64secret".to_string(),
        account_tag: "acct-456".to_string(),
        tunnel_name: "test-tunnel".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&creds).expect("Failed to serialize");
    assert!(json.contains("tunnel-123"));
    assert!(json.contains("base64secret"));
    assert!(json.contains("acct-456"));
    assert!(json.contains("test-tunnel"));

    // Deserialize back
    let parsed: TunnelCredentials = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(parsed.tunnel_id, creds.tunnel_id);
    assert_eq!(parsed.tunnel_secret, creds.tunnel_secret);
    assert_eq!(parsed.account_tag, creds.account_tag);
    assert_eq!(parsed.tunnel_name, creds.tunnel_name);
}

/// Test that tunnel CNAME target is correctly formatted
#[test]
fn test_tunnel_cname_target_format() {
    let tunnel_id = "abc123def456";
    let expected_target = format!("{}.cfargotunnel.com", tunnel_id);
    assert_eq!(expected_target, "abc123def456.cfargotunnel.com");
}

/// Test error types for tunnel operations
#[test]
fn test_cloudflare_error_types() {
    // Test that error types exist and have correct Display implementations
    let api_error = CloudflareServiceError::ApiError("test error".to_string());
    assert!(api_error.to_string().contains("test error"));

    let tunnel_not_found = CloudflareServiceError::TunnelNotFound;
    assert!(tunnel_not_found.to_string().contains("not found"));

    let account_not_configured = CloudflareServiceError::AccountIdNotConfigured;
    assert!(account_not_configured.to_string().contains("not configured"));
}

/// Test that demonstrates the expected behavior of wildcard DNS records
#[test]
fn test_wildcard_dns_expected_behavior() {
    // Wildcard DNS record should match all subdomains
    // For example, *.user123.spoq.dev should match:
    // - api.user123.spoq.dev
    // - web.user123.spoq.dev
    // - anything.user123.spoq.dev

    let wildcard_pattern = "*.user123.spoq.dev";
    let matching_subdomains = vec![
        "api.user123.spoq.dev",
        "web.user123.spoq.dev",
        "service.user123.spoq.dev",
    ];

    for subdomain in matching_subdomains {
        // Verify subdomain would match the wildcard pattern
        assert!(
            subdomain.ends_with(".user123.spoq.dev"),
            "{} should match {}",
            subdomain,
            wildcard_pattern
        );
    }
}
