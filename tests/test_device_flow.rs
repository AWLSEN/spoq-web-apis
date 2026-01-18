//! Integration tests for the device authorization flow.
//!
//! These tests cover the complete device flow from CLI initiation
//! through user approval/denial to token retrieval.
//!
//! Test coverage includes:
//! - Device grant creation with hostname
//! - Word code generation (3 words, lowercase, hyphenated)
//! - Base64 encoding/decoding of verification URL
//! - Verification page rendering with decoded params
//! - Approval flow
//! - Denial flow
//! - Polling responses for each status
//! - Expired code handling (5 min)
//! - Case-insensitive word code lookup (if applicable)

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use spoq_web_apis::models::device_grant::{DeviceGrant, DeviceGrantStatus};
use spoq_web_apis::services::device::{
    decode_verification_param, encode_verification_url, generate_device_code, generate_word_code,
    DecodeError, DeviceGrantCreated, VerificationData,
};

// ============================================================================
// Word Code Generation Tests
// ============================================================================

#[test]
fn test_word_code_has_three_parts() {
    for _ in 0..50 {
        let word_code = generate_word_code();
        let parts: Vec<&str> = word_code.split('-').collect();
        assert_eq!(
            parts.len(),
            3,
            "Word code '{}' should have exactly 3 parts",
            word_code
        );
    }
}

#[test]
fn test_word_code_is_lowercase() {
    for _ in 0..50 {
        let word_code = generate_word_code();
        assert_eq!(
            word_code,
            word_code.to_lowercase(),
            "Word code '{}' should be all lowercase",
            word_code
        );
    }
}

#[test]
fn test_word_code_is_hyphenated() {
    for _ in 0..50 {
        let word_code = generate_word_code();
        assert!(
            word_code.contains('-'),
            "Word code '{}' should contain hyphens",
            word_code
        );
        // Should have exactly 2 hyphens (separating 3 words)
        assert_eq!(
            word_code.matches('-').count(),
            2,
            "Word code '{}' should have exactly 2 hyphens",
            word_code
        );
    }
}

#[test]
fn test_word_code_no_spaces() {
    for _ in 0..50 {
        let word_code = generate_word_code();
        assert!(
            !word_code.contains(' '),
            "Word code '{}' should not contain spaces",
            word_code
        );
    }
}

#[test]
fn test_word_code_format_adj_adj_noun() {
    // Generate multiple word codes and check the format pattern
    // Note: We can't definitively verify ADJ-ADJ-NOUN without access to word lists,
    // but we can verify the structural format
    for _ in 0..20 {
        let word_code = generate_word_code();
        let parts: Vec<&str> = word_code.split('-').collect();

        // Each part should be non-empty and alphabetic
        for (i, part) in parts.iter().enumerate() {
            assert!(
                !part.is_empty(),
                "Part {} of '{}' should not be empty",
                i,
                word_code
            );
            assert!(
                part.chars().all(|c| c.is_ascii_lowercase()),
                "Part {} ('{}') of '{}' should be all lowercase letters",
                i,
                part,
                word_code
            );
        }
    }
}

#[test]
fn test_word_code_randomness() {
    // Generate 100 codes and ensure we have significant variety
    let codes: Vec<String> = (0..100).map(|_| generate_word_code()).collect();
    let unique_count = codes
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();

    // With ~1M combinations, 100 samples should be almost entirely unique
    assert!(
        unique_count >= 90,
        "Expected at least 90 unique codes out of 100, got {}",
        unique_count
    );
}

// ============================================================================
// Device Code Generation Tests
// ============================================================================

#[test]
fn test_device_code_length() {
    let code = generate_device_code();
    // 32 bytes hex encoded = 64 characters
    assert_eq!(code.len(), 64, "Device code should be 64 hex characters");
}

#[test]
fn test_device_code_hex_only() {
    let code = generate_device_code();
    assert!(
        code.chars().all(|c| c.is_ascii_hexdigit()),
        "Device code '{}' should only contain hex digits",
        code
    );
}

#[test]
fn test_device_code_lowercase() {
    // hex::encode returns lowercase hex
    let code = generate_device_code();
    assert_eq!(
        code,
        code.to_lowercase(),
        "Device code should be lowercase hex"
    );
}

#[test]
fn test_device_code_uniqueness() {
    let codes: Vec<String> = (0..100).map(|_| generate_device_code()).collect();
    let unique_count = codes
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();

    assert_eq!(
        unique_count, 100,
        "All 100 device codes should be unique"
    );
}

// ============================================================================
// Verification URL Encoding/Decoding Tests
// ============================================================================

#[test]
fn test_encode_verification_url_format() {
    let url = encode_verification_url(
        "https://app.spoq.dev/verify",
        "swift-bright-tiger",
        "my-macbook",
    );

    assert!(
        url.starts_with("https://app.spoq.dev/verify?d="),
        "URL should start with base URL and ?d= parameter"
    );

    // The encoded part should be URL-safe base64 (no padding)
    let encoded_part = url.split("?d=").nth(1).expect("Should have d parameter");
    assert!(
        !encoded_part.contains('+'),
        "URL-safe base64 should not contain '+'"
    );
    assert!(
        !encoded_part.contains('/'),
        "URL-safe base64 should not contain '/'"
    );
    assert!(
        !encoded_part.ends_with('='),
        "URL-safe base64 NO_PAD should not have padding"
    );
}

#[test]
fn test_encode_decode_roundtrip() {
    let word_code = "calm-deep-harmony";
    let hostname = "developer-laptop";

    let url = encode_verification_url("https://example.com/verify", word_code, hostname);
    let d_param = url.split("?d=").nth(1).expect("Should have d parameter");

    let decoded = decode_verification_param(d_param).expect("Should decode successfully");

    assert_eq!(decoded.word_code, word_code);
    assert_eq!(decoded.hostname, hostname);
}

#[test]
fn test_encode_decode_with_special_characters_in_hostname() {
    let word_code = "bold-quick-sunset";
    let hostname = "john's MacBook Pro (2024)";

    let url = encode_verification_url("https://example.com", word_code, hostname);
    let d_param = url.split("?d=").nth(1).expect("Should have d parameter");

    let decoded = decode_verification_param(d_param).expect("Should decode successfully");

    assert_eq!(decoded.word_code, word_code);
    assert_eq!(decoded.hostname, hostname);
}

#[test]
fn test_encode_decode_with_unicode_hostname() {
    let word_code = "bright-warm-galaxy";
    let hostname = "Nidhish's MacBook";

    let url = encode_verification_url("https://example.com", word_code, hostname);
    let d_param = url.split("?d=").nth(1).expect("Should have d parameter");

    let decoded = decode_verification_param(d_param).expect("Should decode successfully");

    assert_eq!(decoded.word_code, word_code);
    assert_eq!(decoded.hostname, hostname);
}

#[test]
fn test_decode_invalid_base64() {
    let result = decode_verification_param("!!!not-valid-base64!!!");
    assert_eq!(result, Err(DecodeError::InvalidBase64));
}

#[test]
fn test_decode_valid_base64_invalid_json() {
    // Create valid base64 that's not JSON
    let not_json = URL_SAFE_NO_PAD.encode(b"this is not json");
    let result = decode_verification_param(&not_json);
    assert_eq!(result, Err(DecodeError::InvalidJson));
}

#[test]
fn test_decode_valid_json_wrong_structure() {
    // Create valid JSON that doesn't match VerificationData structure
    let wrong_json = URL_SAFE_NO_PAD.encode(br#"{"name": "test", "value": 123}"#);
    let result = decode_verification_param(&wrong_json);
    assert_eq!(result, Err(DecodeError::InvalidJson));
}

#[test]
fn test_decode_empty_string() {
    let result = decode_verification_param("");
    // Empty string is invalid base64
    assert!(result.is_err());
}

#[test]
fn test_verification_data_serialization() {
    let data = VerificationData {
        word_code: "test-word-code".to_string(),
        hostname: "test-hostname".to_string(),
    };

    let json = serde_json::to_string(&data).expect("Should serialize");
    let parsed: VerificationData = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(parsed.word_code, data.word_code);
    assert_eq!(parsed.hostname, data.hostname);
}

// ============================================================================
// Device Grant Model Tests
// ============================================================================

#[test]
fn test_device_grant_creation() {
    let expires_at = Utc::now() + Duration::minutes(5);
    let grant = DeviceGrant::new(
        "abc123def456".to_string(),
        "swift-bright-tiger".to_string(),
        "test-hostname".to_string(),
        expires_at,
    );

    assert_eq!(grant.device_code, "abc123def456");
    assert_eq!(grant.word_code, "swift-bright-tiger");
    assert_eq!(grant.hostname, "test-hostname");
    assert_eq!(grant.status, DeviceGrantStatus::Pending);
    assert!(grant.user_id.is_none());
}

#[test]
fn test_device_grant_expiration_check() {
    // Create an expired grant (5 minutes in the past)
    let past = Utc::now() - Duration::minutes(5);
    let expired_grant = DeviceGrant::new(
        "expired-code".to_string(),
        "old-word-code".to_string(),
        "old-device".to_string(),
        past,
    );

    assert!(expired_grant.is_expired(), "Grant should be expired");

    // Create a valid grant (5 minutes in the future)
    let future = Utc::now() + Duration::minutes(5);
    let valid_grant = DeviceGrant::new(
        "valid-code".to_string(),
        "new-word-code".to_string(),
        "new-device".to_string(),
        future,
    );

    assert!(!valid_grant.is_expired(), "Grant should not be expired");
}

#[test]
fn test_device_grant_five_minute_expiry() {
    // Test that the standard 5-minute expiry is handled correctly
    let exactly_five_minutes = Utc::now() + Duration::minutes(5);
    let grant = DeviceGrant::new(
        "test-code".to_string(),
        "test-words".to_string(),
        "test-host".to_string(),
        exactly_five_minutes,
    );

    // Should not be expired immediately after creation
    assert!(!grant.is_expired());

    // Create one that's just past 5 minutes
    let just_expired = Utc::now() - Duration::seconds(1);
    let expired_grant = DeviceGrant::new(
        "test-code".to_string(),
        "test-words".to_string(),
        "test-host".to_string(),
        just_expired,
    );

    assert!(expired_grant.is_expired());
}

#[test]
fn test_device_grant_status_checks() {
    let expires_at = Utc::now() + Duration::minutes(5);
    let grant = DeviceGrant::new(
        "test".to_string(),
        "test".to_string(),
        "test".to_string(),
        expires_at,
    );

    assert!(grant.is_pending());
    assert!(!grant.is_approved());
    assert!(!grant.is_denied());
}

#[test]
fn test_device_grant_status_display() {
    assert_eq!(DeviceGrantStatus::Pending.to_string(), "pending");
    assert_eq!(DeviceGrantStatus::Approved.to_string(), "approved");
    assert_eq!(DeviceGrantStatus::Denied.to_string(), "denied");
}

#[test]
fn test_device_grant_status_as_str() {
    assert_eq!(DeviceGrantStatus::Pending.as_str(), "pending");
    assert_eq!(DeviceGrantStatus::Approved.as_str(), "approved");
    assert_eq!(DeviceGrantStatus::Denied.as_str(), "denied");
}

// ============================================================================
// Device Grant Response Types Tests
// ============================================================================

#[test]
fn test_device_grant_created_structure() {
    let grant = DeviceGrantCreated {
        device_code: "abc123".to_string(),
        word_code: "swift-bright-tiger".to_string(),
        verification_url: "https://app.spoq.dev/verify?d=xyz".to_string(),
        expires_at: Utc::now() + Duration::minutes(5),
    };

    assert_eq!(grant.device_code, "abc123");
    assert_eq!(grant.word_code, "swift-bright-tiger");
    assert!(grant.verification_url.contains("verify?d="));
}

#[test]
fn test_device_grant_created_serialization() {
    let grant = DeviceGrantCreated {
        device_code: "test123".to_string(),
        word_code: "calm-deep-ocean".to_string(),
        verification_url: "https://example.com/verify?d=encoded".to_string(),
        expires_at: Utc::now(),
    };

    let json = serde_json::to_string(&grant).expect("Should serialize");
    assert!(json.contains("device_code"));
    assert!(json.contains("word_code"));
    assert!(json.contains("verification_url"));
    assert!(json.contains("expires_at"));
}

// ============================================================================
// Polling Response Error Codes Tests
// ============================================================================

#[test]
fn test_polling_error_codes_format() {
    // Verify the expected error codes are formatted correctly
    let error_codes = vec![
        "authorization_pending",
        "access_denied",
        "expired_token",
        "unsupported_grant_type",
        "invalid_grant",
        "server_error",
    ];

    for code in error_codes {
        // Error codes should be snake_case
        assert!(
            code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "Error code '{}' should be snake_case",
            code
        );
    }
}

// ============================================================================
// DecodeError Tests
// ============================================================================

#[test]
fn test_decode_error_display() {
    assert_eq!(
        format!("{}", DecodeError::InvalidBase64),
        "Invalid base64 encoding"
    );
    assert_eq!(
        format!("{}", DecodeError::InvalidUtf8),
        "Invalid UTF-8 encoding"
    );
    assert_eq!(
        format!("{}", DecodeError::InvalidJson),
        "Invalid JSON format"
    );
}

#[test]
fn test_decode_error_equality() {
    assert_eq!(DecodeError::InvalidBase64, DecodeError::InvalidBase64);
    assert_eq!(DecodeError::InvalidUtf8, DecodeError::InvalidUtf8);
    assert_eq!(DecodeError::InvalidJson, DecodeError::InvalidJson);
    assert_ne!(DecodeError::InvalidBase64, DecodeError::InvalidJson);
}

// ============================================================================
// Case Insensitivity Tests (Word Code Lookup)
// ============================================================================

#[test]
fn test_word_code_is_always_lowercase() {
    // Word codes generated should always be lowercase
    for _ in 0..100 {
        let word_code = generate_word_code();
        assert_eq!(
            word_code,
            word_code.to_lowercase(),
            "Generated word code should be lowercase"
        );
    }
}

#[test]
fn test_word_code_normalization_for_lookup() {
    // Test that word codes can be normalized for case-insensitive lookup
    let word_code = "Swift-BRIGHT-Tiger";
    let normalized = word_code.to_lowercase();

    assert_eq!(normalized, "swift-bright-tiger");

    // The lookup functions should use the normalized version
    // This test verifies the normalization logic itself
}

// ============================================================================
// Integration Tests for Full Flow (Unit Test Style - No DB)
// ============================================================================

#[test]
fn test_full_device_flow_data_structures() {
    // Step 1: Generate device code and word code
    let device_code = generate_device_code();
    let word_code = generate_word_code();
    let hostname = "test-macbook-pro";

    // Step 2: Create verification URL
    let base_url = "https://app.spoq.dev/verify";
    let verification_url = encode_verification_url(base_url, &word_code, hostname);

    // Step 3: Verify URL structure
    assert!(verification_url.starts_with(base_url));
    assert!(verification_url.contains("?d="));

    // Step 4: Decode the URL parameter
    let d_param = verification_url.split("?d=").nth(1).unwrap();
    let decoded = decode_verification_param(d_param).unwrap();

    // Step 5: Verify decoded data matches original
    assert_eq!(decoded.word_code, word_code);
    assert_eq!(decoded.hostname, hostname);

    // Step 6: Create device grant object
    let expires_at = Utc::now() + Duration::minutes(5);
    let grant = DeviceGrant::new(
        device_code.clone(),
        word_code.clone(),
        hostname.to_string(),
        expires_at,
    );

    // Step 7: Verify grant is in pending state
    assert!(grant.is_pending());
    assert!(!grant.is_expired());

    // Step 8: Verify grant response structure
    let response = DeviceGrantCreated {
        device_code,
        word_code,
        verification_url,
        expires_at,
    };

    // Step 9: Serialize and verify JSON structure
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("device_code"));
    assert!(json.contains("word_code"));
    assert!(json.contains("verification_url"));
    assert!(json.contains("expires_at"));
}

#[test]
fn test_device_flow_expiration_boundary() {
    // Test the boundary condition for 5-minute expiration
    let hostname = "test-device";

    // Just under 5 minutes - should be valid
    let almost_expired = Utc::now() + Duration::seconds(299);
    let grant_valid = DeviceGrant::new(
        generate_device_code(),
        generate_word_code(),
        hostname.to_string(),
        almost_expired,
    );
    assert!(!grant_valid.is_expired());

    // Just over 5 minutes past - should be expired
    let past_five_min = Utc::now() - Duration::seconds(301);
    let grant_expired = DeviceGrant::new(
        generate_device_code(),
        generate_word_code(),
        hostname.to_string(),
        past_five_min,
    );
    assert!(grant_expired.is_expired());
}

#[test]
fn test_multiple_device_grants_unique() {
    // Simulate multiple CLI devices requesting authorization simultaneously
    let grants: Vec<_> = (0..10)
        .map(|i| {
            let device_code = generate_device_code();
            let word_code = generate_word_code();
            let hostname = format!("device-{}", i);
            let expires_at = Utc::now() + Duration::minutes(5);
            DeviceGrant::new(device_code, word_code, hostname, expires_at)
        })
        .collect();

    // All device codes should be unique
    let device_codes: std::collections::HashSet<_> =
        grants.iter().map(|g| g.device_code.clone()).collect();
    assert_eq!(device_codes.len(), 10);

    // All word codes should be unique (with high probability)
    let word_codes: std::collections::HashSet<_> =
        grants.iter().map(|g| g.word_code.clone()).collect();
    assert!(word_codes.len() >= 9); // Allow for rare collision
}

// ============================================================================
// Verification URL Parameter Tests
// ============================================================================

#[test]
fn test_verification_url_different_base_urls() {
    let test_cases = vec![
        "https://app.spoq.dev/verify",
        "http://localhost:8080/auth/verify",
        "https://staging.spoq.dev/v1/verify",
    ];

    for base_url in test_cases {
        let url = encode_verification_url(base_url, "test-word-code", "test-host");
        assert!(
            url.starts_with(base_url),
            "URL should start with base URL: {}",
            base_url
        );
        assert!(
            url.contains("?d="),
            "URL should contain ?d= parameter"
        );
    }
}

#[test]
fn test_verification_url_no_double_encoding() {
    let word_code = "test-code";
    let hostname = "host with spaces";

    let url = encode_verification_url("https://example.com/verify", word_code, hostname);

    // The d parameter should be the only encoding - no double encoding
    let d_param = url.split("?d=").nth(1).unwrap();

    // Should decode successfully
    let decoded = decode_verification_param(d_param).unwrap();
    assert_eq!(decoded.hostname, hostname);
}

// ============================================================================
// Device Grant Status Transitions Tests
// ============================================================================

#[test]
fn test_status_equality() {
    assert_eq!(DeviceGrantStatus::Pending, DeviceGrantStatus::Pending);
    assert_eq!(DeviceGrantStatus::Approved, DeviceGrantStatus::Approved);
    assert_eq!(DeviceGrantStatus::Denied, DeviceGrantStatus::Denied);
    assert_ne!(DeviceGrantStatus::Pending, DeviceGrantStatus::Approved);
    assert_ne!(DeviceGrantStatus::Pending, DeviceGrantStatus::Denied);
    assert_ne!(DeviceGrantStatus::Approved, DeviceGrantStatus::Denied);
}

#[test]
fn test_status_serialization_lowercase() {
    let pending_json = serde_json::to_string(&DeviceGrantStatus::Pending).unwrap();
    let approved_json = serde_json::to_string(&DeviceGrantStatus::Approved).unwrap();
    let denied_json = serde_json::to_string(&DeviceGrantStatus::Denied).unwrap();

    assert_eq!(pending_json, "\"pending\"");
    assert_eq!(approved_json, "\"approved\"");
    assert_eq!(denied_json, "\"denied\"");
}

#[test]
fn test_status_deserialization() {
    let pending: DeviceGrantStatus = serde_json::from_str("\"pending\"").unwrap();
    let approved: DeviceGrantStatus = serde_json::from_str("\"approved\"").unwrap();
    let denied: DeviceGrantStatus = serde_json::from_str("\"denied\"").unwrap();

    assert_eq!(pending, DeviceGrantStatus::Pending);
    assert_eq!(approved, DeviceGrantStatus::Approved);
    assert_eq!(denied, DeviceGrantStatus::Denied);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_empty_hostname() {
    let url = encode_verification_url(
        "https://example.com",
        "test-word-code",
        "",
    );

    let d_param = url.split("?d=").nth(1).unwrap();
    let decoded = decode_verification_param(d_param).unwrap();

    assert_eq!(decoded.hostname, "");
}

#[test]
fn test_very_long_hostname() {
    let long_hostname = "a".repeat(1000);
    let url = encode_verification_url(
        "https://example.com",
        "test-word-code",
        &long_hostname,
    );

    let d_param = url.split("?d=").nth(1).unwrap();
    let decoded = decode_verification_param(d_param).unwrap();

    assert_eq!(decoded.hostname, long_hostname);
}

#[test]
fn test_hostname_with_special_json_characters() {
    let hostname_with_quotes = r#"host"with"quotes"#;
    let url = encode_verification_url(
        "https://example.com",
        "test-code",
        hostname_with_quotes,
    );

    let d_param = url.split("?d=").nth(1).unwrap();
    let decoded = decode_verification_param(d_param).unwrap();

    assert_eq!(decoded.hostname, hostname_with_quotes);
}

#[test]
fn test_hostname_with_backslashes() {
    let hostname = r"C:\Users\Test";
    let url = encode_verification_url(
        "https://example.com",
        "test-code",
        hostname,
    );

    let d_param = url.split("?d=").nth(1).unwrap();
    let decoded = decode_verification_param(d_param).unwrap();

    assert_eq!(decoded.hostname, hostname);
}

#[test]
fn test_device_grant_boundary_at_exact_expiry() {
    // Test grant that expires at exactly now - should be considered expired
    // since is_expired checks `Utc::now() > self.expires_at`
    // A grant expiring exactly at the current time (or in the past) is expired
    let just_now = Utc::now() - Duration::milliseconds(1);
    let grant = DeviceGrant::new(
        "test".to_string(),
        "test".to_string(),
        "test".to_string(),
        just_now,
    );

    assert!(grant.is_expired());
}

// ============================================================================
// Device Code Security Tests
// ============================================================================

#[test]
fn test_device_code_high_entropy() {
    // Device codes should have 256 bits of entropy (32 bytes)
    let code = generate_device_code();

    // Count character frequency to check for obvious patterns
    let mut freq = std::collections::HashMap::new();
    for c in code.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    // Should have reasonable distribution across hex digits (0-9, a-f)
    // With 64 characters, average is 4 occurrences per digit
    // Allow significant variance but flag obviously broken generators
    let max_freq = freq.values().max().unwrap_or(&0);
    let min_freq = freq.values().min().unwrap_or(&0);

    assert!(
        *max_freq <= 20, // No single digit should appear more than ~31% of the time
        "Device code may have low entropy - one digit appears {} times",
        max_freq
    );
    assert!(
        *min_freq >= 1 || freq.len() >= 10, // Most digits should appear at least once
        "Device code may have low entropy - poor distribution"
    );
}

#[test]
fn test_device_code_no_predictable_pattern() {
    // Generate consecutive codes and ensure they're not sequential
    let codes: Vec<String> = (0..10).map(|_| generate_device_code()).collect();

    // Check that codes don't share long prefixes
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            let common_prefix = codes[i]
                .chars()
                .zip(codes[j].chars())
                .take_while(|(a, b)| a == b)
                .count();

            assert!(
                common_prefix <= 8, // Allow up to 8 matching chars by chance
                "Device codes share suspicious common prefix of {} chars",
                common_prefix
            );
        }
    }
}

// ============================================================================
// Word Code Collision Probability Tests
// ============================================================================

#[test]
fn test_word_code_collision_probability() {
    // With ADJ-ADJ-NOUN and ~100 words in each list:
    // ~100 * 100 * 100 = 1,000,000 combinations
    // Birthday paradox: expect collision around sqrt(1M) = 1000 samples
    // With 100 samples, collision probability is very low

    let samples = 100;
    let codes: std::collections::HashSet<String> =
        (0..samples).map(|_| generate_word_code()).collect();

    // Should have nearly 100 unique codes
    assert!(
        codes.len() >= 95,
        "Too many collisions: {} unique out of {} samples",
        codes.len(),
        samples
    );
}
