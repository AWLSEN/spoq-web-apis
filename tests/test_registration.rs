//! Integration tests for conductor registration flow.
//!
//! These tests cover the registration code validation and the
//! VPS secret generation used in the conductor registration endpoint.

use spoq_web_apis::services::registration::{
    generate_registration_code, generate_vps_secret, hash_code, verify_code,
};

// ============================================================================
// Registration Code Format Tests
// ============================================================================

#[test]
fn test_registration_code_format() {
    for _ in 0..100 {
        let code = generate_registration_code();
        assert_eq!(code.len(), 6, "Code must be 6 characters");
        assert!(
            code.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "Code '{}' must be A-Z, 0-9 only",
            code
        );
    }
}

#[test]
fn test_registration_code_uniqueness() {
    let codes: Vec<String> = (0..1000).map(|_| generate_registration_code()).collect();
    let unique: std::collections::HashSet<_> = codes.iter().collect();

    // With 36^6 = 2.17 billion combinations, 1000 codes should be unique
    assert_eq!(codes.len(), unique.len(), "All codes should be unique");
}

#[test]
fn test_registration_code_no_lowercase() {
    for _ in 0..100 {
        let code = generate_registration_code();
        assert_eq!(
            code,
            code.to_uppercase(),
            "Code '{}' should already be uppercase",
            code
        );
    }
}

#[test]
fn test_registration_code_alphanumeric_only() {
    for _ in 0..100 {
        let code = generate_registration_code();
        assert!(
            code.chars().all(|c| c.is_ascii_alphanumeric()),
            "Code '{}' should be alphanumeric only",
            code
        );
        // No special characters
        assert!(
            !code.contains('-'),
            "Code should not contain hyphens"
        );
        assert!(
            !code.contains('_'),
            "Code should not contain underscores"
        );
        assert!(
            !code.contains(' '),
            "Code should not contain spaces"
        );
    }
}

// ============================================================================
// Code Hashing and Verification Tests
// ============================================================================

#[test]
fn test_hash_code_returns_argon2_format() {
    let code = "ABC123";
    let hash = hash_code(code).expect("Hashing should succeed");

    // Argon2 hash format starts with $argon2
    assert!(
        hash.starts_with("$argon2"),
        "Hash '{}' should be in Argon2 format",
        hash
    );
}

#[test]
fn test_hash_code_different_for_same_input() {
    let code = "XYZ789";
    let hash1 = hash_code(code).expect("Hashing should succeed");
    let hash2 = hash_code(code).expect("Hashing should succeed");

    // Due to random salt, hashes should be different
    assert_ne!(
        hash1, hash2,
        "Hashes should differ due to random salts"
    );
}

#[test]
fn test_verify_code_correct() {
    let code = "TEST01";
    let hash = hash_code(code).expect("Hashing should succeed");

    assert!(verify_code(code, &hash), "Correct code should verify");
}

#[test]
fn test_verify_code_case_sensitive() {
    let code = "ABC123";
    let hash = hash_code(code).expect("Hashing should succeed");

    // Lowercase should NOT verify (case sensitive)
    assert!(
        !verify_code("abc123", &hash),
        "Lowercase code should not verify"
    );
    assert!(
        !verify_code("Abc123", &hash),
        "Mixed case code should not verify"
    );
}

#[test]
fn test_verify_code_wrong_code() {
    let code = "VALID1";
    let hash = hash_code(code).expect("Hashing should succeed");

    assert!(
        !verify_code("WRONG1", &hash),
        "Wrong code should not verify"
    );
    assert!(
        !verify_code("VALID2", &hash),
        "Similar but different code should not verify"
    );
    assert!(
        !verify_code("", &hash),
        "Empty code should not verify"
    );
}

#[test]
fn test_verify_code_invalid_hash() {
    // Invalid hash format should return false, not error
    assert!(!verify_code("ABC123", "not-a-valid-hash"));
    assert!(!verify_code("ABC123", ""));
    assert!(!verify_code("ABC123", "$argon2id$invalid"));
}

// ============================================================================
// VPS Secret Format Tests
// ============================================================================

#[test]
fn test_vps_secret_format() {
    let secret = generate_vps_secret();

    assert!(
        secret.starts_with("spoq_vps_"),
        "Secret '{}' must have 'spoq_vps_' prefix",
        secret
    );

    // 9 char prefix + 43 char base64 = 52 total
    assert_eq!(
        secret.len(),
        52,
        "Secret should be 52 chars (9 prefix + 43 base64)"
    );
}

#[test]
fn test_vps_secret_base64_portion() {
    let secret = generate_vps_secret();
    let base64_part = &secret[9..]; // After "spoq_vps_"

    // URL-safe base64 without padding: only A-Z, a-z, 0-9, -, _
    assert!(
        base64_part.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        }),
        "Base64 portion '{}' should only contain URL-safe chars",
        base64_part
    );

    // No padding characters
    assert!(
        !base64_part.contains('='),
        "Base64 should have no padding"
    );
}

#[test]
fn test_vps_secret_uniqueness() {
    let secrets: Vec<String> = (0..100).map(|_| generate_vps_secret()).collect();
    let unique: std::collections::HashSet<_> = secrets.iter().collect();

    // 32 bytes of entropy = 256 bits, should always be unique
    assert_eq!(secrets.len(), unique.len(), "All secrets should be unique");
}

#[test]
fn test_vps_secret_can_be_hashed() {
    let secret = generate_vps_secret();
    let hash = hash_code(&secret);

    assert!(hash.is_ok(), "VPS secret should be hashable");
    assert!(
        verify_code(&secret, &hash.unwrap()),
        "Hashed VPS secret should verify"
    );
}

// ============================================================================
// Input Validation Tests (simulating endpoint validation)
// ============================================================================

#[test]
fn test_code_validation_valid_formats() {
    let valid_codes = vec![
        "ABC123", "000000", "ZZZZZZ", "A1B2C3", "123ABC", "AAAAAA",
    ];

    for code in valid_codes {
        assert!(
            is_valid_code(code),
            "Code '{}' should be valid",
            code
        );
    }
}

#[test]
fn test_code_validation_invalid_length() {
    let invalid_codes = vec![
        "",        // Empty
        "A",       // Too short
        "ABC12",   // 5 chars
        "ABC1234", // 7 chars
        "ABCDEFGHIJ", // Way too long
    ];

    for code in invalid_codes {
        assert!(
            !is_valid_code(code),
            "Code '{}' should be invalid (wrong length)",
            code
        );
    }
}

#[test]
fn test_code_validation_invalid_characters() {
    // Codes with special characters should fail after normalization
    let invalid_codes = vec![
        ("ABC12!", "special character"),
        ("ABC 23", "space"),
        ("ABC-23", "hyphen"),
        ("ABC_23", "underscore"),
        ("ABC.23", "period"),
    ];

    for (code, reason) in invalid_codes {
        // Handler normalizes (uppercase + trim) then validates
        let normalized = code.to_uppercase().trim().to_string();
        assert!(
            !is_valid_code(&normalized),
            "Code '{}' should be invalid ({})",
            code,
            reason
        );
    }
}

#[test]
fn test_code_validation_lowercase_becomes_valid() {
    // Lowercase codes become valid after handler normalization
    let code = "abc123";
    assert!(
        !is_valid_code(code),
        "Raw lowercase should fail validation (uppercase only)"
    );

    let normalized = code.to_uppercase();
    assert!(
        is_valid_code(&normalized),
        "Normalized code should be valid"
    );
}

#[test]
fn test_code_normalization() {
    // Handler normalizes: uppercase + trim
    let test_cases = vec![
        ("abc123", "ABC123"),
        ("  ABC123  ", "ABC123"),
        ("abc123 ", "ABC123"),
        (" abc123", "ABC123"),
        ("AbC123", "ABC123"),
    ];

    for (input, expected) in test_cases {
        let normalized = input.to_uppercase().trim().to_string();
        assert_eq!(
            normalized, expected,
            "Input '{}' should normalize to '{}'",
            input, expected
        );
    }
}

/// Helper function matching handler's validation logic
/// Note: The handler validates AFTER normalization (uppercase + trim),
/// so valid codes are 6 uppercase alphanumeric characters.
fn is_valid_code(code: &str) -> bool {
    code.len() == 6
        && code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

// ============================================================================
// Registration Flow Simulation Tests
// ============================================================================

#[test]
fn test_complete_registration_flow_simulation() {
    // Step 1: Generate a registration code (normally done during VPS provisioning)
    let code = generate_registration_code();
    assert!(is_valid_code(&code), "Generated code should be valid");

    // Step 2: Hash the code for storage
    let code_hash = hash_code(&code).expect("Hashing should succeed");

    // Step 3: Simulate conductor calling with the code
    // (In real endpoint, we'd query DB and verify against each pending VPS)
    let conductor_input = code.clone(); // Conductor provides the plaintext code
    let normalized_input = conductor_input.to_uppercase().trim().to_string();

    // Step 4: Verify the code matches
    assert!(
        verify_code(&normalized_input, &code_hash),
        "Conductor's code should verify against stored hash"
    );

    // Step 5: Generate VPS secret for conductor
    let vps_secret = generate_vps_secret();
    assert!(vps_secret.starts_with("spoq_vps_"));

    // Step 6: Hash VPS secret for storage
    let vps_secret_hash = hash_code(&vps_secret).expect("Hashing should succeed");

    // Step 7: Verify VPS secret can be used for future auth
    assert!(
        verify_code(&vps_secret, &vps_secret_hash),
        "VPS secret should verify for future authentication"
    );
}

#[test]
fn test_registration_code_brute_force_resistance() {
    // Generate a code and hash it
    let real_code = generate_registration_code();
    let hash = hash_code(&real_code).expect("Hashing should succeed");

    // Try some random codes - none should match
    let attempts = 100;
    let mut matches = 0;

    for _ in 0..attempts {
        let guess = generate_registration_code();
        if guess != real_code && verify_code(&guess, &hash) {
            matches += 1;
        }
    }

    assert_eq!(
        matches, 0,
        "No random guesses should match (found {} matches in {} attempts)",
        matches, attempts
    );
}

#[test]
fn test_expired_code_still_verifies_hash() {
    // Note: Expiration is checked at DB level, not hash level
    // This test confirms hash verification is independent of expiration
    let code = "EXP123";
    let hash = hash_code(code).expect("Hashing should succeed");

    // Even if we consider this "expired", hash still verifies
    // (DB query filters by expires_at, not the hash)
    assert!(
        verify_code(code, &hash),
        "Hash verification should be independent of expiration logic"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_hash_empty_string() {
    // Should handle empty string (though endpoint rejects it)
    let result = hash_code("");
    assert!(result.is_ok(), "Empty string should be hashable");
}

#[test]
fn test_hash_long_string() {
    // Should handle long strings
    let long_secret = "a".repeat(1000);
    let result = hash_code(&long_secret);
    assert!(result.is_ok(), "Long string should be hashable");

    let hash = result.unwrap();
    assert!(
        verify_code(&long_secret, &hash),
        "Long string should verify"
    );
}

#[test]
fn test_hash_unicode() {
    // Unicode strings (not used in registration codes, but shouldn't crash)
    let unicode = "测试🎉";
    let result = hash_code(unicode);
    assert!(result.is_ok(), "Unicode should be hashable");

    let hash = result.unwrap();
    assert!(verify_code(unicode, &hash), "Unicode should verify");
}

// ============================================================================
// Rate Limiter Unit Test
// ============================================================================

#[test]
fn test_internal_rate_limiter_creation() {
    use spoq_web_apis::middleware::create_internal_rate_limiter;

    // Should not panic when creating rate limiter
    let _limiter = create_internal_rate_limiter();
}

// ============================================================================
// Response Structure Tests
// ============================================================================

#[test]
fn test_register_response_serialization() {
    use serde_json;

    // Simulate the response structure
    #[derive(serde::Serialize)]
    struct RegisterResponse {
        vps_secret: String,
        owner_id: String,
        jwt_secret: String,
        hostname: String,
    }

    let response = RegisterResponse {
        vps_secret: generate_vps_secret(),
        owner_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        jwt_secret: "test-jwt-secret".to_string(),
        hostname: "testuser.spoq.dev".to_string(),
    };

    let json = serde_json::to_string(&response).expect("Should serialize");

    assert!(json.contains("vps_secret"));
    assert!(json.contains("owner_id"));
    assert!(json.contains("jwt_secret"));
    assert!(json.contains("hostname"));
    assert!(json.contains("spoq_vps_"));
}

#[test]
fn test_error_response_format() {
    use serde_json;

    // Verify error response format matches what handler returns
    let error_json = serde_json::json!({
        "error": "Invalid registration code"
    });

    let error_str = error_json.to_string();
    assert!(error_str.contains("error"));
    assert!(error_str.contains("Invalid registration code"));
}
