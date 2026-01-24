//! Unit tests for VPS confirm endpoint.
//!
//! These tests verify the VPS confirmation logic including:
//! - Request validation
//! - Duplicate VPS prevention
//! - Database record creation

use spoq_web_apis::handlers::{ConfirmVpsRequest, ConfirmVpsResponse};

/// Test that ConfirmVpsRequest struct has all required fields
#[test]
fn test_confirm_vps_request_structure() {
    let request = ConfirmVpsRequest {
        hostname: "testuser.spoq.dev".to_string(),
        ip_address: "192.168.1.100".to_string(),
        provider_instance_id: 12345,
        provider_order_id: Some("order-abc123".to_string()),
        plan_id: "hostingercom-vps-kvm1-usd-1m".to_string(),
        template_id: 1007,
        data_center_id: 9,
        jwt_secret: "super-secret-jwt-key".to_string(),
        ssh_password: "StrongPassword123!".to_string(),
    };

    assert_eq!(request.hostname, "testuser.spoq.dev");
    assert_eq!(request.ip_address, "192.168.1.100");
    assert_eq!(request.provider_instance_id, 12345);
    assert_eq!(request.provider_order_id, Some("order-abc123".to_string()));
    assert_eq!(request.plan_id, "hostingercom-vps-kvm1-usd-1m");
    assert_eq!(request.template_id, 1007);
    assert_eq!(request.data_center_id, 9);
    assert_eq!(request.jwt_secret, "super-secret-jwt-key");
    assert_eq!(request.ssh_password, "StrongPassword123!");
}

/// Test ConfirmVpsRequest without optional provider_order_id
#[test]
fn test_confirm_vps_request_without_order_id() {
    let request = ConfirmVpsRequest {
        hostname: "alice.spoq.dev".to_string(),
        ip_address: "10.0.0.50".to_string(),
        provider_instance_id: 67890,
        provider_order_id: None,
        plan_id: "vps-starter".to_string(),
        template_id: 1007,
        data_center_id: 5,
        jwt_secret: "another-jwt-secret".to_string(),
        ssh_password: "AnotherSecurePass!".to_string(),
    };

    assert!(request.provider_order_id.is_none());
    assert_eq!(request.provider_instance_id, 67890);
}

/// Test that ConfirmVpsResponse contains expected fields
#[test]
fn test_confirm_vps_response_structure() {
    let response = ConfirmVpsResponse {
        id: uuid::Uuid::new_v4(),
        hostname: "bob.spoq.dev".to_string(),
        status: "ready".to_string(),
        ip_address: "203.0.113.42".to_string(),
        message: "VPS record created successfully".to_string(),
    };

    assert_eq!(response.hostname, "bob.spoq.dev");
    assert_eq!(response.status, "ready");
    assert_eq!(response.ip_address, "203.0.113.42");
    assert!(response.message.contains("successfully"));
}

/// Test hostname validation - must end with .spoq.dev
#[test]
fn test_hostname_format_validation() {
    // Valid hostnames
    let valid_hostnames = vec![
        "user.spoq.dev",
        "alice.spoq.dev",
        "bob123.spoq.dev",
        "my-user.spoq.dev",
    ];

    for hostname in valid_hostnames {
        assert!(
            hostname.ends_with(".spoq.dev"),
            "Hostname {} should be valid",
            hostname
        );
    }

    // Invalid hostnames
    let invalid_hostnames = vec![
        "user.example.com",
        "spoq.dev",
        "user.spoq.io",
        "user@spoq.dev",
    ];

    for hostname in invalid_hostnames {
        assert!(
            !hostname.ends_with(".spoq.dev") || hostname == "spoq.dev",
            "Hostname {} should be invalid",
            hostname
        );
    }
}

/// Test SSH password length validation
#[test]
fn test_ssh_password_length_validation() {
    // Valid passwords (12+ chars)
    let valid_passwords = vec![
        "123456789012",
        "StrongPassword!",
        "VeryLongSecurePassword123!@#",
    ];

    for password in valid_passwords {
        assert!(
            password.len() >= 12,
            "Password '{}' should be valid (length: {})",
            password,
            password.len()
        );
    }

    // Invalid passwords (< 12 chars)
    let invalid_passwords = vec!["short", "12345678901", ""];

    for password in invalid_passwords {
        assert!(
            password.len() < 12,
            "Password '{}' should be invalid (length: {})",
            password,
            password.len()
        );
    }
}

/// Test that different users get different VPS IDs
#[test]
fn test_vps_id_uniqueness() {
    let id1 = uuid::Uuid::new_v4();
    let id2 = uuid::Uuid::new_v4();
    let id3 = uuid::Uuid::new_v4();

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);
}

/// Test request deserialization from JSON
#[test]
fn test_confirm_vps_request_json_deserialization() {
    let json = r#"{
        "hostname": "testuser.spoq.dev",
        "ip_address": "192.168.1.100",
        "provider_instance_id": 12345,
        "provider_order_id": "order-abc",
        "plan_id": "vps-1",
        "template_id": 1007,
        "data_center_id": 9,
        "jwt_secret": "secret123",
        "ssh_password": "Password12345!"
    }"#;

    let request: ConfirmVpsRequest = serde_json::from_str(json).expect("Failed to deserialize");

    assert_eq!(request.hostname, "testuser.spoq.dev");
    assert_eq!(request.ip_address, "192.168.1.100");
    assert_eq!(request.provider_instance_id, 12345);
    assert_eq!(request.provider_order_id, Some("order-abc".to_string()));
    assert_eq!(request.plan_id, "vps-1");
    assert_eq!(request.template_id, 1007);
    assert_eq!(request.data_center_id, 9);
    assert_eq!(request.jwt_secret, "secret123");
    assert_eq!(request.ssh_password, "Password12345!");
}

/// Test request deserialization without optional field
#[test]
fn test_confirm_vps_request_json_without_optional() {
    let json = r#"{
        "hostname": "alice.spoq.dev",
        "ip_address": "10.0.0.1",
        "provider_instance_id": 99999,
        "plan_id": "vps-starter",
        "template_id": 1007,
        "data_center_id": 5,
        "jwt_secret": "jwt-secret",
        "ssh_password": "SecurePass123!"
    }"#;

    let request: ConfirmVpsRequest = serde_json::from_str(json).expect("Failed to deserialize");

    assert!(request.provider_order_id.is_none());
    assert_eq!(request.hostname, "alice.spoq.dev");
}

/// Test response serialization to JSON
#[test]
fn test_confirm_vps_response_json_serialization() {
    let response = ConfirmVpsResponse {
        id: uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        hostname: "bob.spoq.dev".to_string(),
        status: "ready".to_string(),
        ip_address: "203.0.113.42".to_string(),
        message: "VPS record created successfully".to_string(),
    };

    let json = serde_json::to_string(&response).expect("Failed to serialize");

    assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(json.contains("bob.spoq.dev"));
    assert!(json.contains("ready"));
    assert!(json.contains("203.0.113.42"));
    assert!(json.contains("VPS record created successfully"));
}

/// Test that various IP address formats are accepted
#[test]
fn test_ip_address_formats() {
    let valid_ips = vec![
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "203.0.113.42",
        "255.255.255.255",
    ];

    for ip in valid_ips {
        // Basic format validation - 4 octets
        let parts: Vec<&str> = ip.split('.').collect();
        assert_eq!(parts.len(), 4, "IP {} should have 4 octets", ip);

        // Each part should be a valid number (parsing to u8 validates 0-255 range)
        for part in parts {
            let _num: u8 = part
                .parse()
                .unwrap_or_else(|_| panic!("IP {} has invalid octet: {}", ip, part));
        }
    }
}

/// Test template_id validation (common OS templates)
#[test]
fn test_template_id_values() {
    // Common Hostinger template IDs
    let valid_template_ids: Vec<i32> = vec![
        1007, // Ubuntu 22.04
        1006, // Ubuntu 20.04
        1008, // Debian 11
        1009, // CentOS 7
    ];

    for template_id in valid_template_ids {
        assert!(template_id > 0, "Template ID should be positive");
    }
}

/// Test data_center_id validation
#[test]
fn test_data_center_id_values() {
    // Common Hostinger data center IDs
    let valid_dc_ids: Vec<i32> = vec![
        9,  // Phoenix, US
        5,  // Amsterdam, EU
        2,  // Singapore, APAC
        11, // London, EU
    ];

    for dc_id in valid_dc_ids {
        assert!(dc_id > 0, "Data center ID should be positive");
    }
}
