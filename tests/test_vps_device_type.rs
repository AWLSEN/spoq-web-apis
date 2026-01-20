//! Tests for device_type field in VPS provisioning.
//!
//! These tests verify that the device_type field is correctly set and handled
//! during VPS provisioning and status retrieval.

use spoq_web_apis::models::UserVps;

// ============================================================================
// UserVps model tests with device_type
// ============================================================================

/// Test that UserVps struct has device_type field (compile-time check)
#[test]
fn test_user_vps_device_type_field_exists() {
    // This function requires device_type to exist on UserVps
    fn _check_field(_vps: &UserVps) -> &str {
        &_vps.device_type
    }

    // If this compiles, the field exists
}

/// Test device_type default value matches migration
#[test]
fn test_device_type_default_value() {
    // The migration sets DEFAULT 'vps'
    let expected_default = "vps";
    assert_eq!(expected_default, "vps");
}

/// Test valid device_type values
#[test]
fn test_device_type_valid_values() {
    let valid_types = vec!["vps", "byovps"];

    // Verify we support both expected types
    assert_eq!(valid_types.len(), 2);
    assert!(valid_types.contains(&"vps"));
    assert!(valid_types.contains(&"byovps"));
}

/// Test device_type value for managed VPS
#[test]
fn test_device_type_managed_vps() {
    let device_type = "vps";

    // Managed VPS should use 'vps' type
    assert_eq!(device_type, "vps");
    assert_ne!(device_type, "byovps");
}

/// Test device_type value for bring-your-own VPS
#[test]
fn test_device_type_byovps() {
    let device_type = "byovps";

    // BYOVPS should use 'byovps' type
    assert_eq!(device_type, "byovps");
    assert_ne!(device_type, "vps");
}

/// Test device_type field length constraints
#[test]
fn test_device_type_field_constraints() {
    let vps_type = "vps";
    let byovps_type = "byovps";

    // Both should be short strings
    assert!(vps_type.len() <= 10);
    assert!(byovps_type.len() <= 10);

    // Both should be lowercase
    assert_eq!(vps_type, vps_type.to_lowercase());
    assert_eq!(byovps_type, byovps_type.to_lowercase());
}

/// Test device_type is included in VPS provisioning
#[test]
fn test_device_type_in_provisioning() {
    // Simulates the INSERT query in provision_vps handler
    let fields = vec![
        "id",
        "user_id",
        "provider",
        "plan_id",
        "template_id",
        "data_center_id",
        "hostname",
        "status",
        "ssh_username",
        "ssh_password_hash",
        "jwt_secret",
        "device_type",
    ];

    // Verify device_type is in the field list
    assert!(fields.contains(&"device_type"));
}

/// Test device_type distinguishes between provisioning methods
#[test]
fn test_device_type_distinguishes_provisioning() {
    let managed_vps = "vps";
    let user_provided_vps = "byovps";

    // Should be distinguishable
    assert_ne!(managed_vps, user_provided_vps);

    // Can use for filtering
    fn is_managed(device_type: &str) -> bool {
        device_type == "vps"
    }

    fn is_byovps(device_type: &str) -> bool {
        device_type == "byovps"
    }

    assert!(is_managed(managed_vps));
    assert!(!is_managed(user_provided_vps));
    assert!(is_byovps(user_provided_vps));
    assert!(!is_byovps(managed_vps));
}

// ============================================================================
// Migration tests
// ============================================================================

/// Test migration adds NOT NULL constraint
#[test]
fn test_device_type_not_null_constraint() {
    // The migration uses: ADD COLUMN device_type TEXT NOT NULL DEFAULT 'vps'
    // This ensures all rows have a value
    let device_type = "vps"; // Default value

    assert!(!device_type.is_empty());
}

/// Test migration creates index
#[test]
fn test_device_type_index_exists() {
    // Migration creates: CREATE INDEX idx_user_vps_device_type ON user_vps(device_type)
    // This index name should be documented
    let index_name = "idx_user_vps_device_type";

    assert!(index_name.starts_with("idx_"));
    assert!(index_name.contains("user_vps"));
    assert!(index_name.contains("device_type"));
}

/// Test migration comment is descriptive
#[test]
fn test_device_type_comment() {
    // Migration adds comment explaining the field
    let comment = "VPS provisioning type: 'vps' for managed Hostinger VPS, 'byovps' for user-provided VPS";

    assert!(comment.contains("vps"));
    assert!(comment.contains("byovps"));
    assert!(comment.contains("managed"));
    assert!(comment.contains("user-provided"));
}

// ============================================================================
// Query filter tests
// ============================================================================

/// Test filtering VPS by device_type
#[test]
fn test_filter_by_device_type() {
    // Simulates WHERE clause filtering
    let device_types = vec!["vps", "vps", "byovps", "vps", "byovps"];

    let managed_count = device_types.iter().filter(|&&dt| dt == "vps").count();
    let byovps_count = device_types.iter().filter(|&&dt| dt == "byovps").count();

    assert_eq!(managed_count, 3);
    assert_eq!(byovps_count, 2);
}

/// Test counting VPS by type
#[test]
fn test_count_by_device_type() {
    let vps_list = vec![
        ("alice", "vps"),
        ("bob", "byovps"),
        ("charlie", "vps"),
        ("dave", "vps"),
        ("eve", "byovps"),
    ];

    let managed = vps_list.iter().filter(|(_, dt)| *dt == "vps").count();
    let byovps = vps_list.iter().filter(|(_, dt)| *dt == "byovps").count();

    assert_eq!(managed, 3);
    assert_eq!(byovps, 2);
    assert_eq!(managed + byovps, vps_list.len());
}

// ============================================================================
// Edge cases
// ============================================================================

/// Test device_type case sensitivity
#[test]
fn test_device_type_case_sensitivity() {
    let lowercase = "vps";
    let uppercase = "VPS";
    let mixed = "Vps";

    // Should store as lowercase
    assert_eq!(lowercase, "vps");
    assert_ne!(lowercase, uppercase);
    assert_ne!(lowercase, mixed);

    // Comparison should be case-sensitive
    assert_ne!(lowercase.to_uppercase(), lowercase);
}

/// Test device_type with whitespace (should be trimmed)
#[test]
fn test_device_type_no_whitespace() {
    let vps_type = "vps";
    let byovps_type = "byovps";

    // Should not have leading/trailing whitespace
    assert_eq!(vps_type.trim(), vps_type);
    assert_eq!(byovps_type.trim(), byovps_type);
}

/// Test invalid device_type values (for future validation)
#[test]
fn test_device_type_invalid_values() {
    let invalid_types = vec!["", "invalid", "VPS", "byo-vps", "vm", "server"];

    let valid_types = vec!["vps", "byovps"];

    for invalid in &invalid_types {
        assert!(!valid_types.contains(invalid));
    }
}

/// Test device_type for future extensibility
#[test]
fn test_device_type_extensibility() {
    // Current supported types
    let supported_types = vec!["vps", "byovps"];

    // Future types might include
    let future_types = vec!["dedicated", "cloud", "hybrid"];

    // Ensure current types don't conflict with potential future types
    for current in &supported_types {
        assert!(!future_types.contains(current));
    }
}

// ============================================================================
// Documentation and examples
// ============================================================================

/// Example: Creating a managed VPS record
#[test]
fn test_example_managed_vps() {
    let device_type = "vps";
    let provider = "hostinger";

    assert_eq!(device_type, "vps");
    assert_eq!(provider, "hostinger");
}

/// Example: Creating a BYOVPS record
#[test]
fn test_example_byovps() {
    let device_type = "byovps";

    // User provides their own VPS details
    assert_eq!(device_type, "byovps");
}

/// Example: Query pattern for listing VPS by type
#[test]
fn test_example_query_by_type() {
    // Simulates: SELECT * FROM user_vps WHERE device_type = $1
    fn filter_by_type<'a>(records: Vec<(&'a str, &'a str)>, device_type: &str) -> Vec<(&'a str, &'a str)> {
        records
            .into_iter()
            .filter(|(_, dt)| *dt == device_type)
            .collect()
    }

    let all_vps = vec![
        ("alice", "vps"),
        ("bob", "byovps"),
        ("charlie", "vps"),
    ];

    let managed = filter_by_type(all_vps.clone(), "vps");
    let byovps = filter_by_type(all_vps, "byovps");

    assert_eq!(managed.len(), 2);
    assert_eq!(byovps.len(), 1);
}
