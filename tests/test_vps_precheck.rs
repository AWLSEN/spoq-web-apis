//! Unit tests for VPS precheck endpoint response models.
//!
//! These tests verify the VpsPrecheckResponse model and status mapping
//! used in the GET /api/vps/precheck endpoint for CLI setup flow Step 1.

use chrono::Utc;
use spoq_web_apis::models::{VpsPrecheckResponse, VpsPrecheckStatus};
use uuid::Uuid;

// ============================================================================
// VpsPrecheckStatus Tests
// ============================================================================

#[test]
fn test_precheck_status_from_ready() {
    let status = VpsPrecheckStatus::from_db_status("ready");
    assert_eq!(status, VpsPrecheckStatus::Ready);
}

#[test]
fn test_precheck_status_from_stopped() {
    let status = VpsPrecheckStatus::from_db_status("stopped");
    assert_eq!(status, VpsPrecheckStatus::Stopped);
}

#[test]
fn test_precheck_status_from_failed() {
    let status = VpsPrecheckStatus::from_db_status("failed");
    assert_eq!(status, VpsPrecheckStatus::Error);
}

#[test]
fn test_precheck_status_from_terminated() {
    let status = VpsPrecheckStatus::from_db_status("terminated");
    assert_eq!(status, VpsPrecheckStatus::Error);
}

#[test]
fn test_precheck_status_from_provisioning_states() {
    // All these states map to Provisioning
    let provisioning_states = vec![
        "pending",
        "provisioning",
        "registering",
        "configuring",
    ];

    for state in provisioning_states {
        let status = VpsPrecheckStatus::from_db_status(state);
        assert_eq!(
            status,
            VpsPrecheckStatus::Provisioning,
            "State '{}' should map to Provisioning",
            state
        );
    }
}

#[test]
fn test_precheck_status_from_unknown_state() {
    // Unknown states should default to Provisioning
    let status = VpsPrecheckStatus::from_db_status("unknown_state");
    assert_eq!(status, VpsPrecheckStatus::Provisioning);
}

// ============================================================================
// VpsPrecheckResponse::no_vps() Tests
// ============================================================================

#[test]
fn test_no_vps_response() {
    let response = VpsPrecheckResponse::no_vps();

    assert!(!response.has_vps);
    assert!(response.vps_id.is_none());
    assert!(response.vps_url.is_none());
    assert!(response.healthy.is_none());
    assert!(response.status.is_none());
}

#[test]
fn test_no_vps_response_serialization() {
    let response = VpsPrecheckResponse::no_vps();
    let json = serde_json::to_string(&response).expect("Should serialize");

    // Should contain has_vps: false
    assert!(json.contains("\"has_vps\":false"));

    // Should NOT contain null fields (they're skipped via skip_serializing_if)
    assert!(!json.contains("vps_id"));
    assert!(!json.contains("vps_url"));
    assert!(!json.contains("healthy"));
    assert!(!json.contains("status"));
}

// ============================================================================
// VpsPrecheckResponse::from_vps() Tests
// ============================================================================

/// Mock UserVps for testing (minimal fields needed for precheck)
struct MockUserVps {
    id: Uuid,
    hostname: String,
    status: String,
    registered_at: Option<chrono::DateTime<Utc>>,
}

impl MockUserVps {
    fn new(hostname: &str, status: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            hostname: hostname.to_string(),
            status: status.to_string(),
            registered_at: None,
        }
    }

    fn with_registered(mut self) -> Self {
        self.registered_at = Some(Utc::now());
        self
    }
}

/// Convert MockUserVps to VpsPrecheckResponse (simulates from_vps logic)
fn mock_from_vps(vps: &MockUserVps, healthy: Option<bool>) -> VpsPrecheckResponse {
    let status = VpsPrecheckStatus::from_db_status(&vps.status);

    // Only provide vps_url if the VPS is ready or at least registered
    let vps_url = if vps.status == "ready" || vps.registered_at.is_some() {
        Some(format!("https://{}", vps.hostname))
    } else {
        None
    };

    VpsPrecheckResponse {
        has_vps: true,
        vps_id: Some(vps.id),
        vps_url,
        healthy,
        status: Some(status),
    }
}

#[test]
fn test_from_vps_ready_and_healthy() {
    let vps = MockUserVps::new("testuser.spoq.dev", "ready").with_registered();
    let response = mock_from_vps(&vps, Some(true));

    assert!(response.has_vps);
    assert_eq!(response.vps_id, Some(vps.id));
    assert_eq!(response.vps_url, Some("https://testuser.spoq.dev".to_string()));
    assert_eq!(response.healthy, Some(true));
    assert_eq!(response.status, Some(VpsPrecheckStatus::Ready));
}

#[test]
fn test_from_vps_provisioning_no_url() {
    let vps = MockUserVps::new("newuser.spoq.dev", "provisioning");
    let response = mock_from_vps(&vps, None);

    assert!(response.has_vps);
    assert_eq!(response.vps_id, Some(vps.id));
    // URL should be None when not registered yet
    assert!(response.vps_url.is_none());
    assert!(response.healthy.is_none());
    assert_eq!(response.status, Some(VpsPrecheckStatus::Provisioning));
}

#[test]
fn test_from_vps_registered_has_url() {
    let vps = MockUserVps::new("registered.spoq.dev", "configuring").with_registered();
    let response = mock_from_vps(&vps, Some(false));

    assert!(response.has_vps);
    // URL should be present because registered_at is set
    assert_eq!(response.vps_url, Some("https://registered.spoq.dev".to_string()));
    assert_eq!(response.healthy, Some(false));
    assert_eq!(response.status, Some(VpsPrecheckStatus::Provisioning));
}

#[test]
fn test_from_vps_stopped() {
    let vps = MockUserVps::new("stopped.spoq.dev", "stopped").with_registered();
    let response = mock_from_vps(&vps, Some(false));

    assert!(response.has_vps);
    assert_eq!(response.vps_url, Some("https://stopped.spoq.dev".to_string()));
    assert_eq!(response.healthy, Some(false));
    assert_eq!(response.status, Some(VpsPrecheckStatus::Stopped));
}

#[test]
fn test_from_vps_failed() {
    let vps = MockUserVps::new("failed.spoq.dev", "failed");
    let response = mock_from_vps(&vps, Some(false));

    assert!(response.has_vps);
    assert!(response.vps_url.is_none()); // Not registered
    assert_eq!(response.healthy, Some(false));
    assert_eq!(response.status, Some(VpsPrecheckStatus::Error));
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_precheck_response_json_structure() {
    let response = VpsPrecheckResponse {
        has_vps: true,
        vps_id: Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()),
        vps_url: Some("https://test.spoq.dev".to_string()),
        healthy: Some(true),
        status: Some(VpsPrecheckStatus::Ready),
    };

    let json = serde_json::to_string(&response).expect("Should serialize");

    assert!(json.contains("\"has_vps\":true"));
    assert!(json.contains("\"vps_id\":\"550e8400-e29b-41d4-a716-446655440000\""));
    assert!(json.contains("\"vps_url\":\"https://test.spoq.dev\""));
    assert!(json.contains("\"healthy\":true"));
    assert!(json.contains("\"status\":\"ready\""));
}

#[test]
fn test_precheck_status_serializes_lowercase() {
    // Verify enum variants serialize to lowercase
    let statuses = vec![
        (VpsPrecheckStatus::Provisioning, "\"provisioning\""),
        (VpsPrecheckStatus::Ready, "\"ready\""),
        (VpsPrecheckStatus::Stopped, "\"stopped\""),
        (VpsPrecheckStatus::Error, "\"error\""),
    ];

    for (status, expected) in statuses {
        let json = serde_json::to_string(&status).expect("Should serialize");
        assert_eq!(json, expected, "Status {:?} should serialize to {}", status, expected);
    }
}

#[test]
fn test_precheck_response_optional_fields_skipped() {
    // When fields are None, they should be omitted from JSON
    let response = VpsPrecheckResponse {
        has_vps: true,
        vps_id: Some(Uuid::new_v4()),
        vps_url: None,
        healthy: None,
        status: Some(VpsPrecheckStatus::Provisioning),
    };

    let json = serde_json::to_string(&response).expect("Should serialize");

    assert!(json.contains("has_vps"));
    assert!(json.contains("vps_id"));
    assert!(!json.contains("vps_url"));  // Should be skipped
    assert!(!json.contains("healthy"));   // Should be skipped
    assert!(json.contains("status"));
}

// ============================================================================
// CLI Setup Flow Scenario Tests
// ============================================================================

#[test]
fn test_scenario_new_user_no_vps() {
    // Scenario: New user has never provisioned a VPS
    let response = VpsPrecheckResponse::no_vps();

    // CLI should proceed to Step 2: PROVISION
    assert!(!response.has_vps);
    assert!(response.status.is_none());
}

#[test]
fn test_scenario_user_with_ready_vps() {
    // Scenario: User has a fully provisioned, healthy VPS
    let vps = MockUserVps::new("existing.spoq.dev", "ready").with_registered();
    let response = mock_from_vps(&vps, Some(true));

    // CLI should skip to Step 4: CREDS-SYNC
    assert!(response.has_vps);
    assert_eq!(response.status, Some(VpsPrecheckStatus::Ready));
    assert_eq!(response.healthy, Some(true));
    assert!(response.vps_url.is_some());
}

#[test]
fn test_scenario_vps_still_provisioning() {
    // Scenario: User started provisioning but VPS not ready yet
    let vps = MockUserVps::new("new.spoq.dev", "provisioning");
    let response = mock_from_vps(&vps, None);

    // CLI should continue polling or show "provisioning in progress"
    assert!(response.has_vps);
    assert_eq!(response.status, Some(VpsPrecheckStatus::Provisioning));
    assert!(response.vps_url.is_none());
    assert!(response.healthy.is_none());
}

#[test]
fn test_scenario_vps_registered_but_health_failing() {
    // Scenario: Conductor registered but health check failing
    let vps = MockUserVps::new("unhealthy.spoq.dev", "configuring").with_registered();
    let response = mock_from_vps(&vps, Some(false));

    // CLI should show "configuring" and retry health check
    assert!(response.has_vps);
    assert_eq!(response.status, Some(VpsPrecheckStatus::Provisioning));
    assert_eq!(response.healthy, Some(false));
    assert!(response.vps_url.is_some()); // URL available since registered
}

#[test]
fn test_scenario_vps_stopped_needs_restart() {
    // Scenario: User's VPS was stopped (e.g., unpaid subscription)
    let vps = MockUserVps::new("stopped.spoq.dev", "stopped").with_registered();
    let response = mock_from_vps(&vps, Some(false));

    // CLI should prompt user to restart VPS
    assert!(response.has_vps);
    assert_eq!(response.status, Some(VpsPrecheckStatus::Stopped));
    assert_eq!(response.healthy, Some(false));
}

#[test]
fn test_scenario_vps_failed_needs_reprovision() {
    // Scenario: VPS provisioning failed
    let vps = MockUserVps::new("failed.spoq.dev", "failed");
    let response = mock_from_vps(&vps, Some(false));

    // CLI should allow user to retry provisioning
    assert!(response.has_vps);
    assert_eq!(response.status, Some(VpsPrecheckStatus::Error));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_hostname_formats() {
    let hostnames = vec![
        "a.spoq.dev",
        "user-with-dash.spoq.dev",
        "user123.spoq.dev",
        "CamelCase.spoq.dev",
    ];

    for hostname in hostnames {
        let vps = MockUserVps::new(hostname, "ready").with_registered();
        let response = mock_from_vps(&vps, Some(true));

        assert_eq!(
            response.vps_url,
            Some(format!("https://{}", hostname)),
            "Hostname {} should be in URL",
            hostname
        );
    }
}

#[test]
fn test_response_equality() {
    let response1 = VpsPrecheckResponse::no_vps();
    let response2 = VpsPrecheckResponse::no_vps();

    // Both should serialize to the same JSON
    let json1 = serde_json::to_string(&response1).unwrap();
    let json2 = serde_json::to_string(&response2).unwrap();
    assert_eq!(json1, json2);
}
