//! Integration tests for VPS provisioning flow.
//!
//! These tests verify the VPS provisioning logic without making real API calls
//! to Hostinger (which would incur charges).

use spoq_web_apis::services::hostinger::generate_post_install_script;

/// Test that post-install script is generated correctly with all required components
#[test]
fn test_post_install_script_contains_required_components() {
    let script = generate_post_install_script(
        "TestPassword123!",                      // ssh_password
        "ABC123",                                // registration_code
        "https://api.spoq.dev",                  // api_url
        "testuser.spoq.dev",                     // hostname
        "https://download.spoq.dev/conductor",   // conductor_url
        "super-secret-jwt-key-12345",            // jwt_secret
        "550e8400-e29b-41d4-a716-446655440000",  // owner_id
    );

    // Verify owner_id is injected
    assert!(
        script.contains("OWNER_ID=\"550e8400-e29b-41d4-a716-446655440000\""),
        "Script should contain owner_id"
    );

    // Verify jwt_secret is injected
    assert!(
        script.contains("JWT_SECRET=\"super-secret-jwt-key-12345\""),
        "Script should contain jwt_secret"
    );

    // Verify hostname is injected
    assert!(
        script.contains("HOSTNAME=\"testuser.spoq.dev\""),
        "Script should contain hostname"
    );
}

/// Test that post-install script configures Conductor with environment variables
#[test]
fn test_post_install_script_conductor_env_vars() {
    let script = generate_post_install_script(
        "TestPassword123!",
        "ABC123",
        "https://api.spoq.dev",
        "alice.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret-456",
        "user-uuid-123",
    );

    // Verify Conductor systemd service uses env vars (not config file)
    assert!(
        script.contains("CONDUCTOR_AUTH__JWT_SECRET=$JWT_SECRET"),
        "Conductor should use JWT_SECRET env var"
    );
    assert!(
        script.contains("CONDUCTOR_AUTH__OWNER_ID=$OWNER_ID"),
        "Conductor should use OWNER_ID env var"
    );

    // Verify systemd service is created
    assert!(
        script.contains("[Unit]"),
        "Script should create systemd unit"
    );
    assert!(
        script.contains("Description=Spoq Conductor"),
        "Script should have Conductor description"
    );
}

/// Test that post-install script includes Caddy setup
#[test]
fn test_post_install_script_caddy_setup() {
    let script = generate_post_install_script(
        "TestPassword123!",
        "ABC123",
        "https://api.spoq.dev",
        "bob.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret",
        "user-uuid",
    );

    // Verify Caddy installation
    assert!(
        script.contains("apt-get install -y caddy"),
        "Script should install Caddy"
    );

    // Verify Caddy GPG key is added
    assert!(
        script.contains("caddy/stable/gpg.key"),
        "Script should add Caddy GPG key"
    );

    // Verify Caddyfile is configured with hostname
    assert!(
        script.contains("bob.spoq.dev"),
        "Caddyfile should use the hostname"
    );
    assert!(
        script.contains("reverse_proxy localhost:8080"),
        "Caddy should reverse proxy to port 8080"
    );

    // Verify Caddy is enabled
    assert!(
        script.contains("systemctl enable caddy"),
        "Script should enable Caddy"
    );
}

/// Test that post-install script configures firewall correctly
#[test]
fn test_post_install_script_firewall() {
    let script = generate_post_install_script(
        "user-uuid",
        "jwt-secret",
        "test.spoq.dev",
    );

    // Verify firewall rules
    assert!(script.contains("ufw allow 22"), "Should allow SSH");
    assert!(script.contains("ufw allow 80"), "Should allow HTTP for Let's Encrypt");
    assert!(script.contains("ufw allow 443"), "Should allow HTTPS");
    assert!(script.contains("ufw allow 8080"), "Should allow Conductor direct access");
    assert!(script.contains("ufw --force enable"), "Should enable firewall");
}

/// Test that post-install script creates VPS marker file
#[test]
fn test_post_install_script_vps_marker() {
    let script = generate_post_install_script(
        "user-uuid",
        "jwt-secret",
        "marker.spoq.dev",
    );

    // Verify marker file creation
    assert!(
        script.contains("mkdir -p /etc/spoq"),
        "Should create /etc/spoq directory"
    );
    assert!(
        script.contains("/etc/spoq/vps.marker"),
        "Should create vps.marker file"
    );
    assert!(
        script.contains("\"vps\": true"),
        "Marker should indicate VPS environment"
    );
    assert!(
        script.contains("\"conductor\": \"http://localhost:8080\""),
        "Marker should have conductor URL"
    );
}

/// Test that post-install script has proper error handling
#[test]
fn test_post_install_script_error_handling() {
    let script = generate_post_install_script(
        "user-uuid",
        "jwt-secret",
        "test.spoq.dev",
    );

    // Verify set -e for fail-fast behavior
    assert!(
        script.contains("set -e"),
        "Script should fail on first error"
    );

    // Verify logging
    assert!(
        script.contains("/var/log/spoq-setup.log"),
        "Script should log to file"
    );
}

/// Test that different users get different scripts
#[test]
fn test_post_install_script_uniqueness() {
    let script1 = generate_post_install_script(
        "user-1-uuid",
        "secret-1",
        "user1.spoq.dev",
    );

    let script2 = generate_post_install_script(
        "user-2-uuid",
        "secret-2",
        "user2.spoq.dev",
    );

    // Scripts should be different
    assert_ne!(script1, script2, "Different users should get different scripts");

    // Each should contain their own values
    assert!(script1.contains("user-1-uuid"));
    assert!(script1.contains("secret-1"));
    assert!(script1.contains("user1.spoq.dev"));

    assert!(script2.contains("user-2-uuid"));
    assert!(script2.contains("secret-2"));
    assert!(script2.contains("user2.spoq.dev"));
}

/// Test script doesn't contain hardcoded sensitive values from other users
#[test]
fn test_post_install_script_no_cross_contamination() {
    let script = generate_post_install_script(
        "my-user-id",
        "my-secret",
        "myhost.spoq.dev",
    );

    // Should not contain any placeholder text
    assert!(!script.contains("__OWNER_ID__"), "Should not have placeholder");
    assert!(!script.contains("__JWT_SECRET__"), "Should not have placeholder");
    assert!(!script.contains("__HOSTNAME__"), "Should not have placeholder");

    // Should not contain example values from docs
    assert!(!script.contains("alice.spoq.dev") || script.contains("myhost.spoq.dev"));
}

/// Test hostname validation in Caddy config
#[test]
fn test_post_install_script_hostname_in_caddy() {
    let hostnames = vec![
        "simple.spoq.dev",
        "with-dash.spoq.dev",
        "user123.spoq.dev",
        "a.spoq.dev",
    ];

    for hostname in hostnames {
        let script = generate_post_install_script("uid", "secret", hostname);

        // Hostname should be in the HOSTNAME variable
        assert!(
            script.contains(&format!("HOSTNAME=\"{}\"", hostname)),
            "Script should have HOSTNAME variable for {}",
            hostname
        );

        // Caddyfile uses $HOSTNAME variable (with escaped braces in format string)
        assert!(
            script.contains("$HOSTNAME {"),
            "Caddyfile should use $HOSTNAME variable"
        );
    }
}

/// Test that script sets up welcome message
#[test]
fn test_post_install_script_welcome_message() {
    let script = generate_post_install_script(
        "user-uuid",
        "jwt-secret",
        "welcome.spoq.dev",
    );

    assert!(
        script.contains("Welcome to Spoq"),
        "Should have welcome message"
    );
    assert!(
        script.contains(".bashrc"),
        "Should modify bashrc for welcome"
    );
}

/// Test that post-install script downloads Conductor and CLI binaries
#[test]
fn test_post_install_script_downloads_binaries() {
    let script = generate_post_install_script(
        "user-uuid",
        "jwt-secret",
        "download.spoq.dev",
    );

    // Verify Conductor download
    assert!(
        script.contains("https://download.spoq.dev/conductor"),
        "Script should download Conductor binary"
    );

    // Verify CLI download
    assert!(
        script.contains("https://download.spoq.dev/cli"),
        "Script should download CLI binary"
    );

    // Verify curl commands are present
    assert!(
        script.contains("curl -fsSL"),
        "Script should use curl to download"
    );
}

// ============================================================================
// Mock-based tests for VPS provisioning flow
// ============================================================================

/// Simulated VPS provisioning request for testing
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MockProvisionRequest {
    user_id: String,
    username: String,
    ssh_password: String,
    plan_id: Option<String>,
    data_center_id: Option<i32>,
}

/// Simulated VPS provisioning response
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MockProvisionResponse {
    vps_id: String,
    hostname: String,
    status: String,
    script_id: i64,
}

/// Simulate the provisioning flow without real API calls
fn simulate_provision_flow(req: MockProvisionRequest) -> MockProvisionResponse {
    // 1. Generate hostname from username
    let hostname = format!("{}.spoq.dev", req.username.to_lowercase());

    // 2. Generate post-install script
    let jwt_secret = "test-jwt-secret";
    let script = generate_post_install_script(&req.user_id, jwt_secret, &hostname);

    // 3. Verify script was generated correctly
    assert!(script.contains(&req.user_id));
    assert!(script.contains(&hostname));

    // 4. Simulate Hostinger script creation (would return script_id)
    let script_id = 12345_i64; // Mock ID

    // 5. Return mock response
    MockProvisionResponse {
        vps_id: format!("vps-{}", &req.user_id[..8]),
        hostname,
        status: "provisioning".to_string(),
        script_id,
    }
}

#[test]
fn test_simulate_provision_flow_basic() {
    let req = MockProvisionRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        username: "testuser".to_string(),
        ssh_password: "SecurePassword123!".to_string(),
        plan_id: None,
        data_center_id: None,
    };

    let response = simulate_provision_flow(req);

    assert_eq!(response.hostname, "testuser.spoq.dev");
    assert_eq!(response.status, "provisioning");
    assert!(response.script_id > 0);
}

#[test]
fn test_simulate_provision_flow_different_usernames() {
    let users = vec![
        ("user1-uuid-1234", "alice"),
        ("user2-uuid-5678", "bob"),
        ("user3-uuid-9012", "Charlie"), // Mixed case
        ("user4-uuid-3456", "user-with-dash"),
    ];

    for (user_id, username) in users {
        let req = MockProvisionRequest {
            user_id: user_id.to_string(),
            username: username.to_string(),
            ssh_password: "Password12345!".to_string(),
            plan_id: None,
            data_center_id: None,
        };

        let response = simulate_provision_flow(req);

        // Hostname should be lowercase
        assert_eq!(
            response.hostname,
            format!("{}.spoq.dev", username.to_lowercase())
        );
    }
}

#[test]
fn test_provision_generates_unique_scripts_per_user() {
    let user1 = MockProvisionRequest {
        user_id: "user-1-id".to_string(),
        username: "alice".to_string(),
        ssh_password: "Password123!".to_string(),
        plan_id: None,
        data_center_id: None,
    };

    let user2 = MockProvisionRequest {
        user_id: "user-2-id".to_string(),
        username: "bob".to_string(),
        ssh_password: "Password456!".to_string(),
        plan_id: None,
        data_center_id: None,
    };

    let script1 = generate_post_install_script(
        &user1.user_id,
        "jwt-secret",
        &format!("{}.spoq.dev", user1.username),
    );

    let script2 = generate_post_install_script(
        &user2.user_id,
        "jwt-secret",
        &format!("{}.spoq.dev", user2.username),
    );

    // Scripts should be different
    assert_ne!(script1, script2);

    // Each script should only contain its own user's info
    assert!(script1.contains("user-1-id"));
    assert!(!script1.contains("user-2-id"));

    assert!(script2.contains("user-2-id"));
    assert!(!script2.contains("user-1-id"));
}
