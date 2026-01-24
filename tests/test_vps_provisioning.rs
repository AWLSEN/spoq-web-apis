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
        "alice.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret-456",
        "user-uuid-123",
    );

    // Verify Conductor download
    assert!(
        script.contains("https://download.spoq.dev/conductor"),
        "Script should download conductor"
    );

    // Verify Conductor systemd service is configured with environment variables
    assert!(
        script.contains("conductor.service") && script.contains("CONDUCTOR_AUTH__JWT_SECRET"),
        "Script should configure conductor service with env vars"
    );
}

/// Test that post-install script sets up systemd service
#[test]
fn test_post_install_script_systemd_setup() {
    let script = generate_post_install_script(
        "password123",
        "bob.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret",
        "user-uuid",
    );

    // Verify systemd service is created
    assert!(
        script.contains("conductor.service") || script.contains("systemctl"),
        "Script should set up systemd service"
    );
}

/// Test that post-install script handles SSH password correctly
#[test]
fn test_post_install_script_ssh_password() {
    let password = "Complex!Pass#123";
    let script = generate_post_install_script(
        password,
        "test.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret",
        "user-uuid",
    );

    // Password should be in the script for the chpasswd command
    assert!(
        script.contains(password),
        "Script should contain SSH password"
    );
}

/// Test that post-install script sets proper permissions
#[test]
fn test_post_install_script_permissions() {
    let script = generate_post_install_script(
        "password",
        "test.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret",
        "user-uuid",
    );

    // Should set proper permissions on conductor binary
    assert!(
        script.contains("chmod"),
        "Script should set file permissions"
    );
}

/// Test that post-install script creates required directories
#[test]
fn test_post_install_script_directories() {
    let script = generate_post_install_script(
        "password",
        "test.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret",
        "user-uuid",
    );

    // Should create /opt/spoq directory
    assert!(
        script.contains("/opt/spoq") || script.contains("mkdir"),
        "Script should create required directories"
    );
}

/// Test post-install script with different hostnames
#[test]
fn test_post_install_script_hostname_variations() {
    // Test with subdomain
    let script1 = generate_post_install_script(
        "pass",
        "user1.spoq.dev",
        "https://download.spoq.dev/conductor",
        "secret-1",
        "user-1-id",
    );
    assert!(script1.contains("user1.spoq.dev"));

    // Test with different user
    let script2 = generate_post_install_script(
        "pass",
        "anotheruser.spoq.dev",
        "https://download.spoq.dev/conductor",
        "secret-2",
        "user-2-id",
    );
    assert!(script2.contains("anotheruser.spoq.dev"));
}

/// Test that different users get different owner_ids in their scripts
#[test]
fn test_post_install_script_user_isolation() {
    struct MockUser {
        user_id: String,
    }

    let user1 = MockUser {
        user_id: "user-1-uuid".to_string(),
    };
    let user2 = MockUser {
        user_id: "user-2-uuid".to_string(),
    };

    let script1 = generate_post_install_script(
        "pass1",
        "user1.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret",
        &user1.user_id,
    );

    let script2 = generate_post_install_script(
        "pass2",
        "user2.spoq.dev",
        "https://download.spoq.dev/conductor",
        "jwt-secret",
        &user2.user_id,
    );

    // Each user should have their own owner_id
    assert!(script1.contains("user-1-uuid"));
    assert!(script2.contains("user-2-uuid"));

    // Scripts should be different
    assert_ne!(script1, script2);
}
