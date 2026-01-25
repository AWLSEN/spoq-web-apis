//! Integration tests for VPS provisioning flow.
//!
//! These tests verify the VPS provisioning logic without making real API calls
//! to Hostinger (which would incur charges).

use spoq_web_apis::services::hostinger::{generate_post_install_script, PostInstallParams};

/// Helper to create test params with tunnel credentials
fn make_params<'a>(
    ssh_password: &'a str,
    hostname: &'a str,
    jwt_secret: &'a str,
    owner_id: &'a str,
) -> PostInstallParams<'a> {
    PostInstallParams {
        ssh_password,
        hostname,
        conductor_url: "https://download.spoq.dev/conductor",
        jwt_secret,
        owner_id,
        tunnel_id: "test-tunnel-id",
        tunnel_secret: "dGVzdC10dW5uZWwtc2VjcmV0",
        account_id: "test-account-id",
    }
}

/// Test that post-install script is generated correctly with all required components
#[test]
fn test_post_install_script_contains_required_components() {
    let params = make_params(
        "TestPassword123!",
        "testuser.spoq.dev",
        "super-secret-jwt-key-12345",
        "550e8400-e29b-41d4-a716-446655440000",
    );
    let script = generate_post_install_script(&params);

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

    // Verify tunnel credentials are injected
    assert!(
        script.contains("TUNNEL_ID=\"test-tunnel-id\""),
        "Script should contain tunnel_id"
    );
}

/// Test that post-install script configures Conductor with environment variables
#[test]
fn test_post_install_script_conductor_env_vars() {
    let params = make_params(
        "TestPassword123!",
        "alice.spoq.dev",
        "jwt-secret-456",
        "user-uuid-123",
    );
    let script = generate_post_install_script(&params);

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
    let params = make_params(
        "password123",
        "bob.spoq.dev",
        "jwt-secret",
        "user-uuid",
    );
    let script = generate_post_install_script(&params);

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
    let params = make_params(
        password,
        "test.spoq.dev",
        "jwt-secret",
        "user-uuid",
    );
    let script = generate_post_install_script(&params);

    // Password should be in the script for the chpasswd command
    assert!(
        script.contains(password),
        "Script should contain SSH password"
    );
}

/// Test that post-install script sets proper permissions
#[test]
fn test_post_install_script_permissions() {
    let params = make_params(
        "password",
        "test.spoq.dev",
        "jwt-secret",
        "user-uuid",
    );
    let script = generate_post_install_script(&params);

    // Should set proper permissions on conductor binary
    assert!(
        script.contains("chmod"),
        "Script should set file permissions"
    );
}

/// Test that post-install script creates required directories
#[test]
fn test_post_install_script_directories() {
    let params = make_params(
        "password",
        "test.spoq.dev",
        "jwt-secret",
        "user-uuid",
    );
    let script = generate_post_install_script(&params);

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
    let params1 = make_params(
        "pass",
        "user1.spoq.dev",
        "secret-1",
        "user-1-id",
    );
    let script1 = generate_post_install_script(&params1);
    assert!(script1.contains("user1.spoq.dev"));

    // Test with different user
    let params2 = make_params(
        "pass",
        "anotheruser.spoq.dev",
        "secret-2",
        "user-2-id",
    );
    let script2 = generate_post_install_script(&params2);
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

    let params1 = make_params(
        "pass1",
        "user1.spoq.dev",
        "jwt-secret",
        &user1.user_id,
    );
    let script1 = generate_post_install_script(&params1);

    let params2 = make_params(
        "pass2",
        "user2.spoq.dev",
        "jwt-secret",
        &user2.user_id,
    );
    let script2 = generate_post_install_script(&params2);

    // Each user should have their own owner_id
    assert!(script1.contains("user-1-uuid"));
    assert!(script2.contains("user-2-uuid"));

    // Scripts should be different
    assert_ne!(script1, script2);
}

/// Test that cloudflared is configured correctly in the post-install script
#[test]
fn test_post_install_script_cloudflared_setup() {
    let params = PostInstallParams {
        ssh_password: "password",
        hostname: "test.spoq.dev",
        conductor_url: "https://download.spoq.dev/conductor",
        jwt_secret: "jwt-secret",
        owner_id: "user-uuid",
        tunnel_id: "abc-123-tunnel",
        tunnel_secret: "c2VjcmV0LWtleQ==",
        account_id: "cf-account-456",
    };
    let script = generate_post_install_script(&params);

    // Verify cloudflared installation
    assert!(script.contains("cloudflared-linux-amd64.deb"));
    assert!(script.contains("dpkg -i /tmp/cloudflared.deb"));

    // Verify tunnel credentials
    assert!(script.contains("TUNNEL_ID=\"abc-123-tunnel\""));
    assert!(script.contains("TUNNEL_SECRET=\"c2VjcmV0LWtleQ==\""));
    assert!(script.contains("CF_ACCOUNT_ID=\"cf-account-456\""));

    // Verify cloudflared config
    assert!(script.contains("/etc/cloudflared/config.yml"));
    assert!(script.contains("tunnel: $TUNNEL_ID"));
    assert!(script.contains("credentials-file:"));

    // Verify cloudflared service
    assert!(script.contains("cloudflared service install"));
    assert!(script.contains("systemctl enable cloudflared"));
    assert!(script.contains("systemctl start cloudflared"));

    // Should NOT contain Caddy (replaced by cloudflared)
    assert!(!script.contains("caddy"), "Script should not contain caddy");

    // Firewall should only allow SSH (no 80/443 needed for tunnel)
    assert!(script.contains("ufw allow 22"));
    assert!(!script.contains("ufw allow 80"), "Port 80 not needed for cloudflared tunnel");
    assert!(!script.contains("ufw allow 443"), "Port 443 not needed for cloudflared tunnel");
}
