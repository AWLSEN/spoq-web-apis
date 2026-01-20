//! Tests for SSH Installer Service.
//!
//! These tests verify the SSH installer configuration and error handling.
//! Integration tests that require a real SSH server are skipped in the test suite.

use spoq_web_apis::services::ssh_installer::{
    ScriptExecutionResult, SshConfig, SshInstallerError, SshInstallerService,
};

// ============================================================================
// SshConfig tests
// ============================================================================

#[test]
fn test_ssh_config_new_defaults() {
    let config = SshConfig::new("10.0.0.1", "admin", "password123");

    assert_eq!(config.host, "10.0.0.1");
    assert_eq!(config.port, 22);
    assert_eq!(config.username, "admin");
    assert_eq!(config.password, "password123");
    assert_eq!(config.timeout_secs, 30); // DEFAULT_TIMEOUT_SECS
    assert_eq!(config.exec_timeout_secs, 300); // DEFAULT_EXEC_TIMEOUT_SECS
}

#[test]
fn test_ssh_config_custom_port() {
    let config = SshConfig::new("192.168.1.100", "root", "secret").with_port(2222);

    assert_eq!(config.port, 2222);
    assert_eq!(config.host, "192.168.1.100");
}

#[test]
fn test_ssh_config_custom_timeouts() {
    let config = SshConfig::new("example.com", "user", "pass")
        .with_timeout(60)
        .with_exec_timeout(600);

    assert_eq!(config.timeout_secs, 60);
    assert_eq!(config.exec_timeout_secs, 600);
}

#[test]
fn test_ssh_config_builder_pattern() {
    let config = SshConfig::new("vps.example.com", "deploy", "deploy123")
        .with_port(22022)
        .with_timeout(45)
        .with_exec_timeout(900);

    assert_eq!(config.host, "vps.example.com");
    assert_eq!(config.username, "deploy");
    assert_eq!(config.password, "deploy123");
    assert_eq!(config.port, 22022);
    assert_eq!(config.timeout_secs, 45);
    assert_eq!(config.exec_timeout_secs, 900);
}

#[test]
fn test_ssh_config_accepts_ip_addresses() {
    let ipv4 = SshConfig::new("203.0.113.45", "admin", "pass");
    assert_eq!(ipv4.host, "203.0.113.45");

    let ipv6 = SshConfig::new("2001:db8::1", "admin", "pass");
    assert_eq!(ipv6.host, "2001:db8::1");
}

#[test]
fn test_ssh_config_accepts_hostnames() {
    let hostname = SshConfig::new("vps-prod-01.example.com", "root", "secret");
    assert_eq!(hostname.host, "vps-prod-01.example.com");
}

#[test]
fn test_ssh_config_clone() {
    let config1 = SshConfig::new("192.168.1.1", "user", "password")
        .with_port(2222)
        .with_timeout(120);

    let config2 = config1.clone();

    assert_eq!(config1.host, config2.host);
    assert_eq!(config1.port, config2.port);
    assert_eq!(config1.username, config2.username);
    assert_eq!(config1.password, config2.password);
    assert_eq!(config1.timeout_secs, config2.timeout_secs);
}

#[test]
fn test_ssh_config_debug_trait() {
    let config = SshConfig::new("test.local", "admin", "secret");
    let debug_str = format!("{:?}", config);

    // Debug output should contain the struct name
    assert!(debug_str.contains("SshConfig"));
}

// ============================================================================
// ScriptExecutionResult tests
// ============================================================================

#[test]
fn test_script_execution_result_success() {
    let result = ScriptExecutionResult {
        stdout: "Installation complete\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };

    assert!(result.is_success());
    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_script_execution_result_failure() {
    let result = ScriptExecutionResult {
        stdout: String::new(),
        stderr: "Error: command not found\n".to_string(),
        exit_code: 127,
    };

    assert!(!result.is_success());
    assert_eq!(result.exit_code, 127);
}

#[test]
fn test_script_execution_result_with_output() {
    let result = ScriptExecutionResult {
        stdout: "Hello, World!\nSecond line\n".to_string(),
        stderr: "Warning: deprecated syntax\n".to_string(),
        exit_code: 0,
    };

    assert!(result.is_success());
    assert!(result.stdout.contains("Hello, World!"));
    assert!(result.stderr.contains("Warning"));
}

#[test]
fn test_script_execution_result_clone() {
    let result1 = ScriptExecutionResult {
        stdout: "output".to_string(),
        stderr: "error".to_string(),
        exit_code: 1,
    };

    let result2 = result1.clone();

    assert_eq!(result1.stdout, result2.stdout);
    assert_eq!(result1.stderr, result2.stderr);
    assert_eq!(result1.exit_code, result2.exit_code);
}

// ============================================================================
// SshInstallerError tests
// ============================================================================

#[test]
fn test_ssh_installer_error_connection_failed() {
    let error = SshInstallerError::ConnectionFailed {
        host: "192.168.1.1".to_string(),
        port: 22,
        message: "Connection timed out".to_string(),
    };

    let error_str = error.to_string();
    assert!(error_str.contains("192.168.1.1"));
    assert!(error_str.contains("22"));
    assert!(error_str.contains("Connection timed out"));
}

#[test]
fn test_ssh_installer_error_handshake_failed() {
    let error = SshInstallerError::HandshakeFailed("Protocol mismatch".to_string());
    let error_str = error.to_string();
    assert!(error_str.contains("SSH handshake failed"));
    assert!(error_str.contains("Protocol mismatch"));
}

#[test]
fn test_ssh_installer_error_authentication_failed() {
    let error = SshInstallerError::AuthenticationFailed {
        username: "admin".to_string(),
        message: "Invalid password".to_string(),
    };

    let error_str = error.to_string();
    assert!(error_str.contains("admin"));
    assert!(error_str.contains("Invalid password"));
}

#[test]
fn test_ssh_installer_error_execution_failed() {
    let error = SshInstallerError::ExecutionFailed("Command not found".to_string());
    let error_str = error.to_string();
    assert!(error_str.contains("Script execution failed"));
    assert!(error_str.contains("Command not found"));
}

#[test]
fn test_ssh_installer_error_non_zero_exit_code() {
    let error = SshInstallerError::NonZeroExitCode { exit_code: 127 };
    let error_str = error.to_string();
    assert!(error_str.contains("127"));
    assert!(error_str.contains("non-zero exit code"));
}

#[test]
fn test_ssh_installer_error_timeout() {
    let error = SshInstallerError::Timeout { seconds: 30 };
    let error_str = error.to_string();
    assert!(error_str.contains("30"));
    assert!(error_str.contains("timeout"));
}

#[test]
fn test_ssh_installer_error_session_error() {
    let error = SshInstallerError::SessionError("Session closed unexpectedly".to_string());
    let error_str = error.to_string();
    assert!(error_str.contains("Session closed unexpectedly"));
}

#[test]
fn test_ssh_installer_error_debug_trait() {
    let error = SshInstallerError::NonZeroExitCode { exit_code: 1 };
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("NonZeroExitCode"));
}

// ============================================================================
// SshInstallerService connection tests (negative cases)
// ============================================================================

#[test]
fn test_connection_to_invalid_ip_fails() {
    // 192.0.2.0/24 is reserved for documentation/testing (TEST-NET-1)
    let config = SshConfig::new("192.0.2.999", "root", "password").with_timeout(1);

    let result = SshInstallerService::connect(config);
    assert!(result.is_err());
}

#[test]
fn test_connection_to_unreachable_host_fails() {
    // Use a very short timeout to make test fast
    let config = SshConfig::new("240.0.0.1", "root", "password").with_timeout(1);

    let result = SshInstallerService::connect(config);
    assert!(result.is_err());

    match result {
        Err(SshInstallerError::ConnectionFailed { host, port, .. }) => {
            assert_eq!(host, "240.0.0.1");
            assert_eq!(port, 22);
        }
        _ => panic!("Expected ConnectionFailed error"),
    }
}

#[test]
fn test_connection_with_invalid_address_format() {
    let config = SshConfig::new("not-a-valid-address:extra:parts", "user", "pass")
        .with_timeout(1);

    let result = SshInstallerService::connect(config);
    assert!(result.is_err());
}

#[test]
fn test_connection_respects_timeout() {
    use std::time::Instant;

    let config = SshConfig::new("192.0.2.1", "root", "password").with_timeout(2);

    let start = Instant::now();
    let result = SshInstallerService::connect(config);
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // Should timeout within reasonable time (2-5 seconds)
    assert!(elapsed.as_secs() <= 5);
}

// ============================================================================
// Documentation tests
// ============================================================================

/// Verify that SshConfig::new creates a valid configuration
#[test]
fn test_ssh_config_usage_example() {
    // Example from documentation
    let config = SshConfig::new("vps.example.com", "root", "secure-password-123")
        .with_port(22)
        .with_timeout(30);

    assert_eq!(config.host, "vps.example.com");
    assert_eq!(config.username, "root");
    assert_eq!(config.port, 22);
    assert_eq!(config.timeout_secs, 30);
}

/// Verify that ScriptExecutionResult provides useful feedback
#[test]
fn test_script_result_usage_example() {
    let success_result = ScriptExecutionResult {
        stdout: "Package installed successfully\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };

    if success_result.is_success() {
        println!("Script succeeded: {}", success_result.stdout);
    }

    assert!(success_result.is_success());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_script_result_with_negative_exit_code() {
    let result = ScriptExecutionResult {
        stdout: String::new(),
        stderr: "Signal terminated".to_string(),
        exit_code: -1,
    };

    assert!(!result.is_success());
}

#[test]
fn test_script_result_with_large_exit_code() {
    let result = ScriptExecutionResult {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 255,
    };

    assert!(!result.is_success());
}

#[test]
fn test_ssh_config_with_empty_password() {
    // Empty password is technically valid (could use key auth)
    let config = SshConfig::new("host", "user", "");
    assert_eq!(config.password, "");
}

#[test]
fn test_ssh_config_with_very_long_timeout() {
    let config = SshConfig::new("host", "user", "pass")
        .with_timeout(86400) // 24 hours
        .with_exec_timeout(86400);

    assert_eq!(config.timeout_secs, 86400);
    assert_eq!(config.exec_timeout_secs, 86400);
}

#[test]
fn test_ssh_config_with_zero_timeout() {
    // Zero timeout might not make sense but should be allowed
    let config = SshConfig::new("host", "user", "pass").with_timeout(0);
    assert_eq!(config.timeout_secs, 0);
}
