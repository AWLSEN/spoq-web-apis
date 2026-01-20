//! SSH Installer Service for remote VPS script execution.
//!
//! This module provides SSH client functionality to connect to remote VPS instances
//! and execute post-install scripts, capturing their output for logging and verification.

use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use thiserror::Error;

/// Default SSH connection timeout in seconds
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default command execution timeout in seconds
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 300; // 5 minutes for scripts

/// Errors that can occur during SSH operations
#[derive(Debug, Error)]
pub enum SshInstallerError {
    #[error("Failed to connect to {host}:{port}: {message}")]
    ConnectionFailed {
        host: String,
        port: u16,
        message: String,
    },

    #[error("SSH handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Authentication failed for user '{username}': {message}")]
    AuthenticationFailed { username: String, message: String },

    #[error("Script execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Command returned non-zero exit code: {exit_code}")]
    NonZeroExitCode { exit_code: i32 },

    #[error("SSH session error: {0}")]
    SessionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Connection timeout after {seconds} seconds")]
    Timeout { seconds: u64 },
}

/// Result of executing a script on a remote VPS
#[derive(Debug, Clone)]
pub struct ScriptExecutionResult {
    /// Standard output from the script
    pub stdout: String,
    /// Standard error from the script
    pub stderr: String,
    /// Exit code from the script (0 = success)
    pub exit_code: i32,
}

impl ScriptExecutionResult {
    /// Check if the script execution was successful
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

/// SSH connection configuration
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// Remote host IP address or hostname
    pub host: String,
    /// SSH port (default: 22)
    pub port: u16,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Command execution timeout in seconds
    pub exec_timeout_secs: u64,
}

impl SshConfig {
    /// Create a new SSH configuration with default timeouts
    pub fn new(host: impl Into<String>, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 22,
            username: username.into(),
            password: password.into(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            exec_timeout_secs: DEFAULT_EXEC_TIMEOUT_SECS,
        }
    }

    /// Set a custom SSH port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set a custom connection timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_secs = seconds;
        self
    }

    /// Set a custom execution timeout
    pub fn with_exec_timeout(mut self, seconds: u64) -> Self {
        self.exec_timeout_secs = seconds;
        self
    }
}

/// SSH Installer Service for connecting to VPS and executing scripts
pub struct SshInstallerService {
    // Note: Session doesn't implement Debug, so we can't derive Debug
    session: Session,
    config: SshConfig,
}

impl std::fmt::Debug for SshInstallerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshInstallerService")
            .field("config", &self.config)
            .field("session", &"<ssh2::Session>")
            .finish()
    }
}

impl SshInstallerService {
    /// Connect to a remote VPS using the provided configuration
    ///
    /// # Arguments
    /// * `config` - SSH connection configuration
    ///
    /// # Returns
    /// * `Ok(SshInstallerService)` - Connected service ready for script execution
    /// * `Err(SshInstallerError)` - Connection or authentication failure
    pub fn connect(config: SshConfig) -> Result<Self, SshInstallerError> {
        tracing::info!(
            "Connecting to {}:{} as user '{}'",
            config.host,
            config.port,
            config.username
        );

        // Establish TCP connection
        let addr = format!("{}:{}", config.host, config.port);
        let tcp = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| SshInstallerError::ConnectionFailed {
                host: config.host.clone(),
                port: config.port,
                message: format!("Invalid address: {}", e),
            })?,
            Duration::from_secs(config.timeout_secs),
        )
        .map_err(|e| SshInstallerError::ConnectionFailed {
            host: config.host.clone(),
            port: config.port,
            message: e.to_string(),
        })?;

        // Set read/write timeouts
        tcp.set_read_timeout(Some(Duration::from_secs(config.exec_timeout_secs)))
            .map_err(|e| SshInstallerError::IoError(e))?;
        tcp.set_write_timeout(Some(Duration::from_secs(config.timeout_secs)))
            .map_err(|e| SshInstallerError::IoError(e))?;

        // Create SSH session
        let mut session = Session::new().map_err(|e| {
            SshInstallerError::SessionError(format!("Failed to create SSH session: {}", e))
        })?;

        session.set_tcp_stream(tcp);

        // Perform SSH handshake
        session.handshake().map_err(|e| {
            SshInstallerError::HandshakeFailed(e.to_string())
        })?;

        // Authenticate with password
        session
            .userauth_password(&config.username, &config.password)
            .map_err(|e| SshInstallerError::AuthenticationFailed {
                username: config.username.clone(),
                message: e.to_string(),
            })?;

        if !session.authenticated() {
            return Err(SshInstallerError::AuthenticationFailed {
                username: config.username.clone(),
                message: "Authentication succeeded but session not authenticated".to_string(),
            });
        }

        tracing::info!(
            "Successfully connected to {}:{} as '{}'",
            config.host,
            config.port,
            config.username
        );

        Ok(Self { session, config })
    }

    /// Execute a bash script on the remote VPS
    ///
    /// # Arguments
    /// * `script` - The bash script content to execute
    ///
    /// # Returns
    /// * `Ok(ScriptExecutionResult)` - Script output and exit code
    /// * `Err(SshInstallerError)` - Execution failure
    pub fn execute_script(&self, script: &str) -> Result<ScriptExecutionResult, SshInstallerError> {
        tracing::info!(
            "Executing script on {}:{} ({} bytes)",
            self.config.host,
            self.config.port,
            script.len()
        );

        // Open a channel for command execution
        let mut channel = self.session.channel_session().map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to open channel: {}", e))
        })?;

        // Execute the script via bash
        // We use 'bash -s' to read script from stdin, allowing multi-line scripts
        channel.exec("bash -s").map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to execute command: {}", e))
        })?;

        // Write the script to stdin
        use std::io::Write;
        channel.write_all(script.as_bytes()).map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to write script: {}", e))
        })?;

        // Close stdin to signal end of input
        channel.send_eof().map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to send EOF: {}", e))
        })?;

        // Read stdout
        let mut stdout = String::new();
        channel.read_to_string(&mut stdout).map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to read stdout: {}", e))
        })?;

        // Read stderr
        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr).map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to read stderr: {}", e))
        })?;

        // Wait for channel to close and get exit status
        channel.wait_close().map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to close channel: {}", e))
        })?;

        let exit_code = channel.exit_status().map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to get exit status: {}", e))
        })?;

        tracing::info!(
            "Script execution completed on {}:{} with exit code {}",
            self.config.host,
            self.config.port,
            exit_code
        );

        if !stderr.is_empty() {
            tracing::warn!(
                "Script stderr on {}:{}: {}",
                self.config.host,
                self.config.port,
                stderr.trim()
            );
        }

        Ok(ScriptExecutionResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    /// Execute a script and return an error if the exit code is non-zero
    ///
    /// # Arguments
    /// * `script` - The bash script content to execute
    ///
    /// # Returns
    /// * `Ok(ScriptExecutionResult)` - Successful script execution (exit code 0)
    /// * `Err(SshInstallerError::NonZeroExitCode)` - Script returned non-zero exit code
    /// * `Err(SshInstallerError)` - Other execution failure
    pub fn execute_script_checked(&self, script: &str) -> Result<ScriptExecutionResult, SshInstallerError> {
        let result = self.execute_script(script)?;

        if result.exit_code != 0 {
            return Err(SshInstallerError::NonZeroExitCode {
                exit_code: result.exit_code,
            });
        }

        Ok(result)
    }

    /// Execute a simple command on the remote VPS
    ///
    /// # Arguments
    /// * `command` - The command to execute
    ///
    /// # Returns
    /// * `Ok(ScriptExecutionResult)` - Command output and exit code
    /// * `Err(SshInstallerError)` - Execution failure
    pub fn execute_command(&self, command: &str) -> Result<ScriptExecutionResult, SshInstallerError> {
        tracing::debug!(
            "Executing command on {}:{}: {}",
            self.config.host,
            self.config.port,
            command
        );

        let mut channel = self.session.channel_session().map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to open channel: {}", e))
        })?;

        channel.exec(command).map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to execute command: {}", e))
        })?;

        let mut stdout = String::new();
        channel.read_to_string(&mut stdout).map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to read stdout: {}", e))
        })?;

        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr).map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to read stderr: {}", e))
        })?;

        channel.wait_close().map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to close channel: {}", e))
        })?;

        let exit_code = channel.exit_status().map_err(|e| {
            SshInstallerError::ExecutionFailed(format!("Failed to get exit status: {}", e))
        })?;

        Ok(ScriptExecutionResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    /// Get the host this service is connected to
    pub fn host(&self) -> &str {
        &self.config.host
    }

    /// Get the port this service is connected to
    pub fn port(&self) -> u16 {
        self.config.port
    }

    /// Get the username used for authentication
    pub fn username(&self) -> &str {
        &self.config.username
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_config_new() {
        let config = SshConfig::new("192.168.1.1", "root", "password123");

        assert_eq!(config.host, "192.168.1.1");
        assert_eq!(config.port, 22);
        assert_eq!(config.username, "root");
        assert_eq!(config.password, "password123");
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(config.exec_timeout_secs, DEFAULT_EXEC_TIMEOUT_SECS);
    }

    #[test]
    fn test_ssh_config_with_port() {
        let config = SshConfig::new("192.168.1.1", "root", "password")
            .with_port(2222);

        assert_eq!(config.port, 2222);
    }

    #[test]
    fn test_ssh_config_with_timeout() {
        let config = SshConfig::new("192.168.1.1", "root", "password")
            .with_timeout(60);

        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_ssh_config_with_exec_timeout() {
        let config = SshConfig::new("192.168.1.1", "root", "password")
            .with_exec_timeout(600);

        assert_eq!(config.exec_timeout_secs, 600);
    }

    #[test]
    fn test_ssh_config_builder_chain() {
        let config = SshConfig::new("10.0.0.1", "admin", "secret")
            .with_port(22022)
            .with_timeout(45)
            .with_exec_timeout(900);

        assert_eq!(config.host, "10.0.0.1");
        assert_eq!(config.port, 22022);
        assert_eq!(config.username, "admin");
        assert_eq!(config.password, "secret");
        assert_eq!(config.timeout_secs, 45);
        assert_eq!(config.exec_timeout_secs, 900);
    }

    #[test]
    fn test_script_execution_result_is_success() {
        let success_result = ScriptExecutionResult {
            stdout: "Hello, world!".to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        assert!(success_result.is_success());

        let failure_result = ScriptExecutionResult {
            stdout: String::new(),
            stderr: "Error occurred".to_string(),
            exit_code: 1,
        };
        assert!(!failure_result.is_success());

        let negative_result = ScriptExecutionResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: -1,
        };
        assert!(!negative_result.is_success());
    }

    #[test]
    fn test_ssh_installer_error_display() {
        let conn_error = SshInstallerError::ConnectionFailed {
            host: "192.168.1.1".to_string(),
            port: 22,
            message: "Connection refused".to_string(),
        };
        assert_eq!(
            conn_error.to_string(),
            "Failed to connect to 192.168.1.1:22: Connection refused"
        );

        let auth_error = SshInstallerError::AuthenticationFailed {
            username: "root".to_string(),
            message: "Invalid password".to_string(),
        };
        assert_eq!(
            auth_error.to_string(),
            "Authentication failed for user 'root': Invalid password"
        );

        let exit_error = SshInstallerError::NonZeroExitCode { exit_code: 127 };
        assert_eq!(
            exit_error.to_string(),
            "Command returned non-zero exit code: 127"
        );

        let timeout_error = SshInstallerError::Timeout { seconds: 30 };
        assert_eq!(
            timeout_error.to_string(),
            "Connection timeout after 30 seconds"
        );

        let handshake_error = SshInstallerError::HandshakeFailed("Protocol mismatch".to_string());
        assert_eq!(
            handshake_error.to_string(),
            "SSH handshake failed: Protocol mismatch"
        );

        let exec_error = SshInstallerError::ExecutionFailed("Channel closed".to_string());
        assert_eq!(
            exec_error.to_string(),
            "Script execution failed: Channel closed"
        );

        let session_error = SshInstallerError::SessionError("Session timeout".to_string());
        assert_eq!(
            session_error.to_string(),
            "SSH session error: Session timeout"
        );
    }

    #[test]
    fn test_connection_to_invalid_host_fails() {
        // Test that connecting to an invalid/unreachable host fails with appropriate error
        let config = SshConfig::new("192.0.2.1", "root", "password")
            .with_timeout(1); // Very short timeout for faster test

        let result = SshInstallerService::connect(config);

        assert!(result.is_err());
        let err = result.unwrap_err();

        // Should be a connection failure (timeout or refused)
        match err {
            SshInstallerError::ConnectionFailed { host, port, .. } => {
                assert_eq!(host, "192.0.2.1");
                assert_eq!(port, 22);
            }
            _ => panic!("Expected ConnectionFailed error, got: {:?}", err),
        }
    }

    #[test]
    fn test_connection_to_invalid_address_fails() {
        // Test that invalid address format fails
        let config = SshConfig::new("not-a-valid-ip:extra", "root", "password")
            .with_timeout(1);

        let result = SshInstallerService::connect(config);

        assert!(result.is_err());
    }

    // Integration tests would require a real SSH server
    // These tests verify the public interface works correctly with mock data

    #[test]
    fn test_default_timeout_constants() {
        assert_eq!(DEFAULT_TIMEOUT_SECS, 30);
        assert_eq!(DEFAULT_EXEC_TIMEOUT_SECS, 300);
    }
}
