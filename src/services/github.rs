//! GitHub OAuth service for authentication.
//!
//! This module provides functionality for:
//! - Generating GitHub OAuth authorization URLs
//! - Exchanging authorization codes for access tokens
//! - Fetching GitHub user information

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration for GitHub OAuth.
#[derive(Debug, Clone)]
pub struct GitHubOAuthConfig {
    /// GitHub OAuth App Client ID
    pub client_id: String,
    /// GitHub OAuth App Client Secret
    pub client_secret: String,
    /// Redirect URI registered with GitHub
    pub redirect_uri: String,
}

/// Response from GitHub's token endpoint.
#[derive(Debug, Deserialize)]
pub struct GitHubTokenResponse {
    /// The access token to use for API requests
    pub access_token: String,
}

/// GitHub user information returned from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubUser {
    /// GitHub's unique user ID
    pub id: i64,
    /// GitHub username (login)
    pub login: String,
    /// User's email address (may be None if private)
    pub email: Option<String>,
    /// URL to the user's avatar image
    pub avatar_url: Option<String>,
}

/// Errors that can occur during GitHub OAuth operations.
#[derive(Debug, Error)]
pub enum GithubError {
    /// HTTP request failed
    #[error("Request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    /// Failed to parse response from GitHub
    #[error("Invalid response from GitHub")]
    InvalidResponse,

    /// GitHub API returned an error
    #[error("GitHub API error: {0}")]
    ApiError(String),
}

/// Generates the GitHub OAuth authorization URL.
///
/// # Arguments
///
/// * `config` - The GitHub OAuth configuration
/// * `state` - A random state parameter for CSRF protection
///
/// # Returns
///
/// The complete authorization URL to redirect users to
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::github::{GitHubOAuthConfig, get_authorize_url};
///
/// let config = GitHubOAuthConfig {
///     client_id: "your_client_id".to_string(),
///     client_secret: "your_client_secret".to_string(),
///     redirect_uri: "https://example.com/callback".to_string(),
/// };
///
/// let url = get_authorize_url(&config, "random_state_123");
/// assert!(url.contains("client_id=your_client_id"));
/// assert!(url.contains("state=random_state_123"));
/// ```
pub fn get_authorize_url(config: &GitHubOAuthConfig, state: &str) -> String {
    format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&config.redirect_uri),
        urlencoding::encode(state)
    )
}

/// Exchanges an authorization code for an access token.
///
/// # Arguments
///
/// * `client` - The reqwest HTTP client
/// * `config` - The GitHub OAuth configuration
/// * `code` - The authorization code from the callback
///
/// # Returns
///
/// A Result containing the access token string, or a GithubError
///
/// # Errors
///
/// Returns `GithubError::RequestFailed` if the HTTP request fails
/// Returns `GithubError::InvalidResponse` if the response cannot be parsed
/// Returns `GithubError::ApiError` if GitHub returns an error response
pub async fn exchange_code(
    client: &reqwest::Client,
    config: &GitHubOAuthConfig,
    code: &str,
) -> Result<String, GithubError> {
    #[derive(Serialize)]
    struct TokenRequest<'a> {
        client_id: &'a str,
        client_secret: &'a str,
        code: &'a str,
        redirect_uri: &'a str,
    }

    #[derive(Deserialize)]
    struct TokenResponseWithError {
        access_token: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    let response = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&TokenRequest {
            client_id: &config.client_id,
            client_secret: &config.client_secret,
            code,
            redirect_uri: &config.redirect_uri,
        })
        .send()
        .await?;

    let token_response: TokenResponseWithError = response.json().await?;

    if let Some(error) = token_response.error {
        let description = token_response
            .error_description
            .unwrap_or_else(|| error.clone());
        return Err(GithubError::ApiError(description));
    }

    token_response
        .access_token
        .ok_or(GithubError::InvalidResponse)
}

/// Fetches the authenticated user's information from GitHub.
///
/// # Arguments
///
/// * `client` - The reqwest HTTP client
/// * `access_token` - The access token obtained from `exchange_code`
///
/// # Returns
///
/// A Result containing the GitHubUser, or a GithubError
///
/// # Errors
///
/// Returns `GithubError::RequestFailed` if the HTTP request fails
/// Returns `GithubError::InvalidResponse` if the response cannot be parsed
/// Returns `GithubError::ApiError` if GitHub returns an error response
pub async fn get_user(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<GitHubUser, GithubError> {
    let response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", "spoq-web-apis")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(GithubError::ApiError(format!(
            "GitHub API returned {}: {}",
            status, body
        )));
    }

    let user: GitHubUser = response.json().await.map_err(|_| GithubError::InvalidResponse)?;
    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_authorize_url() {
        let config = GitHubOAuthConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_secret".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
        };

        let url = get_authorize_url(&config, "test_state_123");

        assert!(url.starts_with("https://github.com/login/oauth/authorize"));
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains("scope=user:email")); // scope is in the literal string, not URL encoded
        assert!(url.contains("state=test_state_123"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
    }

    #[test]
    fn test_get_authorize_url_special_characters() {
        let config = GitHubOAuthConfig {
            client_id: "client&id=test".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://example.com/callback?foo=bar".to_string(),
        };

        let url = get_authorize_url(&config, "state with spaces");

        // Special characters should be URL encoded
        assert!(url.contains("client_id=client%26id%3Dtest"));
        assert!(url.contains("state=state%20with%20spaces"));
    }

    #[test]
    fn test_github_user_serialization() {
        let user = GitHubUser {
            id: 12345,
            login: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            avatar_url: Some("https://avatars.githubusercontent.com/u/12345".to_string()),
        };

        let json = serde_json::to_string(&user).expect("Failed to serialize");
        assert!(json.contains("\"id\":12345"));
        assert!(json.contains("\"login\":\"testuser\""));
        assert!(json.contains("\"email\":\"test@example.com\""));
    }

    #[test]
    fn test_github_user_deserialization() {
        let json = r#"{
            "id": 12345,
            "login": "testuser",
            "email": "test@example.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/12345"
        }"#;

        let user: GitHubUser = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(user.id, 12345);
        assert_eq!(user.login, "testuser");
        assert_eq!(user.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_github_user_deserialization_null_fields() {
        let json = r#"{
            "id": 12345,
            "login": "testuser",
            "email": null,
            "avatar_url": null
        }"#;

        let user: GitHubUser = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(user.id, 12345);
        assert_eq!(user.login, "testuser");
        assert!(user.email.is_none());
        assert!(user.avatar_url.is_none());
    }

    #[test]
    fn test_github_error_display() {
        let request_error = GithubError::InvalidResponse;
        assert_eq!(format!("{}", request_error), "Invalid response from GitHub");

        let api_error = GithubError::ApiError("Bad credentials".to_string());
        assert_eq!(format!("{}", api_error), "GitHub API error: Bad credentials");
    }

    #[test]
    fn test_github_oauth_config_clone() {
        let config = GitHubOAuthConfig {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
        };

        let cloned = config.clone();
        assert_eq!(cloned.client_id, config.client_id);
        assert_eq!(cloned.client_secret, config.client_secret);
        assert_eq!(cloned.redirect_uri, config.redirect_uri);
    }
}
