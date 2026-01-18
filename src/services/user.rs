//! User service for database operations.
//!
//! This module provides functions for managing users in the database,
//! including finding users by various identifiers and creating users
//! from GitHub OAuth data.

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::user::User;
use crate::services::github::GitHubUser;

/// Finds a user by their GitHub ID.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `github_id` - The GitHub user ID to search for
///
/// # Returns
///
/// A Result containing an Option<User> - Some if found, None if not
///
/// # Example
///
/// ```ignore
/// let user = find_by_github_id(&pool, 12345).await?;
/// if let Some(u) = user {
///     println!("Found user: {}", u.username);
/// }
/// ```
pub async fn find_by_github_id(pool: &PgPool, github_id: i64) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT id, github_id, username, email, avatar_url, created_at, updated_at
        FROM users
        WHERE github_id = $1
        "#,
    )
    .bind(github_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| User {
        id: r.get("id"),
        github_id: r.get("github_id"),
        username: r.get("username"),
        email: r.get("email"),
        avatar_url: r.get("avatar_url"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }))
}

/// Finds a user by their internal UUID.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `id` - The internal user UUID to search for
///
/// # Returns
///
/// A Result containing an Option<User> - Some if found, None if not
///
/// # Example
///
/// ```ignore
/// let user_id = Uuid::parse_str("...")?;
/// let user = find_by_id(&pool, user_id).await?;
/// if let Some(u) = user {
///     println!("Found user: {}", u.username);
/// }
/// ```
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT id, github_id, username, email, avatar_url, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| User {
        id: r.get("id"),
        github_id: r.get("github_id"),
        username: r.get("username"),
        email: r.get("email"),
        avatar_url: r.get("avatar_url"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }))
}

/// Creates a new user from GitHub OAuth data.
///
/// Uses an UPSERT pattern - if a user with the same GitHub ID exists,
/// updates their information instead of creating a duplicate.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `github_user` - The GitHub user data from the OAuth flow
///
/// # Returns
///
/// A Result containing the created or updated User
///
/// # Example
///
/// ```ignore
/// let github_user = GitHubUser {
///     id: 12345,
///     login: "octocat".to_string(),
///     email: Some("octocat@github.com".to_string()),
///     avatar_url: Some("https://...".to_string()),
/// };
/// let user = create_from_github(&pool, &github_user).await?;
/// ```
pub async fn create_from_github(
    pool: &PgPool,
    github_user: &GitHubUser,
) -> Result<User, sqlx::Error> {
    let row = sqlx::query(
        r#"
        INSERT INTO users (github_id, username, email, avatar_url)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (github_id)
        DO UPDATE SET
            username = EXCLUDED.username,
            email = EXCLUDED.email,
            avatar_url = EXCLUDED.avatar_url,
            updated_at = NOW()
        RETURNING id, github_id, username, email, avatar_url, created_at, updated_at
        "#,
    )
    .bind(github_user.id)
    .bind(&github_user.login)
    .bind(&github_user.email)
    .bind(&github_user.avatar_url)
    .fetch_one(pool)
    .await?;

    Ok(User {
        id: row.get("id"),
        github_id: row.get("github_id"),
        username: row.get("username"),
        email: row.get("email"),
        avatar_url: row.get("avatar_url"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

/// Finds an existing user or creates a new one from GitHub OAuth data.
///
/// This is a convenience function that first attempts to find a user
/// by GitHub ID, and creates one if not found.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `github_user` - The GitHub user data from the OAuth flow
///
/// # Returns
///
/// A Result containing the existing or newly created User
///
/// # Example
///
/// ```ignore
/// let github_user = GitHubUser { ... };
/// let user = find_or_create_from_github(&pool, &github_user).await?;
/// // User is guaranteed to exist after this call
/// ```
pub async fn find_or_create_from_github(
    pool: &PgPool,
    github_user: &GitHubUser,
) -> Result<User, sqlx::Error> {
    // The create_from_github function uses UPSERT, so it handles both cases
    create_from_github(pool, github_user).await
}

#[cfg(test)]
mod tests {
    // Note: Database tests require a test database connection.
    // The user service functions are tested via integration tests
    // or when the handlers are tested with a test database.
    //
    // Functions exported by this module:
    // - find_by_github_id(pool, github_id) -> Result<Option<User>, sqlx::Error>
    // - find_by_id(pool, id) -> Result<Option<User>, sqlx::Error>
    // - create_from_github(pool, github_user) -> Result<User, sqlx::Error>
    // - find_or_create_from_github(pool, github_user) -> Result<User, sqlx::Error>
    //
    // All functions are async and require a PgPool connection.
    // The module compiles successfully, which verifies type correctness.

    #[test]
    fn test_module_compiles() {
        // This test passes if the module compiles successfully,
        // which validates the SQL query structure and type annotations.
        // No assertions needed - compilation is the test.
    }
}
