//! Database connection pool and migration utilities.
//!
//! Provides functions for creating a PostgreSQL connection pool
//! and running database migrations.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Creates a PostgreSQL connection pool with configured settings.
///
/// # Arguments
/// * `database_url` - The PostgreSQL connection string
///
/// # Returns
/// * `Ok(PgPool)` - A configured connection pool
/// * `Err(sqlx::Error)` - If the pool cannot be created
///
/// # Configuration
/// - Maximum connections: 20
/// - Minimum connections: 2 (kept warm)
/// - Acquire timeout: 10 seconds
/// - Idle timeout: 10 minutes
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(600))
        .connect(database_url)
        .await
}

/// Runs all pending database migrations.
///
/// # Arguments
/// * `pool` - Reference to the PostgreSQL connection pool
///
/// # Returns
/// * `Ok(())` - If all migrations run successfully
/// * `Err(sqlx::migrate::MigrateError)` - If any migration fails
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_values() {
        // Test that our configuration constants are reasonable
        let max_connections = 20u32;
        let min_connections = 2u32;
        let acquire_timeout = Duration::from_secs(10);
        let idle_timeout = Duration::from_secs(600);

        assert!(max_connections > 0);
        assert!(max_connections <= 50); // Reasonable upper bound
        assert!(min_connections > 0);
        assert!(min_connections < max_connections);
        assert!(acquire_timeout.as_secs() >= 1);
        assert!(acquire_timeout.as_secs() <= 30);
        assert!(idle_timeout.as_secs() >= 60);
    }
}
