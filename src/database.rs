use std::{str::FromStr, time::Duration};

use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use thiserror::Error;

use crate::config::SecretString;

pub const DATABASE_TIMEOUT: Duration = Duration::from_secs(3);
pub const REQUIRED_SCHEMA_VERSION: i64 = 17;
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database connection unavailable")]
    Connection,
    #[error("runtime database role has administrative or schema creation privileges")]
    RuntimeRole,
    #[error("database migration failed")]
    Migration,
    #[error("database migration deadline exceeded")]
    MigrationTimeout,
    #[error("identity setup unavailable or configured binding differs")]
    Identity,
}

async fn connect(url: &SecretString, max_connections: u32) -> Result<PgPool, DatabaseError> {
    let options = PgConnectOptions::from_str(url.expose())
        .map_err(|_| DatabaseError::Connection)?
        .disable_statement_logging();
    let result = tokio::time::timeout(
        DATABASE_TIMEOUT,
        PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(DATABASE_TIMEOUT)
            .connect_with(options),
    )
    .await
    .map_err(|_| DatabaseError::Connection)?
    .map_err(|_| DatabaseError::Connection);
    if result.is_ok() {
        tracing::debug!(
            module = "database",
            scope = "database",
            event.name = "database.connection.opened",
            max_connections,
            outcome = "ok"
        );
    }
    result
}

pub async fn connect_runtime(url: &SecretString) -> Result<PgPool, DatabaseError> {
    let pool = connect(url, 8).await?;
    let privileged = tokio::time::timeout(DATABASE_TIMEOUT, sqlx::query_scalar::<_, bool>(
        "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR has_schema_privilege(current_user, 'public', 'CREATE') FROM pg_roles WHERE rolname = current_user"
    ).fetch_one(&pool)).await.map_err(|_| DatabaseError::Connection)?.map_err(|_| DatabaseError::Connection)?;
    if privileged {
        return Err(DatabaseError::RuntimeRole);
    }
    Ok(pool)
}

/// Explicit operator action. This credential is never passed to the HTTP server.
pub async fn migrate(url: &SecretString) -> Result<(), DatabaseError> {
    let started = std::time::Instant::now();
    tracing::info!(
        module = "database",
        scope = "database",
        event.name = "database.migration.started",
        outcome = "started"
    );
    let pool = connect(url, 1).await?;
    let result = tokio::time::timeout(MIGRATION_TIMEOUT, sqlx::migrate!().run(&pool))
        .await
        .map_err(|_| DatabaseError::MigrationTimeout)
        .and_then(|result| result.map_err(|_| DatabaseError::Migration));
    // Closing the pool also closes a cancelled migration's connection/transaction.
    pool.close().await;
    if result.is_ok() {
        tracing::info!(
            module = "database",
            scope = "database",
            event.name = "database.migration.completed",
            migration.version = REQUIRED_SCHEMA_VERSION,
            duration_ms = started.elapsed().as_secs_f64() * 1000.0,
            outcome = "ok"
        );
    }
    result
}
