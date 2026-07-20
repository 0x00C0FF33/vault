//! Database Module
//!
//! `SQLite` database layer with FTS5 full-text search.

pub mod connection;
pub mod models;
pub mod queries;
pub mod schema;

use thiserror::Error;

/// Database errors
#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    /// The database was written by a schema this build does not read.
    #[error("Unsupported schema: {0}")]
    UnsupportedVersion(String),
}

pub type DbResult<T> = Result<T, DbError>;

// Re-exports
pub use connection::{Database, DatabaseConfig};
pub use models::{AuditAction, AuditLog, Credential, CredentialType};
pub use queries::*;
