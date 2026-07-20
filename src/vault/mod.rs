//! Vault Module
//!
//! Secure credential storage with encryption and key management.

pub mod audit;
pub mod credential;
pub mod manager;
pub mod search;
pub mod export;

use thiserror::Error;

/// Vault errors
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Vault is locked")]
    Locked,

    #[error("Vault not found")]
    NotFound,

    #[error("Vault already exists")]
    AlreadyExists,

    #[error("Invalid password")]
    InvalidPassword,

    /// The vault predates a format this build still understands. Carries what
    /// was expected so the message can say which version is required.
    #[error("Unsupported vault format: {0}")]
    UnsupportedFormat(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] crate::db::DbError),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Operation failed: {0}")]
    OperationFailed(String),
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        Self::DatabaseError(crate::db::DbError::Sqlite(e))
    }
}

pub type VaultResult<T> = Result<T, VaultError>;

// Re-exports
pub use manager::{Vault, VaultConfig};
