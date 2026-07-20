//! Database Connection Management
//!
//! Handles `SQLite` database connections and configuration.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use super::{schema::init_schema, DbResult};

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Path to the database file
    pub path: PathBuf,
    /// Enable WAL mode for better concurrency
    pub wal_mode: bool,
    /// Enable foreign keys
    pub foreign_keys: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            wal_mode: true,
            foreign_keys: true,
        }
    }
}

impl DatabaseConfig {
    /// Create config for in-memory database (testing)
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::from(":memory:"),
            wal_mode: false,
            foreign_keys: true,
        }
    }

    /// Create config for a specific path
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }
}

/// Get default database path (~/.vault/vault.db)
fn default_db_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".vault")
        .join("vault.db")
}

/// Database wrapper with connection management
pub struct Database {
    conn: Connection,
    config: DatabaseConfig,
}

impl Database {
    /// Open or create a database with the given config
    pub fn open(config: DatabaseConfig) -> DbResult<Self> {
        ensure_parent_dir(&config)?;
        let conn = open_connection(&config)?;
        configure_connection(&conn, &config)?;
        init_schema(&conn)?;
        Ok(Self { conn, config })
    }

    /// Open in-memory database for testing
    #[cfg(test)]
    pub fn open_in_memory() -> DbResult<Self> {
        Self::open(DatabaseConfig::in_memory())
    }

    /// Get reference to connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Get mutable reference to connection
    #[allow(dead_code)]
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Get database path
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.config.path
    }

    /// Check if database exists at the configured path
    #[allow(dead_code)]
    pub fn exists(&self) -> bool {
        if self.config.path.to_str() == Some(":memory:") {
            return true;
        }
        self.config.path.exists()
    }

    /// Vacuum the database to reclaim space
    #[allow(dead_code)]
    pub fn vacuum(&self) -> DbResult<()> {
        self.conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// Get database size in bytes
    #[allow(dead_code)]
    pub fn size(&self) -> std::io::Result<u64> {
        if self.config.path.to_str() == Some(":memory:") {
            return Ok(0);
        }
        Ok(std::fs::metadata(&self.config.path)?.len())
    }

    /// Execute a function within a transaction
    #[allow(dead_code)]
    pub fn transaction<T, F>(&mut self, f: F) -> DbResult<T>
    where
        F: FnOnce(&Connection) -> DbResult<T>,
    {
        let tx = self.conn.transaction()?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}

fn ensure_parent_dir(config: &DatabaseConfig) -> DbResult<()> {
    if config.path.to_str() == Some(":memory:") {
        return Ok(());
    }
    let Some(parent) = config.path.parent() else { return Ok(()) };
    if parent.exists() {
        return Ok(());
    }
    create_dir_or_error(parent)
}

fn create_dir_or_error(path: &Path) -> DbResult<()> {
    std::fs::create_dir_all(path).map_err(make_dir_error)?;
    Ok(())
}

// Takes the error by value so it can be passed point-free to `map_err`.
#[allow(clippy::needless_pass_by_value)]
fn make_dir_error(e: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(1),
        Some(format!("Failed to create directory: {e}")),
    )
}

fn open_connection(config: &DatabaseConfig) -> DbResult<Connection> {
    if config.path.to_str() == Some(":memory:") {
        return Ok(Connection::open_in_memory()?);
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    Ok(Connection::open_with_flags(&config.path, flags)?)
}

fn configure_connection(conn: &Connection, config: &DatabaseConfig) -> DbResult<()> {
    if config.foreign_keys {
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    }
    if config.wal_mode && config.path.to_str() != Some(":memory:") {
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    }
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.exists());
    }

    #[test]
    fn test_transaction() {
        let mut db = Database::open_in_memory().unwrap();
        let result = db.transaction(insert_test_credential);
        assert_eq!(result.unwrap(), 42);
        assert_eq!(count_test_credentials(&db), 1);
    }

    fn insert_test_credential(conn: &Connection) -> DbResult<i32> {
        conn.execute(
            "INSERT INTO credentials (id, name, credential_type, encrypted_secret, created_at, updated_at) 
            VALUES ('test', 'Test', 'password', 'encrypted', datetime('now'), datetime('now'))",
            [],
        )?;
        Ok(42)
    }

    fn count_test_credentials(db: &Database) -> i32 {
        db.conn()
            .query_row("SELECT COUNT(*) FROM credentials WHERE id = 'test'", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn test_foreign_keys_enabled() {
        let db = Database::open_in_memory().unwrap();
        let enabled: i32 = db.conn().query_row("PRAGMA foreign_keys", [], |row| row.get(0)).unwrap();
        assert_eq!(enabled, 1);
    }
}
