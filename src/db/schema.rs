//! Database Schema
//!
//! `SQLite` schema with FTS5 for full-text search.

use rusqlite::Connection;

use super::{DbError, DbResult};

/// Table structure this build reads and writes.
///
/// A database carrying any other version is refused rather than adapted;
/// conversion between structures is added when a structure change is, and
/// removed once no database needs it.
pub const SCHEMA_VERSION: i32 = 3;

/// Create the schema, or check that an existing one is readable.
pub fn init_schema(conn: &Connection) -> DbResult<()> {
    let has_schema: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='metadata'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !has_schema {
        return create_schema(conn);
    }

    require_current_version(conn)
}

/// Reject a database written by a different schema.
///
/// The version is checked rather than inferred, so a mismatch reports what it
/// found instead of failing later on a missing column.
fn require_current_version(conn: &Connection) -> DbResult<()> {
    let version = get_schema_version(conn);
    if version == SCHEMA_VERSION {
        return Ok(());
    }

    Err(DbError::UnsupportedVersion(format!(
        "database is schema_version {version}, this build reads {SCHEMA_VERSION}"
    )))
}

/// Create the full schema
fn create_schema(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        r"
        -- Metadata table for vault configuration
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- Credentials table
        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            username TEXT,
            encrypted_secret TEXT NOT NULL,
            encrypted_notes TEXT,
            encrypted_totp_secret TEXT,
            url TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            accessed_at TEXT
        );

        -- FTS5 virtual table for full-text search
        CREATE VIRTUAL TABLE IF NOT EXISTS credentials_fts USING fts5(
            name,
            username,
            url,
            tags,
            content='credentials',
            content_rowid='rowid'
        );

        -- Triggers to keep FTS index in sync
        CREATE TRIGGER IF NOT EXISTS credentials_ai AFTER INSERT ON credentials BEGIN
            INSERT INTO credentials_fts(rowid, name, username, url, tags)
            VALUES (new.rowid, new.name, new.username, new.url, new.tags);
        END;

        CREATE TRIGGER IF NOT EXISTS credentials_ad AFTER DELETE ON credentials BEGIN
            INSERT INTO credentials_fts(credentials_fts, rowid, name, username, url, tags)
            VALUES ('delete', old.rowid, old.name, old.username, old.url, old.tags);
        END;

        CREATE TRIGGER IF NOT EXISTS credentials_au AFTER UPDATE ON credentials BEGIN
            INSERT INTO credentials_fts(credentials_fts, rowid, name, username, url, tags)
            VALUES ('delete', old.rowid, old.name, old.username, old.url, old.tags);
            INSERT INTO credentials_fts(rowid, name, username, url, tags)
            VALUES (new.rowid, new.name, new.username, new.url, new.tags);
        END;

        -- Audit log table
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            credential_id TEXT,
            credential_name TEXT,
            username TEXT,
            details TEXT,
            hmac TEXT NOT NULL
        );

        -- Indexes for common queries
        CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
        CREATE INDEX IF NOT EXISTS idx_credentials_updated ON credentials(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
        ",
    )?;

    // Written from the constant rather than inlined above, so bumping
    // SCHEMA_VERSION cannot leave new databases stamped with an old number
    // that their own version check would then reject.
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?1)",
        [SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}

/// Get current schema version
pub fn get_schema_version(conn: &Connection) -> i32 {
    let version: String = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".to_string());

    version.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_schema() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();

        assert!(tables.contains(&"credentials".to_string()));
        assert!(tables.contains(&"audit_log".to_string()));
        assert!(tables.contains(&"metadata".to_string()));
    }

    #[test]
    fn test_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let version = get_schema_version(&conn);
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// A database from a different schema must say so, not fail later on a
    /// missing column.
    #[test]
    fn test_foreign_schema_version_is_rejected() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '99')",
            [],
        )
        .unwrap();

        assert!(matches!(
            init_schema(&conn),
            Err(DbError::UnsupportedVersion(_))
        ));
    }

    /// Re-opening an existing database must not be mistaken for a foreign one.
    #[test]
    fn test_reopening_current_schema_succeeds() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap();

        assert_eq!(get_schema_version(&conn), SCHEMA_VERSION);
    }

    #[test]
    fn test_fts_index() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        insert_test_fts_credential(&conn);
        assert!(fts_search_found(&conn, "GitHub"));
    }

    fn insert_test_fts_credential(conn: &Connection) {
        conn.execute(
            r"INSERT INTO credentials (id, name, credential_type, encrypted_secret, created_at, updated_at)
            VALUES ('test-1', 'GitHub Token', 'api_key', 'encrypted', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
    }

    fn fts_search_found(conn: &Connection, query: &str) -> bool {
        let sql = "SELECT COUNT(*) > 0 FROM credentials_fts WHERE credentials_fts MATCH ?1";
        conn.query_row(sql, [query], |row| row.get(0)).unwrap()
    }
}

