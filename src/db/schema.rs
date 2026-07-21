//! Database Schema
//!
//! `SQLite` schema and the conversions between its versions.

use rusqlite::Connection;

use super::{DbError, DbResult};

/// Table structure this build reads and writes.
///
/// A database carrying any other version is refused rather than adapted;
/// conversion between structures is added when a structure change is, and
/// removed once no database needs it.
pub const SCHEMA_VERSION: i32 = 4;

/// Last version that carried the FTS5 index. See [`convert_v3_to_v4`].
const SCHEMA_VERSION_WITH_FTS: i32 = 3;

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

    convert_v3_to_v4(conn)?;
    require_current_version(conn)
}

/// Drop the FTS5 index a v3 database still carries.
///
/// `credentials_fts` and its three triggers were maintained on every insert,
/// update and delete, and no query read them — search is a substring match
/// over the already-fetched list. v4 removes them.
///
/// Temporary, and the only conversion in the codebase. Once the databases in
/// use have been opened by this build it goes, along with
/// `SCHEMA_VERSION_WITH_FTS`, leaving `require_current_version` to reject a v3
/// database outright.
fn convert_v3_to_v4(conn: &Connection) -> DbResult<()> {
    if get_schema_version(conn) != SCHEMA_VERSION_WITH_FTS {
        return Ok(());
    }

    // One transaction, so a failure part-way leaves a v3 database intact for
    // the next attempt rather than a half-dropped index stamped v4.
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        r"
        DROP TRIGGER IF EXISTS credentials_ai;
        DROP TRIGGER IF EXISTS credentials_ad;
        DROP TRIGGER IF EXISTS credentials_au;
        DROP TABLE IF EXISTS credentials_fts;
        ",
    )?;
    tx.execute(
        "UPDATE metadata SET value = ?1 WHERE key = 'schema_version'",
        [SCHEMA_VERSION.to_string()],
    )?;
    tx.commit()?;

    Ok(())
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

    /// A fresh database must not be born with the index the conversion
    /// removes.
    #[test]
    fn new_databases_carry_no_fts_index() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        assert!(fts_objects(&conn).is_empty());
    }

    /// The conversion has to be exercised against a database that actually
    /// carries the index. Testing it against a fresh one would pass just as
    /// well if the conversion did nothing at all.
    #[test]
    fn opening_a_v3_database_removes_the_fts_index() {
        let conn = Connection::open_in_memory().unwrap();
        create_v3_schema(&conn);
        assert!(
            !fts_objects(&conn).is_empty(),
            "the v3 fixture must carry the index the conversion removes"
        );

        init_schema(&conn).unwrap();

        assert_eq!(fts_objects(&conn), Vec::<String>::new());
        assert_eq!(get_schema_version(&conn), SCHEMA_VERSION);
    }

    /// Converting must not disturb the rows the index was built over.
    #[test]
    fn converting_a_v3_database_preserves_credentials() {
        let conn = Connection::open_in_memory().unwrap();
        create_v3_schema(&conn);
        insert_test_credential(&conn);

        init_schema(&conn).unwrap();

        let name: String = conn
            .query_row("SELECT name FROM credentials WHERE id = 'test-1'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(name, "GitHub Token");
    }

    /// Writes must still work once the triggers that referenced the dropped
    /// table are gone — a trigger left behind would fail on insert.
    #[test]
    fn a_converted_database_still_accepts_writes() {
        let conn = Connection::open_in_memory().unwrap();
        create_v3_schema(&conn);
        init_schema(&conn).unwrap();

        insert_test_credential(&conn);

        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    /// The v3 schema: the current one plus the FTS5 index and the three
    /// triggers that maintained it. Reproduced here because the code that
    /// wrote it no longer exists.
    fn create_v3_schema(conn: &Connection) {
        init_schema(conn).unwrap();
        conn.execute_batch(
            r"
            CREATE VIRTUAL TABLE credentials_fts USING fts5(
                name,
                username,
                url,
                tags,
                content='credentials',
                content_rowid='rowid'
            );

            CREATE TRIGGER credentials_ai AFTER INSERT ON credentials BEGIN
                INSERT INTO credentials_fts(rowid, name, username, url, tags)
                VALUES (new.rowid, new.name, new.username, new.url, new.tags);
            END;

            CREATE TRIGGER credentials_ad AFTER DELETE ON credentials BEGIN
                INSERT INTO credentials_fts(credentials_fts, rowid, name, username, url, tags)
                VALUES ('delete', old.rowid, old.name, old.username, old.url, old.tags);
            END;

            CREATE TRIGGER credentials_au AFTER UPDATE ON credentials BEGIN
                INSERT INTO credentials_fts(credentials_fts, rowid, name, username, url, tags)
                VALUES ('delete', old.rowid, old.name, old.username, old.url, old.tags);
                INSERT INTO credentials_fts(rowid, name, username, url, tags)
                VALUES (new.rowid, new.name, new.username, new.url, new.tags);
            END;
            ",
        )
        .unwrap();
        conn.execute(
            "UPDATE metadata SET value = ?1 WHERE key = 'schema_version'",
            [SCHEMA_VERSION_WITH_FTS.to_string()],
        )
        .unwrap();
    }

    /// Every schema object the FTS index owns, including the shadow tables
    /// `fts5` creates alongside it.
    fn fts_objects(conn: &Connection) -> Vec<String> {
        conn.prepare(
            r"SELECT name FROM sqlite_master
            WHERE name LIKE 'credentials_fts%'
               OR name IN ('credentials_ai', 'credentials_ad', 'credentials_au')
            ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    fn insert_test_credential(conn: &Connection) {
        conn.execute(
            r"INSERT INTO credentials (id, name, credential_type, encrypted_secret, created_at, updated_at)
            VALUES ('test-1', 'GitHub Token', 'api_key', 'encrypted', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
    }
}


