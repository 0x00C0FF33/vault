//! Database Queries
//!
//! Parameterized queries for CRUD operations on credentials.

use chrono::{DateTime, Local};
use rusqlite::{params, Connection, Row};

use super::{
    models::{AuditAction, AuditLog, Credential, CredentialType},
    DbError, DbResult,
};

// ============================================================================
// Credential Queries
// ============================================================================

/// Create a new credential
pub fn create_credential(conn: &Connection, credential: &Credential) -> DbResult<()> {
    let tags_json = serde_json::to_string(&credential.tags).unwrap_or_else(|_| "[]".to_string());

    conn.execute(
        r"
        INSERT INTO credentials (id, name, credential_type, username, encrypted_secret, encrypted_notes, encrypted_totp_secret, url, tags, created_at, updated_at, accessed_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ",
        params![
            credential.id,
            credential.name,
            credential.credential_type.as_str(),
            credential.username,
            credential.encrypted_secret,
            credential.encrypted_notes,
            credential.encrypted_totp_secret,
            credential.url,
            tags_json,
            credential.created_at.to_rfc3339(),
            credential.updated_at.to_rfc3339(),
            credential.accessed_at.map(|dt| dt.to_rfc3339()),
        ],
    )?;

    Ok(())
}

/// Get a credential by ID
pub fn get_credential(conn: &Connection, id: &str) -> DbResult<Credential> {
    conn.query_row(
        r"
        SELECT id, name, credential_type, username, encrypted_secret, encrypted_notes, encrypted_totp_secret, url, tags, created_at, updated_at, accessed_at
        FROM credentials
        WHERE id = ?1
        ",
        [id],
        row_to_credential,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(format!("Credential: {id}")),
        _ => e.into(),
    })
}

/// Get all credentials
pub fn get_all_credentials(conn: &Connection) -> DbResult<Vec<Credential>> {
    let mut stmt = conn.prepare(
        r"
        SELECT id, name, credential_type, username, encrypted_secret, encrypted_notes, encrypted_totp_secret, url, tags, created_at, updated_at, accessed_at
        FROM credentials
        ORDER BY name
        ",
    )?;

    let credentials = stmt
        .query_map([], row_to_credential)?
        .filter_map(Result::ok)
        .collect();

    Ok(credentials)
}

/// Get credentials by tags (AND logic - must have all tags)
pub fn get_credentials_by_tag(conn: &Connection, tags: &[String]) -> DbResult<Vec<Credential>> {
    if tags.is_empty() {
        return get_all_credentials(conn);
    }

    // Build query with multiple LIKE conditions (AND logic)
    let conditions: Vec<String> = tags
        .iter()
        .enumerate()
        .map(|(i, _)| format!("tags LIKE ?{}", i + 1))
        .collect();
    
    let query = format!(
        r"
        SELECT id, name, credential_type, username, encrypted_secret, encrypted_notes, encrypted_totp_secret, url, tags, created_at, updated_at, accessed_at
        FROM credentials
        WHERE {}
        ORDER BY name
        ",
        conditions.join(" AND ")
    );

    let mut stmt = conn.prepare(&query)?;
    
    let patterns: Vec<String> = tags.iter().map(|t| format!("%\"{t}\"%")).collect();
    let params: Vec<&dyn rusqlite::ToSql> = patterns.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
    
    let credentials = stmt
        .query_map(params.as_slice(), row_to_credential)?
        .filter_map(Result::ok)
        .collect();

    Ok(credentials)
}

/// Search credentials using FTS5
pub fn search_credentials(conn: &Connection, query: &str) -> DbResult<Vec<Credential>> {
    // Escape special FTS5 characters
    let escaped_query = query
        .replace('"', "\"\"")
        .replace(['*', ':'], "");

    if escaped_query.trim().is_empty() {
        return get_all_credentials(conn);
    }

    // Use prefix matching for better UX
    let fts_query = format!("\"{escaped_query}\"*");

    let mut stmt = conn.prepare(
        r"
        SELECT c.id, c.name, c.credential_type, c.username, c.encrypted_secret, c.encrypted_notes, c.encrypted_totp_secret, c.url, c.tags, c.created_at, c.updated_at, c.accessed_at
        FROM credentials c
        INNER JOIN credentials_fts fts ON c.rowid = fts.rowid
        WHERE credentials_fts MATCH ?1
        ORDER BY rank
        ",
    )?;

    let credentials = stmt
        .query_map([fts_query], row_to_credential)?
        .filter_map(Result::ok)
        .collect();

    Ok(credentials)
}

/// Update a credential
pub fn update_credential(conn: &Connection, credential: &Credential) -> DbResult<()> {
    let tags_json = serde_json::to_string(&credential.tags).unwrap_or_else(|_| "[]".to_string());

    let rows = conn.execute(
        r"
        UPDATE credentials
        SET name = ?2, credential_type = ?3, username = ?4, encrypted_secret = ?5, encrypted_notes = ?6, encrypted_totp_secret = ?7, url = ?8, tags = ?9, updated_at = ?10
        WHERE id = ?1
        ",
        params![
            credential.id,
            credential.name,
            credential.credential_type.as_str(),
            credential.username,
            credential.encrypted_secret,
            credential.encrypted_notes,
            credential.encrypted_totp_secret,
            credential.url,
            tags_json,
            Local::now().to_rfc3339(),
        ],
    )?;

    if rows == 0 {
        return Err(DbError::NotFound(format!("Credential: {}", credential.id)));
    }

    Ok(())
}

/// Update credential access time
pub fn touch_credential(conn: &Connection, id: &str) -> DbResult<()> {
    conn.execute(
        "UPDATE credentials SET accessed_at = ?2 WHERE id = ?1",
        params![id, Local::now().to_rfc3339()],
    )?;
    Ok(())
}

/// Delete a credential
pub fn delete_credential(conn: &Connection, id: &str) -> DbResult<()> {
    let rows = conn.execute("DELETE FROM credentials WHERE id = ?1", [id])?;

    if rows == 0 {
        return Err(DbError::NotFound(format!("Credential: {id}")));
    }

    Ok(())
}

fn row_to_credential(row: &Row) -> rusqlite::Result<Credential> {
    let tags_json: String = row.get(8)?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();

    let accessed_at: Option<String> = row.get(11)?;

    Ok(Credential {
        id: row.get(0)?,
        name: row.get(1)?,
        credential_type: CredentialType::from_str(&row.get::<_, String>(2)?),
        username: row.get(3)?,
        encrypted_secret: row.get(4)?,
        encrypted_notes: row.get(5)?,
        encrypted_totp_secret: row.get(6)?,
        url: row.get(7)?,
        tags,
        created_at: parse_datetime(&row.get::<_, String>(9)?),
        updated_at: parse_datetime(&row.get::<_, String>(10)?),
        accessed_at: accessed_at.as_deref().map(parse_datetime),
    })
}

// ============================================================================
// Audit Log Queries
// ============================================================================

/// Create an audit log entry
pub fn create_audit_log(conn: &Connection, log: &AuditLog) -> DbResult<i64> {
    conn.execute(
        r"
        INSERT INTO audit_log (timestamp, action, credential_id, credential_name, username, details, hmac)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ",
        params![
            log.timestamp.to_rfc3339(),
            log.action.as_str(),
            log.credential_id,
            log.credential_name,
            log.username,
            log.details,
            log.hmac,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Get recent audit logs
pub fn get_recent_audit_logs(conn: &Connection, limit: usize) -> DbResult<Vec<AuditLog>> {
    let mut stmt = conn.prepare(
        r"
        SELECT id, timestamp, action, credential_id, credential_name, username, details, hmac
        FROM audit_log
        ORDER BY timestamp DESC
        LIMIT ?1
        ",
    )?;

    let logs = stmt
        .query_map([limit], row_to_audit_log)?
        .filter_map(Result::ok)
        .collect();

    Ok(logs)
}

/// Get audit logs for a credential
pub fn get_credential_audit_logs(conn: &Connection, credential_id: &str) -> DbResult<Vec<AuditLog>> {
    let mut stmt = conn.prepare(
        r"
        SELECT id, timestamp, action, credential_id, credential_name, username, details, hmac
        FROM audit_log
        WHERE credential_id = ?1
        ORDER BY timestamp DESC
        ",
    )?;

    let logs = stmt
        .query_map([credential_id], row_to_audit_log)?
        .filter_map(Result::ok)
        .collect();

    Ok(logs)
}

fn row_to_audit_log(row: &Row) -> rusqlite::Result<AuditLog> {
    Ok(AuditLog {
        id: row.get(0)?,
        timestamp: parse_datetime(&row.get::<_, String>(1)?),
        action: AuditAction::from_str(&row.get::<_, String>(2)?),
        credential_id: row.get(3)?,
        credential_name: row.get(4)?,
        username: row.get(5)?,
        details: row.get(6)?,
        hmac: row.get(7)?,
    })
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_datetime(s: &str) -> DateTime<Local> {
    DateTime::parse_from_rfc3339(s).map_or_else(|_| Local::now(), |dt| dt.with_timezone(&Local))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn test_credential_crud() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut cred = Credential::new(
            "GitHub Token".to_string(),
            CredentialType::ApiKey,
            "encrypted_secret".to_string(),
        );
        cred.username = Some("user".to_string());
        cred.tags = vec!["dev".to_string(), "api".to_string()];

        create_credential(conn, &cred).unwrap();

        let fetched = get_credential(conn, &cred.id).unwrap();
        assert_eq!(fetched.name, "GitHub Token");
        assert_eq!(fetched.tags.len(), 2);

        delete_credential(conn, &cred.id).unwrap();
        assert!(get_credential(conn, &cred.id).is_err());
    }

    #[test]
    fn test_fts_search() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let cred1 = Credential::new(
            "AWS Production".to_string(),
            CredentialType::ApiKey,
            "enc".to_string(),
        );
        let cred2 = Credential::new(
            "AWS Staging".to_string(),
            CredentialType::ApiKey,
            "enc".to_string(),
        );
        let cred3 = Credential::new(
            "GitHub Token".to_string(),
            CredentialType::ApiKey,
            "enc".to_string(),
        );

        create_credential(conn, &cred1).unwrap();
        create_credential(conn, &cred2).unwrap();
        create_credential(conn, &cred3).unwrap();

        let results = search_credentials(conn, "AWS").unwrap();
        assert_eq!(results.len(), 2);

        let results = search_credentials(conn, "GitHub").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_audit_log() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let log = AuditLog::new(
            AuditAction::Create,
            Some("cred-1".to_string()),
            Some("user_foo".to_string()),
            Some("bar123".to_string()),
            Some("Created credential".to_string()),
            "hmac_value".to_string(),
        );

        let id = create_audit_log(conn, &log).unwrap();
        assert!(id > 0);

        let recent = get_recent_audit_logs(conn, 10).unwrap();
        assert!(!recent.is_empty());
    }
}
