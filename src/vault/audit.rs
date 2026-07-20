//! Audit Trail
//!
//! HMAC-signed audit logging for tamper detection.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::DerivedKey;
use crate::db::{self, AuditAction, AuditLog};

use super::VaultResult;

type HmacSha256 = Hmac<Sha256>;

/// Create an audit log entry with HMAC signature
pub fn log_action(
    conn: &rusqlite::Connection,
    audit_key: &DerivedKey,
    action: AuditAction,
    credential_id: Option<&str>,
    credential_name: Option<&str>,
    username: Option<&str>,
    details: Option<&str>,
) -> VaultResult<i64> {
    // HMAC signs all fields for tamper detection
    let message = format!(
        "{}:{}:{}:{}:{}",
        action.as_str(),
        credential_id.unwrap_or(""),
        credential_name.unwrap_or(""),
        username.unwrap_or(""),
        details.unwrap_or(""),
    );

    let hmac = compute_hmac(audit_key.as_bytes(), &message);

    let log = AuditLog::new(
        action,
        credential_id.map(ToString::to_string),
        credential_name.map(ToString::to_string),
        username.map(ToString::to_string),
        details.map(ToString::to_string),
        hmac,
    );

    let id = db::create_audit_log(conn, &log)?;
    Ok(id)
}

/// Verify an audit log entry's HMAC
pub fn verify_log(audit_key: &DerivedKey, log: &AuditLog) -> bool {
    // Must match the format used in log_action
    let message = format!(
        "{}:{}:{}:{}:{}",
        log.action.as_str(),
        log.credential_id.as_deref().unwrap_or(""),
        log.credential_name.as_deref().unwrap_or(""),
        log.username.as_deref().unwrap_or(""),
        log.details.as_deref().unwrap_or(""),
    );

    let expected_hmac = compute_hmac(audit_key.as_bytes(), &message);
    expected_hmac == log.hmac
}

/// Get recent audit logs
pub fn get_recent_logs(conn: &rusqlite::Connection, limit: usize) -> VaultResult<Vec<AuditLog>> {
    Ok(db::get_recent_audit_logs(conn, limit)?)
}

/// Get audit logs for a specific credential
#[allow(dead_code)]
pub fn get_credential_logs(conn: &rusqlite::Connection, credential_id: &str) -> VaultResult<Vec<AuditLog>> {
    Ok(db::get_credential_audit_logs(conn, credential_id)?)
}

/// Verify all audit logs in the database
pub fn verify_all_logs(conn: &rusqlite::Connection, audit_key: &DerivedKey) -> VaultResult<Vec<(AuditLog, bool)>> {
    let logs = db::get_recent_audit_logs(conn, 10000)?;
    let results: Vec<_> = logs
        .into_iter()
        .map(|log| {
            let valid = verify_log(audit_key, &log);
            (log, valid)
        })
        .collect();
    Ok(results)
}

fn compute_hmac(key: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoResult, MasterKey};
    use crate::crypto::key_hierarchy::KeyHierarchy;
    use crate::db::Database;

    fn test_audit_key() -> CryptoResult<DerivedKey> {
        let master = MasterKey::from_bytes([0x42u8; 32]);
        let hierarchy = KeyHierarchy::new(master)?;
        hierarchy.derive_audit_key()
    }

    #[test]
    fn test_log_action() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;

        let id = log_action(
            db.conn(),
            &key,
            AuditAction::Create,
            Some("cred-123"),
            Some("GitHub Token"),
            Some("user@example.com"),
            Some("Created new credential"),
        )
        .unwrap();

        assert!(id > 0);

        let logs = get_recent_logs(db.conn(), 10).unwrap();
        assert!(!logs.is_empty());
        assert_eq!(logs[0].credential_name.as_deref(), Some("GitHub Token"));
        assert_eq!(logs[0].username.as_deref(), Some("user@example.com"));

        Ok(())
    }

    #[test]
    fn test_verify_log() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;

        log_action(
            db.conn(),
            &key,
            AuditAction::Read,
            Some("cred-456"),
            Some("AWS Key"),
            Some("admin"),
            None,
        )
        .unwrap();

        let logs = get_recent_logs(db.conn(), 1).unwrap();
        let log = &logs[0];

        assert!(verify_log(&key, log));

        Ok(())
    }

    #[test]
    fn test_tampered_log_fails_verification() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;

        log_action(
            db.conn(),
            &key,
            AuditAction::Copy,
            Some("cred-789"),
            Some("Secret Key"),
            Some("user"),
            Some("Original details"),
        )
        .unwrap();

        let logs = get_recent_logs(db.conn(), 1).unwrap();
        let mut tampered_log = logs[0].clone();
        tampered_log.details = Some("Tampered details".to_string());

        assert!(!verify_log(&key, &tampered_log));

        Ok(())
    }

    #[test]
    fn test_tampered_name_fails_verification() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;

        log_action(
            db.conn(),
            &key,
            AuditAction::Update,
            Some("cred-abc"),
            Some("Original Name"),
            Some("user"),
            None,
        )
        .unwrap();

        let logs = get_recent_logs(db.conn(), 1).unwrap();
        let mut tampered_log = logs[0].clone();
        tampered_log.credential_name = Some("Tampered Name".to_string());

        assert!(!verify_log(&key, &tampered_log));

        Ok(())
    }

    #[test]
    fn test_wrong_key_fails_verification() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key1 = test_audit_key()?;
        
        let master2 = MasterKey::from_bytes([0x43u8; 32]);
        let hierarchy2 = KeyHierarchy::new(master2).unwrap();
        let key2 = hierarchy2.derive_audit_key()?;

        log_action(
            db.conn(),
            &key1,
            AuditAction::Delete,
            Some("cred"),
            Some("Test"),
            None,
            None,
        ).unwrap();

        let logs = get_recent_logs(db.conn(), 1).unwrap();
        assert!(!verify_log(&key2, &logs[0]));

        Ok(())
    }

    #[test]
    fn test_vault_actions_without_credentials() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;

        // Test unlock action (no credential)
        log_action(
            db.conn(),
            &key,
            AuditAction::Unlock,
            None,
            None,
            None,
            Some("Vault initialized"),
        ).unwrap();

        // Test lock action (no credential)
        log_action(
            db.conn(),
            &key,
            AuditAction::Lock,
            None,
            None,
            None,
            None,
        ).unwrap();

        let logs = get_recent_logs(db.conn(), 2).unwrap();
        
        // Both should verify correctly
        assert!(verify_log(&key, &logs[0])); // Lock (most recent)
        assert!(verify_log(&key, &logs[1])); // Unlock

        Ok(())
    }
}
