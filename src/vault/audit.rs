//! Audit Trail
//!
//! Hash-chained, HMAC-signed audit log.
//!
//! Each entry is signed over its own fields *and* the HMAC of the entry before
//! it, so the log forms a chain:
//!
//! ```text
//! genesis ──▶ entry₁ ──▶ entry₂ ──▶ entry₃ ──▶ head
//!             hmac₁      hmac₂      hmac₃
//!
//! hmacᵢ = HMAC(audit_key, hmacᵢ₋₁ ‖ timestamp ‖ action ‖ … )
//! ```
//!
//! Removing or reordering an entry changes what the following entry chains
//! onto, so the following entry stops verifying. Deleting from the end breaks
//! nothing in the chain itself, which is why the head — the entry count and
//! the final HMAC — is signed separately and stored in metadata.
//!
//! Fields are length-prefixed before signing so that no combination of field
//! contents can produce the message of a different combination.
//!
//! The audit key is derived from the DEK, so an attacker who can write to the
//! database but does not know the password cannot forge or re-sign entries.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::crypto::DerivedKey;
use crate::db::{self, AuditAction, AuditLog};

use super::{VaultError, VaultResult};

type HmacSha256 = Hmac<Sha256>;

/// What the first entry chains onto.
const GENESIS: &str = "vault:audit:genesis";

/// Domain separator for the head signature, keeping it distinct from any
/// entry signature.
const HEAD_LABEL: &str = "vault:audit:head";

/// Metadata key holding the signed chain head.
const META_AUDIT_HEAD: &str = "audit_head";

/// Metadata key recording which signing scheme the log uses.
const META_AUDIT_VERSION: &str = "audit_version";

/// Current signing scheme. A log not carrying this version is not readable by
/// this build.
const AUDIT_VERSION: &str = "2";

/// Append an entry, chaining it onto the current head.
pub fn log_action(
    conn: &rusqlite::Connection,
    audit_key: &DerivedKey,
    action: AuditAction,
    credential_id: Option<&str>,
    credential_name: Option<&str>,
    username: Option<&str>,
    details: Option<&str>,
) -> VaultResult<i64> {
    let previous = db::get_last_audit_hmac(conn).unwrap_or_else(|| GENESIS.to_string());

    // The entry is built first so the timestamp it will be stored with is the
    // one that gets signed.
    let mut log = AuditLog::new(
        action,
        credential_id.map(ToString::to_string),
        credential_name.map(ToString::to_string),
        username.map(ToString::to_string),
        details.map(ToString::to_string),
        String::new(),
    );
    log.hmac = compute_hmac(audit_key.as_bytes(), &entry_message(&previous, &log));

    let id = db::create_audit_log(conn, &log)?;
    sign_head(conn, audit_key)?;

    Ok(id)
}

/// Verify one entry against the HMAC it should chain onto.
pub fn verify_log(audit_key: &DerivedKey, previous_hmac: &str, log: &AuditLog) -> bool {
    let expected = compute_hmac(audit_key.as_bytes(), &entry_message(previous_hmac, log));
    constant_time_eq(&expected, &log.hmac)
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

/// Walk the whole chain, reporting each entry's validity.
///
/// Each entry is checked against the *stored* HMAC of its predecessor rather
/// than the recomputed one. A modified entry therefore flags only itself,
/// which keeps attribution precise, while a removed entry still invalidates
/// the entry that followed it.
pub fn verify_all_logs(
    conn: &rusqlite::Connection,
    audit_key: &DerivedKey,
) -> VaultResult<Vec<(AuditLog, bool)>> {
    let logs = db::get_all_audit_logs_ascending(conn)?;

    let mut previous = GENESIS.to_string();
    let mut results = Vec::with_capacity(logs.len());

    for log in logs {
        let valid = verify_log(audit_key, &previous, &log);
        previous.clone_from(&log.hmac);
        results.push((log, valid));
    }

    Ok(results)
}

/// Check that the log has not been truncated.
///
/// The chain alone cannot detect entries removed from the end, because what
/// remains is still internally consistent. The head signature covers the entry
/// count and the final HMAC, and cannot be recomputed without the audit key.
pub fn verify_chain_head(
    conn: &rusqlite::Connection,
    audit_key: &DerivedKey,
) -> VaultResult<bool> {
    let Some(stored) = db::get_metadata(conn, META_AUDIT_HEAD) else {
        // No head recorded means the chain was never started, which
        // `require_current_version` rejects at unlock.
        return Ok(false);
    };

    Ok(constant_time_eq(&expected_head(conn, audit_key)?, &stored))
}

/// Start the chain on a freshly created vault.
///
/// Records the scheme version and signs the head over an empty log, so the
/// first append and the first verification both have something to chain onto.
pub fn begin_chain(conn: &rusqlite::Connection, audit_key: &DerivedKey) -> VaultResult<()> {
    sign_head(conn, audit_key)?;
    db::set_metadata(conn, META_AUDIT_VERSION, AUDIT_VERSION)?;
    Ok(())
}

/// Reject a log written under a scheme this build no longer reads.
///
/// Conversion from the unchained format was removed once no such log
/// remained; recovering one means checking out a build that still had it.
pub fn require_current_version(conn: &rusqlite::Connection) -> VaultResult<()> {
    match db::get_metadata(conn, META_AUDIT_VERSION) {
        Some(version) if version == AUDIT_VERSION => Ok(()),
        Some(version) => Err(VaultError::UnsupportedFormat(format!(
            "audit log declares audit_version {version}, this build reads {AUDIT_VERSION}"
        ))),
        None => Err(VaultError::UnsupportedFormat(format!(
            "audit log predates audit_version {AUDIT_VERSION} and can no longer be verified"
        ))),
    }
}

fn sign_head(conn: &rusqlite::Connection, audit_key: &DerivedKey) -> VaultResult<()> {
    let head = expected_head(conn, audit_key)?;
    db::set_metadata(conn, META_AUDIT_HEAD, &head)?;
    Ok(())
}

fn expected_head(conn: &rusqlite::Connection, audit_key: &DerivedKey) -> VaultResult<String> {
    let count = db::count_audit_logs(conn)?;
    let last = db::get_last_audit_hmac(conn).unwrap_or_else(|| GENESIS.to_string());

    let mut message = String::new();
    push_field(&mut message, HEAD_LABEL);
    push_field(&mut message, &count.to_string());
    push_field(&mut message, &last);

    Ok(compute_hmac(audit_key.as_bytes(), &message))
}

/// Build the signed message for an entry.
///
/// The timestamp is included so it cannot be rewritten, and the predecessor's
/// HMAC is included to form the chain.
fn entry_message(previous_hmac: &str, log: &AuditLog) -> String {
    let mut message = String::new();

    push_field(&mut message, previous_hmac);
    push_field(&mut message, &log.timestamp.to_rfc3339());
    push_field(&mut message, log.action.as_str());
    push_field(&mut message, log.credential_id.as_deref().unwrap_or(""));
    push_field(&mut message, log.credential_name.as_deref().unwrap_or(""));
    push_field(&mut message, log.username.as_deref().unwrap_or(""));
    push_field(&mut message, log.details.as_deref().unwrap_or(""));

    message
}

/// Append a length-prefixed field, so field boundaries are unambiguous
/// regardless of what the values contain.
fn push_field(message: &mut String, value: &str) {
    message.push_str(&value.len().to_string());
    message.push(':');
    message.push_str(value);
}

fn compute_hmac(key: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
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

    /// Append `count` entries and return the connection-backed database.
    fn log_n(db: &Database, key: &DerivedKey, count: usize) {
        for i in 0..count {
            log_action(
                db.conn(),
                key,
                AuditAction::Read,
                Some(&format!("cred-{i}")),
                Some("Entry"),
                None,
                None,
            )
            .unwrap();
        }
    }

    fn validity(db: &Database, key: &DerivedKey) -> Vec<bool> {
        verify_all_logs(db.conn(), key)
            .unwrap()
            .into_iter()
            .map(|(_, valid)| valid)
            .collect()
    }

    #[test]
    fn test_chain_verifies_end_to_end() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;
        log_n(&db, &key, 5);

        assert_eq!(validity(&db, &key), vec![true; 5]);
        assert!(verify_chain_head(db.conn(), &key).unwrap());

        Ok(())
    }

    /// A deleted entry cannot be detected by checking entries in isolation —
    /// this is what the chain is for.
    #[test]
    fn test_deleted_entry_breaks_chain() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;
        log_n(&db, &key, 5);

        db.conn()
            .execute("DELETE FROM audit_log WHERE id = 3", [])
            .unwrap();

        // The entry that followed the removed one no longer chains onto it.
        let valid = validity(&db, &key);
        assert_eq!(valid, vec![true, true, false, true]);

        Ok(())
    }

    #[test]
    fn test_reordered_entries_break_chain() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;
        log_n(&db, &key, 3);

        // Swap the order two entries occupy in the chain.
        db.conn()
            .execute("UPDATE audit_log SET id = 99 WHERE id = 1", [])
            .unwrap();

        assert!(validity(&db, &key).contains(&false));

        Ok(())
    }

    /// The timestamp is inside the signature, so editing it invalidates the
    /// entry it belongs to.
    #[test]
    fn test_edited_timestamp_is_detected() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;
        log_n(&db, &key, 3);

        db.conn()
            .execute(
                "UPDATE audit_log SET timestamp = '2000-01-01T00:00:00+00:00' WHERE id = 2",
                [],
            )
            .unwrap();

        assert_eq!(validity(&db, &key), vec![true, false, true]);

        Ok(())
    }

    /// Cutting entries off the end leaves a self-consistent chain, so only the
    /// signed head reveals it.
    #[test]
    fn test_truncation_detected_by_head() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;
        log_n(&db, &key, 5);

        db.conn()
            .execute("DELETE FROM audit_log WHERE id > 3", [])
            .unwrap();

        // Every surviving entry still verifies ...
        assert_eq!(validity(&db, &key), vec![true; 3]);
        // ... but the head does not match what remains.
        assert!(!verify_chain_head(db.conn(), &key).unwrap());

        Ok(())
    }

    /// An attacker without the audit key cannot re-sign the head to cover
    /// their truncation.
    #[test]
    fn test_head_cannot_be_forged_without_key() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key()?;
        let other = {
            let master = MasterKey::from_bytes([0x11u8; 32]);
            KeyHierarchy::new(master)?.derive_audit_key()?
        };

        log_n(&db, &key, 4);
        db.conn()
            .execute("DELETE FROM audit_log WHERE id > 2", [])
            .unwrap();

        // Re-signing with the wrong key does not restore the head.
        sign_head(db.conn(), &other).unwrap();
        assert!(!verify_chain_head(db.conn(), &key).unwrap());

        Ok(())
    }

    /// A log without the current version marker is refused rather than read
    /// on a guess.
    #[test]
    fn test_unversioned_log_is_rejected() -> CryptoResult<()> {
        let db = Database::open_in_memory().unwrap();

        assert!(matches!(
            require_current_version(db.conn()),
            Err(VaultError::UnsupportedFormat(_))
        ));

        let key = test_audit_key()?;
        begin_chain(db.conn(), &key).unwrap();
        assert!(require_current_version(db.conn()).is_ok());

        Ok(())
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

        let results = verify_all_logs(db.conn(), &key).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].1);

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

        assert!(!verify_log(&key, GENESIS, &tampered_log));

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

        assert!(!verify_log(&key, GENESIS, &tampered_log));

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
        assert!(!verify_log(&key2, GENESIS, &logs[0]));

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

        let results = verify_all_logs(db.conn(), &key).unwrap();

        // Both should verify correctly, in chain order
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, valid)| *valid));

        Ok(())
    }
}
