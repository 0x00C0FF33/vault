//! Credential Operations
//!
//! Encrypted CRUD operations for credentials.
//!
//! Credentials are encrypted with a Data Encryption Key (DEK), not the
//! master key directly.

use chrono::{DateTime, Local};
use secrecy::SecretString;

use crate::crypto::{decrypt_string, encrypt_string, DataEncryptionKey};
use crate::db::{self, Credential, CredentialType};

use super::{VaultError, VaultResult};

#[derive(Clone)]
pub struct DecryptedCredential {
    pub id: String,
    pub name: String,
    pub credential_type: CredentialType,
    pub username: Option<String>,
    pub secret: Option<SecretString>,
    pub notes: Option<SecretString>,
    pub totp_secret: Option<SecretString>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Local>,
    pub updated_at: DateTime<Local>,
}

impl DecryptedCredential {
    pub fn from_credential(
        cred: &Credential,
        secret: Option<String>,
        notes: Option<String>,
        totp_secret: Option<String>,
    ) -> Self {
        Self {
            id: cred.id.clone(),
            name: cred.name.clone(),
            credential_type: cred.credential_type,
            username: cred.username.clone(),
            secret: secret.map(SecretString::from),
            notes: notes.map(SecretString::from),
            totp_secret: totp_secret.map(SecretString::from),
            url: cred.url.clone(),
            tags: cred.tags.clone(),
            created_at: cred.created_at,
            updated_at: cred.updated_at,
        }
    }
}

fn encrypt_secret(dek: &DataEncryptionKey, secret: &str) -> VaultResult<String> {
    encrypt_string(dek.as_ref(), secret).map_err(|e| VaultError::CryptoError(e.to_string()))
}

fn encrypt_notes(dek: &DataEncryptionKey, notes: Option<&str>) -> VaultResult<Option<String>> {
    let Some(n) = notes else {
        return Ok(None);
    };
    let encrypted = encrypt_string(dek.as_ref(), n)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    Ok(Some(encrypted))
}

fn decrypt_secret(dek: &DataEncryptionKey, encrypted: &str) -> VaultResult<String> {
    decrypt_string(dek.as_ref(), &encrypted.to_string()).map_err(|e| VaultError::CryptoError(e.to_string()))
}

fn decrypt_notes(dek: &DataEncryptionKey, encrypted: Option<&String>) -> VaultResult<Option<String>> {
    let Some(n) = encrypted else {
        return Ok(None);
    };
    let decrypted = decrypt_string(dek.as_ref(), n)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    Ok(Some(decrypted))
}

fn decrypt_totp_secret(dek: &DataEncryptionKey, encrypted: Option<&String>) -> VaultResult<Option<String>> {
    let Some(t) = encrypted else {
        return Ok(None);
    };
    let decrypted = decrypt_string(dek.as_ref(), t)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    Ok(Some(decrypted))
}

fn encrypt_totp_secret(dek: &DataEncryptionKey, totp: Option<&str>) -> VaultResult<Option<String>> {
    let Some(t) = totp else {
        return Ok(None);
    };
    if t.is_empty() {
        return Ok(None);
    }
    let encrypted = encrypt_string(dek.as_ref(), t)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    Ok(Some(encrypted))
}

fn encrypt_notes_for_update(dek: &DataEncryptionKey, notes: Option<&str>) -> VaultResult<Option<String>> {
    let Some(n) = notes else {
        return Ok(None);
    };
    if n.is_empty() {
        return Ok(None);
    }
    let encrypted = encrypt_string(dek.as_ref(), n)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    Ok(Some(encrypted))
}

#[allow(clippy::too_many_arguments)]
pub fn create_credential(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    name: String,
    credential_type: CredentialType,
    secret: &str,
    username: Option<String>,
    url: Option<String>,
    tags: Vec<String>,
    notes: Option<&str>,
    totp_secret: Option<&str>,
) -> VaultResult<Credential> {
    let encrypted_secret = encrypt_secret(dek, secret)?;
    let encrypted_notes = encrypt_notes(dek, notes)?;
    let encrypted_totp = encrypt_totp_secret(dek, totp_secret)?;

    let mut cred = Credential::new(name, credential_type, encrypted_secret);
    cred.username = username;
    cred.url = url;
    cred.tags = tags;
    cred.encrypted_notes = encrypted_notes;
    cred.encrypted_totp_secret = encrypted_totp;

    db::create_credential(conn, &cred)?;
    Ok(cred)
}

pub fn decrypt_credential(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    cred: &Credential,
    log_access: bool,
) -> VaultResult<DecryptedCredential> {
    let secret = decrypt_secret(dek, &cred.encrypted_secret)?;
    let notes = decrypt_notes(dek, cred.encrypted_notes.as_ref())?;
    let totp_secret = decrypt_totp_secret(dek, cred.encrypted_totp_secret.as_ref())?;

    if log_access {
        db::touch_credential(conn, &cred.id)?;
    }

    Ok(DecryptedCredential::from_credential(cred, Some(secret), notes, totp_secret))
}

pub fn update_credential(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    cred: &mut Credential,
    new_secret: Option<&str>,
    new_notes: Option<&str>,
    new_totp_secret: Option<&str>,
) -> VaultResult<()> {
    if let Some(secret) = new_secret {
        cred.encrypted_secret = encrypt_secret(dek, secret)?;
    }

    cred.encrypted_notes = encrypt_notes_for_update(dek, new_notes)?;
    cred.encrypted_totp_secret = encrypt_totp_secret(dek, new_totp_secret)?;
    db::update_credential(conn, cred)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use crate::crypto::DataEncryptionKey;
    use crate::db::Database;

    fn test_dek() -> DataEncryptionKey {
        DataEncryptionKey::generate()
    }

    fn setup_test_db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn create_test_credential(
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        name: &str,
        secret: &str,
    ) -> Credential {
        create_credential(
            conn,
            dek,
            name.to_string(),
            CredentialType::Password,
            secret,
            None,
            None,
            vec![],
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_create_and_decrypt() {
        let db = setup_test_db();
        let conn = db.conn();
        let dek = test_dek();

        let cred = create_credential(
            conn,
            &dek,
            "Test Credential".to_string(),
            CredentialType::Password,
            "my_secret_password",
            Some("testuser".to_string()),
            Some("https://example.com".to_string()),
            vec!["test".to_string()],
            Some("These are notes"),
            None,
        )
        .unwrap();

        let decrypted = decrypt_credential(conn, &dek, &cred, false).unwrap();

        assert_eq!(decrypted.name, "Test Credential");
        assert_eq!(
            decrypted.secret.as_ref().map(secrecy::ExposeSecret::expose_secret),
            Some("my_secret_password")
        );
        assert_eq!(
            decrypted.notes.as_ref().map(secrecy::ExposeSecret::expose_secret),
            Some("These are notes")
        );
        assert_eq!(decrypted.username, Some("testuser".to_string()));
    }

    #[test]
    fn test_update_credential() {
        let db = setup_test_db();
        let conn = db.conn();
        let dek = test_dek();

        let mut cred = create_test_credential(conn, &dek, "Test", "old_secret");
        update_credential(conn, &dek, &mut cred, Some("new_secret"), Some("new notes"), None).unwrap();

        let fetched = db::get_credential(conn, &cred.id).unwrap();
        let decrypted = decrypt_credential(conn, &dek, &fetched, false).unwrap();

        assert_eq!(
            decrypted.secret.as_ref().map(secrecy::ExposeSecret::expose_secret),
            Some("new_secret")
        );
        assert_eq!(
            decrypted.notes.as_ref().map(secrecy::ExposeSecret::expose_secret),
            Some("new notes")
        );
    }

    #[test]
    fn test_delete_credential() {
        let db = setup_test_db();
        let conn = db.conn();
        let dek = test_dek();

        let cred = create_test_credential(conn, &dek, "Test", "secret");
        db::delete_credential(conn, &cred.id).unwrap();
        assert!(db::get_credential(conn, &cred.id).is_err());
    }

    #[test]
    fn test_dek_change_simulation() {
        let db = setup_test_db();
        let conn = db.conn();
        let dek = DataEncryptionKey::generate();

        let cred = create_test_credential(conn, &dek, "Test", "secret_password");
        
        // Use same DEK to decrypt
        let decrypted = decrypt_credential(conn, &dek, &cred, false).unwrap();

        assert_eq!(
            decrypted.secret.as_ref().map(|s| s.expose_secret().to_string()),
            Some("secret_password".to_string())
        );
    }
}
