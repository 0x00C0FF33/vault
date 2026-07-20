//! Search Operations
//!
//! Fast search and filtering of credentials.

use crate::db::{self, Credential, CredentialType};

use super::VaultResult;

pub fn get_all(conn: &rusqlite::Connection) -> VaultResult<Vec<Credential>> {
    db::get_all_credentials(conn).map_err(Into::into)
}

#[allow(dead_code)]
pub fn search_credentials(conn: &rusqlite::Connection, query: &str) -> VaultResult<Vec<Credential>> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return get_all(conn);
    }
    db::search_credentials(conn, trimmed).map_err(Into::into)
}

pub fn filter_by_tags(conn: &rusqlite::Connection, tags: &[String]) -> VaultResult<Vec<Credential>> {
    db::get_credentials_by_tag(conn, tags).map_err(Into::into)
}

/// Narrows an already-fetched set in place so a type filter composes with the
/// tag filter instead of issuing a second query that would discard it.
pub fn retain_type(credentials: &mut Vec<Credential>, cred_type: CredentialType) {
    credentials.retain(|c| c.credential_type == cred_type);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_string, MasterKey};
    use crate::db::Database;

    fn test_key() -> MasterKey {
        MasterKey::from_bytes([0x42u8; 32])
    }

    fn create_test_credential(name: &str, ctype: CredentialType, tags: Vec<&str>) -> Credential {
        let key = test_key();
        let blob = encrypt_string(key.as_ref(), "secret").unwrap();
        let mut cred = Credential::new(name.to_string(), ctype, blob);
        cred.tags = tags.into_iter().map(ToString::to_string).collect();
        cred
    }

    fn setup_test_data(conn: &rusqlite::Connection) {
        let creds = vec![
            ("AWS Prod", CredentialType::ApiKey, vec!["cloud", "prod"]),
            ("AWS Staging", CredentialType::ApiKey, vec!["cloud", "staging"]),
            ("GitHub Token", CredentialType::ApiKey, vec!["dev"]),
            ("Gmail", CredentialType::Password, vec!["personal"]),
        ];

        for (name, ctype, tags) in creds {
            let cred = create_test_credential(name, ctype, tags);
            db::create_credential(conn, &cred).unwrap();
        }
    }

    #[test]
    fn test_search() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let results = search_credentials(db.conn(), "AWS").unwrap();
        assert_eq!(results.len(), 2);

        let results = search_credentials(db.conn(), "GitHub").unwrap();
        assert_eq!(results.len(), 1);

        let results = search_credentials(db.conn(), "").unwrap();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_filter_by_type() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let mut results = get_all(db.conn()).unwrap();
        retain_type(&mut results, CredentialType::ApiKey);
        assert_eq!(results.len(), 3);

        let mut results = get_all(db.conn()).unwrap();
        retain_type(&mut results, CredentialType::Password);
        assert_eq!(results.len(), 1);
    }

    /// The type filter narrows an existing set rather than re-querying, so it
    /// composes with the tag filter instead of replacing it.
    #[test]
    fn retain_type_narrows_a_tag_filtered_set() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let mut results = filter_by_tags(db.conn(), &["cloud".to_string()]).unwrap();
        retain_type(&mut results, CredentialType::ApiKey);
        assert_eq!(results.len(), 2);
    }

    /// The only Password credential carries no `cloud` tag, so a re-querying
    /// implementation would surface it here and a composing one cannot.
    #[test]
    fn retain_type_cannot_reintroduce_rows_the_tag_filter_excluded() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let mut results = filter_by_tags(db.conn(), &["cloud".to_string()]).unwrap();
        retain_type(&mut results, CredentialType::Password);
        assert!(results.is_empty());
    }

    #[test]
    fn retain_type_on_an_absent_type_empties_the_set() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let mut results = get_all(db.conn()).unwrap();
        retain_type(&mut results, CredentialType::Certificate);
        assert!(results.is_empty());
    }

    #[test]
    fn test_filter_by_tags() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let results = filter_by_tags(db.conn(), &["cloud".to_string()]).unwrap();
        assert_eq!(results.len(), 2);
    }
}
