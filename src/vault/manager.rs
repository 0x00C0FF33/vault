//! Vault Manager
//!
//! Core vault state, including storage, key management, and lock/unlock flow.
//!
//! Uses a wrapped DEK (Data Encryption Key) model so password changes do not
//! require re-encrypting stored data.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::crypto::{
    derive_master_key, verify_master_key, DataEncryptionKey, KdfParams, KeyHierarchy, MasterKey,
};
use crate::db::{Database, DatabaseConfig};

use super::{VaultError, VaultResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Uninitialized,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub path: PathBuf,
}

impl Default for VaultConfig {
    fn default() -> Self {
        let path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vault")
            .join("vault.db");

        Self { path }
    }
}

impl VaultConfig {
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
        }
    }
}

pub struct Vault {
    config: VaultConfig,
    db: Option<Database>,
    key_hierarchy: Option<KeyHierarchy>,
    password_hash: Option<String>,
    last_activity: Instant,
}

impl Vault {
    pub fn new(config: VaultConfig) -> Self {
        Self {
            config,
            db: None,
            key_hierarchy: None,
            password_hash: None,
            last_activity: Instant::now(),
        }
    }

    pub fn state(&self) -> VaultState {
        if self.key_hierarchy.is_some() {
            return VaultState::Unlocked;
        }
        if self.config.path.exists() {
            return VaultState::Locked;
        }
        VaultState::Uninitialized
    }

    pub fn is_unlocked(&self) -> bool {
        self.state() == VaultState::Unlocked
    }

    pub fn initialize(&mut self, password: &str) -> VaultResult<()> {
        if self.config.path.exists() {
            return Err(VaultError::AlreadyExists);
        }

        self.create_parent_directory()?;
        let (master_key, password_hash) = Self::derive_new_master_key(password)?;
        let key_hierarchy = Self::create_key_hierarchy(master_key)?;
        let db = self.open_database()?;

        Self::store_password_hash(db.conn(), &password_hash)?;
        Self::store_wrapped_dek(db.conn(), key_hierarchy.wrapped_dek())?;

        self.db = Some(db);
        self.key_hierarchy = Some(key_hierarchy);
        self.password_hash = Some(password_hash);
        self.update_activity();

        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> VaultResult<()> {
        if !self.config.path.exists() {
            return Err(VaultError::NotFound);
        }

        let db = self.open_database()?;
        let stored_hash = Self::load_password_hash(db.conn())?;
        let master_key = Self::verify_password_and_get_key(password, &stored_hash)?;
        let wrapped_dek = Self::load_wrapped_dek(db.conn())?;
        let key_hierarchy = Self::reconstruct_key_hierarchy(master_key, wrapped_dek)?;

        self.db = Some(db);
        self.key_hierarchy = Some(key_hierarchy);
        self.password_hash = Some(stored_hash);
        self.update_activity();

        Ok(())
    }

    pub fn lock(&mut self) {
        self.db = None;
        self.key_hierarchy = None;
        self.password_hash = None;
    }

    pub fn time_since_activity(&self) -> Duration {
        self.last_activity.elapsed()
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn db(&self) -> VaultResult<&Database> {
        self.db.as_ref().ok_or(VaultError::Locked)
    }

    pub fn keys(&self) -> VaultResult<&KeyHierarchy> {
        self.key_hierarchy.as_ref().ok_or(VaultError::Locked)
    }

    pub fn dek(&self) -> VaultResult<&DataEncryptionKey> {
        Ok(self.keys()?.dek())
    }

    pub fn verify_password(&self, password: &str) -> VaultResult<()> {
        let hash = self.password_hash.as_ref().ok_or(VaultError::Locked)?;
        verify_master_key(password.as_bytes(), hash).map_err(|_| VaultError::InvalidPassword)?;
        Ok(())
    }

    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> VaultResult<()> {
        self.verify_current_password(old_password)?;
        let (new_master_key, new_hash) = Self::derive_new_master_key(new_password)?;
        let new_wrapped_dek = self.rewrap_dek(new_master_key)?;

        let db = self.db.as_ref().ok_or(VaultError::Locked)?;
        Self::store_password_hash(db.conn(), &new_hash)?;
        Self::store_wrapped_dek(db.conn(), &new_wrapped_dek)?;

        self.password_hash = Some(new_hash);
        self.update_activity();

        Ok(())
    }

    pub fn record_failed_unlock(&self) -> VaultResult<()> {
        if !self.config.path.exists() {
            return Ok(());
        }

        let db_config = DatabaseConfig::with_path(&self.config.path);
        let db = Database::open(db_config)?;

        Self::increment_failed_unlock_counter(db.conn())?;
        Self::update_failed_unlock_timestamp(db.conn())?;

        Ok(())
    }

    pub fn take_pending_failed_attempts(&self) -> VaultResult<Option<(u32, String)>> {
        let db = self.db.as_ref().ok_or(VaultError::Locked)?;

        let count = Self::get_metadata_value(db.conn(), "pending_failed_unlocks");
        let timestamp = Self::get_metadata_value(db.conn(), "last_failed_unlock_at");

        Self::clear_failed_attempt_metadata(db.conn())?;

        Ok(Self::parse_failed_attempts(count, timestamp))
    }
}

impl Vault {
    fn create_parent_directory(&self) -> VaultResult<()> {
        let Some(parent) = self.config.path.parent() else {
            return Ok(());
        };
        std::fs::create_dir_all(parent).map_err(|e| VaultError::IoError(e.to_string()))
    }

    fn derive_new_master_key(password: &str) -> VaultResult<(MasterKey, String)> {
        let params = KdfParams::default();
        derive_master_key(password.as_bytes(), &params)
            .map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    fn create_key_hierarchy(master_key: MasterKey) -> VaultResult<KeyHierarchy> {
        KeyHierarchy::new(master_key).map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    fn open_database(&self) -> VaultResult<Database> {
        let db_config = DatabaseConfig::with_path(&self.config.path);
        Database::open(db_config).map_err(Into::into)
    }

    fn verify_password_and_get_key(password: &str, stored_hash: &str) -> VaultResult<MasterKey> {
        verify_master_key(password.as_bytes(), stored_hash)
            .map_err(|_| VaultError::InvalidPassword)
    }

    fn reconstruct_key_hierarchy(
        master_key: MasterKey,
        wrapped_dek: String,
    ) -> VaultResult<KeyHierarchy> {
        KeyHierarchy::from_wrapped_dek(master_key, wrapped_dek)
            .map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    fn verify_current_password(&self, password: &str) -> VaultResult<()> {
        let hash = self.password_hash.as_ref().ok_or(VaultError::Locked)?;
        verify_master_key(password.as_bytes(), hash).map_err(|_| VaultError::InvalidPassword)?;
        Ok(())
    }

    fn rewrap_dek(&mut self, new_master_key: MasterKey) -> VaultResult<String> {
        let key_hierarchy = self.key_hierarchy.as_mut().ok_or(VaultError::Locked)?;
        key_hierarchy
            .change_master_key(new_master_key)
            .map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    fn store_password_hash(conn: &rusqlite::Connection, hash: &str) -> VaultResult<()> {
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('password_hash', ?1)",
            [hash],
        )?;
        Ok(())
    }

    fn load_password_hash(conn: &rusqlite::Connection) -> VaultResult<String> {
        conn.query_row(
            "SELECT value FROM metadata WHERE key = 'password_hash'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::NotFound)
    }

    fn store_wrapped_dek(conn: &rusqlite::Connection, wrapped_dek: &str) -> VaultResult<()> {
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('wrapped_dek', ?1)",
            [wrapped_dek],
        )?;
        Ok(())
    }

    fn load_wrapped_dek(conn: &rusqlite::Connection) -> VaultResult<String> {
        conn.query_row(
            "SELECT value FROM metadata WHERE key = 'wrapped_dek'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::NotFound)
    }

    fn increment_failed_unlock_counter(conn: &rusqlite::Connection) -> VaultResult<()> {
        conn.execute(
            r"
            INSERT INTO metadata (key, value) VALUES ('pending_failed_unlocks', '1')
            ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
            ",
            [],
        )?;
        Ok(())
    }

    fn update_failed_unlock_timestamp(conn: &rusqlite::Connection) -> VaultResult<()> {
        let now = chrono::Local::now().format("%d-%b-%Y %H:%M").to_string();
        conn.execute(
            r"
            INSERT INTO metadata (key, value) VALUES ('last_failed_unlock_at', ?1)
            ON CONFLICT(key) DO UPDATE SET value = ?1
            ",
            [&now],
        )?;
        Ok(())
    }

    fn get_metadata_value(conn: &rusqlite::Connection, key: &str) -> Option<String> {
        conn.query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .ok()
    }

    fn clear_failed_attempt_metadata(conn: &rusqlite::Connection) -> VaultResult<()> {
        conn.execute(
            "DELETE FROM metadata WHERE key IN ('pending_failed_unlocks', 'last_failed_unlock_at')",
            [],
        )?;
        Ok(())
    }

    fn parse_failed_attempts(
        count: Option<String>,
        timestamp: Option<String>,
    ) -> Option<(u32, String)> {
        let c = count?;
        let t = timestamp?;

        let n: u32 = c.parse().unwrap_or(0);
        if n == 0 {
            return None;
        }

        Some((n, t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_vault() -> (TempDir, VaultConfig) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test_vault.db");
        let config = VaultConfig::with_path(path);
        (dir, config)
    }

    fn create_initialized_vault(config: VaultConfig, password: &str) -> Vault {
        let mut vault = Vault::new(config);
        vault.initialize(password).unwrap();
        vault
    }

    #[test]
    fn test_vault_lifecycle() {
        let (_dir, config) = temp_vault();
        let mut vault = Vault::new(config);

        assert_eq!(vault.state(), VaultState::Uninitialized);

        vault.initialize("test_password").unwrap();
        assert_eq!(vault.state(), VaultState::Unlocked);
        assert!(vault.dek().is_ok());

        vault.lock();
        assert_eq!(vault.state(), VaultState::Locked);

        vault.unlock("test_password").unwrap();
        assert_eq!(vault.state(), VaultState::Unlocked);
    }

    #[test]
    fn test_wrong_password() {
        let (_dir, config) = temp_vault();
        let mut vault = create_initialized_vault(config, "correct_password");
        vault.lock();

        let result = vault.unlock("wrong_password");
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn test_change_password() {
        let (_dir, config) = temp_vault();
        let mut vault = create_initialized_vault(config, "old_password");

        let dek_before = *vault.dek().unwrap().as_bytes();

        vault.change_password("old_password", "new_password").unwrap();

        let dek_after = vault.dek().unwrap().as_bytes();
        assert_eq!(&dek_before, dek_after);

        vault.lock();
        assert!(vault.unlock("old_password").is_err());

        vault.unlock("new_password").unwrap();
        assert!(vault.is_unlocked());
        assert_eq!(&dek_before, vault.dek().unwrap().as_bytes());
    }

    #[test]
    fn test_credentials_accessible_after_password_change() {
        use crate::crypto::{decrypt_string, encrypt_string};

        let (_dir, config) = temp_vault();
        let mut vault = create_initialized_vault(config, "password1");

        let secret = "my_secret_data";
        let encrypted = encrypt_string(vault.dek().unwrap().as_ref(), secret).unwrap();

        vault.change_password("password1", "password2").unwrap();

        let decrypted = decrypt_string(vault.dek().unwrap().as_ref(), &encrypted).unwrap();
        assert_eq!(secret, decrypted);

        vault.lock();
        vault.unlock("password2").unwrap();

        let decrypted = decrypt_string(vault.dek().unwrap().as_ref(), &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }

    fn get_wrapped_dek(conn: &rusqlite::Connection) -> String {
        conn.query_row(
            "SELECT value FROM metadata WHERE key = 'wrapped_dek'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn test_wrapped_dek_stored() {
        let (_dir, config) = temp_vault();
        let vault = create_initialized_vault(config, "password");
        let wrapped_dek = get_wrapped_dek(vault.db().unwrap().conn());
        assert!(!wrapped_dek.is_empty());
    }
}
