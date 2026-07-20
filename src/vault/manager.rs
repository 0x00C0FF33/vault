//! Vault Manager
//!
//! Core vault state, including storage, key management, and lock/unlock flow.
//!
//! Uses a wrapped DEK (Data Encryption Key) model so password changes do not
//! require re-encrypting stored data.
//!
//! Key material on disk lives in the `metadata` table. A vault written by the
//! current scheme carries `kdf_version = 2` plus the salt, cost parameters and
//! verifier described in [`crate::crypto::kdf`]. A vault predating that scheme
//! has a `password_hash` row instead, and is migrated on its next unlock.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::crypto::kdf::{
    create_key_material, verify_and_derive_master_key, verify_legacy_master_key, StoredKeyMaterial,
    SALT_LEN,
};
use crate::crypto::{DataEncryptionKey, KdfParams, KeyHierarchy, MasterKey};
use crate::db::{Database, DatabaseConfig};

use super::{VaultError, VaultResult};

/// Marks the key-derivation scheme a vault was written with. Version 1 is
/// implicit: those vaults have `password_hash` and no `kdf_version` row.
const KDF_VERSION: &str = "2";

const META_KDF_VERSION: &str = "kdf_version";
const META_KDF_SALT: &str = "kdf_salt";
const META_KDF_PARAMS: &str = "kdf_params";
const META_KDF_VERIFIER: &str = "kdf_verifier";
const META_WRAPPED_DEK: &str = "wrapped_dek";
const META_LEGACY_PASSWORD_HASH: &str = "password_hash";

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
    key_material: Option<StoredKeyMaterial>,
    last_activity: Instant,
}

impl Vault {
    pub fn new(config: VaultConfig) -> Self {
        Self {
            config,
            db: None,
            key_hierarchy: None,
            key_material: None,
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
        let (master_key, key_material) = Self::derive_new_key_material(password)?;
        let key_hierarchy = Self::create_key_hierarchy(master_key)?;
        let db = self.open_database()?;

        Self::store_key_material(db.conn(), &key_material)?;
        Self::store_wrapped_dek(db.conn(), key_hierarchy.wrapped_dek())?;

        self.db = Some(db);
        self.key_hierarchy = Some(key_hierarchy);
        self.key_material = Some(key_material);
        self.ensure_audit_chain()?;
        self.update_activity();

        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> VaultResult<()> {
        if !self.config.path.exists() {
            return Err(VaultError::NotFound);
        }

        let mut db = self.open_database()?;

        let (key_hierarchy, key_material) = match Self::load_key_material(db.conn())? {
            Some(stored) => Self::unlock_current(password, &stored, db.conn())?,
            None => Self::unlock_and_migrate_legacy(password, &mut db)?,
        };

        self.db = Some(db);
        self.key_hierarchy = Some(key_hierarchy);
        self.key_material = Some(key_material);
        self.ensure_audit_chain()?;
        self.update_activity();

        Ok(())
    }

    /// Bring the audit log up to the chained signing scheme.
    ///
    /// Runs on unlock because it needs the audit key, which is derived from
    /// the DEK. Entries that fail verification under the previous scheme are
    /// left alone and continue to report as tampered.
    fn ensure_audit_chain(&self) -> VaultResult<()> {
        let audit_key = self
            .keys()?
            .derive_audit_key()
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        super::audit::ensure_chained(self.db()?.conn(), &audit_key)?;
        Ok(())
    }

    pub fn lock(&mut self) {
        self.db = None;
        self.key_hierarchy = None;
        self.key_material = None;
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
        let material = self.key_material.as_ref().ok_or(VaultError::Locked)?;
        verify_and_derive_master_key(password.as_bytes(), material)
            .map_err(|_| VaultError::InvalidPassword)?;
        Ok(())
    }

    /// Re-key the vault under a new password.
    ///
    /// Derives fresh key material, re-wraps the existing DEK under the new
    /// master key, and writes both in one transaction — a partial write would
    /// leave a vault whose verifier and wrapped DEK disagree, which no password
    /// could open.
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> VaultResult<()> {
        self.verify_password(old_password)?;

        let (new_master_key, new_material) = Self::derive_new_key_material(new_password)?;
        let new_wrapped_dek = self.rewrap_dek(new_master_key)?;

        let db = self.db.as_mut().ok_or(VaultError::Locked)?;
        let tx = db.conn_mut().transaction()?;
        Self::store_key_material(&tx, &new_material)?;
        Self::store_wrapped_dek(&tx, &new_wrapped_dek)?;
        tx.commit()?;

        self.key_material = Some(new_material);
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

    fn derive_new_key_material(password: &str) -> VaultResult<(MasterKey, StoredKeyMaterial)> {
        let params = KdfParams::default();
        create_key_material(password.as_bytes(), &params)
            .map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    /// Open a vault written by the current scheme.
    fn unlock_current(
        password: &str,
        stored: &StoredKeyMaterial,
        conn: &Connection,
    ) -> VaultResult<(KeyHierarchy, StoredKeyMaterial)> {
        let master_key = verify_and_derive_master_key(password.as_bytes(), stored)
            .map_err(|_| VaultError::InvalidPassword)?;
        let wrapped_dek = Self::load_wrapped_dek(conn)?;
        let key_hierarchy = Self::reconstruct_key_hierarchy(master_key, wrapped_dek)?;

        Ok((key_hierarchy, stored.clone()))
    }

    /// Open a pre-v2 vault and rewrite its key material in the current scheme.
    ///
    /// The legacy layout stored the Argon2 output as `password_hash`, and that
    /// output *was* the master key — so anyone who could read the database
    /// could unwrap the DEK without knowing the password. Migration derives a
    /// master key that is never persisted, re-wraps the existing DEK under it,
    /// and drops the old row.
    ///
    /// The DEK itself is unchanged, so every stored credential stays readable;
    /// only the layer protecting it is replaced. The rewrite runs in one
    /// transaction, so an interrupted migration leaves the vault openable by
    /// the legacy path rather than half-converted.
    fn unlock_and_migrate_legacy(
        password: &str,
        db: &mut Database,
    ) -> VaultResult<(KeyHierarchy, StoredKeyMaterial)> {
        let legacy_hash = Self::load_legacy_password_hash(db.conn())?;
        let legacy_master = verify_legacy_master_key(password.as_bytes(), &legacy_hash)
            .map_err(|_| VaultError::InvalidPassword)?;

        let wrapped_dek = Self::load_wrapped_dek(db.conn())?;
        let mut key_hierarchy = Self::reconstruct_key_hierarchy(legacy_master, wrapped_dek)?;

        let (new_master_key, new_material) = Self::derive_new_key_material(password)?;
        let rewrapped_dek = key_hierarchy
            .change_master_key(new_master_key)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let tx = db.conn_mut().transaction()?;
        Self::store_key_material(&tx, &new_material)?;
        Self::store_wrapped_dek(&tx, &rewrapped_dek)?;
        tx.execute(
            "DELETE FROM metadata WHERE key = ?1",
            [META_LEGACY_PASSWORD_HASH],
        )?;
        tx.commit()?;

        Ok((key_hierarchy, new_material))
    }

    fn create_key_hierarchy(master_key: MasterKey) -> VaultResult<KeyHierarchy> {
        KeyHierarchy::new(master_key).map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    fn open_database(&self) -> VaultResult<Database> {
        let db_config = DatabaseConfig::with_path(&self.config.path);
        Database::open(db_config).map_err(Into::into)
    }

    fn reconstruct_key_hierarchy(
        master_key: MasterKey,
        wrapped_dek: String,
    ) -> VaultResult<KeyHierarchy> {
        KeyHierarchy::from_wrapped_dek(master_key, wrapped_dek)
            .map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    fn rewrap_dek(&mut self, new_master_key: MasterKey) -> VaultResult<String> {
        let key_hierarchy = self.key_hierarchy.as_mut().ok_or(VaultError::Locked)?;
        key_hierarchy
            .change_master_key(new_master_key)
            .map_err(|e| VaultError::CryptoError(e.to_string()))
    }

    /// Write the salt, cost parameters and verifier.
    ///
    /// None of these values can unwrap the DEK; see [`crate::crypto::kdf`].
    fn store_key_material(conn: &Connection, material: &StoredKeyMaterial) -> VaultResult<()> {
        let params_json = serde_json::to_string(&material.params)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        Self::store_metadata(conn, META_KDF_VERSION, KDF_VERSION)?;
        Self::store_metadata(conn, META_KDF_SALT, &hex::encode(material.salt))?;
        Self::store_metadata(conn, META_KDF_PARAMS, &params_json)?;
        Self::store_metadata(conn, META_KDF_VERIFIER, &hex::encode(material.verifier))?;

        Ok(())
    }

    /// Read the current scheme's key material.
    ///
    /// Returns `Ok(None)` when the vault predates the scheme, which routes
    /// unlock through migration. A vault that declares `kdf_version` but is
    /// missing any component is corrupt, and errors rather than silently
    /// falling back.
    fn load_key_material(conn: &Connection) -> VaultResult<Option<StoredKeyMaterial>> {
        if Self::get_metadata_value(conn, META_KDF_VERSION).is_none() {
            return Ok(None);
        }

        let salt_hex = Self::require_metadata(conn, META_KDF_SALT)?;
        let params_json = Self::require_metadata(conn, META_KDF_PARAMS)?;
        let verifier_hex = Self::require_metadata(conn, META_KDF_VERIFIER)?;

        let salt = decode_fixed::<SALT_LEN>(&salt_hex)?;
        let verifier = decode_fixed::<32>(&verifier_hex)?;
        let params: KdfParams = serde_json::from_str(&params_json)
            .map_err(|e| VaultError::CryptoError(format!("Invalid KDF params: {e}")))?;

        Ok(Some(StoredKeyMaterial {
            salt,
            params,
            verifier,
        }))
    }

    fn load_legacy_password_hash(conn: &Connection) -> VaultResult<String> {
        Self::require_metadata(conn, META_LEGACY_PASSWORD_HASH)
    }

    fn store_wrapped_dek(conn: &Connection, wrapped_dek: &str) -> VaultResult<()> {
        Self::store_metadata(conn, META_WRAPPED_DEK, wrapped_dek)
    }

    fn load_wrapped_dek(conn: &Connection) -> VaultResult<String> {
        Self::require_metadata(conn, META_WRAPPED_DEK)
    }

    fn store_metadata(conn: &Connection, key: &str, value: &str) -> VaultResult<()> {
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            [key, value],
        )?;
        Ok(())
    }

    fn require_metadata(conn: &Connection, key: &str) -> VaultResult<String> {
        Self::get_metadata_value(conn, key).ok_or(VaultError::NotFound)
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

/// Decode a hex metadata value into a fixed-size array, rejecting anything of
/// the wrong length rather than silently truncating.
fn decode_fixed<const N: usize>(value: &str) -> VaultResult<[u8; N]> {
    let bytes =
        hex::decode(value).map_err(|e| VaultError::CryptoError(format!("Invalid hex: {e}")))?;

    bytes.try_into().map_err(|_| {
        VaultError::CryptoError(format!("Expected {N} bytes of key material")) //
    })
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

    /// Build a vault in the pre-v2 on-disk layout: an Argon2 PHC string under
    /// `password_hash`, whose output doubles as the master key wrapping the
    /// DEK. Used to prove migration opens real legacy data.
    fn create_legacy_vault(config: &VaultConfig, password: &str) -> String {
        use crate::crypto::kdf::verify_legacy_master_key;
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{password_hash::rand_core::OsRng, Argon2};

        let salt = SaltString::generate(&mut OsRng);
        let phc = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // The legacy master key is the hash output itself.
        let master_key = verify_legacy_master_key(password.as_bytes(), &phc).unwrap();
        let hierarchy = KeyHierarchy::new(master_key).unwrap();

        let db = Database::open(DatabaseConfig::with_path(&config.path)).unwrap();
        Vault::store_metadata(db.conn(), META_LEGACY_PASSWORD_HASH, &phc).unwrap();
        Vault::store_wrapped_dek(db.conn(), hierarchy.wrapped_dek()).unwrap();

        hex::encode(hierarchy.dek().as_bytes())
    }

    fn read_metadata(config: &VaultConfig, key: &str) -> Option<String> {
        let db = Database::open(DatabaseConfig::with_path(&config.path)).unwrap();
        Vault::get_metadata_value(db.conn(), key)
    }

    #[test]
    fn test_stored_material_is_not_the_master_key() {
        let (_dir, config) = temp_vault();
        let _vault = create_initialized_vault(config.clone(), "test_password");

        // The pre-v2 flaw: the verifier on disk must not unwrap the DEK.
        let verifier_hex = read_metadata(&config, META_KDF_VERIFIER).unwrap();
        let wrapped_dek = read_metadata(&config, META_WRAPPED_DEK).unwrap();

        let forged = MasterKey::from_bytes(decode_fixed::<32>(&verifier_hex).unwrap());
        assert!(DataEncryptionKey::unwrap(&wrapped_dek, &forged).is_err());

        // And the legacy row must not be written at all.
        assert!(read_metadata(&config, META_LEGACY_PASSWORD_HASH).is_none());
    }

    #[test]
    fn test_legacy_vault_migrates_on_unlock() {
        let (_dir, config) = temp_vault();
        let original_dek = create_legacy_vault(&config, "legacy_password");

        assert!(read_metadata(&config, META_LEGACY_PASSWORD_HASH).is_some());
        assert!(read_metadata(&config, META_KDF_VERSION).is_none());

        let mut vault = Vault::new(config.clone());
        vault.unlock("legacy_password").unwrap();

        // The DEK survives, so credentials encrypted under it stay readable.
        assert_eq!(hex::encode(vault.dek().unwrap().as_bytes()), original_dek);

        // The vault is now on the current scheme and the old row is gone.
        assert_eq!(
            read_metadata(&config, META_KDF_VERSION).as_deref(),
            Some(KDF_VERSION)
        );
        assert!(read_metadata(&config, META_LEGACY_PASSWORD_HASH).is_none());

        // Re-unlocking goes through the current path and still works.
        vault.lock();
        vault.unlock("legacy_password").unwrap();
        assert_eq!(hex::encode(vault.dek().unwrap().as_bytes()), original_dek);
    }

    #[test]
    fn test_legacy_vault_rejects_wrong_password() {
        let (_dir, config) = temp_vault();
        create_legacy_vault(&config, "legacy_password");

        let mut vault = Vault::new(config.clone());
        assert!(vault.unlock("wrong_password").is_err());

        // A failed unlock must not migrate or destroy the legacy material.
        assert!(read_metadata(&config, META_LEGACY_PASSWORD_HASH).is_some());
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

