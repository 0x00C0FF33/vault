//! Key Derivation Function
//!
//! Argon2id stretches the password into a root secret, which HKDF then splits
//! into two independent values:
//!
//! ```text
//! password + salt --Argon2id--> root  (never stored)
//!                                 |
//!                                 +-- HKDF("vault:verifier")   --> stored on disk
//!                                 +-- HKDF("vault:master-key") --> wraps the DEK
//! ```
//!
//! Only the verifier reaches the database. HKDF is one-way and the two labels
//! are distinct, so the stored value proves a password was correct while
//! unlocking nothing: recovering the master key from the database alone is not
//! possible, and an attacker holding the file must still brute-force the
//! password through Argon2.

use argon2::{
    password_hash::rand_core::OsRng,
    Algorithm, Argon2, Params, Version,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{CryptoError, CryptoResult, LockedBuffer};

/// Length of the per-vault Argon2 salt.
pub const SALT_LEN: usize = 16;

/// Length of the Argon2 output and of every key derived from it.
const KEY_LEN: usize = 32;

/// HKDF salt. Distinct from the Argon2 salt; scopes derivation to this scheme.
const HKDF_SALT: &[u8] = b"vault-kdf-v2";

/// HKDF labels. These MUST stay distinct — sharing a label would make the
/// stored verifier equal to the master key, which is the flaw this design
/// exists to remove.
const INFO_MASTER_KEY: &[u8] = b"vault:master-key";
const INFO_VERIFIER: &[u8] = b"vault:verifier";

/// Master key (256 bits)
///
/// Wraps the DEK and is never written to disk. Memory-locked to prevent
/// swapping.
#[derive(Clone)]
pub struct MasterKey {
    key: LockedBuffer<KEY_LEN>,
}

impl MasterKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            key: LockedBuffer::new(bytes),
        }
    }

    /// Get key bytes (used in tests; kept for type-safe 32-byte access)
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

impl AsRef<[u8]> for MasterKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

// Debug impl that doesn't leak key material
impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey").finish_non_exhaustive()
    }
}

/// Password-derived material that is safe to persist.
///
/// Everything here can be read by an attacker with the database file without
/// giving them the ability to unwrap the DEK.
#[derive(Debug, Clone)]
pub struct StoredKeyMaterial {
    /// Per-vault Argon2 salt.
    pub salt: [u8; SALT_LEN],
    /// Argon2 cost parameters this vault was created with.
    pub params: KdfParams,
    /// HKDF("vault:verifier") — proves a password without unlocking anything.
    pub verifier: [u8; KEY_LEN],
}

/// KDF parameters for Argon2id
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB (default: 19456 = 19 MiB)
    pub memory_cost: u32,
    /// Time cost (iterations) (default: 2)
    pub time_cost: u32,
    /// Parallelism (default: 1)
    pub parallelism: u32,
    /// Output length in bytes (default: 32)
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost: 19456, // 19 MiB - OWASP recommended minimum
            time_cost: 2,
            parallelism: 1,
            output_len: KEY_LEN,
        }
    }
}

impl KdfParams {
    /// Create params for testing (fast but insecure)
    #[cfg(test)]
    pub fn testing() -> Self {
        Self {
            memory_cost: 1024, // 1 MiB
            time_cost: 1,
            parallelism: 1,
            output_len: KEY_LEN,
        }
    }
}

/// Derive a fresh master key and the material to persist alongside it.
///
/// Generates a new random salt. Used when initialising a vault and when
/// changing the password.
pub fn create_key_material(
    password: &[u8],
    params: &KdfParams,
) -> CryptoResult<(MasterKey, StoredKeyMaterial)> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    derive_from_salt(password, salt, params)
}

/// Check a password against stored material and recover the master key.
///
/// The verifier comparison is constant-time. Returns
/// [`CryptoError::InvalidPassword`] when the password is wrong.
pub fn verify_and_derive_master_key(
    password: &[u8],
    stored: &StoredKeyMaterial,
) -> CryptoResult<MasterKey> {
    let (master_key, derived) = derive_from_salt(password, stored.salt, &stored.params)?;

    if derived.verifier.ct_eq(&stored.verifier).into() {
        return Ok(master_key);
    }
    Err(CryptoError::InvalidPassword)
}

/// Run Argon2id then split the result into a master key and a verifier.
fn derive_from_salt(
    password: &[u8],
    salt: [u8; SALT_LEN],
    params: &KdfParams,
) -> CryptoResult<(MasterKey, StoredKeyMaterial)> {
    let root = derive_root(password, &salt, params)?;

    let mut master_bytes = expand(root.as_ref(), INFO_MASTER_KEY)?;
    let verifier = expand(root.as_ref(), INFO_VERIFIER)?;

    let master_key = MasterKey::from_bytes(master_bytes);
    master_bytes.zeroize();

    let material = StoredKeyMaterial {
        salt,
        params: params.clone(),
        verifier,
    };

    Ok((master_key, material))
}

/// Stretch the password into the root secret. The root is memory-locked and
/// dropped as soon as both subkeys are derived.
fn derive_root(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> CryptoResult<LockedBuffer<KEY_LEN>> {
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut root = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut root)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let locked = LockedBuffer::new(root);
    root.zeroize();

    Ok(locked)
}

/// HKDF-SHA256 expansion of the root secret under a domain-separating label.
fn expand(root: &[u8], info: &[u8]) -> CryptoResult<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), root);

    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_correct_password() {
        let params = KdfParams::testing();
        let (key, material) = create_key_material(b"test_password_123", &params).unwrap();

        let recovered = verify_and_derive_master_key(b"test_password_123", &material).unwrap();
        assert_eq!(key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_wrong_password_fails() {
        let params = KdfParams::testing();
        let (_, material) = create_key_material(b"correct_password", &params).unwrap();

        let result = verify_and_derive_master_key(b"wrong_password", &material);
        assert!(matches!(result, Err(CryptoError::InvalidPassword)));
    }

    #[test]
    fn test_different_salts_different_keys() {
        let params = KdfParams::testing();
        let (key1, m1) = create_key_material(b"same_password", &params).unwrap();
        let (key2, m2) = create_key_material(b"same_password", &params).unwrap();

        assert_ne!(m1.salt, m2.salt);
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_deterministic_for_same_salt() {
        let params = KdfParams::testing();
        let (key1, material) = create_key_material(b"test_password", &params).unwrap();

        let key2 = verify_and_derive_master_key(b"test_password", &material).unwrap();
        let key3 = verify_and_derive_master_key(b"test_password", &material).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key2.as_bytes(), key3.as_bytes());
    }

    /// The whole point of the scheme: what is written to disk must not be the
    /// key that unwraps the DEK.
    #[test]
    fn test_verifier_is_not_the_master_key() {
        let params = KdfParams::testing();
        let (master_key, material) = create_key_material(b"test_password", &params).unwrap();

        assert_ne!(&material.verifier, master_key.as_bytes());
    }

    /// Regression test for the pre-v2 flaw, where the persisted value *was* the
    /// master key and could unwrap the DEK on its own.
    #[test]
    fn test_stored_material_cannot_unwrap_dek() {
        use crate::crypto::dek::DataEncryptionKey;

        let params = KdfParams::testing();
        let (master_key, material) = create_key_material(b"test_password", &params).unwrap();

        let dek = DataEncryptionKey::generate();
        let wrapped = dek.wrap(&master_key).unwrap();

        // An attacker holding the database has exactly `material`. Treating the
        // stored verifier as a key must not open the wrapped DEK.
        let forged = MasterKey::from_bytes(material.verifier);
        assert!(DataEncryptionKey::unwrap(&wrapped, &forged).is_err());
    }

}
