//! Key Derivation Function
//!
//! Argon2id password hashing for master key derivation.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{CryptoError, CryptoResult, LockedBuffer};

/// Master key (256 bits)
///
/// Memory-locked to prevent swapping to disk.
#[derive(Clone)]
pub struct MasterKey {
    key: LockedBuffer<32>,
}

impl MasterKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: LockedBuffer::new(bytes),
        }
    }

    /// Get key bytes (used in tests; kept for type-safe 32-byte access)
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8; 32] {
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

/// KDF parameters for Argon2id
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            output_len: 32,
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
            output_len: 32,
        }
    }
}

/// Derive master key from password using Argon2id
/// Returns (`MasterKey`, `password_hash_string`)
pub fn derive_master_key(password: &[u8], params: &KdfParams) -> CryptoResult<(MasterKey, String)> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params);

    let password_hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    // Extract the hash output as the key
    let hash_output = password_hash
        .hash
        .ok_or_else(|| CryptoError::KeyDerivationFailed("No hash output".to_string()))?;

    let hash_bytes = hash_output.as_bytes();
    if hash_bytes.len() < 32 {
        return Err(CryptoError::KeyDerivationFailed(
            "Hash output too short".to_string(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash_bytes[..32]);

    // MasterKey constructor handles mlock
    let master_key = MasterKey::from_bytes(key_bytes);

    // Zeroize the temporary buffer
    key_bytes.zeroize();

    Ok((master_key, password_hash.to_string()))
}

/// Verify password against stored hash and derive key
pub fn verify_master_key(password: &[u8], password_hash: &str) -> CryptoResult<MasterKey> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    // Verify the password
    Argon2::default()
        .verify_password(password, &parsed_hash)
        .map_err(|_| CryptoError::InvalidPassword)?;

    // Extract key from hash
    let hash_output = parsed_hash
        .hash
        .ok_or_else(|| CryptoError::KeyDerivationFailed("No hash output".to_string()))?;

    let hash_bytes = hash_output.as_bytes();
    if hash_bytes.len() < 32 {
        return Err(CryptoError::KeyDerivationFailed(
            "Hash output too short".to_string(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash_bytes[..32]);

    // MasterKey constructor handles mlock
    let master_key = MasterKey::from_bytes(key_bytes);

    // Zeroize the temporary buffer
    key_bytes.zeroize();

    Ok(master_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key() {
        let password = b"test_password_123";
        let params = KdfParams::testing();

        let (key, hash) = derive_master_key(password, &params).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_verify_master_key() {
        let password = b"test_password_123";
        let params = KdfParams::testing();

        let (original_key, hash) = derive_master_key(password, &params).unwrap();
        let verified_key = verify_master_key(password, &hash).unwrap();

        assert_eq!(original_key.as_bytes(), verified_key.as_bytes());
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let params = KdfParams::testing();

        let (_, hash) = derive_master_key(password, &params).unwrap();
        let result = verify_master_key(wrong_password, &hash);

        assert!(matches!(result, Err(CryptoError::InvalidPassword)));
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = b"same_password";
        let params = KdfParams::testing();

        let (key1, _) = derive_master_key(password, &params).unwrap();
        let (key2, _) = derive_master_key(password, &params).unwrap();

        // Different salts should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_deterministic_verification() {
        let password = b"test_password";
        let params = KdfParams::testing();

        let (key1, hash) = derive_master_key(password, &params).unwrap();
        let key2 = verify_master_key(password, &hash).unwrap();
        let key3 = verify_master_key(password, &hash).unwrap();

        // Verification should always produce the same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key2.as_bytes(), key3.as_bytes());
    }
}
