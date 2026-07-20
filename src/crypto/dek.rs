//! Data Encryption Key (DEK) Management
//!
//! Implements the wrapped DEK model for secure password changes:
//! - DEK is generated once during vault initialization
//! - DEK is encrypted (wrapped) with the Master Key
//! - Credentials are encrypted with DEK, not Master Key
//! - Password change only requires re-wrapping the DEK

use rand::RngCore;
use zeroize::Zeroize;

use super::encryption::{decrypt_bytes, encrypt_bytes};
use super::{CryptoError, CryptoResult, LockedBuffer, MasterKey};

/// Data Encryption Key (256 bits)
///
/// This key is used to encrypt all credentials in the vault.
/// Memory-locked to prevent swapping to disk.
#[derive(Clone)]
pub struct DataEncryptionKey {
    key: LockedBuffer<32>,
}

impl DataEncryptionKey {
    /// Generate a new random DEK
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let dek = Self {
            key: LockedBuffer::new(key),
        };

        // Zeroize the temporary buffer
        key.zeroize();

        dek
    }

    /// Get key bytes for encryption operations
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Wrap (encrypt) the DEK with the master key
    /// Returns a hex-encoded string suitable for database storage
    pub fn wrap(&self, master_key: &MasterKey) -> CryptoResult<String> {
        encrypt_bytes(master_key.as_ref(), &*self.key)
    }

    /// Unwrap (decrypt) a DEK using the master key
    pub fn unwrap(wrapped_dek: &str, master_key: &MasterKey) -> CryptoResult<Self> {
        let mut dek_bytes = decrypt_bytes(master_key.as_ref(), &wrapped_dek.to_string())?;
        let result = build_dek_from_bytes(&dek_bytes);
        dek_bytes.zeroize();
        result
    }

    /// Re-wrap the DEK with a new master key
    /// This is the core operation for password changes
    pub fn rewrap(&self, new_master_key: &MasterKey) -> CryptoResult<String> {
        self.wrap(new_master_key)
    }
}

impl AsRef<[u8]> for DataEncryptionKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

// Debug impl that doesn't leak key material
impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataEncryptionKey").finish_non_exhaustive()
    }
}

fn build_dek_from_bytes(bytes: &[u8]) -> CryptoResult<DataEncryptionKey> {
    if bytes.len() != 32 {
        return Err(CryptoError::DecryptionFailed(format!(
            "Invalid DEK length: expected 32, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    let dek = DataEncryptionKey { key: LockedBuffer::new(key) };
    key.zeroize();
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{create_key_material, KdfParams};

    fn test_master_key() -> MasterKey {
        MasterKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn test_dek_generation() {
        let dek1 = DataEncryptionKey::generate();
        let dek2 = DataEncryptionKey::generate();

        // Each generated DEK should be unique
        assert_ne!(dek1.as_bytes(), dek2.as_bytes());
        assert_eq!(dek1.as_bytes().len(), 32);
    }

    #[test]
    fn test_wrap_unwrap() {
        let master_key = test_master_key();
        let dek = DataEncryptionKey::generate();

        // Wrap the DEK
        let wrapped = dek.wrap(&master_key).unwrap();
        assert!(!wrapped.is_empty());

        // Unwrap should recover the same DEK
        let unwrapped = DataEncryptionKey::unwrap(&wrapped, &master_key).unwrap();
        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn test_wrong_master_key_fails() {
        let master_key1 = MasterKey::from_bytes([0x42u8; 32]);
        let master_key2 = MasterKey::from_bytes([0x43u8; 32]);

        let dek = DataEncryptionKey::generate();
        let wrapped = dek.wrap(&master_key1).unwrap();

        // Unwrapping with wrong key should fail
        let result = DataEncryptionKey::unwrap(&wrapped, &master_key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_rewrap_for_password_change() {
        let params = KdfParams::testing();

        // Simulate initial vault creation
        let (old_master_key, _) = create_key_material(b"old_password", &params).unwrap();
        let dek = DataEncryptionKey::generate();
        let old_wrapped = dek.wrap(&old_master_key).unwrap();

        // Simulate password change
        let (new_master_key, _) = create_key_material(b"new_password", &params).unwrap();

        // Unwrap with old key, rewrap with new key
        let unwrapped_dek = DataEncryptionKey::unwrap(&old_wrapped, &old_master_key).unwrap();
        let new_wrapped = unwrapped_dek.rewrap(&new_master_key).unwrap();

        // Verify: new wrapped DEK should work with new master key
        let final_dek = DataEncryptionKey::unwrap(&new_wrapped, &new_master_key).unwrap();
        assert_eq!(dek.as_bytes(), final_dek.as_bytes());

        // Verify: old wrapped DEK should NOT work with new master key
        let result = DataEncryptionKey::unwrap(&old_wrapped, &new_master_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_dek_used_for_encryption() {
        use crate::crypto::encryption::{decrypt_string, encrypt_string};

        let master_key = test_master_key();
        let dek = DataEncryptionKey::generate();

        // Encrypt data with DEK (not master key)
        let secret = "my_super_secret_password";
        let encrypted = encrypt_string(dek.as_ref(), secret).unwrap();

        // Wrap DEK for storage
        let wrapped_dek = dek.wrap(&master_key).unwrap();

        // Later: unwrap DEK and decrypt data
        let recovered_dek = DataEncryptionKey::unwrap(&wrapped_dek, &master_key).unwrap();
        let decrypted = decrypt_string(recovered_dek.as_ref(), &encrypted).unwrap();

        assert_eq!(secret, decrypted);
    }
}
