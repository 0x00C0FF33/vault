//! Cryptographic Operations
//!
//! Provides secure encryption, key derivation, and password generation.

pub mod dek;
pub mod encryption;
pub mod kdf;
pub mod key_hierarchy;
pub mod password_gen;
pub mod totp;

use std::ops::{Deref, DerefMut};
use thiserror::Error;
use zeroize::Zeroize;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),

    #[error("TOTP generation failed: {0}")]
    TotpFailed(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

/// A buffer that is locked in memory to prevent swapping to disk.
///
/// Uses `mlock()` on Unix and `VirtualLock()` on Windows to advise the OS
/// not to swap these pages. The buffer is automatically zeroed before
/// being unlocked on drop.
///
/// # Security Notes
/// - `mlock` may fail due to resource limits (`RLIMIT_MEMLOCK`) - we handle
///   this gracefully and continue, as the application should still function
/// - The buffer is always zeroized on drop, regardless of lock status
/// - Clone creates a new locked buffer (both copies are locked)
pub struct LockedBuffer<const N: usize> {
    data: [u8; N],
    #[allow(dead_code)]
    locked: bool,
}

impl<const N: usize> LockedBuffer<N> {
    /// Create a new locked buffer with the given data
    pub fn new(data: [u8; N]) -> Self {
        let mut buf = Self {
            data,
            locked: false,
        };
        buf.try_lock();
        buf
    }

    /// Create a zeroed locked buffer
    #[allow(dead_code)]
    pub fn zeroed() -> Self {
        Self::new([0u8; N])
    }

    /// Attempt to lock the memory region
    fn try_lock(&mut self) {
        self.locked = Self::mlock_impl(self.data.as_ptr(), N);
        #[cfg(debug_assertions)]
        if !self.locked {
            eprintln!("Warning: mlock() failed for {N} byte buffer - sensitive data may be swapped to disk");
        }
    }

    /// Unlock the memory region
    fn unlock(&mut self) {
        if self.locked {
            Self::munlock_impl(self.data.as_ptr(), N);
            self.locked = false;
        }
    }

    /// Platform-specific mlock implementation
    #[cfg(unix)]
    fn mlock_impl(ptr: *const u8, len: usize) -> bool {
        // SAFETY: ptr points to valid memory of at least `len` bytes
        unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) == 0 }
    }

    #[cfg(windows)]
    fn mlock_impl(ptr: *const u8, len: usize) -> bool {
        // SAFETY: ptr points to valid memory of at least `len` bytes
        unsafe { windows_sys::Win32::System::Memory::VirtualLock(ptr as *mut _, len) != 0 }
    }

    #[cfg(not(any(unix, windows)))]
    fn mlock_impl(_ptr: *const u8, _len: usize) -> bool {
        // No-op on unsupported platforms
        false
    }

    /// Platform-specific munlock implementation
    #[cfg(unix)]
    fn munlock_impl(ptr: *const u8, len: usize) {
        // SAFETY: ptr points to valid memory of at least `len` bytes
        unsafe {
            libc::munlock(ptr.cast::<libc::c_void>(), len);
        }
    }

    #[cfg(windows)]
    fn munlock_impl(ptr: *const u8, len: usize) {
        // SAFETY: ptr points to valid memory of at least `len` bytes
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *mut _, len);
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn munlock_impl(_ptr: *const u8, _len: usize) {
        // No-op on unsupported platforms
    }

    /// Check if the buffer is currently locked in memory
    #[allow(dead_code)]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<const N: usize> Clone for LockedBuffer<N> {
    fn clone(&self) -> Self {
        // Create a new locked buffer with copied data
        Self::new(self.data)
    }
}

impl<const N: usize> Deref for LockedBuffer<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for LockedBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> AsRef<[u8]> for LockedBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> Zeroize for LockedBuffer<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> Drop for LockedBuffer<N> {
    fn drop(&mut self) {
        // Zeroize while memory is still locked
        self.data.zeroize();
        // Then unlock
        self.unlock();
    }
}

// Prevent debug printing of sensitive data
impl<const N: usize> std::fmt::Debug for LockedBuffer<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedBuffer")
            .field("len", &N)
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

// Re-exports
pub use dek::DataEncryptionKey;
pub use encryption::{decrypt_string, encrypt_string};
pub use kdf::{derive_master_key, verify_master_key, KdfParams, MasterKey};
pub use key_hierarchy::{DerivedKey, KeyHierarchy};
pub use password_gen::{generate_password, password_strength, strength_label, PasswordPolicy};
// pub use totp::{generate_totp, time_remaining, TotpSecret};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_buffer_basic() {
        let data = [0x42u8; 32];
        let buf = LockedBuffer::new(data);
        assert_eq!(*buf, data);
    }

    #[test]
    fn test_locked_buffer_clone() {
        let buf1 = LockedBuffer::new([0x42u8; 32]);
        let buf2 = buf1.clone();
        assert_eq!(*buf1, *buf2);
    }

    #[test]
    fn test_locked_buffer_zeroize() {
        let mut buf = LockedBuffer::new([0x42u8; 32]);
        buf.zeroize();
        assert_eq!(*buf, [0u8; 32]);
    }

    #[test]
    fn test_locked_buffer_deref_mut() {
        let mut buf = LockedBuffer::new([0u8; 32]);
        buf[0] = 0xff;
        assert_eq!(buf[0], 0xff);
    }

    #[test]
    fn test_locked_buffer_debug_no_leak() {
        let buf = LockedBuffer::new([0x42u8; 32]);
        let debug_str = format!("{buf:?}");
        // Should not contain the actual data
        assert!(!debug_str.contains("42"));
        assert!(debug_str.contains("LockedBuffer"));
    }
}
