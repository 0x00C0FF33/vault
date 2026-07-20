//! Time-based One-Time Password (TOTP) Implementation
//!
//! Implements RFC 6238 for 2FA code generation.

use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use super::{CryptoError, CryptoResult};

/// TOTP secret configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    /// Base32-encoded secret (original, not padded)
    pub secret: String,
    /// Account name (e.g., "user@example.com")
    pub account: String,
    /// Issuer (e.g., "GitHub")
    pub issuer: String,
    /// Number of digits (default: 6)
    pub digits: usize,
    /// Time step in seconds (default: 30)
    pub period: u64,
    /// Algorithm (default: SHA1)
    pub algorithm: TotpAlgorithm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub enum TotpAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl From<TotpAlgorithm> for Algorithm {
    fn from(algo: TotpAlgorithm) -> Self {
        match algo {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }
}

impl TotpSecret {
    /// Create a new TOTP secret with defaults
    pub fn new(secret: String, account: String, issuer: String) -> Self {
        Self {
            secret,
            account,
            issuer,
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::SHA1,
        }
    }

    /// Parse from user input - handles both raw secret and otpauth:// URI
    pub fn from_user_input(input: &str, fallback_account: &str, fallback_issuer: &str) -> CryptoResult<Self> {
        let trimmed = input.trim();
        
        if trimmed.is_empty() {
            return Err(CryptoError::TotpFailed("TOTP secret cannot be empty".to_string()));
        }
        
        if trimmed.to_lowercase().starts_with("otpauth://") {
            Self::from_uri(trimmed)
        } else {
            Self::from_raw_secret(trimmed, fallback_account, fallback_issuer)
        }
    }

    /// Create from raw base32 secret
    fn from_raw_secret(secret: &str, account: &str, issuer: &str) -> CryptoResult<Self> {
        let cleaned = normalize_base32(secret);
        validate_base32(&cleaned)?;
        
        Ok(Self::new(cleaned, account.to_string(), issuer.to_string()))
    }

    /// Parse from otpauth:// URI
    fn from_uri(uri: &str) -> CryptoResult<Self> {
        let totp = TOTP::from_url(normalize_otpauth_uri(uri))
            .map_err(|e| CryptoError::TotpFailed(e.to_string()))?;

        let algorithm = match totp.algorithm {
            Algorithm::SHA1 => TotpAlgorithm::SHA1,
            Algorithm::SHA256 => TotpAlgorithm::SHA256,
            Algorithm::SHA512 => TotpAlgorithm::SHA512,
        };

        Ok(Self {
            secret: normalize_base32(&totp.get_secret_base32()),
            account: totp.account_name.clone(),
            issuer: totp.issuer.clone().unwrap_or_default(),
            digits: totp.digits,
            period: totp.step,
            algorithm,
        })
    }

    /// Export as otpauth:// URI for transferring to other apps
    pub fn to_uri(&self) -> CryptoResult<String> {
        let totp = self.build_totp()?;
        Ok(totp.get_url())
    }

    fn build_totp(&self) -> CryptoResult<TOTP> {
        let secret_bytes = self.decode_secret()?;

        Ok(TOTP::new_unchecked(
            self.algorithm.into(),
            self.digits,
            1,
            self.period,
            secret_bytes,
            Some(self.issuer.clone()),
            self.account.clone(),
        ))
    }

    fn decode_secret(&self) -> CryptoResult<Vec<u8>> {
        Secret::Encoded(self.secret.clone())
            .to_bytes()
            .map_err(|e| CryptoError::TotpFailed(format!("Invalid base32 secret: {e}")))
    }
}

fn normalize_otpauth_uri(uri: &str) -> String {
    let mut result = normalize_uri_secret(uri);
    result = align_uri_issuer(result);
    result
}

fn normalize_uri_secret(uri: &str) -> String {
    let Some(secret_start) = uri.find("secret=") else {
        return uri.to_string();
    };
    let value_start = secret_start + 7;
    let value_end = uri[value_start..].find('&').map_or(uri.len(), |i| value_start + i);

    let raw_secret = &uri[value_start..value_end];
    let normalized = normalize_base32(raw_secret);

    format!("{}{}{}", &uri[..value_start], normalized, &uri[value_end..])
}

fn align_uri_issuer(uri: String) -> String {
    let issuer = extract_uri_param(&uri, "issuer");
    let Some(issuer) = issuer else {
        return uri;
    };

    let Some(path_start) = uri.find("//totp/") else {
        return uri;
    };
    let label_start = path_start + 7;
    let query_start = uri[label_start..].find('?').map_or(uri.len(), |i| label_start + i);
    let label = &uri[label_start..query_start];

    if !label.contains(':') && !label.contains("%3A") {
        return uri;
    }

    let account = label.splitn(2, [':', '%']).last().unwrap_or(label);
    let account = account.trim_start_matches("3A").trim_start_matches("3a");

    format!(
        "{}{}:{}{}",
        &uri[..label_start],
        issuer,
        account,
        &uri[query_start..]
    )
}

fn extract_uri_param<'a>(uri: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("{key}=");
    let start = uri.find(&search)?;
    let value_start = start + search.len();
    let value_end = uri[value_start..].find('&').map_or(uri.len(), |i| value_start + i);
    Some(&uri[value_start..value_end])
}

/// Normalize base32 input (remove spaces, dashes, convert to uppercase)
fn normalize_base32(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_uppercase()
}

/// Validate that the secret contains valid base32 characters
fn validate_base32(secret: &str) -> CryptoResult<()> {
    if secret.is_empty() {
        return Err(CryptoError::TotpFailed("TOTP secret cannot be empty".to_string()));
    }

    if secret.len() < 8 {
        return Err(CryptoError::TotpFailed(
            format!("TOTP secret too short. Minimum 8 characters required, got {}", secret.len())
        ));
    }

    let valid_chars = secret.chars().all(|c| {
        matches!(c, 'A'..='Z' | '2'..='7')
    });
    
    if !valid_chars {
        return Err(CryptoError::TotpFailed(
            "Invalid characters in TOTP secret. Must be base32 (A-Z, 2-7)".to_string()
        ));
    }

    Ok(())
}

/// Generate current TOTP code
pub fn generate_totp(secret: &TotpSecret) -> CryptoResult<String> {
    let totp = secret.build_totp()?;
    totp.generate_current()
        .map_err(|e| CryptoError::TotpFailed(e.to_string()))
}

/// Get remaining seconds until code expires
pub fn time_remaining(secret: &TotpSecret) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secret.period - (now % secret.period)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_secret_no_padding() {
        let secret = TotpSecret::from_user_input(
            "JBSWY3DPEHPK3PXP",
            "test@example.com",
            "Test"
        ).unwrap();
        
        let code = generate_totp(&secret).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_raw_secret_with_spaces() {
        let secret = TotpSecret::from_user_input(
            "JBSW Y3DP EHPK 3PXP",
            "test",
            "Test"
        ).unwrap();
        
        assert_eq!(secret.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_raw_secret_lowercase() {
        let secret = TotpSecret::from_user_input(
            "jbswy3dpehpk3pxp",
            "test",
            "Test"
        ).unwrap();
        
        assert_eq!(secret.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_otpauth_uri() {
        let uri = "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=GitHub";
        let secret = TotpSecret::from_user_input(uri, "fallback", "Fallback").unwrap();
        
        assert_eq!(secret.account, "user@example.com");
        assert_eq!(secret.issuer, "GitHub");
        
        // Should generate valid code
        let code = generate_totp(&secret).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_to_uri() {
        let secret = TotpSecret::from_user_input(
            "JBSWY3DPEHPK3PXP",
            "user@example.com",
            "MyService"
        ).unwrap();
        
        let uri = secret.to_uri().unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("MyService"));
    }

    #[test]
    fn test_secret_too_short() {
        let result = TotpSecret::from_user_input("SHORT", "test", "Test");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_characters() {
        let result = TotpSecret::from_user_input("INVALID!@#SECRET", "test", "Test");
        assert!(result.is_err());
    }

    #[test]
    fn test_time_remaining() {
        let secret = TotpSecret::from_user_input(
            "JBSWY3DPEHPK3PXP",
            "test",
            "Test"
        ).unwrap();
        
        let remaining = time_remaining(&secret);
        assert!((1..=30).contains(&remaining));
    }
}
