//! Time-based One-Time Password (TOTP) Implementation
//!
//! Implements RFC 6238 for 2FA code generation.

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use url::Url;

use super::{CryptoError, CryptoResult};

const DEFAULT_DIGITS: usize = 6;
const DEFAULT_PERIOD: u64 = 30;

/// Bounds on a URI-supplied digit count. The raw-secret path always uses
/// `DEFAULT_DIGITS`, so anything here is input we would not otherwise accept;
/// the range stays wide enough for every issuer seen in practice (Steam uses
/// 5, most use 6, some banks 8) while rejecting absurd values.
const DIGITS_RANGE: std::ops::RangeInclusive<usize> = 4..=10;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
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

    /// Parse from otpauth:// URI.
    ///
    /// Parsed field by field rather than delegated to `TOTP::from_url`, which
    /// enforces RFC 4226's 128-bit minimum on the shared secret. `build_totp`
    /// — the path raw-secret entry and every code generation already take —
    /// uses `new_unchecked` and applies no such minimum, so delegating here
    /// made the URI path reject secrets the rest of the app accepts. GitHub
    /// and Google issue 80-bit secrets, which is why pasting a URI failed
    /// while pasting the secret out of that same URI worked.
    fn from_uri(uri: &str) -> CryptoResult<Self> {
        let parsed = Url::parse(uri.trim()).map_err(|e| invalid_uri(&e.to_string()))?;

        if !parsed.scheme().eq_ignore_ascii_case("otpauth") {
            return Err(invalid_uri("expected an otpauth:// URI"));
        }

        let host = parsed.host_str().unwrap_or_default();
        if !host.eq_ignore_ascii_case("totp") {
            return Err(invalid_uri(&format!(
                "only otpauth://totp/ URIs are supported, got {host:?}"
            )));
        }

        let params = query_params(&parsed);

        let Some(raw_secret) = params.get("secret") else {
            return Err(invalid_uri("no secret parameter"));
        };
        let secret = normalize_base32(raw_secret);
        validate_base32(&secret)?;

        let (label_issuer, account) = split_label(parsed.path());
        let issuer = params
            .get("issuer")
            .cloned()
            .filter(|i| !i.is_empty())
            .or(label_issuer)
            .unwrap_or_default();

        Ok(Self {
            secret,
            account,
            issuer,
            digits: parse_digits(params.get("digits"))?,
            period: parse_period(params.get("period"))?,
            algorithm: parse_algorithm(params.get("algorithm"))?,
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

fn invalid_uri(detail: &str) -> CryptoError {
    CryptoError::TotpFailed(format!("Invalid otpauth URI: {detail}"))
}

/// Parameter names are matched case-insensitively; issuers are inconsistent
/// about `algorithm` versus `Algorithm`.
fn query_params(uri: &Url) -> std::collections::HashMap<String, String> {
    uri.query_pairs()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.into_owned()))
        .collect()
}

/// The label is `Issuer:Account` or a bare `Account`, percent-encoded. The
/// separator may itself be encoded, so decode before splitting — splitting
/// first would cut an account name containing a literal `%` in half.
fn split_label(path: &str) -> (Option<String>, String) {
    let decoded = percent_decode_str(path.trim_start_matches('/'))
        .decode_utf8_lossy()
        .into_owned();

    let Some((issuer, account)) = decoded.split_once(':') else {
        return (None, decoded.trim().to_string());
    };

    let issuer = issuer.trim();
    let issuer = (!issuer.is_empty()).then(|| issuer.to_string());
    (issuer, account.trim().to_string())
}

fn parse_digits(raw: Option<&String>) -> CryptoResult<usize> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_DIGITS);
    };
    let digits = raw
        .parse::<usize>()
        .map_err(|_| invalid_uri(&format!("digits must be a number, got {raw:?}")))?;

    if !DIGITS_RANGE.contains(&digits) {
        return Err(invalid_uri(&format!(
            "digits must be between {} and {}, got {digits}",
            DIGITS_RANGE.start(),
            DIGITS_RANGE.end()
        )));
    }
    Ok(digits)
}

fn parse_period(raw: Option<&String>) -> CryptoResult<u64> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_PERIOD);
    };
    let period = raw
        .parse::<u64>()
        .map_err(|_| invalid_uri(&format!("period must be a number, got {raw:?}")))?;

    // time_remaining computes `now % period`; zero would panic the process.
    if period == 0 {
        return Err(invalid_uri("period must be greater than zero"));
    }
    Ok(period)
}

fn parse_algorithm(raw: Option<&String>) -> CryptoResult<TotpAlgorithm> {
    let Some(raw) = raw else {
        return Ok(TotpAlgorithm::default());
    };
    match raw.trim().to_ascii_uppercase().as_str() {
        "SHA1" => Ok(TotpAlgorithm::SHA1),
        "SHA256" => Ok(TotpAlgorithm::SHA256),
        "SHA512" => Ok(TotpAlgorithm::SHA512),
        other => Err(invalid_uri(&format!("unsupported algorithm {other:?}"))),
    }
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



#[cfg(test)]
mod uri_tests {
    use super::*;

    fn parse(uri: &str) -> TotpSecret {
        TotpSecret::from_user_input(uri, "fallback-account", "fallback-issuer")
            .unwrap_or_else(|e| panic!("{uri} should parse: {e}"))
    }

    fn error(uri: &str) -> String {
        match TotpSecret::from_user_input(uri, "acct", "iss") {
            Err(CryptoError::TotpFailed(msg)) => msg,
            Err(other) => panic!("unexpected error kind: {other}"),
            Ok(_) => panic!("{uri} should have been rejected"),
        }
    }

    /// The bug this file's URI parser was rewritten for: `TOTP::from_url`
    /// enforces a 128-bit secret minimum that `build_totp` does not, so a
    /// URI carrying an 80-bit secret was rejected while the very same secret
    /// pasted in raw was accepted. Both paths must now agree.
    #[test]
    fn an_eighty_bit_secret_is_accepted_from_a_uri_as_it_is_raw() {
        let from_raw = parse("JBSWY3DPEHPK3PXP");
        let from_uri = parse("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub");

        assert_eq!(from_raw.secret, from_uri.secret);
        assert!(generate_totp(&from_uri).is_ok());
    }

    #[test]
    fn uri_and_raw_entry_of_one_secret_generate_the_same_code() {
        let from_raw = parse("JBSWY3DPEHPK3PXP");
        let from_uri = parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME");

        assert_eq!(
            generate_totp(&from_raw).unwrap(),
            generate_totp(&from_uri).unwrap()
        );
    }

    #[test]
    fn label_supplies_issuer_and_account() {
        let secret = parse("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(secret.issuer, "GitHub");
        assert_eq!(secret.account, "octocat");
    }

    #[test]
    fn percent_encoded_label_is_decoded() {
        let secret = parse("otpauth://totp/Google%3Auser%40gmail.com?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(secret.issuer, "Google");
        assert_eq!(secret.account, "user@gmail.com");
    }

    /// Splitting the raw path on `%` — as the previous implementation did to
    /// find the label separator — truncated any account containing one.
    #[test]
    fn account_containing_a_literal_percent_survives() {
        let secret = parse("otpauth://totp/ACME:100%25user?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(secret.account, "100%user");
    }

    #[test]
    fn issuer_parameter_wins_over_the_label() {
        let secret = parse("otpauth://totp/Stale:alice?secret=JBSWY3DPEHPK3PXP&issuer=Authoritative");
        assert_eq!(secret.issuer, "Authoritative");
        assert_eq!(secret.account, "alice");
    }

    #[test]
    fn bare_label_leaves_issuer_empty() {
        let secret = parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(secret.account, "alice");
        assert!(secret.issuer.is_empty());
    }

    #[test]
    fn percent_encoded_padding_is_stripped_from_the_secret() {
        let secret = parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP%3D%3D");
        assert_eq!(secret.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn lowercase_secret_is_upcased() {
        assert_eq!(
            parse("otpauth://totp/ACME:alice?secret=jbswy3dpehpk3pxp").secret,
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn scheme_and_host_are_case_insensitive() {
        let secret = parse("OTPAUTH://TOTP/ACME:alice?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(secret.account, "alice");
    }

    #[test]
    fn optional_parameters_are_read() {
        let secret =
            parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60");
        assert_eq!(secret.algorithm, TotpAlgorithm::SHA256);
        assert_eq!(secret.digits, 8);
        assert_eq!(secret.period, 60);
    }

    #[test]
    fn omitted_parameters_take_rfc_defaults() {
        let secret = parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(secret.algorithm, TotpAlgorithm::SHA1);
        assert_eq!(secret.digits, DEFAULT_DIGITS);
        assert_eq!(secret.period, DEFAULT_PERIOD);
    }

    #[test]
    fn parameter_names_are_case_insensitive() {
        let secret = parse("otpauth://totp/ACME:alice?SECRET=JBSWY3DPEHPK3PXP&Digits=8");
        assert_eq!(secret.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(secret.digits, 8);
    }

    /// `time_remaining` computes `now % period`; a zero period would panic the
    /// process, so it has to be refused at the boundary.
    #[test]
    fn zero_period_is_rejected() {
        assert!(error("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&period=0")
            .contains("greater than zero"));
    }

    #[test]
    fn hotp_uris_are_rejected() {
        assert!(error("otpauth://hotp/ACME:alice?secret=JBSWY3DPEHPK3PXP&counter=1")
            .contains("only otpauth://totp/"));
    }

    #[test]
    fn uri_without_a_secret_is_rejected() {
        assert!(error("otpauth://totp/ACME:alice?issuer=ACME").contains("no secret parameter"));
    }

    #[test]
    fn non_base32_secret_is_rejected() {
        assert!(error("otpauth://totp/ACME:alice?secret=THIS-IS-NOT-BASE32-189")
            .contains("base32"));
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        assert!(error("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
            .contains("unsupported algorithm"));
    }

    #[test]
    fn non_numeric_digits_is_rejected() {
        assert!(error("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&digits=many")
            .contains("digits must be a number"));
    }

    #[test]
    fn out_of_range_digits_is_rejected() {
        assert!(error("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&digits=99")
            .contains("digits must be between"));
    }

    #[test]
    fn a_uri_survives_a_round_trip_through_to_uri() {
        let original =
            parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=8&period=60&algorithm=SHA256");
        let round_tripped = parse(&original.to_uri().unwrap());

        assert_eq!(round_tripped.secret, original.secret);
        assert_eq!(round_tripped.account, original.account);
        assert_eq!(round_tripped.issuer, original.issuer);
        assert_eq!(round_tripped.digits, original.digits);
        assert_eq!(round_tripped.period, original.period);
        assert_eq!(round_tripped.algorithm, original.algorithm);
    }
}

/// RFC 6238 Appendix B reference vectors. These pin the parser to published
/// values rather than to whatever this implementation happens to produce, so a
/// wrong algorithm or period mapping cannot pass by agreeing with itself.
#[cfg(test)]
mod rfc6238_vectors {
    use super::*;

    const SHA1_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SHA256_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
    const SHA512_SECRET: &str =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";

    fn code_at(secret: &str, algorithm: &str, unix_time: u64) -> String {
        let uri = format!(
            "otpauth://totp/RFC:vector?secret={secret}&algorithm={algorithm}&digits=8&period=30"
        );
        let parsed = TotpSecret::from_user_input(&uri, "acct", "iss").expect("vector URI parses");
        parsed.build_totp().unwrap().generate(unix_time)
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(code_at(SHA1_SECRET, "SHA1", 59), "94287082");
        assert_eq!(code_at(SHA1_SECRET, "SHA1", 1_111_111_109), "07081804");
        assert_eq!(code_at(SHA1_SECRET, "SHA1", 1_111_111_111), "14050471");
        assert_eq!(code_at(SHA1_SECRET, "SHA1", 1_234_567_890), "89005924");
        assert_eq!(code_at(SHA1_SECRET, "SHA1", 2_000_000_000), "69279037");
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(code_at(SHA256_SECRET, "SHA256", 59), "46119246");
        assert_eq!(code_at(SHA256_SECRET, "SHA256", 1_111_111_109), "68084774");
        assert_eq!(code_at(SHA256_SECRET, "SHA256", 2_000_000_000), "90698825");
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(code_at(SHA512_SECRET, "SHA512", 59), "90693936");
        assert_eq!(code_at(SHA512_SECRET, "SHA512", 1_111_111_109), "25091201");
        assert_eq!(code_at(SHA512_SECRET, "SHA512", 2_000_000_000), "38618901");
    }
}
