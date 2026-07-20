//! Password Generator
//!
//! Cryptographically secure password generation using OS-level entropy.

use rand::rngs::OsRng;
use rand::prelude::IteratorRandom;
use rand::seq::SliceRandom;

/// Password generation policy
// The four character-class toggles are the conventional shape for a generator
// policy; folding them into a bitfield would obscure more than it saves.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub length: usize,
    /// Include uppercase letters
    pub uppercase: bool,
    /// Include lowercase letters
    pub lowercase: bool,
    /// Include digits
    pub digits: bool,
    /// Include symbols
    pub symbols: bool,
    /// Custom symbols to use (if symbols is true)
    pub custom_symbols: Option<String>,
    /// Exclude ambiguous characters (0, O, l, 1, I, |)
    pub exclude_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            custom_symbols: None,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordPolicy {
    /// Create a policy for PIN-style passwords
    #[allow(dead_code)]
    pub fn pin(length: usize) -> Self {
        Self {
            length,
            uppercase: false,
            lowercase: false,
            digits: true,
            symbols: false,
            custom_symbols: None,
            exclude_ambiguous: false,
        }
    }

    /// Create a policy for passphrase-friendly passwords
    #[allow(dead_code)]
    pub fn readable(length: usize) -> Self {
        Self {
            length,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: false,
            custom_symbols: None,
            exclude_ambiguous: true,
        }
    }

    /// Create a quantum-resistant policy.
    ///
    /// Generates 40-character passwords (~262 bits entropy with full charset),
    /// providing 128-bit security against Grover's algorithm which halves
    /// effective entropy for symmetric cryptography.
    ///
    /// Note: This is forward-looking; current threat models don't require this.
    #[allow(dead_code)]
    pub fn quantum_resistant() -> Self {
        Self {
            length: 40,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            custom_symbols: None,
            exclude_ambiguous: false,
        }
    }
}

const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?";
const AMBIGUOUS: &str = "0O1lI|";

// Word list for passphrase generation (EFF short wordlist subset)
#[allow(dead_code)]
const WORDLIST: &[&str] = &[
    "acid", "acorn", "acre", "acts", "afar", "affix", "aged", "agent", "agile", "aging",
    "agony", "ahead", "aide", "aids", "aim", "ajar", "alarm", "album", "alert", "alike",
    "alive", "alley", "allot", "allow", "alloy", "aloft", "alone", "amend", "amino", "ample",
    "angel", "anger", "angle", "ankle", "apple", "april", "apron", "aqua", "area", "arena",
    "argue", "arise", "armor", "army", "aroma", "array", "arrow", "arson", "ashen", "ashes",
    "atlas", "atom", "attic", "audio", "avert", "avoid", "awake", "award", "awful", "axis",
    "bacon", "badge", "badly", "baker", "balmy", "banjo", "barge", "barn", "basin", "batch",
    "bath", "baton", "blade", "blank", "blast", "blaze", "bleak", "blend", "bless", "blimp",
    "blind", "bliss", "block", "blunt", "blurt", "blush", "board", "boil", "bolt", "bonus",
    "book", "booth", "boots", "botch", "boxer", "brace", "brain", "brake", "brand", "brass",
    "brave", "bravo", "bread", "break", "breed", "brick", "bride", "brief", "bring", "brink",
    "brisk", "broad", "broil", "brook", "broom", "brush", "buddy", "buggy", "build", "built",
    "bulge", "bulk", "bully", "bunch", "bunny", "burst", "cable", "cache", "cadet", "cage",
    "calm", "cameo", "canal", "candy", "canon", "cape", "cargo", "carol", "carry", "carve",
    "case", "cash", "cause", "cedar", "chain", "chair", "champ", "chant", "chaos", "charm",
    "chase", "cheek", "cheer", "chess", "chest", "chief", "child", "chill", "chip", "chomp",
    "chord", "chore", "chunk", "churn", "cider", "cigar", "cinch", "city", "civic", "civil",
    "claim", "clamp", "clash", "clasp", "class", "clay", "clean", "clear", "clerk", "click",
    "cliff", "climb", "cling", "cloak", "clock", "clone", "cloth", "cloud", "clown", "club",
    "coast", "coat", "cocoa", "code", "coil", "cola", "cold", "colon", "color", "comet",
];

/// Error type for password generation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    /// No characters available after applying policy filters
    EmptyCharset,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::EmptyCharset => { write!(f, "No characters available with current policy settings") }
        }
    }
}

impl std::error::Error for PasswordError {}

/// Generate a password using the given policy.
///
/// Uses `OsRng` for cryptographically secure randomness.
///
/// # Errors
/// Returns `PasswordError::EmptyCharset` if the policy results in no available characters.
pub fn generate_password(policy: &PasswordPolicy) -> Result<String, PasswordError> {
    let mut rng = OsRng;
    let mut charset = String::new();
    let mut required: Vec<char> = Vec::new();

    // Helper to filter ambiguous characters
    let filter_ambiguous = |chars: &str, exclude: bool| -> String {
        if exclude {
            chars.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect()
        } else {
            chars.to_string()
        }
    };

    // Build character set and collect required characters
    if policy.uppercase {
        let chars = filter_ambiguous(UPPERCASE, policy.exclude_ambiguous);
        if !chars.is_empty() {
            if let Some(c) = chars.chars().choose(&mut rng) { required.push(c); }
            charset.push_str(&chars);
        }
    }

    if policy.lowercase {
        let chars = filter_ambiguous(LOWERCASE, policy.exclude_ambiguous);
        if !chars.is_empty() {
            if let Some(c) = chars.chars().choose(&mut rng) { required.push(c); }
            charset.push_str(&chars);
        }
    }

    if policy.digits {
        let chars = filter_ambiguous(DIGITS, policy.exclude_ambiguous);
        if !chars.is_empty() {
            if let Some(c) = chars.chars().choose(&mut rng) { required.push(c); }
            charset.push_str(&chars);
        }
    }

    if policy.symbols {
        let base_symbols = policy
            .custom_symbols.as_deref()
            .unwrap_or(SYMBOLS);
        // Apply ambiguous filter to custom symbols too
        let chars = filter_ambiguous(base_symbols, policy.exclude_ambiguous);
        if !chars.is_empty() {
            if let Some(c) = chars.chars().choose(&mut rng) { required.push(c); }
            charset.push_str(&chars);
        }
    }

    if charset.is_empty() {
        return Err(PasswordError::EmptyCharset);
    }

    let charset: Vec<char> = charset.chars().collect();

    // Generate password ensuring minimum requirements are met
    let remaining_length = policy.length.saturating_sub(required.len());
    let mut password: Vec<char> = required;

    for _ in 0..remaining_length {
        if let Some(&c) = charset.choose(&mut rng) {
            password.push(c);
        }
    }

    // Shuffle to randomize position of required characters
    password.shuffle(&mut rng);

    Ok(password.into_iter().collect())
}

/// Generate a passphrase from random words.
/// Uses `OsRng` for cryptographically secure randomness.
#[allow(dead_code)]
pub fn generate_passphrase(word_count: usize, separator: &str) -> String {
    let mut rng = OsRng;
    let words: Vec<&str> = WORDLIST
        .choose_multiple(&mut rng, word_count)
        .copied()
        .collect();
    words.join(separator)
}

/// Calculate password strength based on entropy (0-100).
///
/// Scoring based on NIST SP 800-63B thresholds:
/// - < 28 bits: Very Weak (0-20) - trivially crackable
/// - 28-47 bits: Weak (21-40) - vulnerable without rate-limiting
/// - 48-63 bits: Fair (41-60) - needs rate-limiting protection
/// - 64-111 bits: Strong (61-80) - resistant to online attacks
/// - 112+ bits: Very Strong (81-100) - meets NIST full security strength
///
/// Note: For post-quantum resistance (Grover's algorithm), 256 bits (~40 chars
/// with full charset) provides 128-bit equivalent security. See `PasswordPolicy::quantum_resistant()`.
// Entropy is non-negative and every arm below is bounded to 0..=100, so the
// f64 -> u32 narrowing is the intended floor rather than a lossy conversion.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn password_strength(password: &str) -> u32 {
    let len = password.len();
    if len == 0 {
        return 0;
    }

    // Calculate charset size based on character classes present
    let mut charset_size = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        charset_size += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        charset_size += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        charset_size += 10;
    }
    if password.chars().any(|c| !c.is_alphanumeric() && c.is_ascii()) {
        charset_size += 32;
    }
    if !password.is_ascii() {
        charset_size += 100;
    }

    if charset_size == 0 {
        return 0;
    }

    // Entropy in bits: log2(charset_size^len) = len * log2(charset_size)
    let entropy = (len as f64) * f64::from(charset_size).log2();

    match entropy as u32 {
        0..=27 => ((entropy / 28.0) * 20.0) as u32,
        28..=47 => 20 + (((entropy - 28.0) / 20.0) * 20.0) as u32,
        48..=63 => 40 + (((entropy - 48.0) / 16.0) * 20.0) as u32,
        64..=111 => 60 + (((entropy - 64.0) / 48.0) * 20.0) as u32,
        // 112..=255 => 80 + (((entropy - 112.0) / 144.0) * 20.0) as u32, // Quantum-resistant scoring
        _ => 100, // 112+ bits = NIST maximum security strength
        // _ => 100, // 256+ bits = Quantum-resistant (128-bit post-Grover)
    }
}

/// Get strength label for a score
pub fn strength_label(score: u32) -> &'static str {
    match score {
        0..=10 => "Why?",
        11..=20 => "Very Weak",
        21..=40 => "Weak",
        41..=60 => "Fair",
        61..=80 => "Strong",
        _ => "Very Strong",
        // 81..=99 => "Very Strong",
        // _ => "Quantum Resistant",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default() {
        let policy = PasswordPolicy::default();
        let password = generate_password(&policy).unwrap();

        assert_eq!(password.len(), 20);
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_pin() {
        let policy = PasswordPolicy::pin(6);
        let password = generate_password(&policy).unwrap();

        assert_eq!(password.len(), 6);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_readable() {
        let policy = PasswordPolicy::readable(16);
        let password = generate_password(&policy).unwrap();

        assert_eq!(password.len(), 16);
        // Should not contain ambiguous characters
        assert!(!password.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn test_generate_passphrase() {
        let passphrase = generate_passphrase(4, "-");
        let words: Vec<&str> = passphrase.split('-').collect();

        assert_eq!(words.len(), 4);
        assert!(words.iter().all(|w| WORDLIST.contains(w)));
    }

    #[test]
    fn test_password_strength_short_complex() {
        // Short password with full variety should still be weak
        let score = password_strength("Aa1!");
        assert!(score <= 40, "4-char password scored {score}, should be <= 40");
    }

    #[test]
    fn test_password_strength_long_simple() {
        // Long lowercase-only password should be fair/strong due to length
        let score = password_strength("abcdefghijklmnopqrstuvwxyz");
        assert!(score >= 40, "26-char password scored {score}, should be >= 40");
    }

    #[test]
    fn test_password_strength_strong() {
        let score = password_strength("MyP@ssw0rd!2026XyZ");
        assert!(score > 60, "Complex 18-char password scored {score}, should be > 60");
    }

    #[test]
    fn test_password_strength_empty() {
        assert_eq!(password_strength(""), 0);
    }

    #[test]
    fn test_unique_passwords() {
        let policy = PasswordPolicy::default();
        let p1 = generate_password(&policy).unwrap();
        let p2 = generate_password(&policy).unwrap();

        assert_ne!(p1, p2);
    }

    #[test]
    fn test_empty_charset_error() {
        let policy = PasswordPolicy {
            length: 16,
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            custom_symbols: None,
            exclude_ambiguous: false,
        };

        assert_eq!(generate_password(&policy), Err(PasswordError::EmptyCharset));
    }

    #[test]
    fn test_custom_symbols_ambiguous_filter() {
        let policy = PasswordPolicy {
            length: 100,
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: true,
            custom_symbols: Some("|!@#".to_string()),
            exclude_ambiguous: true,
        };

        let password = generate_password(&policy).unwrap();
        // Should not contain | since it's in AMBIGUOUS
        assert!(!password.contains('|'), "Password should not contain ambiguous '|'");
    }

    #[test]
    fn test_strength_labels() {
        assert_eq!(strength_label(15), "Very Weak");
        assert_eq!(strength_label(30), "Weak");
        assert_eq!(strength_label(50), "Fair");
        assert_eq!(strength_label(70), "Strong");
        assert_eq!(strength_label(90), "Very Strong");
    }

    #[test]
    fn test_default_policy_strength() {
        let policy = PasswordPolicy::default();
        for _ in 0..10 {
            let password = generate_password(&policy).unwrap();
            let score = password_strength(&password);
            println!("Password: {password} | Score: {score}");
            assert_eq!(score, 100, "Password '{password}' scored {score}");
        }
    }
}
