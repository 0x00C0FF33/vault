//! Export credentials in different formats with optional encryption.
//!
//! Encryption options:
//! - GPG (AES-256-GCM): `gpg -d export.gpg`
//! - age (ChaCha20-Poly1305): `age -d export.age`
//! - Plaintext: No encryption (dangerous!)

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use chrono::Local;
use serde::Serialize;

use crate::db::models::{Credential, CredentialType};

use super::{VaultError, VaultResult};

/// Export format for the credential data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON format
    Json,
    /// Human-readable plain text
    Text,
}

/// Encryption method for export
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportEncryption {
    /// No encryption (dangerous!)
    None,
    /// GPG symmetric encryption (AES-256)
    Gpg,
    /// age encryption (ChaCha20-Poly1305)
    Age,
}

impl ExportEncryption {
    pub fn file_extension(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Gpg => ".gpg",
            Self::Age => ".age",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::None => "None (plaintext)",
            Self::Gpg => "GPG (AES-256)",
            Self::Age => "age (ChaCha20-Poly1305)",
        }
    }
}

/// Decrypted credential for export (secrets in plaintext)
#[derive(Debug, Clone, Serialize)]
pub struct ExportCredential {
    pub name: String,
    pub credential_type: CredentialType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl ExportCredential {
    fn format_to_text(&self) -> String {
        let mut output = format!("Name: {}\n", self.name);

        if self.credential_type != CredentialType::Password {
            let _ = writeln!(output, "Type: {}", self.credential_type.display_name());
        }

        if let Some(username) = &self.username {
            let _ = writeln!(output, "Username: {username}");
        }

        let _ = writeln!(output, "Secret: {}", self.secret);

        if let Some(url) = &self.url {
            let _ = writeln!(output, "URL: {url}");
        }

        if !self.tags.is_empty() {
            let _ = writeln!(output, "Tags: {}", self.tags.join(", "));
        }

        if let Some(notes) = &self.notes {
            let _ = writeln!(output, "Notes: {notes}");
        }

        output
    }
}

/// Full export container
#[derive(Debug, Clone, Serialize)]
pub struct ExportData {
    pub exported_at: String,
    pub version: u32,
    pub credential_count: usize,
    pub credentials: Vec<ExportCredential>,
}

impl ExportData {
    pub fn new(credentials: Vec<ExportCredential>) -> Self {
        Self {
            exported_at: Local::now().format("%d-%b-%Y %H:%M").to_string(),
            version: 1,
            credential_count: credentials.len(),
            credentials,
        }
    }

    pub fn to_json(&self) -> VaultResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| VaultError::OperationFailed(format!("JSON serialization failed: {e}")))
    }

    pub fn to_text(&self) -> String {
        let header = format!(
            "# Vault Export - {}\n# {} credentials\n\n",
            self.exported_at, self.credential_count
        );

        let credentials: Vec<_> = self.credentials.iter().map(ExportCredential::format_to_text).collect();

        header + &credentials.join("\n---\n\n")
    }
}

pub fn gpg_available() -> bool {
    Command::new("gpg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

pub fn age_available() -> bool {
    Command::new("age")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn ensure_parent_dir(output_path: &Path) -> VaultResult<()> {
    let Some(parent) = output_path.parent() else {
        return Ok(());
    };

    if parent.as_os_str().is_empty() || parent.exists() {
        return Ok(());
    }

    std::fs::create_dir_all(parent)
        .map_err(|e| VaultError::IoError(format!("Failed to create directory: {e}")))
}

fn require_passphrase<'a>(passphrase: Option<&'a str>, method: &str) -> VaultResult<&'a str> {
    passphrase.ok_or_else(|| {
        VaultError::OperationFailed(format!("Passphrase required for {method} encryption"))
    })
}

pub fn export_to_file(
    data: &ExportData,
    format: ExportFormat,
    encryption: ExportEncryption,
    passphrase: Option<&str>,
    output_path: &Path,
) -> VaultResult<()> {
    ensure_parent_dir(output_path)?;

    let content = match format {
        ExportFormat::Json => data.to_json()?,
        ExportFormat::Text => data.to_text(),
    };

    match encryption {
        ExportEncryption::None => {
            std::fs::write(output_path, content).map_err(|e| VaultError::IoError(e.to_string()))
        }
        ExportEncryption::Gpg => {
            encrypt_with_gpg(&content, require_passphrase(passphrase, "GPG")?, output_path)
        }
        ExportEncryption::Age => {
            encrypt_with_age(&content, require_passphrase(passphrase, "age")?, output_path)
        }
    }
}

fn write_gpg_stdin(stdin: &mut std::process::ChildStdin, passphrase: &str, content: &str) -> VaultResult<()> {
    stdin.write_all(passphrase.as_bytes()).map_err(|e| VaultError::IoError(e.to_string()))?;
    stdin.write_all(b"\n").map_err(|e| VaultError::IoError(e.to_string()))?;
    stdin.write_all(content.as_bytes()).map_err(|e| VaultError::IoError(e.to_string()))
}

/// Encrypt data using GPG symmetric encryption (AES-256)
fn encrypt_with_gpg(content: &str, passphrase: &str, output_path: &Path) -> VaultResult<()> {
    if !gpg_available() {
        return Err(VaultError::OperationFailed(
            "gpg is not installed. Install it with: pacman -S gnupg".into(),
        ));
    }

    let mut child = Command::new("gpg")
        .args([
            "--symmetric",
            "--cipher-algo", "AES256",
            "--batch",
            "--yes",
            "--passphrase-fd", "0",
            "--output", output_path.to_str().unwrap_or("-"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| VaultError::IoError(format!("Failed to spawn gpg: {e}")))?;

    let stdin = child.stdin.as_mut()
        .ok_or_else(|| VaultError::IoError("Failed to open gpg stdin".into()))?;
    write_gpg_stdin(stdin, passphrase, content)?;

    let output = child.wait_with_output().map_err(|e| VaultError::IoError(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VaultError::OperationFailed(format!("gpg encryption failed: {stderr}")));
    }

    Ok(())
}

/// Encrypt data using age (ChaCha20-Poly1305)
fn encrypt_with_age(content: &str, passphrase: &str, output_path: &Path) -> VaultResult<()> {
    if !age_available() {
        return Err(VaultError::OperationFailed(
            "age is not installed. Install it with: pacman -S age".into(),
        ));
    }

    let mut child = Command::new("age")
        .args([
            "--passphrase",
            "--output", output_path.to_str().unwrap_or("-"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env("AGE_PASSPHRASE", passphrase)
        .spawn()
        .map_err(|e| VaultError::IoError(format!("Failed to spawn age: {e}")))?;

    let stdin = child.stdin.as_mut()
        .ok_or_else(|| VaultError::IoError("Failed to open age stdin".into()))?;
    stdin.write_all(content.as_bytes()).map_err(|e| VaultError::IoError(e.to_string()))?;

    let output = child.wait_with_output().map_err(|e| VaultError::IoError(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VaultError::OperationFailed(format!("age encryption failed: {stderr}")));
    }

    Ok(())
}

/// Helper to convert a Credential (with encrypted fields) to `ExportCredential`
/// The caller is responsible for decrypting the secret and notes before calling this
pub fn credential_to_export(
    cred: &Credential,
    decrypted_secret: String,
    decrypted_notes: Option<String>,
) -> ExportCredential {
    ExportCredential {
        name: cred.name.clone(),
        credential_type: cred.credential_type,
        username: cred.username.clone(),
        secret: decrypted_secret,
        notes: decrypted_notes,
        url: cred.url.clone(),
        tags: cred.tags.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn github_credential() -> ExportCredential {
        ExportCredential {
            name: "GitHub Token".into(),
            credential_type: CredentialType::ApiKey,
            username: Some("user".into()),
            secret: "ghp_xxxxxxxxxxxx".into(),
            notes: Some("Main account".into()),
            url: Some("https://github.com".into()),
            tags: vec!["dev".into(), "api".into()],
        }
    }

    fn gmail_credential() -> ExportCredential {
        ExportCredential {
            name: "Gmail".into(),
            credential_type: CredentialType::Password,
            username: Some("user@gmail.com".into()),
            secret: "supersecret123".into(),
            notes: None,
            url: None,
            tags: vec![],
        }
    }

    fn sample_credentials() -> Vec<ExportCredential> {
        vec![github_credential(), gmail_credential()]
    }

    fn sample_export_data() -> ExportData {
        ExportData::new(sample_credentials())
    }

    #[test]
    fn test_export_to_json() {
        let data = sample_export_data();
        let json = data.to_json().unwrap();

        assert!(json.contains("GitHub Token"));
        assert!(json.contains("ghp_xxxxxxxxxxxx"));
        assert!(json.contains("credential_count"));
    }

    #[test]
    fn test_export_to_text() {
        let data = sample_export_data();
        let text = data.to_text();

        assert!(text.contains("Name: GitHub Token"));
        assert!(text.contains("Type: API Key"));
        assert!(text.contains("Username: user"));
        assert!(text.contains("Secret: ghp_xxxxxxxxxxxx"));
        assert!(text.contains("Tags: dev, api"));

        assert!(text.contains("Name: Gmail"));
        assert!(text.contains("Secret: supersecret123"));

        let gmail_section = text.split("Gmail").nth(1).unwrap();
        let next_entry = gmail_section.split("---").next().unwrap();
        assert!(!next_entry.contains("Type:"));
    }

    #[test]
    fn test_plaintext_export() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("export.txt");

        let data = sample_export_data();
        export_to_file(&data, ExportFormat::Text, ExportEncryption::None, None, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("GitHub Token"));
    }

    #[test]
    fn test_json_export() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("export.json");

        let data = sample_export_data();
        export_to_file(&data, ExportFormat::Json, ExportEncryption::None, None, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["credential_count"], 2);
    }

    #[test]
    fn test_gpg_export() {
        if !gpg_available() {
            eprintln!("Skipping GPG test - gpg not installed");
            return;
        }

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("export.json.gpg");

        let data = sample_export_data();
        export_to_file(
            &data,
            ExportFormat::Json,
            ExportEncryption::Gpg,
            Some("testpassword"),
            &path,
        ).unwrap();

        assert!(path.exists());
        let content = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&content).contains("GitHub Token"));
    }

    #[test]
    fn test_age_export() {
        if !age_available() {
            eprintln!("Skipping age test - age not installed");
            return;
        }

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("export.json.age");

        let data = sample_export_data();
        export_to_file(
            &data,
            ExportFormat::Json,
            ExportEncryption::Age,
            Some("testpassword"),
            &path,
        ).unwrap();

        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("age-encryption.org"));
    }

    #[test]
    fn test_encryption_requires_passphrase() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("export.gpg");
        let data = sample_export_data();

        let result = export_to_file(&data, ExportFormat::Json, ExportEncryption::Gpg, None, &path);
        assert!(result.is_err());
    }
}
