//! Database Models
//!
//! Data structures for credentials and audit logs.

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

/// Credential type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Password,
    ApiKey,
    SshKey,
    Certificate,
    Note,
    Database,
    Custom,
}

impl CredentialType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::SshKey => "ssh_key",
            Self::Certificate => "certificate",
            Self::Note => "note",
            Self::Database => "database",
            Self::Custom => "custom",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            "api_key" => Self::ApiKey,
            "ssh_key" => Self::SshKey,
            "certificate" => Self::Certificate,
            "note" => Self::Note,
            "database" => Self::Database,
            _ => Self::Custom,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Password => "󰌋",
            Self::ApiKey => "󰯄",
            Self::SshKey => "󰣀",
            Self::Certificate => "󰄤",
            Self::Note => "󰎞",
            Self::Database => "󰆼",
            Self::Custom => "󰘓",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::ApiKey => "API Key",
            Self::SshKey => "SSH Key",
            Self::Certificate => "Certificate",
            Self::Note => "Note",
            Self::Database => "Database",
            Self::Custom => "Custom",
        }
    }
}

/// Credential model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub credential_type: CredentialType,
    pub username: Option<String>,
    pub encrypted_secret: String,
    pub encrypted_notes: Option<String>,
    pub encrypted_totp_secret: Option<String>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Local>,
    pub updated_at: DateTime<Local>,
    pub accessed_at: Option<DateTime<Local>>,
}

impl Credential {
    /// Create a new credential with generated ID
    pub fn new(
        name: String,
        credential_type: CredentialType,
        encrypted_secret: String,
    ) -> Self {
        let now = Local::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            credential_type,
            username: None,
            encrypted_secret,
            encrypted_notes: None,
            encrypted_totp_secret: None,
            url: None,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            accessed_at: None,
        }
    }
}

/// Audit action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Create,
    Read,
    Update,
    Delete,
    Copy,
    Export,
    Import,
    Unlock,
    Lock,
    FailedUnlock,
    /// A stored action string that did not match any known variant. Kept
    /// distinct so a corrupt or future-version row is never displayed as a
    /// routine read.
    Unknown,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Copy => "copy",
            Self::Export => "export",
            Self::Import => "import",
            Self::Unlock => "unlock",
            Self::Lock => "lock",
            Self::FailedUnlock => "failed_unlock",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "create" => Self::Create,
            "read" => Self::Read,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "copy" => Self::Copy,
            "export" => Self::Export,
            "import" => Self::Import,
            "unlock" => Self::Unlock,
            "lock" => Self::Lock,
            "failed_unlock" => Self::FailedUnlock,
            _ => Self::Unknown,
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub timestamp: DateTime<Local>,
    pub action: AuditAction,
    pub credential_id: Option<String>,
    pub credential_name: Option<String>,
    pub username: Option<String>,
    pub details: Option<String>,
    pub hmac: String,
}

impl AuditLog {
    /// Create a new audit log entry (ID assigned by database)
    pub fn new(
        action: AuditAction,
        credential_id: Option<String>,
        credential_name: Option<String>,
        username: Option<String>,
        details: Option<String>,
        hmac: String,
    ) -> Self {
        Self {
            id: 0,
            timestamp: Local::now(),
            action,
            credential_id,
            credential_name,
            username,
            details,
            hmac,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_type_roundtrip() {
        let types = [
            CredentialType::Password,
            CredentialType::ApiKey,
            CredentialType::SshKey,
            CredentialType::Certificate,
            CredentialType::Note,
            CredentialType::Database,
            CredentialType::Custom,
        ];

        for ct in types {
            assert_eq!(CredentialType::from_str(ct.as_str()), ct);
        }
    }

    #[test]
    fn test_audit_action_roundtrip() {
        let actions = [
            AuditAction::Create,
            AuditAction::Read,
            AuditAction::Update,
            AuditAction::Delete,
            AuditAction::Copy,
            AuditAction::Export,
            AuditAction::Import,
            AuditAction::Unlock,
            AuditAction::Lock,
            AuditAction::FailedUnlock,
            AuditAction::Unknown,
        ];

        for action in actions {
            assert_eq!(AuditAction::from_str(action.as_str()), action);
        }
    }

    #[test]
    fn test_audit_action_unrecognized_is_not_read() {
        // A corrupt or future-version row must not be reported as a routine
        // read, which would understate what the audit log shows.
        assert_eq!(AuditAction::from_str("frobnicate"), AuditAction::Unknown);
        assert_eq!(AuditAction::from_str(""), AuditAction::Unknown);
    }

    #[test]
    fn test_credential_new() {
        let cred = Credential::new(
            "Test".to_string(),
            CredentialType::Password,
            "encrypted".to_string(),
        );

        assert!(!cred.id.is_empty());
        assert_eq!(cred.name, "Test");
        assert_eq!(cred.credential_type, CredentialType::Password);
    }
}
