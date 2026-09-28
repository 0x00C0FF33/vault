use std::path::PathBuf;
use std::time::Duration;

use crate::ui::components::form::SecretReplacement;

pub struct AppConfig {
    pub vault_path: PathBuf,
    pub auto_lock_timeout: Duration,
    pub clipboard_timeout: Duration,
    pub password_visibility_timeout: Duration,
}

impl Default for AppConfig {
    fn default() -> Self {
        let vault_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vault")
            .join("vault.db");

        Self {
            vault_path,
            auto_lock_timeout: Duration::from_mins(3),
            clipboard_timeout: Duration::from_secs(15),
            password_visibility_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PendingAction {
    DeleteCredential(String),
    /// Saving the open edit form would overwrite the stored secret.
    SaveReplacingSecret(SecretReplacement),
}

impl PendingAction {
    pub fn confirm_message(&self) -> &'static str {
        match self {
            Self::DeleteCredential(_) => "Delete this credential?",
            Self::SaveReplacingSecret(SecretReplacement::Generated) => {
                "Secret was generated. Overwrite the old one?"
            }
            Self::SaveReplacingSecret(SecretReplacement::Changed) => {
                "Secret was changed. Overwrite the old one?"
            }
        }
    }

    /// Declining a save goes back to the form it came from, edits intact.
    pub fn returns_to_form(&self) -> bool {
        matches!(self, Self::SaveReplacingSecret(_))
    }
}
