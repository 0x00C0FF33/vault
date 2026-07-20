use std::path::PathBuf;
use std::time::Duration;

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
}

impl PendingAction {
    pub fn confirm_message(&self) -> &'static str {
        match self {
            Self::DeleteCredential(_) => "Delete this credential?",
        }
    }
}
