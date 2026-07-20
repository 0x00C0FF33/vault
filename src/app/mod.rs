//! Application State
//!
//! Core application logic tying together vault, UI, and input.

mod actions;
mod clipboard;
mod config;
mod credentials_handler;
mod input;

use std::time::{Duration, Instant};

use ratatui::{layout::Rect, Frame};
use crossterm::event::MouseEvent;

use crate::db::models::Credential;
use crate::db::AuditAction;
use crate::input::modes::ModeState;
use crate::input::keymap::{mouse_action, Action};
use crate::ui::components::help::HelpState;
use crate::ui::components::logs::LogsState;
use crate::ui::components::tags::TagsState;
use crate::ui::components::{
    CredentialDetail, CredentialForm, CredentialItem, 
    ExportDialog, ListViewState, MessageType,
};
use crate::ui::renderer::{Renderer, UiState, View};
use crate::vault::audit;
use crate::vault::credential::DecryptedCredential;
use crate::vault::manager::VaultState;
use crate::vault::Vault;

pub use config::{AppConfig, PendingAction};

#[derive(Default)]
pub struct ClickState {
    last_index: Option<usize>,
    last_time: Option<Instant>,
}

pub struct App {
    pub config: AppConfig,
    pub vault: Vault,
    pub mode_state: ModeState,
    pub view: View,
    pub list_area: Option<Rect>,
    pub click_state: ClickState,
    pub terminal_size: Rect,
    pub list_state: ListViewState,
    pub credentials: Vec<Credential>,
    pub credential_items: Vec<CredentialItem>,
    pub selected_credential: Option<DecryptedCredential>,
    pub selected_detail: Option<CredentialDetail>,
    pub search_query: Option<String>,
    pub filter_tags: Option<Vec<String>>,
    pub message: Option<(String, MessageType, Instant)>,
    pub pending_action: Option<PendingAction>,
    pub password_visible: bool,
    pub password_hide_at: Option<Instant>,
    pub last_totp_tick: Instant,
    pub should_quit: bool,
    pub credential_form: Option<CredentialForm>,
    pub wants_password_change: bool,
    pub help_state: HelpState,
    pub logs_state: LogsState,
    pub tags_state: TagsState,
    pub export_dialog: Option<ExportDialog>,
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        let vault_config = crate::vault::VaultConfig::with_path(&config.vault_path);

        Self {
            vault: Vault::new(vault_config),
            config,
            mode_state: ModeState::new(),
            view: View::List,
            list_area: None,
            click_state: ClickState::default(),
            terminal_size: Rect::default(),
            list_state: ListViewState::new(),
            credentials: Vec::new(),
            credential_items: Vec::new(),
            selected_credential: None,
            selected_detail: None,
            search_query: None,
            filter_tags: None,
            message: None,
            pending_action: None,
            password_visible: false,
            password_hide_at: None,
            last_totp_tick: Instant::now(),
            should_quit: false,
            credential_form: None,
            wants_password_change: false,
            help_state: HelpState::new(),
            logs_state: LogsState::new(),
            tags_state: TagsState::new(),
            export_dialog: None,
        }
    }

        pub fn handle_mouse_event(&mut self, event: MouseEvent) -> bool {
        let action = mouse_action(event);
        let Action::Click(col, row) = action else {
            let _ = self.execute_action(action);
            return false;
        };
        self.handle_click(col, row)
    }

    fn handle_click(&mut self, col: u16, row: u16) -> bool {
        let Some(index) = self.hit_test_list(col, row) else {
            return false;
        };

        let is_double = self.is_double_click(index);
        self.click_state.last_index = Some(index);
        self.click_state.last_time = Some(Instant::now());

        self.list_state.select(Some(index));
        let _ = self.update_selected_detail();

        if is_double {
            let _ = self.select_credential();
        }

        false
    }

    fn hit_test_list(&self, col: u16, row: u16) -> Option<usize> {
        let area = self.list_area?;
        if col < area.x || col >= area.x + area.width {
            return None;
        }
        if row <= area.y || row >= area.y + area.height - 1 {
            return None;
        }
        let offset = self.list_state.list_state_ref().offset();
        let index = offset + (row - area.y - 1) as usize;
        if index >= self.credentials.len() { return None; }
        Some(index)
    }

    fn is_double_click(&self, index: usize) -> bool {
        let Some(last_index) = self.click_state.last_index else { return false };
        let Some(last_time) = self.click_state.last_time else { return false };
        last_index == index && last_time.elapsed() < Duration::from_millis(300)
    }

    pub fn needs_init(&self) -> bool {
        self.vault.state() == VaultState::Uninitialized
    }

    pub fn is_locked(&self) -> bool {
        self.vault.state() == VaultState::Locked
    }

    pub fn initialize(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vault.initialize(password)?;
        self.log_audit(AuditAction::Unlock, None, None, None, Some("Vault Initialized!"))?;
        self.refresh_data()
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vault.unlock(password)?;
        self.handle_failed_attempts()?;
        self.check_audit_integrity();
        self.log_audit(AuditAction::Unlock, None, None, None, None)?;
        self.refresh_data()?;
        self.update_selected_detail()
    }

    fn handle_failed_attempts(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some((count, timestamp)) = self.vault.take_pending_failed_attempts()? else {
            return Ok(());
        };

        let details = format!("{count} unlock attempt(s) on {timestamp}");
        self.log_audit(AuditAction::FailedUnlock, None, None, None, Some(&details))?;
        self.set_message(&format!("Warning: {count} failed unlock attempt(s) detected"), MessageType::Error);
        Ok(())
    }

    fn check_audit_integrity(&mut self) {
        let Ok((tampered, total)) = self.verify_audit_logs() else { return };

        if tampered > 0 {
            self.set_message(
                &format!("Warning: {tampered} of {total} audit logs may be tampered"),
                MessageType::Error,
            );
            return;
        }

        // Entries can all verify while the log has been cut short; only the
        // signed head reveals that.
        if self.audit_head_is_intact() == Some(false) {
            self.set_message(
                "Warning: audit log has been truncated",
                MessageType::Error,
            );
        }
    }

    /// `None` when the check could not run, so a locked or erroring vault is
    /// not reported as tampering.
    fn audit_head_is_intact(&self) -> Option<bool> {
        let keys = self.vault.keys().ok()?;
        let audit_key = keys.derive_audit_key().ok()?;
        let db = self.vault.db().ok()?;
        crate::vault::audit::verify_chain_head(db.conn(), &audit_key).ok()
    }

    pub fn lock(&mut self) {
        let _ = self.log_audit(AuditAction::Lock, None, None, None, None);
        self.vault.lock();
        self.clear_credentials();
    }

    pub fn clear_filters(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let had_filters = self.has_active_filters();
        self.search_query = None;
        self.filter_tags = None;
        if had_filters {
            self.refresh_data()?;
            self.update_selected_detail()?;
        }
        Ok(())
    }

    pub fn has_active_filters(&self) -> bool {
        self.search_query.is_some() || self.filter_tags.is_some()
    }

    pub fn log_audit(
        &self,
        action: AuditAction,
        credential_id: Option<&str>,
        credential_name: Option<&str>,
        username: Option<&str>,
        details: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        audit::log_action(db.conn(), &audit_key, action, credential_id, credential_name, username, details)?;
        Ok(())
    }

    fn verify_audit_logs(&self) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        let results = audit::verify_all_logs(db.conn(), &audit_key)?;
        let total = results.len();
        let tampered = results.iter().filter(|(_, valid)| !valid).count();
        Ok((tampered, total))
    }

    fn load_audit_logs(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let _audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        let logs = crate::vault::audit::get_recent_logs(db.conn(), 500)?;
        self.logs_state.set_logs(logs);
        Ok(())
    }

    pub fn load_tags(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let all_credentials = crate::vault::search::get_all(db.conn())?;
        self.tags_state.set_tags_from_credentials(&all_credentials, self.filter_tags.as_deref());
        Ok(())
    }

    pub fn render(&mut self, frame: &mut Frame) {
        self.terminal_size = frame.area();
        self.check_message_expiry();

        let message = self.message.as_ref().map(|(m, t, _)| (m.as_str(), *t));
        let command_buffer = self.mode_state.mode.is_text_input().then(|| self.mode_state.get_buffer());
        let confirm_message = self.pending_action.as_ref().map(config::PendingAction::confirm_message);

        let mut state = UiState {
            view: self.view,
            mode: self.mode_state.mode,
            credentials: &self.credential_items,
            list_state: &mut self.list_state,
            list_area: &mut self.list_area,
            selected_detail: self.selected_detail.as_ref(),
            search_query: self.search_query.as_deref(),
            filter_tags: self.filter_tags.as_deref(),
            command_buffer,
            message,
            confirm_message,
            password_prompt: None,
            credential_form: self.credential_form.as_ref(),
            help_state: &self.help_state,
            logs_state: &self.logs_state,
            tags_state: &self.tags_state,
            export_dialog: self.export_dialog.as_ref(),
        };

        Renderer::render(frame, &mut state);
    }

    fn check_message_expiry(&mut self) {
        let expired = self
            .message
            .as_ref()
            .is_some_and(|(_, _, time)| time.elapsed() > Duration::from_secs(5));

        if expired {
            self.message = None;
        }
    }

    pub fn set_message(&mut self, msg: &str, msg_type: MessageType) {
        self.message = Some((msg.to_string(), msg_type, Instant::now()));
    }

    pub fn check_password_timeout(&mut self) {
        let Some(hide_at) = self.password_hide_at else { return };
        if Instant::now() < hide_at {
            return;
        }
        self.password_visible = false;
        self.password_hide_at = None;
        let _ = self.update_selected_detail();
    }

    pub fn should_auto_lock(&self) -> bool {
        self.vault.is_unlocked() && self.vault.time_since_activity() > self.config.auto_lock_timeout
    }

    pub fn tick_totp(&mut self) {
        // Only refresh once per second
        if self.last_totp_tick.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_totp_tick = Instant::now();
        self.refresh_totp_display();
    }

    pub fn refresh_totp_display(&mut self) {
        if self.view != View::Detail {
            return;
        }
        
        let Some(ref cred) = self.selected_credential else { return };
        if cred.totp_secret.is_none() { return; }
        
        // Only update TOTP fields in the existing detail
        if let Some(ref mut detail) = self.selected_detail {
            let (code, remaining) = credentials_handler::compute_totp(cred);
            detail.totp_code = code;
            detail.totp_remaining = remaining;
        }
    }
}
