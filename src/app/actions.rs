use std::time::Instant;

use crate::db::AuditAction;
use crate::input::keymap::{parse_command, Action};
use crate::ui::components::scroll::MAX_SCROLLOFF;
use crate::ui::{components::MessageType, renderer::View};

use super::config::PendingAction;
use super::App;

impl App {
    pub fn execute_action(&mut self, action: Action) -> Result<bool, Box<dyn std::error::Error>> {
        match action {
            Action::MoveUp => self.move_list(super::super::ui::components::list::ListViewState::move_up)?,
            Action::MoveDown => self.move_list(super::super::ui::components::list::ListViewState::move_down)?,
            Action::MoveToTop => self.move_list(super::super::ui::components::list::ListViewState::move_to_top)?,
            Action::MoveToBottom => self.move_list(super::super::ui::components::list::ListViewState::move_to_bottom)?,
            Action::PageUp => self.page_move(|ls, h| ls.page_up(h.saturating_sub(1)))?,
            Action::PageDown => self.page_move(|ls, h| ls.page_down(h.saturating_sub(1)))?,
            Action::HalfPageUp => self.page_move(|ls, h| ls.page_up(h / 2))?,
            Action::HalfPageDown => self.page_move(|ls, h| ls.page_down(h / 2))?,

            Action::ShowHelp => self.show_help(),
            Action::ShowTags => self.show_tags()?,
            Action::ShowLogs => self.show_logs()?,
            Action::ChangePassword => self.request_password_change(),

            Action::Select => self.select_credential()?,
            Action::Back => self.go_back()?,

            Action::CopyPassword => self.copy_secret()?,
            Action::CopyUsername => self.copy_username()?,
            Action::CopyTotp => self.copy_totp()?,
            Action::CopyTotpUri => self.copy_totp_uri()?,
            Action::TogglePasswordVisibility => self.toggle_password()?,
            Action::ToggleUsernameVisibility => self.toggle_username(),
            Action::SetScrolloff(lines) => self.set_scrolloff(lines),

            Action::Delete => self.initiate_delete(),
            Action::New => self.new_credential(),
            Action::Edit => self.edit_credential()?,

            Action::EnterCommand => self.mode_state.enter_command_mode(),
            Action::EnterSearch => self.mode_state.enter_search_mode(),

            Action::ExecuteCommand(cmd) => return self.execute_action(parse_command(&cmd)),
            Action::Search(query) => self.search_credentials(&query)?,
            Action::FilterByType(cred_type) => self.filter_by_type(cred_type)?,

            Action::GeneratePassword => self.generate_and_copy_password()?,

            Action::Confirm => self.handle_confirm()?,
            Action::Cancel => self.cancel_pending(),

            Action::Clear => self.set_message("", MessageType::Info),
            Action::Quit => return Ok(self.quit()),
            Action::ForceQuit => return Ok(true),
            Action::Lock => self.lock(),
            Action::Export => self.export(),
            Action::Refresh => self.refresh_data()?,
            Action::VerifyAudit => self.verify_and_report_audit(),
            Action::Invalid(cmd) => self.set_message(&format!("Unknown command: {cmd}"), MessageType::Error),

            _ => {}
        }

        Ok(false)
    }

    fn move_list(&mut self, f: impl FnOnce(&mut crate::ui::components::ListViewState)) -> Result<(), Box<dyn std::error::Error>> {
        f(&mut self.list_state);
        self.update_selected_detail()
    }

    fn page_move(&mut self, f: impl FnOnce(&mut crate::ui::components::ListViewState, usize)) -> Result<(), Box<dyn std::error::Error>> {
        let visible = self.list_visible_height();
        f(&mut self.list_state, visible);
        self.update_selected_detail()
    }

    pub fn list_visible_height(&self) -> usize {
        (self.terminal_size.height as usize).saturating_sub(4)
    }

    fn show_help(&mut self) {
        self.help_state.home();
        self.help_state.scroll.pending_g = false;
        self.mode_state.enter_help_mode();
    }

    fn show_tags(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.vault.is_unlocked() {
            self.set_message("Vault must be unlocked", MessageType::Error);
            return Ok(());
        }
        self.load_tags()?;
        self.tags_state.scroll.pending_g = false;
        self.mode_state.enter_tags_mode();
        Ok(())
    }

    fn show_logs(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.vault.is_unlocked() {
            self.set_message("Vault must be unlocked", MessageType::Error);
            return Ok(());
        }
        self.load_audit_logs()?;
        self.logs_state.scroll.pending_g = false;
        self.mode_state.enter_logs_mode();
        Ok(())
    }

    fn request_password_change(&mut self) {
        if self.vault.is_unlocked() {
            self.wants_password_change = true;
        } else {
            self.set_message("Vault must be unlocked", MessageType::Error);
        }
    }

    pub fn select_credential(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else {
            return Ok(());
        };
        let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());
        self.log_audit(AuditAction::Read, Some(&id), Some(&name), username.as_deref(), None)?;
        self.view = View::Detail;
        Ok(())
    }

    fn go_back(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.view == View::Detail {
            self.view = View::List;
            Ok(())
        } else if self.has_active_filters() {
            self.clear_filters()
        } else {
            Ok(())
        }
    }

    fn toggle_password(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.password_visible {
            self.password_visible = false;
            self.password_hide_at = None;
        } else {
            self.password_visible = true;
            self.password_hide_at = Some(Instant::now() + self.config.password_visibility_timeout);
        }
        
        self.update_selected_detail()?;
        
        if let Some(cred) = &self.selected_credential {
            let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());
            self.log_audit(AuditAction::Read, Some(&id), Some(&name), username.as_deref(), Some("Toggle Password Visibility"))?;
        }
        Ok(())
    }

    fn toggle_username(&mut self) {
        let visible = !self.list_state.usernames_visible();
        self.list_state.set_usernames_visible(visible);

        if let Err(e) = self.save_usernames_visible() {
            self.set_message(&format!("Usernames toggled, but not saved: {e}"), MessageType::Error);
            return;
        }
        let msg = if visible { "Usernames shown" } else { "Usernames hidden" };
        self.set_message(msg, MessageType::Info);
    }

    fn set_scrolloff(&mut self, lines: usize) {
        if lines > MAX_SCROLLOFF {
            self.set_message(&format!("scrolloff must be at most {MAX_SCROLLOFF}"), MessageType::Error);
            return;
        }
        self.scrolloff = lines;

        if let Err(e) = self.save_scrolloff() {
            self.set_message(&format!("scrolloff={lines}, but not saved: {e}"), MessageType::Error);
            return;
        }
        self.set_message(&format!("scrolloff={lines}"), MessageType::Info);
    }

    fn initiate_delete(&mut self) {
        let Some(idx) = self.list_state.selected() else { return };
        let Some(item) = self.credential_items.get(idx) else { return };

        self.pending_action = Some(PendingAction::DeleteCredential(item.id.clone()));
        self.mode_state.enter_confirm_mode();
    }

    fn cancel_pending(&mut self) {
        let pending = self.pending_action.take();
        if pending.as_ref().is_some_and(PendingAction::returns_to_form) {
            self.mode_state.enter_insert_mode();
            return;
        }
        self.mode_state.enter_normal_mode();
    }

    fn handle_confirm(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(action) = self.pending_action.take() else {
            self.mode_state.enter_normal_mode();
            return Ok(());
        };

        match action {
            PendingAction::DeleteCredential(id) => self.delete_credential(&id)?,
            PendingAction::SaveReplacingSecret(_) => self.save_credential_form()?,
        }

        self.mode_state.enter_normal_mode();
        Ok(())
    }

    fn quit(&mut self) -> bool {
        self.should_quit = true;
        true
    }

    fn verify_and_report_audit(&mut self) {
        let (msg, msg_type) = match self.verify_audit_logs() {
            Ok((0, total)) => (format!("Audit OK: {total} logs verified"), MessageType::Success),
            Ok((tampered, total)) => (format!("Warning: {tampered} of {total} logs may be tampered!"), MessageType::Error),
            Err(e) => (format!("Audit check failed: {e}"), MessageType::Error),
        };
        self.set_message(&msg, msg_type);
    }
}
