use secrecy::ExposeSecret;
use std::path::Path;
use std::time::Instant;

use crate::crypto::{totp::{self, TotpSecret}, decrypt_string};
use crate::db::{models::{Credential, CredentialType}, AuditAction};
use crate::ui::{
    components::{
        ExportDialog,
        CredentialDetail,
        detail::TotpDisplay,
        CredentialForm,
        CredentialItem,
        MessageType,
        form::EditFormParams
    },
    renderer::View
};
use crate::vault::{
    credential::DecryptedCredential,
    export::{ExportData, ExportCredential, export_to_file, credential_to_export}
};
use crate::input::TextEditing;

use super::App;

impl App {
    pub fn refresh_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        
        let mut results = self.fetch_base_credentials(db)?;
        
        if let Some(ref query) = self.search_query {
            apply_search_filter(&mut results, query);
        }
        
        self.credentials = results;
        self.credential_items = self.credentials.iter().map(credential_to_item).collect();
        self.list_state.set_total(self.credential_items.len());
        Ok(())
    }

    /// Reload after the search or a filter changed: the list holds a
    /// different set of entries, so the old scroll position means nothing.
    pub fn reload_filtered(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.list_state.scroll_to_top();
        self.refresh_data()
    }

    fn fetch_base_credentials(&self, db: &crate::db::Database) -> Result<Vec<Credential>, Box<dyn std::error::Error>> {
        let mut results = match &self.filter_tags {
            Some(tags) if !tags.is_empty() => crate::vault::search::filter_by_tags(db.conn(), tags)?,
            _ => crate::vault::search::get_all(db.conn())?,
        };

        if let Some(cred_type) = self.filter_type {
            crate::vault::search::retain_type(&mut results, cred_type);
        }

        Ok(results)
    }

    pub fn clear_credentials(&mut self) {
        self.credentials.clear();
        self.credential_items.clear();
        self.selected_credential = None;
        self.selected_detail = None;
    }

    pub fn search_credentials(&mut self, query: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.search_query = if query.is_empty() { None } else { Some(query.to_string()) };
        self.reload_filtered()?;
        self.update_selected_detail()
    }

    pub fn filter_by_tag(&mut self, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        self.filter_tags = if tags.is_empty() { None } else { Some(tags.to_vec()) };
        self.reload_filtered()?;

        if !tags.is_empty() {
            self.set_message(&format_filter_message(tags), MessageType::Info);
        }
        self.update_selected_detail()
    }

    pub fn filter_by_type(&mut self, cred_type: Option<CredentialType>) -> Result<(), Box<dyn std::error::Error>> {
        self.filter_type = cred_type;
        self.reload_filtered()?;

        let message = match cred_type {
            Some(t) => format!("Filtered by type: {}", t.display_name()),
            None => "Type filter cleared".to_string(),
        };
        self.set_message(&message, MessageType::Info);
        self.update_selected_detail()
    }

    pub fn update_selected_detail(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(idx) = self.list_state.selected() else {
            self.selected_detail = None;
            return Ok(());
        };
        let Some(cred) = self.credentials.get(idx) else {
            self.selected_detail = None;
            return Ok(());
        };

        let key = self.vault.dek()?;
        let db = self.vault.db()?;
        let decrypted = crate::vault::credential::decrypt_credential(db.conn(), key, cred, false)?;

        self.selected_detail = Some(build_detail(&decrypted, self.password_visible));
        self.selected_credential = Some(decrypted);
        Ok(())
    }

    pub fn new_credential(&mut self) {
        self.credential_form = Some(CredentialForm::new());
        self.view = View::Form;
        self.mode_state.enter_insert_mode();
    }

    pub fn edit_credential(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(cred) = self.selected_credential.clone() {
            self.open_edit_form(&cred);
            return Ok(());
        }

        let Some(idx) = self.list_state.selected() else {
            return Ok(());
        };
        let Some(cred) = self.credentials.get(idx) else {
            return Ok(());
        };

        let key = self.vault.dek()?;
        let db = self.vault.db()?;
        let decrypted = crate::vault::credential::decrypt_credential(db.conn(), key, cred, false)?;
        self.open_edit_form(&decrypted);
        Ok(())
    }

    fn open_edit_form(&mut self, cred: &DecryptedCredential) {
        let form = CredentialForm::for_edit(EditFormParams {
            id: cred.id.clone(),
            name: cred.name.clone(),
            cred_type: cred.credential_type,
            username: cred.username.clone(),
            secret: cred.secret.as_ref().map(|s| s.expose_secret().to_string()).unwrap_or_default(),
            url: cred.url.clone(),
            tags: cred.tags.clone(),
            totp_secret: cred.totp_secret.as_ref().map(|s| s.expose_secret().to_string()),
            notes: cred.notes.as_ref().map(|s| s.expose_secret().to_string()),
            previous_view: self.view,
        });
        self.credential_form = Some(form);
        self.view = View::Form;
        self.mode_state.enter_insert_mode();
    }

    pub fn save_credential_form(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let form = self.credential_form.take().unwrap();
        let return_to = form.previous_view;
        let editing_id = form.editing_id.clone();

        match editing_id {
            Some(id) => self.do_update_credential(&form, &id)?,
            None => self.do_create_credential(&form)?,
        }

        self.view = return_to;
        self.mode_state.enter_normal_mode();
        
        self.refresh_data()?;
        
        self.update_selected_detail()
    }

    fn do_update_credential(&mut self, form: &CredentialForm, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let key = self.vault.dek()?;

        let mut cred = crate::db::get_credential(db.conn(), id)?;
        cred.name = form.get_name().to_string();
        cred.credential_type = form.credential_type;
        cred.username = form.get_username();
        cred.url = form.get_url();
        cred.tags = form.get_tags();

        crate::vault::credential::update_credential(
            db.conn(),
            key,
            &mut cred,
            Some(form.get_secret()),
            form.get_notes().as_deref(),
            form.get_totp_secret().as_deref(),
        )?;

        self.log_audit(AuditAction::Update, Some(id), Some(&cred.name), cred.username.as_deref(), None)?;
        self.set_message("Credential updated", MessageType::Success);
        Ok(())
    }

    fn do_create_credential(&mut self, form: &CredentialForm) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let key = self.vault.dek()?;

        let cred = crate::vault::credential::create_credential(
            db.conn(),
            key,
            form.get_name().to_string(),
            form.credential_type,
            form.get_secret(),
            form.get_username(),
            form.get_url(),
            form.get_tags(),
            form.get_notes().as_deref(),
            form.get_totp_secret().as_deref(),
        )?;

        self.log_audit(AuditAction::Create, Some(&cred.id), Some(&cred.name), cred.username.as_deref(), None)?;
        self.set_message("Credential created", MessageType::Success);
        Ok(())
    }

    pub fn delete_credential(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let cred = crate::db::get_credential(db.conn(), id)?;
        crate::db::delete_credential(db.conn(), id)?;
        self.log_audit(AuditAction::Delete, Some(id), Some(&cred.name), cred.username.as_deref(), None)?;
        
        let viewing_deleted = self.view == View::Detail
            && self.selected_credential.as_ref().is_some_and(|c| c.id == id);
        if viewing_deleted {
            self.view = View::List;
        }
        
        self.refresh_data()?;
        self.update_selected_detail()?;
        self.set_message("Credential deleted", MessageType::Success);
        Ok(())
    }

    pub fn copy_secret(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else { return Ok(()) };
        let Some(secret) = &cred.secret else { return Ok(()) };

        let text = secret.expose_secret().to_string();
        let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());

        super::clipboard::copy_with_timeout(&text, self.config.clipboard_timeout);
        self.log_audit(AuditAction::Copy, Some(&id), Some(&name), username.as_deref(), Some("Secret"))?;
        self.set_message(&format!("Password copied ({}s)", self.config.clipboard_timeout.as_secs()), MessageType::Success);
        Ok(())
    }

    pub fn copy_username(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else { return Ok(()) };
        let Some(username) = &cred.username else { return Ok(()) };

        let text = username.clone();
        let (id, name, u) = (cred.id.clone(), cred.name.clone(), cred.username.clone());

        super::clipboard::copy_with_timeout(&text, self.config.clipboard_timeout);
        self.log_audit(AuditAction::Copy, Some(&id), Some(&name), u.as_deref(), Some("Username"))?;
        self.set_message(&format!("Username copied ({}s)", self.config.clipboard_timeout.as_secs()), MessageType::Success);
        Ok(())
    }

    pub fn copy_totp(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else { return Ok(()) };
        let Some(totp_input) = &cred.totp_secret else {
            self.set_message("No TOTP secret configured", MessageType::Error);
            return Ok(());
        };

        let totp_secret = parse_totp_secret(totp_input.expose_secret(), &cred.name);
        let totp_secret = match totp_secret {
            Ok(s) => s,
            Err(msg) => { self.set_message(&msg, MessageType::Error); return Ok(()); }
        };

        let code = match totp::generate_totp(&totp_secret) {
            Ok(c) => c,
            Err(e) => { self.set_message(&format!("TOTP generation failed: {e}"), MessageType::Error); return Ok(()); }
        };
        
        let remaining = totp::time_remaining(&totp_secret);
        let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());

        super::clipboard::copy_with_timeout(&code, self.config.clipboard_timeout);
        self.log_audit(AuditAction::Copy, Some(&id), Some(&name), username.as_deref(), Some("TOTP"))?;
        self.set_message(&format!("TOTP copied: {code} ({remaining}s remaining)"), MessageType::Success);
        Ok(())
    }

    pub fn copy_totp_uri(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else { return Ok(()) };
        let Some(totp_input) = &cred.totp_secret else {
            self.set_message("No TOTP secret configured", MessageType::Error);
            return Ok(());
        };

        let totp_secret = parse_totp_secret(totp_input.expose_secret(), &cred.name);
        let totp_secret = match totp_secret {
            Ok(s) => s,
            Err(msg) => { self.set_message(&msg, MessageType::Error); return Ok(()); }
        };

        let uri = match totp_secret.to_uri() {
            Ok(u) => u,
            Err(e) => { self.set_message(&format!("Failed to generate URI: {e}"), MessageType::Error); return Ok(()); }
        };

        let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());

        super::clipboard::copy_with_timeout(&uri, self.config.clipboard_timeout);
        self.log_audit(AuditAction::Copy, Some(&id), Some(&name), username.as_deref(), Some("TOTP URI"))?;
        self.set_message(&format!("TOTP URI copied ({}s)", self.config.clipboard_timeout.as_secs()), MessageType::Success);
        Ok(())
    }

    pub fn generate_and_copy_password(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let password = generate_secret()?;
        super::clipboard::copy_with_timeout(&password, self.config.clipboard_timeout);
        self.set_message(
            &format!("Generated: {} (copied for {}s)", password, self.config.clipboard_timeout.as_secs()),
            MessageType::Success,
        );
        Ok(())
    }

    /// Fill the open form's secret with a generated password, shown for the
    /// same time `Ctrl+s` reveals a secret in the detail view.
    pub fn generate_secret_in_form(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let password = generate_secret()?;
        let timeout = self.config.password_visibility_timeout;
        let Some(form) = self.credential_form.as_mut() else { return Ok(()) };

        form.fill_generated_secret(password, Instant::now() + timeout);
        self.set_message(&format!("Secret generated (hidden in {}s)", timeout.as_secs()), MessageType::Success);
        Ok(())
    }

    pub fn export(&mut self) {
        if !self.vault.is_unlocked() {
            self.set_message("Vault must be unlocked", MessageType::Error);
            return;
        }
        self.export_dialog = Some(ExportDialog::new());
        self.mode_state.enter_export_mode();
    }

    pub fn execute_export(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let dialog = self.export_dialog.as_ref().ok_or("No export dialog")?;

        if let Err(e) = dialog.validate() {
            self.set_export_error(e);
            return Ok(());
        }

        let export_creds = self.build_export_credentials()?;
        let data = ExportData::new(export_creds);

        Self::write_export_file(&data, dialog)?;

        let path = dialog.path.clone();
        self.finalize_export(path.content())?;

        Ok(())
    }
    
    fn set_export_error(&mut self, error: String) {
        if let Some(d) = self.export_dialog.as_mut() {
            d.error = Some(error);
        }
    }
    
    fn build_export_credentials(&self) -> Result<Vec<ExportCredential>, Box<dyn std::error::Error>> {
        let dek = self.vault.dek()?;
        let mut export_creds = Vec::new();
        
        for cred in &self.credentials {
            let secret = decrypt_string(dek.as_ref(), &cred.encrypted_secret)?;
            let notes = Self::decrypt_notes_if_present(dek.as_ref(), cred)?;
            export_creds.push(credential_to_export(cred, secret, notes));
        }
        
        Ok(export_creds)
    }
    
    fn decrypt_notes_if_present(
        dek: &[u8],
        cred: &Credential,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        match &cred.encrypted_notes {
            Some(n) => Ok(Some(decrypt_string(dek, n)?)),
            None => Ok(None),
        }
    }
    
    fn write_export_file(
        data: &ExportData,
        dialog: &ExportDialog,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let passphrase_opt = dialog.get_passphrase();
        let passphrase = passphrase_opt.as_ref().map(secrecy::ExposeSecret::expose_secret);
        export_to_file(data, dialog.format, dialog.encryption, passphrase, Path::new(dialog.path.content()))?;
        Ok(())
    }
    
    fn finalize_export(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let count = self.credentials.len();
        let detail = if self.has_active_filters() {
            format!("Exported {count} credential(s) (filtered) to {path}")
        } else {
            format!("Exported {count} credential(s) to {path}")
        };
        self.log_audit(AuditAction::Export, None, None, None, Some(&detail))?;
        self.set_message(&detail, MessageType::Success);
        self.export_dialog = None;
        self.mode_state.enter_normal_mode();
        Ok(())
    }
    
    pub fn cancel_export(&mut self) {
        self.export_dialog = None;
        self.mode_state.enter_normal_mode();
    }
}

fn parse_totp_secret(input: &str, name: &str) -> Result<TotpSecret, String> {
    TotpSecret::from_user_input(input, name, "Vault")
        .map_err(|e| format!("TOTP error: {e}"))
}

fn apply_search_filter(results: &mut Vec<Credential>, query: &str) {
    if query.is_empty() {
        return;
    }
    let query_lower = query.to_lowercase();
    results.retain(|c| {
        c.name.to_lowercase().contains(&query_lower)
            || c.username.as_ref().is_some_and(|u| u.to_lowercase().contains(&query_lower))
            || c.url.as_ref().is_some_and(|u| u.to_lowercase().contains(&query_lower))
            || c.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
    });
}

fn format_filter_message(tags: &[String]) -> String {
    if tags.len() == 1 {
        return format!("Filtered by tag: {}", tags[0]);
    }
    format!("Filtered by tags: {}", tags.join(", "))
}

pub fn credential_to_item(cred: &Credential) -> CredentialItem {
    CredentialItem {
        id: cred.id.clone(),
        name: cred.name.clone(),
        username: cred.username.clone(),
        credential_type: cred.credential_type,
    }
}

/// The one policy behind every generated secret, so `:gen` and the form's
/// Ctrl+g cannot drift apart.
fn generate_secret() -> Result<String, Box<dyn std::error::Error>> {
    Ok(crate::crypto::generate_password(&crate::crypto::PasswordPolicy::default())?)
}

pub fn build_detail(cred: &DecryptedCredential, password_visible: bool) -> CredentialDetail {
    let totp = compute_totp(cred);

    CredentialDetail {
        name: cred.name.clone(),
        credential_type: cred.credential_type,
        username: cred.username.clone(),
        secret: cred.secret.as_ref().map(|s| s.expose_secret().to_string()),
        secret_visible: password_visible,
        url: cred.url.clone(),
        notes: cred.notes.as_ref().map(|s| s.expose_secret().to_string()),
        tags: cred.tags.clone(),
        created_at: cred.created_at.format("%d-%b-%Y %H:%M").to_string(),
        updated_at: cred.updated_at.format("%d-%b-%Y %H:%M").to_string(),
        totp,
    }
}

pub fn compute_totp(cred: &DecryptedCredential) -> TotpDisplay {
    let Some(ref totp_input) = cred.totp_secret else {
        return TotpDisplay::Absent;
    };

    let parsed = TotpSecret::from_user_input(totp_input.expose_secret(), &cred.name, "Vault");
    let totp_secret = match parsed {
        Ok(secret) => secret,
        Err(e) => return TotpDisplay::Unavailable(e.to_string()),
    };

    match totp::generate_totp(&totp_secret) {
        Ok(code) => TotpDisplay::Code {
            code,
            seconds_remaining: totp::time_remaining(&totp_secret),
        },
        Err(e) => TotpDisplay::Unavailable(e.to_string()),
    }
}

#[cfg(test)]
mod totp_display_tests {
    use super::*;
    use chrono::Local;
    use secrecy::SecretString;

    fn credential_with_totp(totp: Option<&str>) -> DecryptedCredential {
        DecryptedCredential {
            id: "id".to_string(),
            name: "Example".to_string(),
            credential_type: CredentialType::Password,
            username: None,
            secret: None,
            notes: None,
            totp_secret: totp.map(SecretString::from),
            url: None,
            tags: Vec::new(),
            created_at: Local::now(),
            updated_at: Local::now(),
        }
    }

    #[test]
    fn a_credential_without_a_totp_secret_is_absent() {
        assert_eq!(compute_totp(&credential_with_totp(None)), TotpDisplay::Absent);
    }

    #[test]
    fn a_valid_secret_yields_a_code_and_countdown() {
        let display = compute_totp(&credential_with_totp(Some("JBSWY3DPEHPK3PXP")));

        let TotpDisplay::Code { code, seconds_remaining } = display else {
            panic!("expected a code, got {display:?}");
        };
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&seconds_remaining));
    }

    /// A broken secret previously rendered as nothing at all, which is what a
    /// credential with no TOTP also renders as — leaving no way to tell a
    /// misconfigured entry from one that was never configured.
    #[test]
    fn an_unparseable_secret_reports_why_instead_of_rendering_nothing() {
        let display = compute_totp(&credential_with_totp(Some("not valid base32 !!!")));

        assert_ne!(
            display,
            TotpDisplay::Absent,
            "a broken secret must not look identical to having none"
        );

        let TotpDisplay::Unavailable(reason) = display else {
            panic!("expected a reason, got {display:?}");
        };
        assert!(reason.contains("base32"), "reason should name the problem: {reason}");
    }
}

#[cfg(test)]
mod search_filter_tests {
    use super::*;
    use chrono::Local;

    fn credential(name: &str, username: Option<&str>, url: Option<&str>, tags: &[&str]) -> Credential {
        Credential {
            id: name.to_string(),
            name: name.to_string(),
            credential_type: CredentialType::Password,
            username: username.map(ToString::to_string),
            encrypted_secret: String::new(),
            encrypted_notes: None,
            encrypted_totp_secret: None,
            url: url.map(ToString::to_string),
            tags: tags.iter().map(ToString::to_string).collect(),
            created_at: Local::now(),
            updated_at: Local::now(),
            accessed_at: None,
        }
    }

    fn matching_names(query: &str) -> Vec<String> {
        let mut results = vec![
            credential("GitHub", Some("octocat"), Some("https://github.com"), &["dev"]),
            credential("Bank", Some("alice"), Some("https://examplebank.com"), &["money"]),
            credential("Mail", None, None, &["personal"]),
        ];
        apply_search_filter(&mut results, query);
        results.into_iter().map(|c| c.name).collect()
    }

    #[test]
    fn matches_on_name() {
        assert_eq!(matching_names("git"), vec!["GitHub"]);
    }

    #[test]
    fn matches_on_username() {
        assert_eq!(matching_names("octo"), vec!["GitHub"]);
    }

    /// Searching by domain once found nothing: the filter did not consult url
    /// even though it is one of the columns stored in the clear.
    #[test]
    fn matches_on_url() {
        assert_eq!(matching_names("examplebank"), vec!["Bank"]);
    }

    #[test]
    fn matches_on_tag() {
        assert_eq!(matching_names("personal"), vec!["Mail"]);
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(matching_names("GITHUB"), vec!["GitHub"]);
    }

    /// Substring rather than prefix matching: a fragment from the middle of a
    /// name still finds it, which a prefix index would not. This is why the
    /// search is an in-memory filter and not a database query.
    #[test]
    fn matches_a_fragment_inside_a_word() {
        assert_eq!(matching_names("hub"), vec!["GitHub"]);
    }

    #[test]
    fn an_empty_query_keeps_everything() {
        assert_eq!(matching_names("").len(), 3);
    }

    #[test]
    fn a_query_matching_nothing_empties_the_list() {
        assert!(matching_names("zzz").is_empty());
    }
}

#[cfg(test)]
mod list_position_tests {
    use ratatui::{backend::TestBackend, Terminal};
    use tempfile::TempDir;

    use crate::app::{App, AppConfig};
    use crate::db::models::CredentialType;
    use crate::input::keymap::Action;

    const PASSWORD: &str = "test_password";

    /// 16 rows leaves 12 visible list rows, so 30 credentials must scroll.
    fn vault_with_credentials(dir: &TempDir, count: usize) -> (App, Terminal<TestBackend>) {
        let mut app = App::new(AppConfig { vault_path: dir.path().join("vault.db"), ..AppConfig::default() });
        app.initialize(PASSWORD).unwrap();
        for i in 0..count {
            let (db, dek) = (app.vault.db().unwrap(), app.vault.dek().unwrap());
            crate::vault::credential::create_credential(
                db.conn(), dek, format!("item{i:02}"), CredentialType::Password,
                "secret", None, None, Vec::new(), None, None,
            ).unwrap();
        }
        app.refresh_data().unwrap();
        (app, Terminal::new(TestBackend::new(40, 16)).unwrap())
    }

    fn press(app: &mut App, terminal: &mut Terminal<TestBackend>, action: &Action, times: usize) {
        for _ in 0..times {
            app.execute_action(action.clone()).unwrap();
            terminal.draw(|frame| app.render(frame)).unwrap();
        }
    }

    /// Screen row the selected credential is drawn on.
    fn cursor_row(app: &mut App, terminal: &mut Terminal<TestBackend>) -> u16 {
        terminal.draw(|frame| app.render(frame)).unwrap();
        let selected = app.list_state.selected().unwrap();
        let name = app.credential_items[selected].name.clone();
        let buffer = terminal.backend().buffer();
        let row_text = |y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>();
        (0..buffer.area.height).find(|&y| row_text(y).contains(&name)).unwrap()
    }

    fn delete_selected(app: &mut App) {
        let id = app.credential_items[app.list_state.selected().unwrap()].id.clone();
        app.delete_credential(&id).unwrap();
    }

    #[test]
    fn deleting_keeps_the_cursor_on_the_same_screen_row() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut terminal) = vault_with_credentials(&dir, 30);
        press(&mut app, &mut terminal, &Action::MoveDown, 20);
        press(&mut app, &mut terminal, &Action::MoveUp, 5);
        let row_before = cursor_row(&mut app, &mut terminal);

        delete_selected(&mut app);

        assert_eq!(cursor_row(&mut app, &mut terminal), row_before);
    }

    /// List rows are screen rows 1..=12, inside the border.
    #[test]
    fn scrolling_down_keeps_scrolloff_rows_below_the_cursor() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut terminal) = vault_with_credentials(&dir, 30);
        press(&mut app, &mut terminal, &Action::MoveDown, 20);
        assert_eq!(cursor_row(&mut app, &mut terminal), 7);
    }

    #[test]
    fn scrolling_up_keeps_scrolloff_rows_above_the_cursor() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut terminal) = vault_with_credentials(&dir, 30);
        press(&mut app, &mut terminal, &Action::MoveToBottom, 1);
        press(&mut app, &mut terminal, &Action::MoveUp, 20);
        assert_eq!(cursor_row(&mut app, &mut terminal), 6);
    }

    #[test]
    fn scrolloff_zero_lets_the_cursor_reach_the_edge() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut terminal) = vault_with_credentials(&dir, 30);
        press(&mut app, &mut terminal, &Action::SetScrolloff(0), 1);
        press(&mut app, &mut terminal, &Action::MoveDown, 20);
        assert_eq!(cursor_row(&mut app, &mut terminal), 12);
    }

    #[test]
    fn deleting_during_a_search_keeps_the_cursor_on_the_same_screen_row() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut terminal) = vault_with_credentials(&dir, 30);
        app.search_credentials("item").unwrap();
        press(&mut app, &mut terminal, &Action::MoveDown, 20);
        press(&mut app, &mut terminal, &Action::MoveUp, 5);
        let row_before = cursor_row(&mut app, &mut terminal);

        delete_selected(&mut app);

        assert_eq!(cursor_row(&mut app, &mut terminal), row_before);
    }
}


#[cfg(test)]
mod generate_in_form_tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use secrecy::ExposeSecret;
    use tempfile::TempDir;

    use crate::app::{App, AppConfig};
    use crate::input::keymap::Action;

    const PASSWORD: &str = "test_password";

    fn unlocked_app(dir: &TempDir) -> App {
        let mut app = App::new(AppConfig { vault_path: dir.path().join("vault.db"), ..AppConfig::default() });
        app.initialize(PASSWORD).unwrap();
        app
    }

    fn press(app: &mut App, code: KeyCode, mods: KeyModifiers) {
        app.handle_key_event(KeyEvent::new(code, mods)).unwrap();
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            press(app, KeyCode::Char(c), KeyModifiers::NONE);
        }
    }

    fn form_secret(app: &App) -> String {
        app.credential_form.as_ref().unwrap().get_secret().to_string()
    }

    #[test]
    fn ctrl_g_fills_and_shows_a_generated_secret_that_saves() {
        let dir = TempDir::new().unwrap();
        let mut app = unlocked_app(&dir);
        app.execute_action(Action::New).unwrap();
        type_text(&mut app, "github");

        press(&mut app, KeyCode::Char('g'), KeyModifiers::CONTROL);
        let generated = form_secret(&app);
        assert_eq!(generated.len(), 20, "the default policy's length");
        assert!(app.credential_form.as_ref().unwrap().show_password);

        press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        app.select_credential().unwrap();
        let saved = app.selected_credential.as_ref().unwrap();
        assert_eq!(saved.name, "github");
        assert_eq!(saved.secret.as_ref().unwrap().expose_secret(), generated);
    }

    #[test]
    fn the_app_hides_the_generated_secret_after_the_reveal_timeout() {
        let dir = TempDir::new().unwrap();
        let config = AppConfig {
            vault_path: dir.path().join("vault.db"),
            password_visibility_timeout: std::time::Duration::ZERO,
            ..AppConfig::default()
        };
        let mut app = App::new(config);
        app.initialize(PASSWORD).unwrap();
        app.execute_action(Action::New).unwrap();
        press(&mut app, KeyCode::Char('g'), KeyModifiers::CONTROL);

        app.check_password_timeout();

        assert!(!app.credential_form.as_ref().unwrap().show_password);
    }

    /// Save "github" / "old-secret" through the New form.
    fn create_github(app: &mut App) {
        app.execute_action(Action::New).unwrap();
        type_text(app, "github");
        for _ in 0..3 {
            press(app, KeyCode::Tab, KeyModifiers::NONE);
        }
        type_text(app, "old-secret");
        press(app, KeyCode::Enter, KeyModifiers::NONE);
    }

    #[test]
    fn ctrl_g_replaces_the_secret_when_editing() {
        let dir = TempDir::new().unwrap();
        let mut app = unlocked_app(&dir);
        create_github(&mut app);

        app.execute_action(Action::Edit).unwrap();
        assert_eq!(form_secret(&app), "old-secret");
        press(&mut app, KeyCode::Char('g'), KeyModifiers::CONTROL);

        let generated = form_secret(&app);
        assert_ne!(generated, "old-secret");
        assert_eq!(generated.len(), 20);
    }
}
