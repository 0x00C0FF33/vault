use secrecy::ExposeSecret;
use std::path::Path;

use crate::crypto::{totp::{self, TotpSecret}, decrypt_string};
use crate::db::{models::{Credential, CredentialType}, AuditAction};
use crate::ui::{
    components::{
        ExportDialog,
        CredentialDetail,
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
        self.refresh_data()?;
        self.update_selected_detail()
    }

    pub fn filter_by_tag(&mut self, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        self.filter_tags = if tags.is_empty() { None } else { Some(tags.to_vec()) };
        self.refresh_data()?;

        if !tags.is_empty() {
            self.set_message(&format_filter_message(tags), MessageType::Info);
        }
        self.update_selected_detail()
    }

    pub fn filter_by_type(&mut self, cred_type: Option<CredentialType>) -> Result<(), Box<dyn std::error::Error>> {
        self.filter_type = cred_type;
        self.refresh_data()?;

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
        
        if let Some(query) = self.search_query.clone() {
            self.search_credentials(&query)?;
        } else {
            self.refresh_data()?;
        }
        
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
        
        if let Some(query) = self.search_query.clone() {
            self.search_credentials(&query)?;
        } else {
            self.refresh_data()?;
        }
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
        let password = crate::crypto::generate_password(&crate::crypto::PasswordPolicy::default())?;
        super::clipboard::copy_with_timeout(&password, self.config.clipboard_timeout);
        self.set_message(
            &format!("Generated: {} (copied for {}s)", password, self.config.clipboard_timeout.as_secs()),
            MessageType::Success,
        );
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

pub fn build_detail(cred: &DecryptedCredential, password_visible: bool) -> CredentialDetail {
    let (totp_code, totp_remaining) = compute_totp(cred);

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
        totp_code,
        totp_remaining,
    }
}

pub fn compute_totp(cred: &DecryptedCredential) -> (Option<String>, Option<u64>) {
    let Some(ref totp_input) = cred.totp_secret else {
        return (None, None);
    };

    let Ok(totp_secret) = TotpSecret::from_user_input(
        totp_input.expose_secret(),
        &cred.name,
        "Vault"
    ) else {
        return (None, None);
    };

    match totp::generate_totp(&totp_secret) {
        Ok(code) => (Some(code), Some(totp::time_remaining(&totp_secret))),
        Err(_) => (None, None),
    }
}
