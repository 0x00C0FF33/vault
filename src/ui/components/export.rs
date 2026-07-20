//! Export Dialog Component
//!
//! Dialog for selecting export format, encryption, and passphrase.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Clear, Widget},
};
use secrecy::SecretString;
use crossterm::event::{KeyCode, KeyModifiers};

use crate::vault::export::{ExportEncryption, ExportFormat};
use crate::input::{handle_text_key, SecureTextBuffer, TextBuffer, TextEditing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportField {
    Format,
    Encryption,
    Passphrase,
    Path,
}

impl ExportField {
    fn next(self, needs_passphrase: bool) -> Self {
        match self {
            Self::Format => Self::Encryption,
            Self::Encryption => next_after_encryption(needs_passphrase),
            Self::Passphrase => Self::Path,
            Self::Path => Self::Format,
        }
    }

    fn prev(self, needs_passphrase: bool) -> Self {
        match self {
            Self::Format => Self::Path,
            Self::Encryption => Self::Format,
            Self::Passphrase => Self::Encryption,
            Self::Path => prev_before_path(needs_passphrase),
        }
    }
}

fn next_after_encryption(needs_passphrase: bool) -> ExportField {
    if needs_passphrase {
        ExportField::Passphrase
    } else {
        ExportField::Path
    }
}

fn prev_before_path(needs_passphrase: bool) -> ExportField {
    if needs_passphrase {
        ExportField::Passphrase
    } else {
        ExportField::Encryption
    }
}

#[derive(Debug, Clone)]
pub struct ExportDialog {
    pub active_field: ExportField,
    pub format: ExportFormat,
    pub encryption: ExportEncryption,
    passphrase: SecureTextBuffer,
    pub path: TextBuffer,
    pub error: Option<String>,
}

impl Default for ExportDialog {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportDialog {
    pub fn new() -> Self {
        let default_encryption = ExportEncryption::Gpg;
        Self {
            active_field: ExportField::Format,
            format: ExportFormat::Json,
            encryption: default_encryption,
            passphrase: SecureTextBuffer::new(),
            path: TextBuffer::with_content(default_export_path(ExportFormat::Json, default_encryption)),
            error: None,
        }
    }

    pub fn next_field(&mut self) {
        self.active_field = self.active_field.next(self.needs_passphrase());
        self.update_cursor_to_end();
    }

    pub fn prev_field(&mut self) {
        self.active_field = self.active_field.prev(self.needs_passphrase());
        self.update_cursor_to_end();
    }

    fn update_cursor_to_end(&mut self) {
        match self.active_field {
            ExportField::Passphrase => self.passphrase.cursor_end(),
            ExportField::Path => self.path.cursor_end(),
            _ => {}
        }
    }

    pub fn cycle_format(&mut self) {
        self.format = match self.format {
            ExportFormat::Json => ExportFormat::Text,
            ExportFormat::Text => ExportFormat::Json,
        };
        self.update_path_extension();
    }

    pub fn cycle_encryption_forward(&mut self) {
        self.encryption = match self.encryption {
            ExportEncryption::None => ExportEncryption::Gpg,
            ExportEncryption::Gpg => ExportEncryption::Age,
            ExportEncryption::Age => ExportEncryption::None,
        };
        self.handle_encryption_change();
    }

    pub fn cycle_encryption_backward(&mut self) {
        self.encryption = match self.encryption {
            ExportEncryption::None => ExportEncryption::Age,
            ExportEncryption::Gpg => ExportEncryption::None,
            ExportEncryption::Age => ExportEncryption::Gpg,
        };
        self.handle_encryption_change();
    }

    fn handle_encryption_change(&mut self) {
        self.update_path_extension();
        
        if self.needs_passphrase() {
            return;
        }
        
        if self.active_field == ExportField::Passphrase {
            self.active_field = ExportField::Path;
            self.path.cursor_end();
        }
    }

    fn update_path_extension(&mut self) {
        let base = self
            .path
            .content()
            .trim_end_matches(".gpg")
            .trim_end_matches(".age")
            .trim_end_matches(".json")
            .trim_end_matches(".txt");

        let format_ext = match self.format {
            ExportFormat::Json => ".json",
            ExportFormat::Text => ".txt",
        };

        let enc_ext = self.encryption.file_extension();

        self.path.set_content(&format!("{base}{format_ext}{enc_ext}"));
    }

    pub fn insert_char(&mut self, c: char) {
        match self.active_field {
            ExportField::Passphrase if self.needs_passphrase() => self.passphrase.insert_char(c),
            ExportField::Path => self.path.insert_char(c),
            _ => {}
        }
    }

    pub fn handle_text_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        if self.active_field == ExportField::Passphrase && self.needs_passphrase() {
            handle_text_key(&mut self.passphrase, code, mods);
        } else if self.active_field == ExportField::Path {
            handle_text_key(&mut self.path, code, mods);
        }
    }

    pub fn needs_passphrase(&self) -> bool {
        self.encryption != ExportEncryption::None
    }

    // Only expose when needed for export
    pub fn get_passphrase(&self) -> Option<SecretString> {
        if self.needs_passphrase() {
            Some(SecretString::from(self.passphrase.content().to_string()))
        } else {
            None
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.needs_passphrase() && self.passphrase.is_empty() {
            return Err("Passphrase required for encrypted export".into());
        }
        if self.path.content().trim().is_empty() {
            return Err("Output path is required".into());
        }
        Ok(())
    }
}

fn default_export_path(format: ExportFormat, encryption: ExportEncryption) -> String {
    let format_ext = match format {
        ExportFormat::Json => ".json",
        ExportFormat::Text => ".txt",
    };
    let enc_ext = encryption.file_extension();

    let home_path = dirs::home_dir();
    match home_path {
        Some(p) => build_export_path_from_home(&p, format_ext, enc_ext),
        None => format!("./vault_export{format_ext}{enc_ext}"),
    }
}

fn build_export_path_from_home(home: &std::path::Path, format_ext: &str, enc_ext: &str) -> String {
    home.join(format!("vault_export{format_ext}{enc_ext}"))
        .to_string_lossy()
        .into_owned()
}

pub struct ExportDialogWidget<'a> {
    dialog: &'a ExportDialog,
}

impl<'a> ExportDialogWidget<'a> {
    pub fn new(dialog: &'a ExportDialog) -> Self {
        Self { dialog }
    }
}

impl Widget for ExportDialogWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let form_area = calculate_form_area(area, self.dialog.error.is_some());
        let inner = render_form_block(buf, form_area);

        let label_width = 14u16;
        let value_width = inner.width.saturating_sub(label_width + 1);

        let mut y = inner.y;

        y = render_format_field(self.dialog, buf, inner.x, y, label_width, value_width);
        y = render_encryption_field(self.dialog, buf, inner.x, y, label_width, value_width);
        y = render_passphrase_field(self.dialog, buf, inner.x, y, label_width, value_width);
        y = render_path_field(self.dialog, buf, inner.x, y, label_width, value_width);

        render_error_if_present(self.dialog, buf, inner.x, y);
    }
}

fn render_format_field(
    dialog: &ExportDialog,
    buf: &mut Buffer,
    x: u16,
    y: u16,
    label_width: u16,
    value_width: u16,
) -> u16 {
    render_select_field(
        buf,
        x,
        y,
        "Format:",
        &format_display(dialog.format),
        dialog.active_field == ExportField::Format,
        label_width,
        value_width,
    );
    y + 2
}

fn render_encryption_field(
    dialog: &ExportDialog,
    buf: &mut Buffer,
    x: u16,
    y: u16,
    label_width: u16,
    value_width: u16,
) -> u16 {
    render_select_field(
        buf,
        x,
        y,
        "Encryption:",
        dialog.encryption.display_name(),
        dialog.active_field == ExportField::Encryption,
        label_width,
        value_width,
    );
    y + 2
}

fn render_passphrase_field(
    dialog: &ExportDialog,
    buf: &mut Buffer,
    x: u16,
    y: u16,
    label_width: u16,
    value_width: u16,
) -> u16 {
    let passphrase_enabled = dialog.needs_passphrase();
    render_input_field(
        buf,
        x,
        y,
        "Passphrase:",
        dialog.passphrase.content(),
        dialog.passphrase.cursor(),
        dialog.active_field == ExportField::Passphrase && passphrase_enabled,
        true,
        label_width,
        value_width,
        passphrase_enabled,
    );
    y + 2
}

fn render_path_field(
    dialog: &ExportDialog,
    buf: &mut Buffer,
    x: u16,
    y: u16,
    label_width: u16,
    value_width: u16,
) -> u16 {
    render_input_field(
        buf,
        x,
        y,
        "Path:",
        dialog.path.content(),
        dialog.path.cursor(),
        dialog.active_field == ExportField::Path,
        false,
        label_width,
        value_width,
        true,
    );
    y + 2
}

fn render_error_if_present(dialog: &ExportDialog, buf: &mut Buffer, x: u16, y: u16) {
    if let Some(err) = &dialog.error {
        buf.set_string(x, y, err, Style::default().fg(Color::Red));
    }
}

fn calculate_form_area(area: Rect, has_error: bool) -> Rect {
    let content_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(2));
    let form_width = 60u16.min(content_area.width.saturating_sub(4));
    let content_height = if has_error { 12u16 } else { 11u16 };
    let remainder = (content_area.height.saturating_sub(content_height)) % 2;
    let form_height = (content_height + remainder).min(content_area.height);
    let form_x = content_area.x + (content_area.width.saturating_sub(form_width)) / 2;
    let form_y = content_area.y + (content_area.height.saturating_sub(form_height)) / 2;
    Rect::new(form_x, form_y, form_width, form_height)
}

fn render_form_block(buf: &mut Buffer, form_area: Rect) -> Rect {
    Clear.render(form_area, buf);

    let block = Block::default()
        .title(" Export Credentials ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta))
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(form_area);
    block.render(form_area, buf);
    inner
}

fn format_display(format: ExportFormat) -> String {
    match format {
        ExportFormat::Json => "JSON".into(),
        ExportFormat::Text => "Plain Text".into(),
    }
}

fn label_style(is_active: bool) -> Style {
    if is_active {
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

#[allow(clippy::too_many_arguments)]
fn render_select_field(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    label: &str,
    value: &str,
    is_active: bool,
    label_width: u16,
    value_width: u16,
) {
    buf.set_string(x, y, label, label_style(is_active));

    let value_x = x + label_width;
    let bg_color = if is_active {
        Color::DarkGray
    } else {
        Color::Black
    };
    
    fill_background(buf, value_x, y, value_width, bg_color);

    let display = format!("{value}  [Space/Ctrl+Space]");
    let value_style = Style::default().fg(Color::Yellow).bg(bg_color);
    buf.set_string(value_x, y, &display, value_style);
}

#[allow(clippy::too_many_arguments)]
fn render_input_field(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    label: &str,
    value: &str,
    cursor: usize,
    is_active: bool,
    masked: bool,
    label_width: u16,
    value_width: u16,
    enabled: bool,
) {
    let label_s = if enabled {
        label_style(is_active)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    buf.set_string(x, y, label, label_s);

    let value_x = x + label_width;
    let bg_color = compute_input_bg_color(is_active, enabled);
    fill_background(buf, value_x, y, value_width, bg_color);

    if !enabled {
        render_disabled_input(buf, value_x, y, bg_color);
        return;
    }

    render_enabled_input(buf, value_x, y, value, cursor, is_active, masked, value_width, bg_color);
}

fn compute_input_bg_color(is_active: bool, enabled: bool) -> Color {
    if is_active && enabled {
        Color::DarkGray
    } else {
        Color::Black
    }
}

fn render_disabled_input(buf: &mut Buffer, x: u16, y: u16, bg_color: Color) {
    let disabled_text = "(N/A - no encryption)";
    buf.set_string(
        x,
        y,
        disabled_text,
        Style::default().fg(Color::DarkGray).bg(bg_color),
    );
}

#[allow(clippy::too_many_arguments)]
fn render_enabled_input(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    value: &str,
    cursor: usize,
    is_active: bool,
    masked: bool,
    value_width: u16,
    bg_color: Color,
) {
    let display_value = if masked {
        "•".repeat(value.len())
    } else {
        value.to_string()
    };

    let scroll = compute_scroll_offset(cursor, value_width);
    let visible = extract_visible_text(&display_value, scroll, value_width);
    let adjusted_cursor = cursor.saturating_sub(scroll);

    let fg_color = if masked { Color::Green } else { Color::Blue };
    let value_style = Style::default().fg(fg_color).bg(bg_color);
    buf.set_string(x, y, &visible, value_style);

    if is_active {
        render_cursor(buf, x, y, adjusted_cursor, value_width);
    }
}

fn compute_scroll_offset(cursor: usize, value_width: u16) -> usize {
    if cursor >= (value_width as usize).saturating_sub(1) {
        cursor.saturating_sub((value_width as usize).saturating_sub(2))
    } else {
        0
    }
}

fn extract_visible_text(text: &str, scroll: usize, width: u16) -> String {
    text.chars()
        .skip(scroll)
        .take(width as usize)
        .collect()
}

fn render_cursor(buf: &mut Buffer, x: u16, y: u16, cursor: usize, width: u16) {
    let cursor_x = x + cursor as u16;
    if cursor_x >= x + width {
        return;
    }
    if let Some(cell) = buf.cell_mut((cursor_x, y)) {
        cell.set_style(Style::default().bg(Color::White).fg(Color::Black));
    }
}

fn fill_background(buf: &mut Buffer, x: u16, y: u16, width: u16, color: Color) {
    for px in x..x + width {
        if let Some(cell) = buf.cell_mut((px, y)) {
            cell.set_bg(color);
        }
    }
}
