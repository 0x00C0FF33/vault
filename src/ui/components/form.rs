//! Credential Form Component
//!
//! Multi-field form for creating and editing credentials.

use std::time::Instant;

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, BorderType, Clear, Widget},
};

use crate::db::models::CredentialType;
use crate::ui::renderer::View;
use crossterm::event::{KeyCode, KeyModifiers};
use crate::input::{handle_text_key, TextBuffer, TextEditing};

use super::scroll::render_v_scroll_indicator;

#[derive(Debug, Clone)]
pub struct FormField {
    pub label: &'static str,
    pub value: String,
    pub required: bool,
    pub masked: bool,
    pub field_type: FieldType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Password,
    Select,
    MultiLine,
}

impl FormField {
    pub fn text(label: &'static str, required: bool) -> Self {
        Self {
            label,
            value: String::new(),
            required,
            masked: false,
            field_type: FieldType::Text,
        }
    }

    pub fn secret(label: &'static str, required: bool) -> Self {
        Self {
            label,
            value: String::new(),
            required,
            masked: true,
            field_type: FieldType::Password,
        }
    }

    pub fn select(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: true,
            masked: false,
            field_type: FieldType::Select,
        }
    }

    pub fn multiline(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: false,
            masked: false,
            field_type: FieldType::MultiLine,
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct CredentialForm {
    pub fields: Vec<FormField>,
    pub active_field: usize,
    pub cursor: usize,
    pub credential_type: CredentialType,
    pub editing_id: Option<String>,
    pub show_password: bool,
    /// When a generated secret shown by `fill_generated_secret` is hidden
    /// again. `None` while the secret is hidden or was shown by hand.
    secret_hide_at: Option<Instant>,
    pub scroll_offset: usize,
    pub multiline_scroll: usize,
    pub previous_view: View,
}

impl Default for CredentialForm {
    fn default() -> Self {
        Self::new()
    }
}

/// A field's position in `CredentialForm::fields`.
///
/// `ALL` is the only place the on-screen order lives: `default_fields` builds
/// from it and every accessor indexes through it. Adding a field means adding
/// a variant, not renumbering call sites — `field_order_matches_declaration`
/// fails if the two ever drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Name,
    Type,
    Username,
    Secret,
    Url,
    Tags,
    TotpSecret,
    Notes,
}

impl Field {
    const ALL: [Self; 8] = [
        Self::Name,
        Self::Type,
        Self::Username,
        Self::Secret,
        Self::Url,
        Self::Tags,
        Self::TotpSecret,
        Self::Notes,
    ];

    fn index(self) -> usize {
        self as usize
    }

    fn blank(self) -> FormField {
        match self {
            Self::Name => FormField::text("Name", true),
            Self::Type => {
                FormField::select("Type").with_value(CredentialType::Password.display_name())
            }
            Self::Username => FormField::text("Username", false),
            Self::Secret => FormField::secret("Password/Secret", true),
            Self::Url => FormField::text("URL", false),
            Self::Tags => FormField::text("Tags (multiple)", false),
            Self::TotpSecret => FormField::secret("TOTP Secret", false),
            Self::Notes => FormField::multiline("Notes"),
        }
    }
}

fn default_fields() -> Vec<FormField> {
    Field::ALL.iter().map(|field| field.blank()).collect()
}

fn is_secret_required(cred_type: CredentialType) -> bool {
    !matches!(cred_type, CredentialType::Note)
}

fn cycle_type_forward(cred_type: CredentialType) -> CredentialType {
    match cred_type {
        CredentialType::Password => CredentialType::ApiKey,
        CredentialType::ApiKey => CredentialType::SshKey,
        CredentialType::SshKey => CredentialType::Certificate,
        CredentialType::Certificate => CredentialType::Note,
        CredentialType::Note => CredentialType::Database,
        CredentialType::Database => CredentialType::Custom,
        CredentialType::Custom => CredentialType::Password,
    }
}

fn cycle_type_backward(cred_type: CredentialType) -> CredentialType {
    match cred_type {
        CredentialType::Password => CredentialType::Custom,
        CredentialType::ApiKey => CredentialType::Password,
        CredentialType::SshKey => CredentialType::ApiKey,
        CredentialType::Certificate => CredentialType::SshKey,
        CredentialType::Note => CredentialType::Certificate,
        CredentialType::Database => CredentialType::Note,
        CredentialType::Custom => CredentialType::Database,
    }
}

fn trim_to_option(val: &str) -> Option<String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub struct EditFormParams {
    pub id: String,
    pub name: String,
    pub cred_type: CredentialType,
    pub username: Option<String>,
    pub secret: String,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub totp_secret: Option<String>,
    pub notes: Option<String>,
    pub previous_view: View,
}

impl CredentialForm {
    pub fn new() -> Self {
        Self {
            fields: default_fields(),
            active_field: 0,
            cursor: 0,
            credential_type: CredentialType::Password,
            editing_id: None,
            show_password: false,
            secret_hide_at: None,
            scroll_offset: 0,
            multiline_scroll: 0,
            previous_view: View::List,
        }
    }

    pub fn for_edit(params: EditFormParams) -> Self {
        let mut form = Self::new();
        form.editing_id = Some(params.id);
        form.credential_type = params.cred_type;
        form.previous_view = params.previous_view;

        form.set(Field::Name, params.name);
        form.set(Field::Username, params.username.unwrap_or_default());
        form.set(Field::Secret, params.secret);
        form.set(Field::Url, params.url.unwrap_or_default());
        form.set(Field::Tags, params.tags.join(" "));
        form.set(Field::TotpSecret, params.totp_secret.unwrap_or_default());
        form.set(Field::Notes, params.notes.unwrap_or_default());
        form.apply_type_rules();

        form
    }

    fn get(&self, field: Field) -> &str {
        &self.fields[field.index()].value
    }

    fn set(&mut self, field: Field, value: String) {
        self.fields[field.index()].value = value;
    }

    /// The credential type drives both the type field's label and whether a
    /// secret is mandatory; keeping them together stops the two from drifting.
    fn apply_type_rules(&mut self) {
        self.set(Field::Type, self.credential_type.display_name().to_string());
        self.fields[Field::Secret.index()].required = is_secret_required(self.credential_type);
    }

    pub fn is_editing(&self) -> bool {
        self.editing_id.is_some()
    }

    pub fn active_field(&self) -> &FormField {
        &self.fields[self.active_field]
    }

    fn ensure_visible(&mut self, total_height: u16) {
        if self.active_field < self.scroll_offset {
            self.scroll_offset = self.active_field;
            return;
        }
        let value_width = 49usize;
        while !self.is_field_visible(total_height, value_width) {
            self.scroll_offset = (self.scroll_offset + 1).min(self.active_field);
            if self.scroll_offset == self.active_field { return; }
        }
    }

    fn is_field_visible(&self, total_height: u16, value_width: usize) -> bool {
        let visible = count_visible_fields(&self.fields, self.scroll_offset, total_height, value_width);
        self.active_field < self.scroll_offset + visible
    }

    pub fn next_field(&mut self, area_height: u16) {
        self.active_field = (self.active_field + 1) % self.fields.len();
        self.cursor = self.fields[self.active_field].value.len();
        self.multiline_scroll = 0;
        self.ensure_visible(Self::form_inner_height(area_height));
    }

    pub fn prev_field(&mut self, area_height: u16) {
        if self.active_field == 0 {
            self.active_field = self.fields.len() - 1;
        } else {
            self.active_field -= 1;
        }
        self.cursor = self.fields[self.active_field].value.len();
        self.multiline_scroll = 0;
        self.ensure_visible(Self::form_inner_height(area_height));
    }

    fn form_inner_height(area_height: u16) -> u16 {
        let available = area_height.saturating_sub(2); // statusline + helpbar
        let form_height = 30u16.min(available.saturating_sub(2));
        form_height.saturating_sub(2) // block borders
    }

    fn active_buffer(&self) -> TextBuffer {
        let field = &self.fields[self.active_field];
        let mut buf = TextBuffer::with_content(&field.value);
        buf.cursor_home();
        for _ in 0..self.cursor {
            buf.cursor_right();
        }
        buf
    }

    fn apply_buffer(&mut self, buf: &TextBuffer) {
        self.fields[self.active_field].value = buf.content().to_string();
        self.cursor = buf.cursor();
    }

    pub fn handle_text_key(&mut self, code: KeyCode, mods: KeyModifiers, area_height: u16) {
        if self.active_field().field_type == FieldType::Select {
            return;
        }
        let mut buf = self.active_buffer();
        if !handle_text_key(&mut buf, code, mods) {
            return;
        }
        let is_multiline = self.active_field().field_type == FieldType::MultiLine;
        self.apply_buffer(&buf);
        if is_multiline {
            self.ensure_visible(Self::form_inner_height(area_height));
        }
    }

    pub fn cycle_type(&mut self, forward: bool) {
        if self.fields[self.active_field].field_type != FieldType::Select {
            return;
        }
        self.credential_type = if forward {
            cycle_type_forward(self.credential_type)
        } else {
            cycle_type_backward(self.credential_type)
        };
        self.apply_type_rules();
    }

    /// Taking manual control cancels the timed hide of a generated secret.
    pub fn toggle_password_visibility(&mut self) {
        self.show_password = !self.show_password;
        self.secret_hide_at = None;
    }

    /// Replace the secret with a generated one and show it until `hide_at`,
    /// so it can be checked before saving without staying on screen.
    pub fn fill_generated_secret(&mut self, secret: String, hide_at: Instant) {
        self.set(Field::Secret, secret);
        if self.active_field == Field::Secret.index() {
            self.cursor = self.get(Field::Secret).len();
        }
        self.show_password = true;
        self.secret_hide_at = Some(hide_at);
    }

    /// Hide a secret shown by `fill_generated_secret` once its time is up.
    pub fn hide_secret_if_due(&mut self, now: Instant) {
        let Some(hide_at) = self.secret_hide_at else { return };
        if now < hide_at {
            return;
        }
        self.show_password = false;
        self.secret_hide_at = None;
    }

    pub fn validate(&self) -> Result<(), String> {
        for field in &self.fields {
            let is_empty_required = field.required && field.value.trim().is_empty();
            if is_empty_required { return Err(format!("{} is required", field.label)); }
        }
        Ok(())
    }

    pub fn get_name(&self) -> &str {
        self.get(Field::Name)
    }

    pub fn get_username(&self) -> Option<String> {
        trim_to_option(self.get(Field::Username))
    }

    pub fn get_secret(&self) -> &str {
        self.get(Field::Secret)
    }

    pub fn get_url(&self) -> Option<String> {
        trim_to_option(self.get(Field::Url))
    }

    pub fn get_tags(&self) -> Vec<String> {
        self.get(Field::Tags)
            .split(' ')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn get_totp_secret(&self) -> Option<String> {
        trim_to_option(self.get(Field::TotpSecret))
    }

    pub fn get_notes(&self) -> Option<String> {
        trim_to_option(self.get(Field::Notes))
    }
}

pub struct CredentialFormWidget<'a> {
    form: &'a CredentialForm,
    title: &'a str,
}

impl<'a> CredentialFormWidget<'a> {
    pub fn new(form: &'a CredentialForm) -> Self {
        let title = if form.is_editing() {
            " Edit Credential "
        } else {
            " New Credential "
        };
        Self { form, title }
    }
}

fn calculate_form_area(area: Rect) -> Rect {
    let form_width = 70u16.min(area.width.saturating_sub(4));
    let form_height = 30u16.min(area.height.saturating_sub(2));
    let form_x = area.x + (area.width.saturating_sub(form_width)) / 2;
    let form_y = area.y + (area.height.saturating_sub(form_height)) / 2;
    Rect::new(form_x, form_y, form_width, form_height)
}

fn render_form_block(buf: &mut Buffer, form_area: Rect, title: &str) -> Rect {
    Clear.render(form_area, buf);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta))
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(form_area);
    block.render(form_area, buf);
    inner
}

fn format_label(field: &FormField) -> String {
    if field.required {
        format!("{}*:", field.label)
    } else {
        format!("{}:", field.label)
    }
}

fn label_style(is_active: bool) -> Style {
    if is_active {
        Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

fn field_background_style(is_active: bool) -> Style {
    if is_active {
        Style::default().bg(Color::DarkGray)
    } else {
        Style::default()
    }
}

fn find_cursor_line(line_starts: &[usize], cursor_pos: usize) -> usize {
    for (i, &start) in line_starts.iter().enumerate() {
        if i + 1 >= line_starts.len() {
            return i;
        }
        if cursor_pos >= start && cursor_pos < line_starts[i + 1] {
            return i;
        }
    }
    0
}

fn fill_field_background(buf: &mut Buffer, x: u16, y: u16, width: u16, style: Style) {
    for cell_x in x..x + width {
        if let Some(cell) = buf.cell_mut((cell_x, y)) {
            cell.set_style(style);
        }
    }
}

struct DisplayValue {
    text: String,
    cursor: usize,
}

fn compute_select_display(form: &CredentialForm, field: &FormField) -> DisplayValue {
    let icon = form.credential_type.icon();
    DisplayValue {
        text: format!("{} {}  [Space/Ctrl+Space]", icon, field.value),
        cursor: 0,
    }
}

fn compute_text_display(form: &CredentialForm, field: &FormField, value_width: usize, is_active: bool) -> DisplayValue {
    let text = if field.masked && !form.show_password {
        "•".repeat(field.value.len())
    } else {
        field.value.clone()
    };

    let cursor_pos = if is_active { form.cursor } else { 0 };
    let scroll = if cursor_pos >= value_width.saturating_sub(1) {
        cursor_pos.saturating_sub(value_width.saturating_sub(2))
    } else {
        0
    };

    let visible: String = text.chars().skip(scroll).take(value_width).collect();
    let adjusted_cursor = cursor_pos.saturating_sub(scroll);

    DisplayValue {
        text: visible,
        cursor: adjusted_cursor,
    }
}

fn value_style(field: &FormField, is_active: bool) -> Style {
    let bg = if is_active { Color::DarkGray } else { Color::Black };
    let fg = match field.field_type {
        FieldType::Select => Color::Yellow,
        _ if field.masked => Color::Green,
        _ => Color::White,
    };
    Style::default().fg(fg).bg(bg)
}

fn field_row_height(field: &FormField, _value_width: usize) -> u16 {
    if field.field_type == FieldType::MultiLine {
        4 // Fixed height — content scrolls internally
    } else {
        1
    }
}

fn count_visible_fields(fields: &[FormField], offset: usize, height: u16, value_width: usize) -> usize {
    let mut budget = height;
    let mut count = 0;
    for field in fields.iter().skip(offset) {
        let h = field_row_height(field, value_width) + 1;
        if budget < h { break; }
        budget -= h;
        count += 1;
    }
    count
}

fn render_cursor(buf: &mut Buffer, x: u16, y: u16, max_x: u16) {
    if x >= max_x {
        return;
    }
    if let Some(cell) = buf.cell_mut((x, y)) {
        cell.set_style(Style::default().bg(Color::White).fg(Color::Black));
    }
}

fn render_field(
    buf: &mut Buffer,
    form: &CredentialForm,
    field: &FormField,
    field_idx: usize,
    inner: Rect,
    y: u16,
    label_width: u16,
) -> u16 {
    let is_active = field_idx == form.active_field;

    let label = format_label(field);
    buf.set_string(inner.x, y, &label, label_style(is_active));

    let value_x = inner.x + label_width;
    let value_width = inner.width.saturating_sub(label_width + 1);

    if field.field_type == FieldType::MultiLine {
        return render_multiline_field(buf, form, field, is_active, value_x, y, value_width);
    }

    fill_field_background(buf, value_x, y, value_width, field_background_style(is_active));

    let display = if field.field_type == FieldType::Select {
        compute_select_display(form, field)
    } else {
        compute_text_display(form, field, value_width as usize, is_active)
    };

    buf.set_string(value_x, y, &display.text, value_style(field, is_active));

    if is_active && field.field_type != FieldType::Select {
        render_cursor(buf, value_x + display.cursor as u16, y, value_x + value_width);
    }

    1
}

fn render_multiline_field(
    buf: &mut Buffer,
    form: &CredentialForm,
    field: &FormField,
    is_active: bool,
    x: u16,
    y: u16,
    width: u16,
) -> u16 {
    let max_lines: u16 = 4;
    let w = width as usize;
    if w == 0 {
        return 1;
    }

    let text = &field.value;

    // Soft-wrap into visual lines, tracking byte offsets
    let mut lines: Vec<String> = Vec::new();
    let mut line_starts: Vec<usize> = vec![0];
    let mut current_line = String::new();
    let mut byte_idx: usize = 0;

    for ch in text.chars() {
        if ch == '\n' {
            lines.push(current_line.clone());
            current_line.clear();
            byte_idx += ch.len_utf8();
            line_starts.push(byte_idx);
            continue;
        }
        current_line.push(ch);
        byte_idx += ch.len_utf8();
        if current_line.chars().count() >= w {
            lines.push(current_line.clone());
            current_line.clear();
            line_starts.push(byte_idx);
        }
    }
    lines.push(current_line);

    let total_lines = lines.len();
    let visible_lines = max_lines;

    // Find which wrapped line the cursor is on
    let cursor_pos = if is_active { form.cursor } else { 0 };
    let cursor_line = find_cursor_line(&line_starts, cursor_pos);

    // Use form's multiline_scroll, auto-adjust to keep cursor visible
    let scroll = if is_active {
        let mut s = form.multiline_scroll;
        if cursor_line < s {
            s = cursor_line;
        } else if cursor_line >= s + visible_lines as usize {
            s = cursor_line - visible_lines as usize + 1;
        }
        s
    } else {
        0
    };

    let style = value_style(field, is_active);
    let bg_style = field_background_style(is_active);

    for row in 0..visible_lines {
        let line_idx = scroll + row as usize;
        let line_y = y + row;
        fill_field_background(buf, x, line_y, width, bg_style);
        if line_idx < lines.len() {
            buf.set_string(x, line_y, &lines[line_idx], style);
        }
    }

    // Cursor
    if is_active {
        let line_start = line_starts.get(cursor_line).copied().unwrap_or(0);
        let cursor_in_line = cursor_pos.saturating_sub(line_start);
        let cursor_row = cursor_line.saturating_sub(scroll);
        if (cursor_row as u16) < visible_lines {
            let cx = x + cursor_in_line as u16;
            let cy = y + cursor_row as u16;
            render_cursor(buf, cx, cy, x + width);
        }
    }

    // Scroll indicator when content overflows
    if total_lines > visible_lines as usize {
        let indicator = format!("[{}/{}]", scroll + 1, total_lines.saturating_sub(visible_lines as usize) + 1);
        let ind_x = x + width.saturating_sub(indicator.len() as u16);
        buf.set_string(ind_x, y + visible_lines - 1, &indicator, Style::default().fg(Color::DarkGray));
    }

    visible_lines.max(1)
}

impl Widget for CredentialFormWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let form_area = calculate_form_area(area);
        let inner = render_form_block(buf, form_area, self.title);
        let label_width = 18u16;
        let value_width = inner.width.saturating_sub(label_width + 1) as usize;

        let scroll_offset = self.form.scroll_offset;

        // Count how many fields fit from scroll_offset
        let visible_count = count_visible_fields(
            &self.form.fields,
            scroll_offset,
            inner.height,
            value_width,
        );

        let max_v = self.form.fields.len().saturating_sub(visible_count);
        let needs_scrolling = max_v > 0;

        let mut y = inner.y;
        let y_limit = inner.y + inner.height;
        for (i, field) in self.form.fields.iter().enumerate().skip(scroll_offset) {
            if i >= scroll_offset + visible_count { break; }
            if y >= y_limit { break; }
            let rows_used = render_field(buf, self.form, field, i, inner, y, label_width);
            y += rows_used + 1;
        }

        if needs_scrolling {
            render_v_scroll_indicator(buf, form_area, scroll_offset, max_v, Color::Magenta);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn form_with_generated_secret(shown_at: Instant) -> CredentialForm {
        let mut form = CredentialForm::new();
        form.fill_generated_secret("g3n3rated".to_string(), shown_at + Duration::from_secs(5));
        form
    }

    #[test]
    fn a_generated_secret_replaces_the_old_one_and_is_shown() {
        let mut form = CredentialForm::for_edit(edit_params());
        form.fill_generated_secret("g3n3rated".to_string(), Instant::now());
        assert_eq!(form.get_secret(), "g3n3rated");
        assert!(form.show_password);
    }

    #[test]
    fn a_generated_secret_hides_once_its_time_is_up() {
        let shown_at = Instant::now();
        let mut form = form_with_generated_secret(shown_at);

        form.hide_secret_if_due(shown_at + Duration::from_secs(4));
        assert!(form.show_password, "hidden before the timeout");

        form.hide_secret_if_due(shown_at + Duration::from_secs(5));
        assert!(!form.show_password);
    }

    /// Ctrl+s during the reveal hides the secret at once; showing it again
    /// by hand is the user's choice and must not be cut short by the old timer.
    #[test]
    fn toggling_by_hand_cancels_the_timed_hide() {
        let shown_at = Instant::now();
        let mut form = form_with_generated_secret(shown_at);

        form.toggle_password_visibility();
        assert!(!form.show_password);

        form.toggle_password_visibility();
        form.hide_secret_if_due(shown_at + Duration::from_secs(60));
        assert!(form.show_password);
    }

    #[test]
    fn filling_the_active_secret_field_moves_the_cursor_to_its_end() {
        let mut form = CredentialForm::new();
        form.active_field = Field::Secret.index();
        form.fill_generated_secret("g3n3rated".to_string(), Instant::now());
        assert_eq!(form.cursor, "g3n3rated".len());
    }

    fn edit_params() -> EditFormParams {
        EditFormParams {
            id: "cred-1".to_string(),
            name: "GitHub".to_string(),
            cred_type: CredentialType::Password,
            username: Some("octocat".to_string()),
            secret: "hunter2".to_string(),
            url: Some("https://github.com".to_string()),
            tags: vec!["dev".to_string(), "vcs".to_string()],
            totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
            notes: Some("recovery codes in safe".to_string()),
            previous_view: View::List,
        }
    }

    /// `Field::index` returns the discriminant, so `ALL` must stay in
    /// declaration order for the two to describe the same layout.
    #[test]
    fn field_order_matches_declaration() {
        for (position, field) in Field::ALL.iter().enumerate() {
            assert_eq!(field.index(), position, "{field:?} is out of order in ALL");
        }
    }

    #[test]
    fn every_field_is_built_into_the_form() {
        assert_eq!(CredentialForm::new().fields.len(), Field::ALL.len());
    }

    /// Guards the failure mode that commit 3597b38 hit by hand: inserting a
    /// field shifts every later position, and a missed site silently routes
    /// one field's value into another.
    #[test]
    fn every_edit_param_reaches_its_own_accessor() {
        let form = CredentialForm::for_edit(edit_params());

        assert_eq!(form.get_name(), "GitHub");
        assert_eq!(form.get_username(), Some("octocat".to_string()));
        assert_eq!(form.get_secret(), "hunter2");
        assert_eq!(form.get_url(), Some("https://github.com".to_string()));
        assert_eq!(form.get_tags(), vec!["dev".to_string(), "vcs".to_string()]);
        assert_eq!(form.get_totp_secret(), Some("JBSWY3DPEHPK3PXP".to_string()));
        assert_eq!(form.get_notes(), Some("recovery codes in safe".to_string()));
    }

    #[test]
    fn absent_optional_params_read_back_as_none() {
        let form = CredentialForm::for_edit(EditFormParams {
            username: None,
            url: None,
            totp_secret: None,
            notes: None,
            ..edit_params()
        });

        assert_eq!(form.get_username(), None);
        assert_eq!(form.get_url(), None);
        assert_eq!(form.get_totp_secret(), None);
        assert_eq!(form.get_notes(), None);
    }

    #[test]
    fn whitespace_only_optional_field_is_none() {
        let mut form = CredentialForm::new();
        form.set(Field::Username, "   ".to_string());
        assert_eq!(form.get_username(), None);
    }

    #[test]
    fn tags_split_on_whitespace_dropping_empties() {
        let mut form = CredentialForm::new();
        form.set(Field::Tags, "dev  vcs   ".to_string());
        assert_eq!(form.get_tags(), vec!["dev".to_string(), "vcs".to_string()]);
    }

    #[test]
    fn editing_a_note_does_not_require_a_secret() {
        let form = CredentialForm::for_edit(EditFormParams {
            cred_type: CredentialType::Note,
            ..edit_params()
        });
        assert!(!form.fields[Field::Secret.index()].required);
    }

    #[test]
    fn cycling_onto_note_clears_the_secret_requirement() {
        let mut form = CredentialForm::new();
        form.active_field = Field::Type.index();
        assert!(form.fields[Field::Secret.index()].required);

        // Password -> ApiKey -> SshKey -> Certificate -> Note
        for _ in 0..4 {
            form.cycle_type(true);
        }

        assert_eq!(form.credential_type, CredentialType::Note);
        assert!(!form.fields[Field::Secret.index()].required);
        assert_eq!(form.get(Field::Type), "Note");
    }

    #[test]
    fn cycling_is_reversible() {
        let mut form = CredentialForm::new();
        form.active_field = Field::Type.index();
        form.cycle_type(true);
        form.cycle_type(false);
        assert_eq!(form.credential_type, CredentialType::Password);
    }

    #[test]
    fn cycling_off_a_select_field_is_ignored() {
        let mut form = CredentialForm::new();
        form.active_field = Field::Name.index();
        form.cycle_type(true);
        assert_eq!(form.credential_type, CredentialType::Password);
    }

    #[test]
    fn validate_names_the_first_empty_required_field() {
        let form = CredentialForm::new();
        assert_eq!(form.validate(), Err("Name is required".to_string()));
    }

    #[test]
    fn validate_accepts_a_filled_form() {
        assert!(CredentialForm::for_edit(edit_params()).validate().is_ok());
    }

    #[test]
    fn a_new_form_is_not_an_edit() {
        assert!(!CredentialForm::new().is_editing());
        assert!(CredentialForm::for_edit(edit_params()).is_editing());
    }
}
