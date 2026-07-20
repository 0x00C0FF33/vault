//! Credential Form Component
//!
//! Multi-field form for creating and editing credentials.

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
    pub scroll_offset: usize,
    pub multiline_scroll: usize,
    pub previous_view: View,
}

impl Default for CredentialForm {
    fn default() -> Self {
        Self::new()
    }
}

fn default_fields() -> Vec<FormField> {
    vec![
        FormField::text("Name", true),
        FormField::select("Type").with_value(CredentialType::Password.display_name()),
        FormField::text("Username", false),
        FormField::secret("Password/Secret", true),
        FormField::text("URL", false),
        FormField::text("Tags (multiple)", false),
        FormField::secret("TOTP Secret", false),
        FormField::multiline("Notes"),
    ]
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

        form.fields[0].value = params.name;
        form.fields[1].value = params.cred_type.display_name().to_string();
        form.fields[2].value = params.username.unwrap_or_default();
        form.fields[3].value = params.secret;
        form.fields[3].required = is_secret_required(params.cred_type);
        form.fields[4].value = params.url.unwrap_or_default();
        form.fields[5].value = params.tags.join(" ");
        form.fields[6].value = params.totp_secret.unwrap_or_default();
        form.fields[7].value = params.notes.unwrap_or_default();

        form
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
        self.fields[1].value = self.credential_type.display_name().to_string();
        self.fields[3].required = is_secret_required(self.credential_type);
    }

    pub fn toggle_password_visibility(&mut self) {
        self.show_password = !self.show_password;
    }

    pub fn validate(&self) -> Result<(), String> {
        for field in &self.fields {
            let is_empty_required = field.required && field.value.trim().is_empty();
            if is_empty_required { return Err(format!("{} is required", field.label)); }
        }
        Ok(())
    }

    pub fn get_name(&self) -> &str {
        &self.fields[0].value
    }

    pub fn get_username(&self) -> Option<String> {
        trim_to_option(&self.fields[2].value)
    }

    pub fn get_secret(&self) -> &str {
        &self.fields[3].value
    }

    pub fn get_url(&self) -> Option<String> {
        trim_to_option(&self.fields[4].value)
    }

    pub fn get_tags(&self) -> Vec<String> {
        self.fields[5]
            .value
            .split(' ')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn get_totp_secret(&self) -> Option<String> {
        trim_to_option(&self.fields[6].value)
    }

    pub fn get_notes(&self) -> Option<String> {
        trim_to_option(&self.fields[7].value)
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
    inner: &Rect,
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
            let rows_used = render_field(buf, self.form, field, i, &inner, y, label_width);
            y += rows_used + 1;
        }

        if needs_scrolling {
            render_v_scroll_indicator(buf, &form_area, scroll_offset, max_v, Color::Magenta);
        }
    }
}
