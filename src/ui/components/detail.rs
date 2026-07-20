//! Detail View Component
//!
//! Displays credential details in a panel.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Paragraph, Widget, Wrap},
};

use crate::db::models::CredentialType;

#[derive(Debug, Clone)]
pub struct CredentialDetail {
    pub name: String,
    pub credential_type: CredentialType,
    pub username: Option<String>,
    pub secret: Option<String>,
    pub secret_visible: bool,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub totp_code: Option<String>,
    pub totp_remaining: Option<u64>,
}

pub struct DetailView<'a> {
    detail: &'a CredentialDetail,
}

impl<'a> DetailView<'a> {
    pub fn new(detail: &'a CredentialDetail) -> Self {
        Self { detail }
    }
}

fn render_field(buf: &mut Buffer, x: u16, y: &mut u16, _width: u16, label: &str, value: &[Span]) {
    let label_style = Style::default().fg(Color::White);
    buf.set_string(x, *y, format!("{label}:"), label_style);

    let value_x = x + 12;
    let line = Line::from(value.to_vec());
    buf.set_line(value_x, *y, &line, 60);

    *y += 1;
}

fn type_color(cred_type: CredentialType) -> Color {
    match cred_type {
        CredentialType::Password => Color::Green,
        CredentialType::ApiKey => Color::Yellow,
        CredentialType::SshKey => Color::Cyan,
        CredentialType::Certificate => Color::Magenta,
        CredentialType::Note => Color::Gray,
        CredentialType::Database => Color::Red,
        CredentialType::Custom => Color::White,
    }
}

fn strength_color(strength: u32) -> Color {
    match strength {
        0..=20 => Color::Red,
        21..=40 => Color::LightRed,
        41..=60 => Color::Yellow,
        61..=80 => Color::LightGreen,
        _ => Color::Green,
    }
}

fn render_type_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, detail: &CredentialDetail) {
    let color = type_color(detail.credential_type);
    let value_style = Style::default().fg(Color::White);
    render_field(buf, x, y, width, "Type", &[
        Span::styled(detail.credential_type.icon(), Style::default().fg(color)),
        Span::raw(" "),
        Span::styled(detail.credential_type.display_name(), value_style),
    ]);
}

fn render_username_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, username: &str) {
    let value_style = Style::default().fg(Color::White);
    render_field(buf, x, y, width, "Username", &[Span::styled(username, value_style)]);
}

fn render_secret_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, secret: &str, visible: bool) {
    let secret_style = Style::default().fg(Color::Yellow);
    let display_secret = if visible {
        secret.to_string()
    } else {
        "•".repeat(secret.len().min(20))
    };
    render_field(buf, x, y, width, "Secret", &[Span::styled(display_secret, secret_style)]);
}

fn render_strength_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, secret: &str) {
    let strength = crate::crypto::password_strength(secret);
    let label = crate::crypto::strength_label(strength);
    let color = strength_color(strength);
    render_field(buf, x, y, width, "Strength", &[
        Span::styled(format!("{label} ({strength}%)"), Style::default().fg(color)),
    ]);
}

fn render_secret_and_strength(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, secret: &str, detail: &CredentialDetail) {
    if secret.is_empty() {
        return;
    }
    render_secret_field(buf, x, y, width, secret, detail.secret_visible);
    if detail.credential_type == CredentialType::Password {
        render_strength_field(buf, x, y, width, secret);
    }
}

fn render_totp_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, code: &str, remaining: u64) {
    render_field(buf, x, y, width, "TOTP", &[
        Span::styled(code, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" ({remaining}s)"), Style::default().fg(Color::DarkGray)),
    ]);
}

fn render_url_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, url: &str) {
    render_field(buf, x, y, width, "URL", &[
        Span::styled(url, Style::default().fg(Color::Blue)),
    ]);
}

fn render_tags_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, tags: &[String]) {
    let tag_spans: Vec<Span> = tags
        .iter()
        .flat_map(|tag| vec![
            Span::styled(format!("#{tag}"), Style::default().fg(Color::Magenta)),
            Span::raw(" "),
        ])
        .collect();
    render_field(buf, x, y, width, "Tags", &tag_spans);
}

fn render_notes_section(buf: &mut Buffer, inner: &Rect, y: &mut u16, notes: &str) {
    let label_style = Style::default().fg(Color::Yellow);
    buf.set_string(inner.x, *y, "Notes:", label_style);
    *y += 1;

    let note_area = Rect::new(inner.x, *y, inner.width, inner.height.saturating_sub(*y - inner.y));
    let note_widget = Paragraph::new(notes)
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true });
    note_widget.render(note_area, buf);
}

fn render_timestamps(buf: &mut Buffer, inner: &Rect, y: u16, created: &str, updated: &str) {
    let footer_y = inner.y + inner.height.saturating_sub(2);
    if footer_y <= y {
        return;
    }
    let label_style = Style::default().fg(Color::Green);
    let value_style = Style::default().fg(Color::White);
    buf.set_string(inner.x, footer_y, "Created: ", label_style);
    buf.set_string(inner.x + 9, footer_y, created, value_style);
    buf.set_string(inner.x, footer_y + 1, "Updated: ", label_style);
    buf.set_string(inner.x + 9, footer_y + 1, updated, value_style);
}

fn render_detail_block(area: Rect, buf: &mut Buffer, name: &str) -> Rect {
    let block = Block::default()
        .title(format!(" {name} "))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta));

    let inner = block.inner(area);
    block.render(area, buf);
    inner
}

impl Widget for DetailView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let inner = render_detail_block(area, buf, &self.detail.name);
        let mut y = inner.y;

        render_type_field(buf, inner.x, &mut y, inner.width, self.detail);

        if let Some(ref username) = self.detail.username {
            render_username_field(buf, inner.x, &mut y, inner.width, username);
        }

        if let Some(ref secret) = self.detail.secret {
            render_secret_and_strength(buf, inner.x, &mut y, inner.width, secret, self.detail);
        }

        if let (Some(code), Some(remaining)) = (&self.detail.totp_code, self.detail.totp_remaining) {
            render_totp_field(buf, inner.x, &mut y, inner.width, code, remaining);
        }

        if let Some(ref url) = self.detail.url {
            render_url_field(buf, inner.x, &mut y, inner.width, url);
        }

        if !self.detail.tags.is_empty() {
            render_tags_field(buf, inner.x, &mut y, inner.width, &self.detail.tags);
        }

        y += 1;

        if let Some(ref notes) = self.detail.notes {
            render_notes_section(buf, &inner, &mut y, notes);
        }

        render_timestamps(buf, &inner, y, &self.detail.created_at, &self.detail.updated_at);
    }
}
