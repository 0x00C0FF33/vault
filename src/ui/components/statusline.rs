//! Status Line Component
//!
//! Displays mode indicator, messages, and vault info.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Widget,
};

use crate::db::models::CredentialType;
use crate::input::InputMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Info,
    Success,
    #[allow(dead_code)]
    Warning,
    Error,
}

impl MessageType {
    pub fn color(self) -> Color {
        match self {
            Self::Info => Color::Blue,
            Self::Success => Color::Green,
            Self::Warning => Color::Yellow,
            Self::Error => Color::Red,
        }
    }
}

pub struct StatusLine<'a> {
    mode: InputMode,
    command_buffer: Option<&'a str>,
    message: Option<(&'a str, MessageType)>,
    item_count: Option<(usize, usize)>,
    search_query: Option<&'a str>,
    filter_tags: Option<&'a [String]>,
    filter_type: Option<CredentialType>,
}

impl<'a> StatusLine<'a> {
    pub fn new(mode: InputMode) -> Self {
        Self {
            mode,
            command_buffer: None,
            message: None,
            item_count: None,
            search_query: None,
            filter_tags: None,
            filter_type: None,
        }
    }

    pub fn command_buffer(mut self, buffer: &'a str) -> Self {
        self.command_buffer = Some(buffer);
        self
    }

    pub fn message(mut self, msg: &'a str, msg_type: MessageType) -> Self {
        self.message = Some((msg, msg_type));
        self
    }

    pub fn item_count(mut self, selected: usize, total: usize) -> Self {
        self.item_count = Some((selected, total));
        self
    }

    pub fn search_query(mut self, query: &'a str) -> Self {
        self.search_query = Some(query);
        self
    }

    pub fn filter_type(mut self, cred_type: CredentialType) -> Self {
        self.filter_type = Some(cred_type);
        self
    }

    pub fn filter_tags(mut self, tags: &'a [String]) -> Self {
        self.filter_tags = Some(tags);
        self
    }
}

// One arm per mode keeps this readable as a table; two modes sharing a colour
// is incidental, not a reason to merge them.
#[allow(clippy::match_same_arms)]
fn mode_style(mode: InputMode) -> Style {
    let base = Style::default().fg(Color::Black);
    match mode {
        InputMode::Normal => base.bg(Color::Magenta),
        InputMode::Insert => base.bg(Color::Blue),
        InputMode::Command => base.bg(Color::Red),
        InputMode::Search => base.bg(Color::Green),
        InputMode::Confirm => base.bg(Color::Red),
        InputMode::Help => base.bg(Color::Yellow),
        InputMode::Logs => base.bg(Color::Green),
        InputMode::Tags => base.bg(Color::Magenta),
        InputMode::Export => base.bg(Color::Red),
    }
}

fn command_prefix(mode: InputMode) -> &'static str {
    match mode {
        InputMode::Command => ":",
        InputMode::Search => "/",
        _ => "",
    }
}

fn render_mode_indicator(buf: &mut Buffer, area: Rect, mode: InputMode) -> u16 {
    let style = mode_style(mode).add_modifier(Modifier::BOLD);
    let mode_text = format!(" {} ", mode.indicator());
    buf.set_string(area.x, area.y, &mode_text, style);
    mode_text.len() as u16
}

fn render_command_or_message(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    mode: InputMode,
    command_buffer: Option<&str>,
    message: Option<(&str, MessageType)>,
) {
    let style_base = Style::default().bg(Color::DarkGray);

    if let Some(buffer) = command_buffer {
        let cmd_text = format!("{}{}", command_prefix(mode), buffer);
        buf.set_string(x, y, &cmd_text, style_base.fg(Color::White));
        return;
    }

    if let Some((msg, msg_type)) = message {
        buf.set_string(x, y, msg, style_base.fg(msg_type.color()));
    }
}

fn render_right_section(
    buf: &mut Buffer,
    area: Rect,
    search_query: Option<&str>,
    filter_tags: Option<&[String]>,
    filter_type: Option<CredentialType>,
    item_count: Option<(usize, usize)>,
) {
    let mut spans: Vec<Span> = Vec::new();
    let sep = Span::styled(" | ", Style::default().fg(Color::White)); // opts: |, │
    
    if let Some(tags) = filter_tags {
        let tags_display = if tags.len() > 2 {
            format!("{}+{}", tags[..2].join(","), tags.len() - 2)
        } else {
            tags.join(", ")
        };
        spans.push(Span::styled("Tags: ", Style::default().fg(Color::Green).bg(Color::DarkGray)));
        spans.push(Span::styled(tags_display, Style::default().fg(Color::Magenta).bg(Color::DarkGray).add_modifier(Modifier::BOLD)));
    }
    
    if let Some(cred_type) = filter_type {
        if !spans.is_empty() { spans.push(sep.clone()); }
        spans.push(Span::styled("Type: ", Style::default().fg(Color::Cyan).bg(Color::DarkGray)));
        spans.push(Span::styled(cred_type.display_name(), Style::default().fg(Color::Magenta).bg(Color::DarkGray).add_modifier(Modifier::BOLD)));
    }

    if let Some(query) = search_query {
        if !spans.is_empty() { spans.push(sep.clone()); }
        spans.push(Span::styled("Search: ", Style::default().fg(Color::Yellow).bg(Color::DarkGray)));
        spans.push(Span::styled(query, Style::default().fg(Color::Magenta).bg(Color::DarkGray).add_modifier(Modifier::BOLD)));
    }
    
    if let Some((selected, total)) = item_count {
        if !spans.is_empty() { spans.push(sep.clone()); }
        spans.push(Span::styled(
            (selected + 1).to_string(),
            Style::default().fg(Color::Cyan).bg(Color::DarkGray).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled("/", Style::default().fg(Color::White).bg(Color::DarkGray)));
        spans.push(Span::styled(
            total.to_string(),
            Style::default().fg(Color::Cyan).bg(Color::DarkGray),
        ));
    }
    
    let line = Line::from(spans);
    let width = line.width() as u16;
    let x = area.x + area.width.saturating_sub(width + 1);
    buf.set_line(x, area.y, &line, width);
}

impl Widget for StatusLine<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_style(area, Style::default().bg(Color::DarkGray));

        let mode_width = render_mode_indicator(buf, area, self.mode);
        let x = area.x + mode_width;

        buf.set_string(x, area.y, " ", Style::default().bg(Color::DarkGray));
        let x = x + 1;

        render_command_or_message(buf, x, area.y, self.mode, self.command_buffer, self.message);

        render_right_section(buf, area, self.search_query, self.filter_tags, self.filter_type, self.item_count);
    }
}

pub struct HelpBar<'a> {
    hints: Vec<(&'a str, &'a str)>,
}

impl HelpBar<'_> {
    pub fn for_mode(mode: InputMode) -> Self {
        Self { hints: hints_for_mode(mode) }
    }
}

fn hints_for_mode(mode: InputMode) -> Vec<(&'static str, &'static str)> {
    match mode {
        InputMode::Normal => vec![
            ("L", "lock vault"),
            ("i", "logs"),
            ("t", "tags"),
            ("/", "search"),
            (":", "command"),
            ("?", "help"),
        ],
        // Saving comes first after cancel so a narrow terminal cuts the
        // least important hints; the whole bar fits 80 columns.
        InputMode::Insert => vec![
            ("esc", "cancel"),
            ("enter", "save"),
            ("tab/shift+tab", "field"),
            ("ctrl+s", "show pwd"),
            ("ctrl+g", "gen pwd"),
        ],
        InputMode::Command | InputMode::Search => vec![
            ("Esc", "cancel"),
            ("Enter", "execute"),
        ],
        InputMode::Confirm => vec![
            ("y", "yes"),
            ("n", "no"),
        ],
        InputMode::Help | InputMode::Logs => vec![
            ("esc", "close"),
            ("j/k", "scroll"),
            ("ctrl+[d/u]", "page"),
            ("h/l", "pan"),
            ("0/$", "start/end"),
            ("gg/G", "top/bottom"),
        ],
        InputMode::Tags => vec![
            ("esc", "close"),
            ("j/k", "scroll"),
            ("ctrl+[d/u]", "page"),
            ("space", "select"),
            ("enter", "filter"),
        ],
        InputMode::Export => vec![
            ("tab/shift+tab", "cycle field"),
            ("space/ctrl+space", "cycle option"),
            ("enter", "export"),
            ("esc", "cancel"),
        ]
    }
}

fn build_hint_spans<'a>(hints: &[(&'a str, &'a str)]) -> Vec<Span<'a>> {
    let mut spans: Vec<Span> = Vec::new();

    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        }
        spans.push(Span::styled(*key, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {desc}"), Style::default().fg(Color::Gray)));
    }

    spans
}

impl Widget for HelpBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let spans = build_hint_spans(&self.hints);
        let line = Line::from(spans);
        buf.set_line(area.x, area.y, &line, area.width);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_hints_fit_an_80_column_terminal() {
        let width: usize = build_hint_spans(&hints_for_mode(InputMode::Insert))
            .iter()
            .map(Span::width)
            .sum();
        assert!(width <= 80, "form help bar is {width} columns");
    }
}
