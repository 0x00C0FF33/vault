//! Audit logs screen and state

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Clear, Widget},
};

use crate::db::{AuditAction, AuditLog};

use super::layout::{
    centered_rect, create_popup_block, render_empty_message, render_separator_line,
    render_text_at_virtual_x,
};
use super::scroll::{render_h_scroll_indicator, render_v_scroll_indicator, ScrollState};

#[derive(Clone)]
struct LogsColumns {
    timestamp: u16,
    action: u16,
    name: u16,
    username: u16,
    details: u16,
}

impl LogsColumns {
    const GAP: u16 = 2;

    fn from_logs(logs: &[AuditLog]) -> Self {
        let max_name = logs
            .iter()
            .filter_map(|l| l.credential_name.as_ref())
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(4) as u16;
        let max_username = logs
            .iter()
            .filter_map(|l| l.username.as_ref())
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(8) as u16;
        let max_details = logs
            .iter()
            .filter_map(|l| l.details.as_ref())
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(7) as u16;

        Self {
            timestamp: 17,
            action: 6,
            name: max_name.max(4),
            username: max_username.max(8),
            details: max_details.max(7),
        }
    }

    fn total_width(&self) -> u16 {
        self.timestamp + self.action + self.name + self.username + self.details + (Self::GAP * 4)
    }

    fn positions(&self) -> (u16, u16, u16, u16, u16) {
        let ts_x = 0;
        let act_x = ts_x + self.timestamp + Self::GAP;
        let name_x = act_x + self.action + Self::GAP;
        let user_x = name_x + self.name + Self::GAP;
        let det_x = user_x + self.username + Self::GAP;
        (ts_x, act_x, name_x, user_x, det_x)
    }
}

#[derive(Default)]
pub struct LogsState {
    pub scroll: ScrollState,
    pub logs: Vec<AuditLog>,
    columns: Option<LogsColumns>,
}

impl LogsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_logs(&mut self, logs: Vec<AuditLog>) {
        self.columns = Some(LogsColumns::from_logs(&logs));
        self.logs = logs;
        self.scroll.reset();
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll.scroll_up(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max: usize) {
        self.scroll.scroll_down(amount, max);
    }

    pub fn scroll_left(&mut self, amount: usize) {
        self.scroll.scroll_left(amount);
    }

    pub fn scroll_right(&mut self, amount: usize, max: usize) {
        self.scroll.scroll_right(amount, max);
    }

    pub fn page_down(&mut self, amount: usize, max: usize) {
        self.scroll.scroll_down(amount, max);
    }

    pub fn page_up(&mut self, amount: usize) {
        self.scroll.scroll_up(amount);
    }

    pub fn home(&mut self) {
        self.scroll.home();
    }

    pub fn end(&mut self, max: usize) {
        self.scroll.end(max);
    }

    pub fn h_home(&mut self) {
        self.scroll.h_home();
    }

    pub fn h_end(&mut self, max: usize) {
        self.scroll.h_end(max);
    }

    pub fn max_scroll(&self, visible_height: u16) -> usize {
        self.logs.len().saturating_sub(visible_height as usize)
    }

    pub fn max_h_scroll(&self, visible_width: u16) -> usize {
        let total = self.columns.as_ref().map_or(0, LogsColumns::total_width);
        (total as usize).saturating_sub(visible_width as usize)
    }

    fn columns(&self) -> LogsColumns {
        self.columns.clone().unwrap_or_else(|| LogsColumns::from_logs(&self.logs))
    }
}

pub struct LogsScreen<'a> {
    state: &'a LogsState,
}

impl<'a> LogsScreen<'a> {
    pub fn new(state: &'a LogsState) -> Self {
        Self { state }
    }

    pub fn visible_height(area: Rect) -> u16 {
        let popup = centered_rect(85, 75, area);
        popup.height.saturating_sub(4)
    }

    pub fn visible_width(area: Rect) -> u16 {
        let popup = centered_rect(85, 75, area);
        popup.width.saturating_sub(2)
    }
}

impl Widget for LogsScreen<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(85, 75, area);
        Clear.render(popup, buf);

        let block = create_popup_block(" Audit Logs (last 500) ", Color::Magenta);
        let inner = block.inner(popup);
        block.render(popup, buf);

        if self.state.logs.is_empty() {
            render_empty_message(inner, buf, "No audit logs found");
            return;
        }

        let columns = self.state.columns();

        // Header takes 2 rows (header + separator)
        let header_height = 2u16;
        let entries_area_height = inner.height.saturating_sub(header_height) as usize;
        let max_v = self.state.logs.len().saturating_sub(entries_area_height);
        let max_h = (columns.total_width() as usize).saturating_sub(inner.width as usize);

        let needs_v_scroll = max_v > 0;
        let needs_h_scroll = max_h > 0;

        // Render header (always at top)
        render_logs_header(inner, buf, self.state.scroll.h_scroll, &columns);
        render_separator_line(buf, inner.x, inner.y + 1, inner.width);

        // Calculate entries area that reserves bottom line for scroll indicator
        let entries_start_y = inner.y + header_height;

        render_logs_entries(
            inner.x,
            entries_start_y,
            inner.width,
            entries_area_height,
            self.state,
            &columns,
            buf,
        );

        // Render scroll indicators
        if needs_v_scroll {
            render_v_scroll_indicator(buf, &popup, self.state.scroll.v_scroll, max_v, Color::Magenta);
        }
        if needs_h_scroll {
            render_h_scroll_indicator(buf, &popup, self.state.scroll.h_scroll, max_h, Color::Magenta);
        }
    }
}

fn render_logs_header(inner: Rect, buf: &mut Buffer, h_offset: usize, columns: &LogsColumns) {
    let style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let (ts_x, act_x, name_x, user_x, det_x) = columns.positions();

    render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset, ts_x, "TIMESTAMP", style);
    render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset, act_x, "ACTION", style);
    render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset, name_x, "NAME", style);
    render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset, user_x, "USERNAME", style);
    render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset, det_x, "DETAILS", style);
}

fn render_logs_entries(
    x: u16,
    start_y: u16,
    width: u16,
    visible_count: usize,
    state: &LogsState,
    columns: &LogsColumns,
    buf: &mut Buffer,
) {
    let h_offset = state.scroll.h_scroll;

    for (i, log) in state.logs.iter().enumerate().skip(state.scroll.v_scroll) {
        let row = i - state.scroll.v_scroll;
        if row >= visible_count {
            break;
        }
        render_log_row(x, start_y + row as u16, width, h_offset, columns, log, buf);
    }
}

fn render_log_row(
    base_x: u16,
    y: u16,
    view_width: u16,
    h_offset: usize,
    columns: &LogsColumns,
    log: &AuditLog,
    buf: &mut Buffer,
) {
    let (ts_x, act_x, name_x, user_x, det_x) = columns.positions();
    let timestamp = log.timestamp.format("%d-%b-%Y %H:%M").to_string();
    let (action_str, action_color) = action_display(&log.action);

    let name = log.credential_name.as_deref().unwrap_or("-");
    let username = log.username.as_deref().unwrap_or("-");
    let details = log.details.as_deref().unwrap_or("-");

    render_text_at_virtual_x(
        buf, base_x, y, view_width, h_offset, ts_x, &timestamp,
        Style::default().fg(Color::Magenta),
    );
    render_text_at_virtual_x(
        buf, base_x, y, view_width, h_offset, act_x, action_str,
        Style::default().fg(action_color),
    );
    render_text_at_virtual_x(
        buf, base_x, y, view_width, h_offset, name_x, name,
        Style::default().fg(Color::White),
    );
    render_text_at_virtual_x(
        buf, base_x, y, view_width, h_offset, user_x, username,
        Style::default().fg(Color::White),
    );
    render_text_at_virtual_x(
        buf, base_x, y, view_width, h_offset, det_x, details,
        Style::default().fg(Color::DarkGray),
    );
}

fn action_display(action: &AuditAction) -> (&'static str, Color) {
    match action {
        AuditAction::Create => ("CREATE", Color::Green),
        AuditAction::Read => ("READ", Color::Blue),
        AuditAction::Update => ("UPDATE", Color::Yellow),
        AuditAction::Delete => ("DELETE", Color::Red),
        AuditAction::Copy => ("COPY", Color::Magenta),
        AuditAction::Export => ("EXPORT", Color::Yellow),
        AuditAction::Import => ("IMPORT", Color::Cyan),
        AuditAction::Unlock => ("UNLOCK", Color::Cyan),
        AuditAction::Lock => ("LOCK", Color::Yellow),
        AuditAction::FailedUnlock => ("FAILED", Color::Red),
        AuditAction::Unknown => ("UNKNOWN", Color::Red),
    }
}
