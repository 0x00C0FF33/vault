//! Help screen and state

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Clear, Widget},
};

use super::layout::{centered_rect, create_popup_block, render_text_at_virtual_x};
use super::scroll::{render_h_scroll_indicator, render_v_scroll_indicator, ScrollState};

#[derive(Default)]
pub struct HelpState {
    pub scroll: ScrollState,
}

impl HelpState {
    pub fn new() -> Self {
        Self::default()
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
}

pub struct HelpScreen<'a> {
    state: &'a HelpState,
}

impl<'a> HelpScreen<'a> {
    pub fn new(state: &'a HelpState) -> Self {
        Self { state }
    }

    pub fn visible_height(area: Rect) -> u16 {
        let popup = centered_rect(70, 80, area);
        popup.height.saturating_sub(2)
    }

    pub fn max_scroll(area: Rect) -> usize {
        let visible = Self::visible_height(area) as usize;
        let content = Self::content_height(area);
        content.saturating_sub(visible)
    }

    pub fn max_h_scroll(area: Rect) -> usize {
        let popup = centered_rect(70, 80, area);
        let inner_width = popup.width.saturating_sub(2) as usize;
        single_column_width().saturating_sub(inner_width)
    }

    fn content_height(area: Rect) -> usize {
        let popup = centered_rect(70, 80, area);
        let inner_width = popup.width.saturating_sub(2);
        if inner_width >= TWO_COLUMN_MIN_WIDTH {
            two_column_height()
        } else {
            single_column_height()
        }
    }
}

const TWO_COLUMN_MIN_WIDTH: u16 = 85;

fn single_column_height() -> usize {
    help_sections().iter().map(|(_, b)| 1 + b.len() + 1).sum::<usize>().saturating_sub(1)
}

fn two_column_height() -> usize {
    let sections = help_sections();
    let (left, right) = split_sections_for_columns(&sections);
    let left_h: usize = left.iter().map(|(_, b)| 1 + b.len() + 1).sum::<usize>().saturating_sub(1);
    let right_h: usize = right.iter().map(|(_, b)| 1 + b.len() + 1).sum::<usize>().saturating_sub(1);
    left_h.max(right_h)
}

fn single_column_width() -> usize {
    let mut max_width = 0usize;
    for (header, bindings) in &help_sections() {
        max_width = max_width.max(header.len());
        for (_key, desc) in bindings {
            max_width = max_width.max(16 + desc.len());
        }
    }
    max_width
}

impl Widget for HelpScreen<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(70, 75, area);
        Clear.render(popup, buf);

        let block = create_popup_block(" Help Page ", Color::Magenta);
        let inner = block.inner(popup);
        block.render(popup, buf);

        let use_two_columns = inner.width >= TWO_COLUMN_MIN_WIDTH;
        let content_height = if use_two_columns { two_column_height() } else { single_column_height() };
        let visible_height = inner.height as usize;
        let max_v = content_height.saturating_sub(visible_height);
        let max_h = if use_two_columns { 0 } else { HelpScreen::max_h_scroll(area) };

        // Calculate content area that reserves bottom line for scroll indicator
        let content_height = inner.height;
        let content_area = Rect::new(inner.x, inner.y, inner.width, content_height);

        if use_two_columns {
            render_help_two_columns(content_area, buf, self.state.scroll.v_scroll);
        } else {
            render_help_single_column(content_area, buf, self.state.scroll.v_scroll, self.state.scroll.h_scroll);
        }

        // Render scroll indicators
        let can_scroll_vertically = max_v > 0;
        let can_scroll_horizontally = max_h > 0;

        if can_scroll_vertically {
            render_v_scroll_indicator(buf, popup, self.state.scroll.v_scroll, max_v, Color::Magenta);
        }
        if can_scroll_horizontally {
            render_h_scroll_indicator(buf, popup, self.state.scroll.h_scroll, max_h, Color::Magenta);
        }
    }
}

fn render_help_single_column(area: Rect, buf: &mut Buffer, v_scroll: usize, h_scroll: usize) {
    let sections = help_sections();
    let lines = build_help_lines(&sections);

    for (i, line) in lines.iter().enumerate().skip(v_scroll) {
        let y = area.y + (i - v_scroll) as u16;
        if y >= area.y + area.height {
            break;
        }
        render_help_line_scrollable(area.x, y, area.width, h_scroll, line, buf);
    }
}

fn render_help_two_columns(area: Rect, buf: &mut Buffer, v_scroll: usize) {
    let sections = help_sections();
    let (left_sections, right_sections) = split_sections_for_columns(&sections);
    let left_lines = build_help_lines(&left_sections);
    let right_lines = build_help_lines(&right_sections);

    let gap = 4u16;
    let col_width = (area.width.saturating_sub(gap)) / 2;
    let right_x = area.x + col_width + gap;
    let max_lines = left_lines.len().max(right_lines.len());

    for i in v_scroll..max_lines {
        let y = area.y + (i - v_scroll) as u16;
        if y >= area.y + area.height {
            break;
        }
        if let Some(line) = left_lines.get(i) {
            render_help_line(area.x, y, col_width, line, buf);
        }
        if let Some(line) = right_lines.get(i) {
            render_help_line(right_x, y, col_width, line, buf);
        }
    }
}

enum HelpLine<'a> {
    Header(&'a str),
    Binding(&'a str, &'a str),
    Empty,
}

fn build_help_lines<'a>(sections: &'a [(&'a str, Vec<(&'a str, &'a str)>)]) -> Vec<HelpLine<'a>> {
    let mut lines = Vec::new();
    for (i, (header, bindings)) in sections.iter().enumerate() {
        lines.push(HelpLine::Header(header));
        for (key, desc) in bindings {
            lines.push(HelpLine::Binding(key, desc));
        }
        if i < sections.len() - 1 {
            lines.push(HelpLine::Empty);
        }
    }
    lines
}

fn render_help_line(x: u16, y: u16, width: u16, line: &HelpLine, buf: &mut Buffer) {
    match line {
        HelpLine::Header(title) => {
            let style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
            buf.set_string(x, y, *title, style);
        }
        HelpLine::Binding(key, desc) => {
            buf.set_string(x + 4, y, *key, Style::default().fg(Color::Cyan));
            let desc_x = x + 16;
            let desc_width = width.saturating_sub(16) as usize;
            let truncated: String = desc.chars().take(desc_width).collect();
            buf.set_string(desc_x, y, &truncated, Style::default().fg(Color::Gray));
        }
        HelpLine::Empty => {}
    }
}

fn render_help_line_scrollable(
    base_x: u16,
    y: u16,
    view_width: u16,
    h_scroll: usize,
    line: &HelpLine,
    buf: &mut Buffer,
) {
    match line {
        HelpLine::Header(title) => {
            let style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
            render_text_at_virtual_x(buf, base_x, y, view_width, h_scroll, 0, title, style);
        }
        HelpLine::Binding(key, desc) => {
            render_text_at_virtual_x(buf, base_x, y, view_width, h_scroll, 4, key, Style::default().fg(Color::Cyan));
            render_text_at_virtual_x(buf, base_x, y, view_width, h_scroll, 16, desc, Style::default().fg(Color::Gray));
        }
        HelpLine::Empty => {}
    }
}

type HelpSection<'a> = Vec<(&'a str, Vec<(&'a str, &'a str)>)>;

fn split_sections_for_columns<'a>(
    sections: &'a [(&'a str, Vec<(&'a str, &'a str)>)],
) -> (HelpSection<'a>, HelpSection<'a>) {
    let total_lines: usize = sections.iter().map(|(_, b)| 1 + b.len() + 1).sum();
    let target = total_lines / 2;

    let mut left = Vec::new();
    let mut right = Vec::new();
    let mut current = 0;

    for section in sections {
        let section_lines = 1 + section.1.len() + 1;
        if current < target {
            left.push((section.0, section.1.clone()));
        } else {
            right.push((section.0, section.1.clone()));
        }
        current += section_lines;
    }

    (left, right)
}

fn help_sections() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("Navigation", vec![
            ("j / ↓", "Move down"),
            ("k / ↑", "Move up"),
            ("gg", "Go to top"),
            ("G", "Go to bottom"),
            ("Ctrl+d", "Half page down"),
            ("Ctrl+u", "Half page up"),
            ("Ctrl+f", "Page down"),
            ("Ctrl+b", "Page up"),
        ]),
        ("Actions", vec![
            ("l / Enter", "View details"),
            ("n", "New credential"),
            ("e", "Edit credential"),
            ("dd / x", "Delete credential"),
        ]),
        ("Clipboard", vec![
            ("yy / c", "Copy password/secret"),
            ("u", "Copy username"),
            ("T", "Copy TOTP code"),
            ("Ctrl+t", "Copy TOTP secret"),
        ]),
        ("View", vec![
            ("Ctrl+s", "Toggle password"),
            ("U", "Toggle usernames in list"),
            ("/", "Search"),
            ("i", "Show logs"),
            ("t", "Show tags"),
        ]),
        ("Commands", vec![
            (":", "Command mode"),
            (":q", "Quit"),
            (":clear", "Clear message"),
            (":changepw", "Change master key"),
            (":audit", "Verify audit log integrity"),
            (":log", "View logs"),
            (":tag", "View tags"),
            (":type <name>", "Filter by type (bare :type clears)"),
            (":set so=<n>", "Keep n rows around cursor (default 5)"),
            (":new", "New credential"),
            (":gen", "Generate password"),
            (":export", "Export Credentials"),
        ]),
        ("Other", vec![
            ("?", "Show this help"),
            ("Ctrl+l", "Clear message"),
            ("Ctrl+p", "Change master key"),
            ("L", "Lock vault"),
            ("q", "Quit"),
        ]),
    ]
}
