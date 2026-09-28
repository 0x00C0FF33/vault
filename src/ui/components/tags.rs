//! Tags popup and state

use std::collections::{HashMap, HashSet};

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Clear, Widget},
};

use crate::db::Credential;

use super::layout::{
    centered_rect_fixed, create_popup_block, highlight_row, render_empty_message,
    render_separator_line, truncate_with_ellipsis,
};
use super::scroll::{render_v_scroll_indicator, ScrollState};

#[derive(Default)]
pub struct TagsState {
    pub scroll: ScrollState,
    pub tags: Vec<(String, usize)>,
    pub selected: usize,
    pub selected_tags: HashSet<String>,
}

impl TagsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_tags_from_credentials(&mut self, credentials: &[Credential], active_filter: Option<&[String]>) {
        self.tags = aggregate_tags(credentials);
        self.scroll.reset();
        self.selected = 0;
        self.selected_tags.clear();
        
        let Some(filter_tags) = active_filter else { return };
        for tag in filter_tags {
            self.selected_tags.insert(tag.clone());
        }
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        if self.selected < self.tags.len().saturating_sub(1) {
            self.selected += 1;
        }
    }

    pub fn page_down(&mut self, amount: usize) {
        self.selected = (self.selected + amount).min(self.tags.len().saturating_sub(1));
    }

    pub fn page_up(&mut self, amount: usize) {
        self.selected = self.selected.saturating_sub(amount);
    }

    pub fn home(&mut self) {
        self.selected = 0;
    }

    pub fn end(&mut self) {
        self.selected = self.tags.len().saturating_sub(1);
    }

    pub fn toggle_selected(&mut self) {
        let Some((tag, _)) = self.tags.get(self.selected) else { return };
        if self.selected_tags.contains(tag) {
            self.selected_tags.remove(tag);
        } else {
            self.selected_tags.insert(tag.clone());
        }
    }

    pub fn get_selected_tags(&self) -> Vec<String> {
        self.selected_tags.iter().cloned().collect()
    }
}

fn aggregate_tags(credentials: &[Credential]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for cred in credentials {
        for tag in &cred.tags {
            *counts.entry(tag.clone()).or_insert(0) += 1;
        }
    }
    let mut tags: Vec<_> = counts.into_iter().collect();
    tags.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    tags
}

pub struct TagsPopup<'a> {
    state: &'a TagsState,
}

impl<'a> TagsPopup<'a> {
    pub fn new(state: &'a TagsState) -> Self {
        Self { state }
    }

    pub fn visible_height(area: Rect) -> u16 {
        let popup = centered_rect_fixed(50, 20, area, true);
        popup.height.saturating_sub(4)
    }
}

impl Widget for TagsPopup<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let height = calculate_tags_height(self.state.tags.len(), area.height);
        let popup = centered_rect_fixed(55, height, area, true);
        Clear.render(popup, buf);

        let block = create_popup_block(" Tags ", Color::Magenta);
        let inner = block.inner(popup);
        block.render(popup, buf);

        if self.state.tags.is_empty() {
            render_empty_message(inner, buf, "No tags found");
            return;
        }

        // Header takes 2 rows (header + separator)
        let header_height = 2u16;
        let list_area_height = inner.height.saturating_sub(header_height) as usize;
        let max_v = self.state.tags.len().saturating_sub(list_area_height);
        let can_scroll_vertically = max_v > 0;

        // Render header (always at top)
        render_tags_header(inner, buf);
        render_separator_line(buf, inner.x, inner.y + 1, inner.width);

        // Calculate list area that reserves bottom line for scroll indicator
        let list_start_y = inner.y + header_height;

        // Calculate list area that reserves bottom line for scroll indicator
        let scroll_offset = calculate_scroll_offset(self.state.selected, list_area_height);

        render_tags_list(inner, buf, list_start_y, list_area_height, scroll_offset, self.state);

        // Render scroll indicator
        if can_scroll_vertically {
            render_v_scroll_indicator(buf, popup, scroll_offset, max_v, Color::Magenta);
        }
    }
}

fn calculate_tags_height(count: usize, area_height: u16) -> u16 {
    let available = area_height.saturating_sub(2);
    // +4 = 2 border + 2 header (header row + separator)
    let desired = (count as u16).saturating_add(4);
    desired.min((available * 75) / 100).max(8)
}

fn render_tags_header(inner: Rect, buf: &mut Buffer) {
    let style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    buf.set_string(inner.x, inner.y, "TAG", style);
    buf.set_string(inner.x + inner.width - 5, inner.y, "COUNT", style);
}

fn render_tags_list(
    inner: Rect,
    buf: &mut Buffer,
    start_y: u16,
    visible_count: usize,
    scroll_offset: usize,
    state: &TagsState,
) {
    for (i, (tag, count)) in state.tags.iter().enumerate().skip(scroll_offset) {
        let row = i - scroll_offset;
        if row >= visible_count {
            break;
        }
        render_tag_row(inner, buf, start_y + row as u16, i, tag, *count, state);
    }
}

fn calculate_scroll_offset(selected: usize, visible: usize) -> usize {
    if selected >= visible { selected - visible + 1 } else { 0 }
}

fn render_tag_row(
    inner: Rect,
    buf: &mut Buffer,
    y: u16,
    idx: usize,
    tag: &str,
    count: usize,
    state: &TagsState,
) {
    let is_cursor = idx == state.selected;
    let is_checked = state.selected_tags.contains(tag);

    if is_cursor {
        highlight_row(buf, inner.x, y, inner.width);
    }

    render_tag_checkbox(buf, inner.x, y, is_checked, is_cursor);
    render_tag_name(buf, inner.x + 2, y, inner.width, tag, is_cursor);
    render_tag_count(buf, inner.x + inner.width - 5, y, count, is_cursor);
}

fn render_tag_checkbox(buf: &mut Buffer, x: u16, y: u16, checked: bool, highlight: bool) {
    let icon = if checked { "󰗠 " } else { "󰄰 " };
    let style = Style::default().fg(Color::Green);
    let style = if highlight { style.bg(Color::DarkGray) } else { style };
    buf.set_string(x, y, icon, style);
}

fn render_tag_name(buf: &mut Buffer, x: u16, y: u16, inner_width: u16, tag: &str, highlight: bool) {
    let max_width = (inner_width as usize).saturating_sub(8);
    let display = truncate_with_ellipsis(tag, max_width);
    let style = Style::default().fg(Color::White);
    let style = if highlight { style.bg(Color::DarkGray) } else { style };
    buf.set_string(x, y, &display, style);
}

fn render_tag_count(buf: &mut Buffer, x: u16, y: u16, count: usize, highlight: bool) {
    let style = Style::default().fg(Color::Cyan);
    let style = if highlight { style.bg(Color::DarkGray) } else { style };
    buf.set_string(x, y, format!("{count:>5}"), style);
}
