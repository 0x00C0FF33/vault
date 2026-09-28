//! Layout helpers and common rendering utilities

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::{Widget, Block, BorderType, Borders, Paragraph},
};

/// Percentage based layout
pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let content_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(2));
    let width = (u32::from(content_area.width) * u32::from(percent_x) / 100) as u16;
    let height = (u32::from(content_area.height) * u32::from(percent_y) / 100) as u16;
    let remainder_x = (content_area.width.saturating_sub(width)) % 2;
    let remainder_y = (content_area.height.saturating_sub(height)) % 2;
    let adj_w = width + remainder_x;
    let adj_h = height + remainder_y;
    let x = content_area.x + (content_area.width.saturating_sub(adj_w)) / 2;
    let y = content_area.y + (content_area.height.saturating_sub(adj_h)) / 2;
    Rect::new(x, y, adj_w.min(content_area.width), adj_h.min(content_area.height))
}

/// Fixed sized layout
pub fn centered_rect_fixed(width: u16, height: u16, area: Rect, unlocked: bool) -> Rect {
    let available_height = if unlocked { area.height.saturating_sub(2) } else { area.height };
    let remainder_x = (area.width.saturating_sub(width)) % 2;
    let remainder_y = (available_height.saturating_sub(height)) % 2;
    let adj_w = width + remainder_x;
    let adj_h = height + remainder_y;
    let x = area.x + (area.width.saturating_sub(adj_w)) / 2;
    let y = area.y + (available_height.saturating_sub(adj_h)) / 2;
    Rect::new(x, y, adj_w.min(area.width), adj_h.min(available_height))
}

pub fn create_popup_block(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .style(Style::default().bg(Color::Black))
}

pub fn render_empty_message(area: Rect, buf: &mut Buffer, msg: &str) {
    Paragraph::new(msg)
        .style(Style::default().fg(Color::DarkGray))
        .render(area, buf);
}

pub fn render_separator_line(buf: &mut Buffer, x: u16, y: u16, width: u16) {
    for px in x..x + width {
        buf.set_string(px, y, "─", Style::default().fg(Color::DarkGray));
    }
}

pub fn highlight_row(buf: &mut Buffer, x: u16, y: u16, width: u16) {
    for px in x..x + width {
        if let Some(cell) = buf.cell_mut((px, y)) {
            cell.set_bg(Color::DarkGray);
        }
    }
}

pub fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    format!("{}…", &s[..max_len.saturating_sub(1)])
}

#[allow(clippy::too_many_arguments)]
pub fn render_text_at_virtual_x(
    buf: &mut Buffer,
    base_x: u16,
    y: u16,
    view_width: u16,
    h_offset: usize,
    virtual_x: u16,
    text: &str,
    style: Style,
) {
    let h_off = h_offset as u16;
    let text_len = text.chars().count() as u16;

    if virtual_x + text_len <= h_off {
        return;
    }
    if virtual_x >= h_off + view_width {
        return;
    }

    let screen_x = if virtual_x >= h_off { base_x + virtual_x - h_off } else { base_x };
    let skip_chars = if virtual_x < h_off { (h_off - virtual_x) as usize } else { 0 };
    let available = (base_x + view_width).saturating_sub(screen_x) as usize;

    let visible_text: String = text.chars().skip(skip_chars).take(available).collect();
    buf.set_string(screen_x, y, &visible_text, style);
}
