//! Scroll state management

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};

#[derive(Default, Clone)]
pub struct ScrollState {
    pub v_scroll: usize,
    pub h_scroll: usize,
    pub pending_g: bool,
}

impl ScrollState {
    pub fn reset(&mut self) {
        self.v_scroll = 0;
        self.h_scroll = 0;
        self.pending_g = false;
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.v_scroll = self.v_scroll.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max: usize) {
        self.v_scroll = (self.v_scroll + amount).min(max);
    }

    pub fn scroll_left(&mut self, amount: usize) {
        self.h_scroll = self.h_scroll.saturating_sub(amount);
    }

    pub fn scroll_right(&mut self, amount: usize, max: usize) {
        self.h_scroll = (self.h_scroll + amount).min(max);
    }

    pub fn home(&mut self) {
        self.v_scroll = 0;
    }

    pub fn end(&mut self, max: usize) {
        self.v_scroll = max;
    }

    pub fn h_home(&mut self) {
        self.h_scroll = 0;
    }

    pub fn h_end(&mut self, max: usize) {
        self.h_scroll = max;
    }
}

/// Renders a vertical scroll indicator (up/down arrow) centered horizontally
pub fn render_v_scroll_indicator(buf: &mut Buffer, inner: Rect, v_offset: usize, max_v: usize, color: Color) {
    if max_v == 0 {
        return;
    }
    let icon = match (v_offset == 0, v_offset >= max_v) {
        (true, _) => "  ",   // at top, can scroll down
        (_, true) => "  ",   // at bottom, can scroll up
        _ => "  ",           // mid-scroll, can scroll both
    };
    let x = inner.x + (inner.width.saturating_sub(icon.chars().count() as u16)) / 2;
    let y = inner.y + inner.height.saturating_sub(1);
    buf.set_string(x, y, icon, Style::default().fg(color));
}

/// Renders a horizontal scroll indicator in top-right corner
pub fn render_h_scroll_indicator(
    buf: &mut Buffer,
    inner: Rect,
    h_offset: usize,
    max_h: usize,
    color: Color,
) {
    if max_h == 0 {
        return;
    }
    let indicator = match (h_offset == 0, h_offset >= max_h) {
        (true, _) => "  ",
        (_, true) => "  ",
        _ => "  ",
    };
    let x = inner.x + inner.width.saturating_sub(indicator.len() as u16);
    buf.set_string(x, inner.y, indicator, Style::default().fg(color));
}
