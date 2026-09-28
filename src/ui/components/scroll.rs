//! Scroll state management

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};

/// Rows kept visible above and below a cursor, as vim's `scrolloff`.
pub const DEFAULT_SCROLLOFF: usize = 5;
/// vim's conventional "always centre" value. Anything larger behaves the same
/// and only costs ratatui more work shrinking the padding to fit.
pub const MAX_SCROLLOFF: usize = 999;

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

/// The rows a cursor-following view currently shows.
///
/// For views that draw their own rows; ratatui's `List` does the same job
/// through `scroll_padding`.
#[derive(Debug, Clone, Copy)]
pub struct Viewport {
    /// First visible row.
    pub offset: usize,
    /// Rows that fit on screen.
    pub height: usize,
    /// Rows in total.
    pub len: usize,
}

impl Viewport {
    /// The offset that keeps `cursor` at least `scrolloff` rows from either
    /// edge, moving as little as possible from the current one, as vim does.
    ///
    /// The padding shrinks to fit a short view, which centres the cursor when
    /// it is too large, and the view never scrolls past its last row.
    pub fn follow(self, cursor: usize, scrolloff: usize) -> usize {
        if self.height == 0 {
            return 0;
        }
        let padding = scrolloff.min((self.height - 1) / 2);
        let lowest = (cursor + padding + 1).saturating_sub(self.height);
        let highest = cursor.saturating_sub(padding);
        let last_page = self.len.saturating_sub(self.height);

        self.offset.max(lowest).min(highest).min(last_page)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 30 rows through a 12-row window: the most that leaves room for a
    /// scrolloff of 5 on both sides of the cursor.
    fn window_at(offset: usize) -> Viewport {
        Viewport { offset, height: 12, len: 30 }
    }

    #[test]
    fn moving_down_scrolls_once_the_cursor_enters_the_padding() {
        assert_eq!(window_at(0).follow(6, 5), 0);
        assert_eq!(window_at(0).follow(7, 5), 1);
        assert_eq!(window_at(1).follow(8, 5), 2);
    }

    #[test]
    fn moving_up_inside_the_window_does_not_scroll() {
        assert_eq!(window_at(10).follow(15, 5), 10);
        assert_eq!(window_at(10).follow(14, 2), 10);
    }

    #[test]
    fn moving_up_scrolls_once_the_cursor_enters_the_top_padding() {
        assert_eq!(window_at(10).follow(14, 5), 9);
    }

    #[test]
    fn the_last_page_is_not_scrolled_past() {
        assert_eq!(window_at(18).follow(29, 5), 18);
        assert_eq!(window_at(0).follow(29, 5), 18);
    }

    #[test]
    fn scrolloff_zero_scrolls_only_at_the_edge() {
        assert_eq!(window_at(0).follow(11, 0), 0);
        assert_eq!(window_at(0).follow(12, 0), 1);
    }

    /// A 10-row window fits only 4 rows either side of the cursor.
    #[test]
    fn padding_shrinks_to_fit_a_short_window() {
        let short = Viewport { offset: 0, height: 10, len: 30 };
        assert_eq!(short.follow(5, 5), 0);
        assert_eq!(short.follow(6, 5), 1);
    }

    #[test]
    fn an_oversized_scrolloff_centres_the_cursor() {
        let odd = Viewport { offset: 0, height: 11, len: 30 };
        assert_eq!(odd.follow(15, 999), 10);
    }

    #[test]
    fn a_list_shorter_than_the_window_never_scrolls() {
        let short = Viewport { offset: 0, height: 12, len: 4 };
        assert_eq!(short.follow(3, 5), 0);
    }

    #[test]
    fn a_zero_height_window_stays_at_the_top() {
        let hidden = Viewport { offset: 7, height: 0, len: 30 };
        assert_eq!(hidden.follow(12, 5), 0);
    }
}
