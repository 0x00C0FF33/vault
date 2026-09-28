//! List View Component
//!
//! Displays credentials in a scrollable list.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, StatefulWidget, Widget},
};

use crate::db::models::CredentialType;
use crate::ui::renderer::Renderer;

#[derive(Debug, Clone)]
pub struct CredentialItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub credential_type: CredentialType,
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct ListViewState {
    pub selected: Option<usize>,
    pub total: usize,
    /// Stored inverted so the derived default shows usernames.
    usernames_hidden: bool,
    list_state: ListState,
}


impl ListViewState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list_state_ref(&self) -> &ListState {
        &self.list_state
    }

    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
        self.list_state.select(index);
    }

    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    /// Keeps the scroll position, so removing or adding one entry does not
    /// move the rows around the cursor. Replacing the contents wholesale is
    /// the caller's cue to `scroll_to_top` as well.
    pub fn set_total(&mut self, total: usize) {
        self.total = total;
        self.select(compute_selection_after_total_change(self.selected, total));
    }

    pub fn scroll_to_top(&mut self) {
        *self.list_state.offset_mut() = 0;
    }

    pub fn move_up(&mut self) {
        if self.total == 0 {
            return;
        }
        let new_index = self.selected.unwrap_or(0).saturating_sub(1);
        self.select(Some(new_index));
    }

    pub fn move_down(&mut self) {
        if self.total == 0 {
            return;
        }
        let new_index = self.selected.map_or(0, |i| (i + 1).min(self.total - 1));
        self.select(Some(new_index));
    }

    pub fn move_to_top(&mut self) {
        if self.total > 0 {
            self.select(Some(0));
        }
    }

    pub fn move_to_bottom(&mut self) {
        if self.total > 0 {
            self.select(Some(self.total - 1));
        }
    }

    pub fn page_up(&mut self, page_size: usize) {
        if self.total == 0 {
            return;
        }
        let new_index = self.selected.unwrap_or(0).saturating_sub(page_size);
        self.select(Some(new_index));
    }

    pub fn page_down(&mut self, page_size: usize) {
        if self.total == 0 {
            return;
        }
        let new_index = self.selected.map_or(0, |i| (i + page_size).min(self.total - 1));
        self.select(Some(new_index));
    }

    pub fn usernames_visible(&self) -> bool {
        !self.usernames_hidden
    }

    pub fn set_usernames_visible(&mut self, visible: bool) {
        self.usernames_hidden = !visible;
    }

    pub fn list_state_mut(&mut self) -> &mut ListState {
        &mut self.list_state
    }
}

fn compute_selection_after_total_change(selected: Option<usize>, total: usize) -> Option<usize> {
    if total == 0 {
        return None;
    }
    match selected {
        Some(sel) if sel >= total => Some(total - 1),
        Some(sel) => Some(sel),
        None => Some(0),
    }
}

pub struct CredentialList<'a> {
    items: &'a [CredentialItem],
    block: Option<Block<'a>>,
    highlight_style: Style,
    show_username: bool,
}

impl<'a> CredentialList<'a> {
    pub fn new(items: &'a [CredentialItem]) -> Self {
        Self {
            items,
            block: None,
            highlight_style: Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD),
            show_username: true,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn show_username(mut self, show: bool) -> Self {
        self.show_username = show;
        self
    }
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

fn build_selection_symbol(is_selected: bool) -> Span<'static> {
    if is_selected {
        Span::styled(" ", Style::default().fg(Color::Magenta).bg(Color::DarkGray))
    } else {
        Span::raw("  ")
    }
}

fn build_item_spans(
    item: &CredentialItem,
    is_selected: bool,
    highlight_style: Style,
    show_username: bool,
) -> Vec<Span<'_>> {
    let base_style = if is_selected { highlight_style } else { Style::default() };
    let icon = item.credential_type.icon();
    let color = type_color(item.credential_type);
    let mut spans = vec![
        build_selection_symbol(is_selected),
        Span::styled(format!("{icon} "), base_style.fg(color)),
        Span::styled(item.name.as_str(), base_style.fg(Color::White)),
    ];
    append_username_span(&mut spans, item, base_style, show_username);
    spans
}

fn append_username_span<'a>(spans: &mut Vec<Span<'a>>, item: &'a CredentialItem, base_style: Style, show_username: bool) {
    if !show_username { return }
    let Some(ref username) = item.username else { return };
    spans.push(Span::styled(
        format!(" ({username})"),
        base_style.fg(Renderer::hex_color(0x004C_566A)),
    ));
}

fn build_list_item(
    item: &CredentialItem,
    index: usize,
    selected: Option<usize>,
    highlight_style: Style,
    show_username: bool,
) -> ListItem<'_> {
    let is_selected = Some(index) == selected;
    let spans = build_item_spans(item, is_selected, highlight_style, show_username);
    let mut list_item = ListItem::new(Line::from(spans));

    if is_selected {
        list_item = list_item.style(highlight_style);
    }

    list_item
}

impl StatefulWidget for CredentialList<'_> {
    type State = ListViewState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let selected = state.selected();

        let items: Vec<ListItem> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| build_list_item(item, i, selected, self.highlight_style, self.show_username))
            .collect();

        let list = List::new(items);
        let list = match self.block {
            Some(block) => list.block(block),
            None => list,
        };

        StatefulWidget::render(list, area, buf, state.list_state_mut());
    }
}

pub struct EmptyState<'a> {
    message: &'a str,
    hint: Option<&'a str>,
    block: Option<Block<'a>>,
}

impl<'a> EmptyState<'a> {
    pub fn new(message: &'a str) -> Self {
        Self { message, hint: None, block: None }
    }

    pub fn hint(mut self, hint: &'a str) -> Self {
        self.hint = Some(hint);
        self
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
}

impl Widget for EmptyState<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let inner = render_optional_block(area, buf, self.block.as_ref());

        let center_y = inner.y + inner.height / 2;
        let msg_x = center_x(&inner, self.message.len());
        buf.set_string(msg_x, center_y, self.message, Style::default().fg(Color::DarkGray));
        render_optional_hint(buf, &inner, center_y, self.hint);
    }
}

fn center_x(area: &Rect, text_len: usize) -> u16 {
    area.x + (area.width.saturating_sub(text_len as u16)) / 2
}

fn render_optional_block(area: Rect, buf: &mut Buffer, block: Option<&Block>) -> Rect {
    let Some(block) = block else { return area };
    let inner = block.inner(area);
    block.clone().render(area, buf);
    inner
}

fn render_optional_hint(buf: &mut Buffer, area: &Rect, center_y: u16, hint: Option<&str>) {
    let Some(hint) = hint else { return };
    let hint_x = center_x(area, hint.len());
    let style = Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC);
    buf.set_string(hint_x, center_y + 1, hint, style);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_state_navigation() {
        let mut state = ListViewState::new();
        state.set_total(5);

        assert_eq!(state.selected(), Some(0));

        state.move_down();
        assert_eq!(state.selected(), Some(1));

        state.move_up();
        assert_eq!(state.selected(), Some(0));

        state.move_to_bottom();
        assert_eq!(state.selected(), Some(4));

        state.move_to_top();
        assert_eq!(state.selected(), Some(0));
    }

    fn render_row(list: CredentialList) -> String {
        let area = Rect::new(0, 0, 40, 1);
        let mut buf = Buffer::empty(area);
        let mut state = ListViewState::new();
        state.set_total(1);
        list.render(area, &mut buf, &mut state);
        (0..area.width).map(|x| buf[(x, 0)].symbol()).collect()
    }

    fn sample_items() -> Vec<CredentialItem> {
        vec![CredentialItem {
            id: "1".to_string(),
            name: "github".to_string(),
            username: Some("me@example.com".to_string()),
            credential_type: CredentialType::Password,
        }]
    }

    #[test]
    fn username_is_shown_by_default() {
        let items = sample_items();
        assert!(render_row(CredentialList::new(&items)).contains("(me@example.com)"));
    }

    #[test]
    fn username_can_be_hidden() {
        let items = sample_items();
        let row = render_row(CredentialList::new(&items).show_username(false));
        assert!(row.contains("github"));
        assert!(!row.contains("me@example.com"));
    }

    #[test]
    fn usernames_visibility_on_list_state() {
        let mut state = ListViewState::new();
        assert!(state.usernames_visible());

        state.set_usernames_visible(false);
        assert!(!state.usernames_visible());

        state.set_total(3);
        assert!(!state.usernames_visible(), "reloading the list must not reset the choice");

        state.set_usernames_visible(true);
        assert!(state.usernames_visible());
    }

    #[test]
    fn test_list_state_empty() {
        let mut state = ListViewState::new();
        state.set_total(0);

        state.move_down();
        assert_eq!(state.selected(), None);
    }
}
