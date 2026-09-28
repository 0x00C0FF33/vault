//! Renderer
//!
//! Main rendering logic for the application.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, BorderType, Widget},
    Frame,
};

use super::components::{
    ConfirmDialog, CredentialDetail, CredentialForm, CredentialFormWidget, CredentialItem,
    CredentialList, DetailView, EmptyState, HelpBar, HelpScreen, ListViewState, MessageType,
    PasswordDialog, StatusLine,
};
use crate::db::models::CredentialType;
use crate::input::InputMode;
use crate::ui::components::help::HelpState;
use crate::ui::components::logs::{LogsScreen, LogsState};
use crate::ui::components::tags::{TagsPopup, TagsState};
use crate::ui::components::export::{ExportDialog, ExportDialogWidget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    List,
    Detail,
    Form,
}

pub struct UiState<'a> {
    pub view: View,
    pub mode: InputMode,
    pub credentials: &'a [CredentialItem],
    pub list_state: &'a mut ListViewState,
    pub scrolloff: usize,
    pub list_area: &'a mut Option<Rect>,
    pub selected_detail: Option<&'a CredentialDetail>,
    pub search_query: Option<&'a str>,
    pub filter_tags: Option<&'a [String]>,
    pub filter_type: Option<CredentialType>,
    pub command_buffer: Option<&'a str>,
    pub message: Option<(&'a str, MessageType)>,
    pub confirm_message: Option<&'a str>,
    pub password_prompt: Option<PasswordPrompt<'a>>,
    pub credential_form: Option<&'a CredentialForm>,
    pub help_state: &'a HelpState,
    pub logs_state: &'a LogsState,
    pub tags_state: &'a mut TagsState,
    pub export_dialog: Option<&'a ExportDialog>,
}

pub struct PasswordPrompt<'a> {
    pub title: &'a str,
    pub prompt: &'a str,
    pub value: &'a str,
    pub cursor: usize,
    pub error: Option<&'a str>,
}

pub struct Renderer;

impl Renderer {
    pub fn hex_color(rgb: u32) -> Color {
        Color::Rgb(
            ((rgb >> 16) & 0xFF) as u8,
            ((rgb >> 8) & 0xFF) as u8,
            (rgb & 0xFF) as u8,
        )
    }

    pub fn render(frame: &mut Frame, state: &mut UiState) {
        let size = frame.area();
        let chunks = create_main_layout(size);

        render_content(frame, chunks[0], state);
        render_status_line(frame, chunks[1], state);
        render_help_bar(frame, chunks[2], state.mode);
        render_overlays(frame, size, state);
    }
}

fn create_main_layout(size: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(size)
}

fn render_content(frame: &mut Frame, area: Rect, state: &mut UiState) {
    match state.view {
        View::List => render_list(frame, area, state),
        View::Detail => render_detail(frame, area, state),
        View::Form => render_form(frame, area, state),
    }
}

fn render_status_line(frame: &mut Frame, area: Rect, state: &UiState) {
    let mut status = StatusLine::new(state.mode);

    if let Some(buffer) = state.command_buffer {
        status = status.command_buffer(buffer);
    } else if let Some((msg, msg_type)) = state.message {
        status = status.message(msg, msg_type);
    }

    if let Some(cred_type) = state.filter_type {
        status = status.filter_type(cred_type);
    }
    if let Some(tags) = state.filter_tags {
        status = status.filter_tags(tags);
    }

    if let Some(query) = state.search_query {
        status = status.search_query(query);
    }

    if let Some(selected) = state.list_state.selected() {
        status = status.item_count(selected, state.list_state.total);
    }

    frame.render_widget(status, area);
}

fn render_help_bar(frame: &mut Frame, area: Rect, mode: InputMode) {
    let help_bar = HelpBar::for_mode(mode);
    frame.render_widget(help_bar, area);
}

fn render_list(frame: &mut Frame, area: Rect, state: &mut UiState) {
    *state.list_area = Some(area);

    if state.credentials.is_empty() {
        let empty = EmptyState::new("No credentials found")
            .hint("Press 'n' to add one");
        frame.render_widget(empty, area);
        return;
    }

    let block = create_credentials_block(Color::Magenta);
    let list = CredentialList::new(state.credentials)
        .show_username(state.list_state.usernames_visible())
        .scrolloff(state.scrolloff)
        .block(block);
    frame.render_stateful_widget(list, area, state.list_state);
}

fn render_detail(frame: &mut Frame, area: Rect, state: &mut UiState) {
    let half = area.width / 2;
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(half), Constraint::Fill(1)])
        .split(area);

    render_detail_list(frame, chunks[0], state);
    render_detail_panel(frame, chunks[1], state.selected_detail);
}

fn render_detail_list(frame: &mut Frame, area: Rect, state: &mut UiState) {
    *state.list_area = Some(area);

    let block = create_credentials_block(Color::DarkGray);
    let list = CredentialList::new(state.credentials)
        .show_username(state.list_state.usernames_visible())
        .scrolloff(state.scrolloff)
        .block(block);
    frame.render_stateful_widget(list, area, state.list_state);
}

fn render_detail_panel(frame: &mut Frame, area: Rect, detail: Option<&CredentialDetail>) {
    match detail {
        Some(d) => frame.render_widget(DetailView::new(d), area),
        None => render_empty_detail_panel(frame, area),
    }
}

fn render_empty_detail_panel(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Detail ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));
    frame.render_widget(
        EmptyState::new("No credential selected")
            .hint("Select from list or press 'n' to add")
            .block(block),
        area,
    );
}

fn create_credentials_block(border_color: Color) -> Block<'static> {
    Block::default()
        .title(" Credentials ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
}

fn render_form(frame: &mut Frame, area: Rect, state: &UiState) {
    match state.credential_form {
        Some(form) => frame.render_widget(CredentialFormWidget::new(form), area),
        None => frame.render_widget(create_fallback_form_block(), area),
    }
}

fn create_fallback_form_block() -> Block<'static> {
    Block::default()
        .title(" Form ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Green))
}

fn render_overlays(frame: &mut Frame, area: Rect, state: &mut UiState) {
    if render_help_overlay(frame, area, state) {
        return;
    }

    render_tags_overlay(frame, state);
    render_logs_overlay(frame, state);
    render_export_overlay(frame, area, state);

    if render_confirm_overlay(frame, area, state) {
        return;
    }

    render_password_overlay(frame, area, state);
}

fn render_help_overlay(frame: &mut Frame, area: Rect, state: &UiState) -> bool {
    if state.mode != InputMode::Help {
        return false;
    }
    frame.render_widget(HelpScreen::new(state.help_state), area);
    true
}

fn render_tags_overlay(frame: &mut Frame, state: &mut UiState) {
    if state.mode != InputMode::Tags {
        return;
    }
    frame.render_stateful_widget(TagsPopup::new(state.scrolloff), frame.area(), state.tags_state);
}

fn render_logs_overlay(frame: &mut Frame, state: &UiState) {
    if state.mode != InputMode::Logs {
        return;
    }
    LogsScreen::new(state.logs_state).render(frame.area(), frame.buffer_mut());
}

fn render_export_overlay(frame: &mut Frame, area: Rect, state: &UiState) {
    if state.mode != InputMode::Export {
        return;
    }
    if let Some(dialog) = state.export_dialog {
        ExportDialogWidget::new(dialog).render(area, frame.buffer_mut());
    }
}

fn render_confirm_overlay(frame: &mut Frame, area: Rect, state: &UiState) -> bool {
    if state.mode != InputMode::Confirm {
        return false;
    }
    if let Some(msg) = state.confirm_message {
        let dialog = ConfirmDialog::new(" Confirm ", msg);
        frame.render_widget(dialog, area);
    }
    true
}

fn render_password_overlay(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(prompt) = &state.password_prompt else {
        return;
    };

    let mut dialog = PasswordDialog::new(prompt.title, prompt.prompt, prompt.value, prompt.cursor);
    if let Some(err) = prompt.error {
        dialog = dialog.error(err);
    }
    frame.render_widget(dialog, area);
}
