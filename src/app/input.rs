use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::input::{
    keymap::{confirm_action, normal_mode_action, text_input_action, Action},
    modes::InputMode,
};
use crate::ui::{
    components::{help::HelpScreen, logs::LogsScreen, tags::TagsPopup},
    components::{CredentialForm, MessageType, export::ExportField}
};

use super::config::PendingAction;
use super::App;

type KeyHandler = fn(&mut App, KeyCode, KeyModifiers) -> Option<Action>;

/// Outcome of a popup's exit-key check: the key may be unclaimed, claimed with
/// nothing further to do, or claimed and yielding an action.
enum ExitOutcome {
    NotExit,
    Exited,
    Action(Action),
}

impl App {
    pub fn handle_key_event(&mut self, key: KeyEvent) -> Result<bool, Box<dyn std::error::Error>> {
        if key.kind != KeyEventKind::Press {
            return Ok(false);
        }

        if self.mode_state.mode == InputMode::Insert && self.credential_form.is_some() {
            return self.handle_form_key(key);
        }

        let action = self.resolve_action(key);
        self.execute_action(action)
    }

    fn resolve_action(&mut self, key: KeyEvent) -> Action {
        match self.mode_state.mode {
            InputMode::Normal => self.resolve_normal_action(key),
            InputMode::Command | InputMode::Search => self.resolve_text_action(key),
            InputMode::Confirm => confirm_action(key),
            InputMode::Help => self.popup_action(key, help_key_handler),
            InputMode::Logs => self.popup_action(key, logs_key_handler),
            InputMode::Tags => self.popup_action(key, tags_key_handler),
            InputMode::Export => self.handle_export_key(key),
            InputMode::Insert => Action::None,
        }
    }

    fn resolve_normal_action(&mut self, key: KeyEvent) -> Action {
        let (action, pending) = normal_mode_action(key, self.mode_state.pending);
        self.mode_state.pending = pending;
        action
    }

    fn resolve_text_action(&mut self, key: KeyEvent) -> Action {
        let action = text_input_action(key);
        self.handle_text_input(action)
    }

    fn popup_action(&mut self, key: KeyEvent, handler: KeyHandler) -> Action {
        self.handle_popup_key(key, handler);
        Action::None
    }

    fn handle_popup_key(&mut self, key: KeyEvent, handler: KeyHandler) {
        let Some(action) = handler(self, key.code, key.modifiers) else {
            return;
        };
        let _ = self.execute_action(action);
    }

    fn handle_text_input(&mut self, action: Action) -> Action {
        match action {
            Action::InsertChar(c) => { self.mode_state.insert_char(c); Action::None }
            Action::DeleteChar => { self.mode_state.delete_char(); Action::None }
            Action::DeleteWord => { self.mode_state.delete_word(); Action::None }
            Action::CursorLeft => { self.mode_state.cursor_left(); Action::None }
            Action::CursorRight => { self.mode_state.cursor_right(); Action::None }
            Action::CursorWordLeft => { self.mode_state.cursor_word_left(); Action::None }
            Action::CursorWordRight => { self.mode_state.cursor_word_right(); Action::None }
            Action::CursorHome => { self.mode_state.cursor_home(); Action::None }
            Action::CursorEnd => { self.mode_state.cursor_end(); Action::None }
            Action::ClearToStart => { self.mode_state.clear_to_start(); Action::None }
            Action::Submit => self.submit_text_input(),
            Action::Cancel => { self.mode_state.enter_normal_mode(); Action::None }
            _ => action,
        }
    }

    fn submit_text_input(&mut self) -> Action {
        let buffer = self.mode_state.get_buffer().to_string();
        let result = match self.mode_state.mode {
            InputMode::Command => Action::ExecuteCommand(buffer),
            InputMode::Search => Action::Search(buffer),
            _ => Action::None,
        };
        self.mode_state.enter_normal_mode();
        result
    }

    fn handle_form_key(&mut self, key: KeyEvent) -> Result<bool, Box<dyn std::error::Error>> {
        let form = self.credential_form.as_mut().unwrap();
        let return_to = form.previous_view;

        if key.code == KeyCode::Esc {
            self.credential_form = None;
            self.view = return_to;
            self.mode_state.enter_normal_mode();
            return Ok(false);
        }

        if key.code == KeyCode::Enter && key.modifiers == KeyModifiers::NONE {
            return self.submit_form();
        }

        if key.code == KeyCode::Char('g') && key.modifiers == KeyModifiers::CONTROL {
            self.generate_secret_in_form()?;
            return Ok(false);
        }

        let form = self.credential_form.as_mut().unwrap();
        dispatch_form_key(form, key.code, key.modifiers, self.terminal_size.height);
        Ok(false)
    }

    fn submit_form(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let form = self.credential_form.as_ref().unwrap();
        if let Err(e) = form.validate() {
            self.set_message(&e, MessageType::Error);
            return Ok(false);
        }
        // The secret field is masked, so a stray Ctrl+g or keystroke would
        // otherwise overwrite the only copy of the old secret unseen.
        if let Some(replacement) = form.secret_replacement() {
            self.pending_action = Some(PendingAction::SaveReplacingSecret(replacement));
            self.mode_state.enter_confirm_mode();
            return Ok(false);
        }
        self.save_credential_form()?;
        Ok(false)
    }

    fn handle_export_key(&mut self, key: KeyEvent) -> Action {
        let Some(dialog) = self.export_dialog.as_mut() else {
            return Action::None;
        };

        match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => self.cancel_export(),
            (KeyCode::Enter, KeyModifiers::NONE) => { let _ = self.execute_export(); }
            (KeyCode::Tab, KeyModifiers::NONE) | (KeyCode::Down, _) => dialog.next_field(),
            (KeyCode::BackTab | KeyCode::Up, _) => dialog.prev_field(),
            (KeyCode::Char(' '), KeyModifiers::NONE) => handle_export_space(dialog),
            (KeyCode::Char(' '), KeyModifiers::CONTROL) => handle_export_ctrl_space(dialog),
            _ => { dialog.handle_text_key(key.code, key.modifiers); }
        }

        Action::None
    }
}

fn handle_export_space(dialog: &mut crate::ui::components::export::ExportDialog) {
    match dialog.active_field {
        ExportField::Format => dialog.cycle_format(),
        ExportField::Encryption => dialog.cycle_encryption_forward(),
        _ => dialog.insert_char(' '),
    }
}

fn handle_export_ctrl_space(dialog: &mut crate::ui::components::export::ExportDialog) {
    match dialog.active_field {
        ExportField::Format => dialog.cycle_format(),
        ExportField::Encryption => dialog.cycle_encryption_backward(),
        _ => {}
    }
}

fn dispatch_form_key(form: &mut CredentialForm, code: KeyCode, mods: KeyModifiers, area_height: u16) {
    match (code, mods) {
        (KeyCode::Tab, KeyModifiers::NONE) | (KeyCode::Down, _) => form.next_field(area_height),
        (KeyCode::BackTab | KeyCode::Up, _) => form.prev_field(area_height),
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => form.toggle_password_visibility(),
        (KeyCode::Char(' '), m) if form.is_select_field() => form.cycle_type(m != KeyModifiers::CONTROL),
        _ => { form.handle_text_key(code, mods, area_height); }
    }
}

fn help_key_handler(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Option<Action> {
    match help_exit_action(app, code, mods) {
        ExitOutcome::Exited => return None,
        ExitOutcome::Action(action) => return Some(action),
        ExitOutcome::NotExit => {}
    }

    let was_pending = app.help_state.scroll.pending_g;
    app.help_state.scroll.pending_g = false;

    let size = app.terminal_size;
    let visible = HelpScreen::visible_height(size) as usize;
    let max_v = HelpScreen::max_scroll(size);
    let max_h = HelpScreen::max_h_scroll(size);

    help_scroll_action(app, code, mods, was_pending, visible, max_v, max_h);
    None
}

fn help_exit_action(app: &mut App, code: KeyCode, mods: KeyModifiers) -> ExitOutcome {
    match (code, mods) {
        (KeyCode::Char('?'), KeyModifiers::NONE | KeyModifiers::SHIFT)
        | (KeyCode::Char('q'), KeyModifiers::NONE)
        | (KeyCode::Esc, _) => {
            app.mode_state.enter_normal_mode();
            ExitOutcome::Exited
        }
        (KeyCode::Char('i'), KeyModifiers::NONE) => ExitOutcome::Action(Action::ShowLogs),
        (KeyCode::Char('t'), KeyModifiers::NONE) => ExitOutcome::Action(Action::ShowTags),
        _ => ExitOutcome::NotExit,
    }
}

fn help_scroll_action(app: &mut App, code: KeyCode, mods: KeyModifiers, was_pending: bool, visible: usize, max_v: usize, max_h: usize) {
    match (code, mods) {
        (KeyCode::Char('g'), KeyModifiers::NONE) if was_pending => app.help_state.home(),
        (KeyCode::Char('g'), KeyModifiers::NONE) => app.help_state.scroll.pending_g = true,
        (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, _) => app.help_state.scroll_down(1, max_v),
        (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, _) => app.help_state.scroll_up(1),
        (KeyCode::Char('G'), KeyModifiers::SHIFT) => app.help_state.end(max_v),
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => app.help_state.page_down(visible / 2, max_v),
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => app.help_state.page_up(visible / 2),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => app.help_state.page_down(visible.saturating_sub(1), max_v),
        (KeyCode::Char('b'), KeyModifiers::CONTROL) => app.help_state.page_up(visible.saturating_sub(1)),
        (KeyCode::Char('h'), KeyModifiers::NONE) | (KeyCode::Left, _) => app.help_state.scroll_left(5),
        (KeyCode::Char('l'), KeyModifiers::NONE) | (KeyCode::Right, _) => app.help_state.scroll_right(5, max_h),
        (KeyCode::Char('0'), KeyModifiers::NONE) => app.help_state.h_home(),
        (KeyCode::Char('$'), _) => app.help_state.h_end(max_h),
        _ => {}
    }
}

fn logs_key_handler(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Option<Action> {
    match logs_exit_action(app, code, mods) {
        ExitOutcome::Exited => return None,
        ExitOutcome::Action(action) => return Some(action),
        ExitOutcome::NotExit => {}
    }

    let size = app.terminal_size;
    let state = &mut app.logs_state;

    let was_pending = state.scroll.pending_g;
    state.scroll.pending_g = false;

    let visible_height = LogsScreen::visible_height(size);
    let visible = visible_height as usize;
    let max_v = state.max_scroll(visible_height);
    let visible_width = LogsScreen::visible_width(size);
    let max_h = state.max_h_scroll(visible_width);

    logs_scroll_action(state, code, mods, was_pending, visible, max_v, max_h);
    None
}

fn logs_exit_action(app: &mut App, code: KeyCode, mods: KeyModifiers) -> ExitOutcome {
    match (code, mods) {
        (KeyCode::Char('i' | 'q'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
            app.mode_state.enter_normal_mode();
            ExitOutcome::Exited
        }
        (KeyCode::Char('?'), KeyModifiers::NONE | KeyModifiers::SHIFT) => ExitOutcome::Action(Action::ShowHelp),
        (KeyCode::Char('t'), KeyModifiers::NONE) => ExitOutcome::Action(Action::ShowTags),
        _ => ExitOutcome::NotExit,
    }
}

fn logs_scroll_action(state: &mut crate::ui::components::logs::LogsState, code: KeyCode, mods: KeyModifiers, was_pending: bool, visible: usize, max_v: usize, max_h: usize) {
    match (code, mods) {
        (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, _) => state.scroll_down(1, max_v),
        (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, _) => state.scroll_up(1),
        (KeyCode::Char('g'), KeyModifiers::NONE) if was_pending => state.home(),
        (KeyCode::Char('g'), KeyModifiers::NONE) => state.scroll.pending_g = true,
        (KeyCode::Char('G'), KeyModifiers::SHIFT) => state.end(max_v),
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => state.page_down(visible / 2, max_v),
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => state.page_up(visible / 2),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => state.page_down(visible.saturating_sub(1), max_v),
        (KeyCode::Char('b'), KeyModifiers::CONTROL) => state.page_up(visible.saturating_sub(1)),
        (KeyCode::Char('h'), KeyModifiers::NONE) | (KeyCode::Left, _) => state.scroll_left(5),
        (KeyCode::Char('l'), KeyModifiers::NONE) | (KeyCode::Right, _) => state.scroll_right(5, max_h),
        (KeyCode::Char('0'), KeyModifiers::NONE) => state.h_home(),
        (KeyCode::Char('$'), _) => state.h_end(max_h),
        _ => {}
    }
}

fn tags_key_handler(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Option<Action> {
    match tags_exit_action(app, code, mods) {
        ExitOutcome::Exited => return None,
        ExitOutcome::Action(action) => return Some(action),
        ExitOutcome::NotExit => {}
    }

    let size = app.terminal_size;
    let state = &mut app.tags_state;

    let was_pending = state.scroll.pending_g;
    state.scroll.pending_g = false;

    let visible = TagsPopup::visible_height(size) as usize;

    tags_scroll_action(app, code, mods, was_pending, visible)
}

fn tags_exit_action(app: &mut App, code: KeyCode, mods: KeyModifiers) -> ExitOutcome {
    match (code, mods) {
        (KeyCode::Char('t' | 'q'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
            app.mode_state.enter_normal_mode();
            ExitOutcome::Exited
        }
        (KeyCode::Char('?'), KeyModifiers::NONE | KeyModifiers::SHIFT) => ExitOutcome::Action(Action::ShowHelp),
        (KeyCode::Char('i'), KeyModifiers::NONE) => ExitOutcome::Action(Action::ShowLogs),
        _ => ExitOutcome::NotExit,
    }
}

fn tags_scroll_action(app: &mut App, code: KeyCode, mods: KeyModifiers, was_pending: bool, visible: usize) -> Option<Action> {
    let state = &mut app.tags_state;

    match (code, mods) {
        (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, _) => state.scroll_down(),
        (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, _) => state.scroll_up(),
        (KeyCode::Char('g'), KeyModifiers::NONE) if was_pending => state.home(),
        (KeyCode::Char('g'), KeyModifiers::NONE) => state.scroll.pending_g = true,
        (KeyCode::Char('G'), KeyModifiers::SHIFT) => state.end(),
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => state.page_down(visible / 2),
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => state.page_up(visible / 2),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => state.page_down(visible.saturating_sub(1)),
        (KeyCode::Char('b'), KeyModifiers::CONTROL) => state.page_up(visible.saturating_sub(1)),
        (KeyCode::Char(' '), KeyModifiers::NONE) => tags_toggle_and_advance(state),
        (KeyCode::Enter, _) | (KeyCode::Char('l'), KeyModifiers::NONE) => return handle_tags_select(app),
        _ => {}
    }

    None
}

fn tags_toggle_and_advance(state: &mut crate::ui::components::tags::TagsState) {
    state.toggle_selected();
    state.scroll_down();
}

fn handle_tags_select(app: &mut App) -> Option<Action> {
    let tags = app.tags_state.get_selected_tags();
    
    app.mode_state.enter_normal_mode();
    // Empty tags will clear the filter
    let _ = app.filter_by_tag(&tags);
    None
}

impl crate::ui::components::CredentialForm {
    pub fn is_select_field(&self) -> bool {
        self.active_field().field_type == crate::ui::components::form::FieldType::Select
    }
}
