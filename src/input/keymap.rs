//! Keymap
//!
//! Vim-style key bindings mapped to actions.

// Each binding gets its own arm even when two keys share an action; collapsing
// them into or-patterns would obscure which keys are bound.
#![allow(clippy::match_same_arms)]

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind, MouseButton};

use crate::db::models::CredentialType;

/// Actions that can be triggered by key presses
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    // Navigation
    MoveUp,
    MoveDown,
    MoveToTop,
    MoveToBottom,
    PageUp,
    PageDown,
    HalfPageUp,
    HalfPageDown,
    Click(u16, u16),

    // Selection
    Select,
    Back,

    // CRUD
    New,
    Edit,
    Delete,
    
    // Clipboard
    CopyPassword,
    CopyUsername,
    CopyTotp,
    CopyTotpUri,

    // View
    TogglePasswordVisibility,
    
    // Mode changes
    EnterCommand,
    EnterSearch,
    ShowHelp,
    ShowTags,

    // Commands
    ExecuteCommand(String),
    Search(String),
    /// `None` clears the type filter.
    FilterByType(Option<CredentialType>),
    GeneratePassword,
    ChangePassword,
    VerifyAudit,
    ShowLogs,
    
    // Confirmation
    Confirm,
    Cancel,

    // Application
    Clear,
    Quit,
    ForceQuit,
    Refresh,
    Lock,
    Export,

    // Text input
    InsertChar(char),
    DeleteChar,
    DeleteCharForward,
    DeleteWord,
    ClearToStart,
    CursorLeft,
    CursorRight,
    CursorWordLeft,
    CursorWordRight,
    CursorHome,
    CursorEnd,
    Submit,

    // No action
    None,
    Invalid(String),
}

/// Map key event to action in normal mode
pub fn normal_mode_action(key: KeyEvent, pending: Option<char>) -> (Action, Option<char>) {
    match (key.code, key.modifiers, pending) {
        // Navigation
        (KeyCode::Char('j'), KeyModifiers::NONE, _) => (Action::MoveDown, None),
        (KeyCode::Down, _, _) => (Action::MoveDown, None),
        (KeyCode::Char('k'), KeyModifiers::NONE, _) => (Action::MoveUp, None),
        (KeyCode::Up, _, _) => (Action::MoveUp, None),
        (KeyCode::Char('g'), KeyModifiers::NONE, None) => (Action::None, Some('g')),
        (KeyCode::Char('g'), KeyModifiers::NONE, Some('g')) => (Action::MoveToTop, None),
        (KeyCode::Char('G'), KeyModifiers::SHIFT, _) => (Action::MoveToBottom, None),
        (KeyCode::Char('d'), KeyModifiers::CONTROL, _) => (Action::HalfPageDown, None),
        (KeyCode::Char('u'), KeyModifiers::CONTROL, _) => (Action::HalfPageUp, None),
        (KeyCode::Char('f'), KeyModifiers::CONTROL, _) => (Action::PageDown, None),
        (KeyCode::Char('b'), KeyModifiers::CONTROL, _) => (Action::PageUp, None),
        (KeyCode::PageDown, _, _) => (Action::PageDown, None),
        (KeyCode::PageUp, _, _) => (Action::PageUp, None),

        // Selection
        (KeyCode::Char('l'), KeyModifiers::CONTROL, _) => (Action::Clear, None),
        (KeyCode::Enter, _, _) => (Action::Select, None),
        (KeyCode::Char('l'), KeyModifiers::NONE, _) => (Action::Select, None),
        (KeyCode::Right, _, _) => (Action::Select, None),
        (KeyCode::Esc, _, _) => (Action::Back, None),
        (KeyCode::Char('h'), KeyModifiers::NONE, _) => (Action::Back, None),
        (KeyCode::Left, _, _) => (Action::Back, None),

        // CRUD
        (KeyCode::Char('n'), KeyModifiers::NONE, _) => (Action::New, None),
        (KeyCode::Char('e'), KeyModifiers::NONE, _) => (Action::Edit, None),
        (KeyCode::Char('d'), KeyModifiers::NONE, None) => (Action::None, Some('d')),
        (KeyCode::Char('d'), KeyModifiers::NONE, Some('d')) => (Action::Delete, None),
        (KeyCode::Char('x'), KeyModifiers::NONE, _) => (Action::Delete, None),

        // Clipboard
        (KeyCode::Char('c'), KeyModifiers::NONE, None) => (Action::None, Some('y')),
        (KeyCode::Char('y'), KeyModifiers::NONE, None) => (Action::None, Some('y')),
        (KeyCode::Char('y'), KeyModifiers::NONE, Some('y')) => (Action::CopyPassword, None),
        (KeyCode::Char('c'), KeyModifiers::NONE, Some('y')) => (Action::CopyPassword, None),
        (KeyCode::Char('u'), KeyModifiers::NONE, None) => (Action::CopyUsername, None),
        (KeyCode::Char('T'), KeyModifiers::SHIFT, _) => (Action::CopyTotp, None),
        (KeyCode::Char('t'), KeyModifiers::CONTROL, _) => (Action::CopyTotpUri, None),

        // View
        (KeyCode::Char('s'), KeyModifiers::CONTROL, _) => (Action::TogglePasswordVisibility, None),

        // Mode changes
        (KeyCode::Char(':'), KeyModifiers::NONE | KeyModifiers::SHIFT, _) => (Action::EnterCommand, None),
        (KeyCode::Char('/'), KeyModifiers::NONE, _) => (Action::EnterSearch, None),
        (KeyCode::Char('?'), KeyModifiers::NONE | KeyModifiers::SHIFT, _) => (Action::ShowHelp, None),
        (KeyCode::Char('t'), KeyModifiers::NONE, _) => (Action::ShowTags, None),

        // Application
        (KeyCode::Char('q'), KeyModifiers::NONE, _) => (Action::Quit, None),
        (KeyCode::Char('Q'), KeyModifiers::SHIFT, _) => (Action::ForceQuit, None),
        (KeyCode::Char('r'), KeyModifiers::CONTROL, _) => (Action::Refresh, None),
        (KeyCode::Char('p'), KeyModifiers::CONTROL, _) => (Action::ChangePassword, None),
        (KeyCode::Char('i'), KeyModifiers::NONE, _) => (Action::ShowLogs, None),
        (KeyCode::Char('L'), KeyModifiers::SHIFT, _) => (Action::Lock, None),

        _ => (Action::None, None),
    }
}

/// Map key event to action in text input modes
pub fn text_input_action(key: KeyEvent) -> Action {
    match (key.code, key.modifiers) {
        (KeyCode::Esc, _) => Action::Cancel,
        (KeyCode::Enter, _) => Action::Submit,
        (KeyCode::Backspace, KeyModifiers::CONTROL | KeyModifiers::ALT) => Action::DeleteWord,
        (KeyCode::Backspace, _) => Action::DeleteChar,
        (KeyCode::Delete, _) => Action::DeleteCharForward,
        (KeyCode::Left, KeyModifiers::ALT) => Action::CursorWordLeft,
        (KeyCode::Right, KeyModifiers::ALT) => Action::CursorWordRight,
        (KeyCode::Left, _) => Action::CursorLeft,
        (KeyCode::Right, _) => Action::CursorRight,
        (KeyCode::Home, _) | (KeyCode::Char('a'), KeyModifiers::CONTROL) => Action::CursorHome,
        (KeyCode::End, _) | (KeyCode::Char('e'), KeyModifiers::CONTROL) => Action::CursorEnd,
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => Action::ClearToStart,
        (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => Action::InsertChar(c),
        _ => Action::None,
    }
}

/// Map key event to action in confirm mode
pub fn confirm_action(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('y' | 'Y') | KeyCode::Enter => Action::Confirm,
        KeyCode::Char('n' | 'N') | KeyCode::Esc => Action::Cancel,
        _ => Action::None,
    }
}

/// Map mouse event to action
pub fn mouse_action(event: MouseEvent) -> Action {
    match event.kind {
        MouseEventKind::ScrollUp => Action::MoveUp,
        MouseEventKind::ScrollDown => Action::MoveDown,
        MouseEventKind::Down(MouseButton::Left) => Action::Click(event.column, event.row),
        MouseEventKind::Down(MouseButton::Right) => Action::Back,
        _ => Action::None,
    }
}

/// Parse command string into action
pub fn parse_command(cmd: &str) -> Action {
    let cmd = cmd.trim();
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let command = parts[0];
    let argument = parts.get(1).map(|a| a.trim()).filter(|a| !a.is_empty());

    match command {
        "ty" | "type" => parse_type_filter(argument),
        "cls" | "clear" => Action::Clear,
        "q" | "quit" => Action::Quit,
        "q!" | "quit!" => Action::ForceQuit,
        "w" | "write" => Action::None, // Auto-save, no action needed
        "wq" => Action::Quit,
        "n" | "new" => Action::New,
        "e" | "edit" => Action::Edit,
        "del" | "delete" => Action::Delete,
        "gen" | "generate" => Action::GeneratePassword,
        "h" | "help" => Action::ShowHelp,
        "passwd" | "password" | "changepw" => Action::ChangePassword,
        "lock" => Action::Lock,
        "ref" | "resh" => Action::Refresh,
        "log" | "logs" => Action::ShowLogs,
        "aud" | "audit" | "verify" => Action::VerifyAudit,
        "tag" | "tags" => Action::ShowTags,
        "exp" | "export" => Action::Export,
        "" => Action::None,
        other => Action::Invalid(other.to_string()),
    }
}

/// A bare `:type` clears the filter; a named type sets it. An unrecognised
/// name is reported rather than filtered on, so a typo cannot look like a
/// vault holding no credentials of that type.
fn parse_type_filter(argument: Option<&str>) -> Action {
    let Some(name) = argument else {
        return Action::FilterByType(None);
    };
    match CredentialType::parse_name(name) {
        Some(cred_type) => Action::FilterByType(Some(cred_type)),
        None => Action::Invalid(format!("type {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_command_sets_the_filter() {
        assert_eq!(
            parse_command("type password"),
            Action::FilterByType(Some(CredentialType::Password))
        );
        assert_eq!(
            parse_command("ty note"),
            Action::FilterByType(Some(CredentialType::Note))
        );
    }

    #[test]
    fn type_names_accept_hyphens_spaces_and_case() {
        for name in ["api_key", "api-key", "API Key", "Api-Key"] {
            assert_eq!(
                parse_command(&format!("type {name}")),
                Action::FilterByType(Some(CredentialType::ApiKey)),
                "{name} should parse as ApiKey"
            );
        }
    }

    #[test]
    fn bare_type_command_clears_the_filter() {
        assert_eq!(parse_command("type"), Action::FilterByType(None));
        assert_eq!(parse_command("type   "), Action::FilterByType(None));
    }

    /// A typo must not read as "no credentials of that type" —
    /// `CredentialType::from_str` falls back to `Custom` when parsing stored
    /// values, and that fallback would be a silent wrong answer here.
    #[test]
    fn unknown_type_name_is_rejected_rather_than_treated_as_custom() {
        assert_eq!(
            parse_command("type banana"),
            Action::Invalid("type banana".to_string())
        );
    }

    #[test]
    fn custom_is_still_selectable_by_name() {
        assert_eq!(
            parse_command("type custom"),
            Action::FilterByType(Some(CredentialType::Custom))
        );
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn key_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn test_normal_navigation() {
        assert_eq!(normal_mode_action(key(KeyCode::Char('j')), None).0, Action::MoveDown);
        assert_eq!(normal_mode_action(key(KeyCode::Char('k')), None).0, Action::MoveUp);
        assert_eq!(normal_mode_action(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT), None).0, Action::MoveToBottom);
    }

    #[test]
    fn test_gg_sequence() {
        let (action1, pending1) = normal_mode_action(key(KeyCode::Char('g')), None);
        assert_eq!(action1, Action::None);
        assert_eq!(pending1, Some('g'));

        let (action2, pending2) = normal_mode_action(key(KeyCode::Char('g')), pending1);
        assert_eq!(action2, Action::MoveToTop);
        assert_eq!(pending2, None);
    }

    #[test]
    fn test_dd_sequence() {
        let (action1, pending1) = normal_mode_action(key(KeyCode::Char('d')), None);
        assert_eq!(action1, Action::None);
        assert_eq!(pending1, Some('d'));

        let (action2, pending2) = normal_mode_action(key(KeyCode::Char('d')), pending1);
        assert_eq!(action2, Action::Delete);
        assert_eq!(pending2, None);
    }

    #[test]
    fn test_text_input() {
        assert_eq!(text_input_action(key(KeyCode::Char('a'))), Action::InsertChar('a'));
        assert_eq!(text_input_action(key(KeyCode::Backspace)), Action::DeleteChar);
        assert_eq!(text_input_action(key(KeyCode::Enter)), Action::Submit);
        assert_eq!(text_input_action(key(KeyCode::Esc)), Action::Cancel);
    }

    #[test]
    fn test_ctrl_shortcuts() {
        assert_eq!(text_input_action(key_ctrl(KeyCode::Char('a'))), Action::CursorHome);
        assert_eq!(text_input_action(key_ctrl(KeyCode::Char('e'))), Action::CursorEnd);
    }

    #[test]
    fn test_parse_command() {
        assert_eq!(parse_command("q"), Action::Quit);
        assert_eq!(parse_command("quit"), Action::Quit);
        assert_eq!(parse_command("q!"), Action::ForceQuit);
        assert_eq!(parse_command("new"), Action::New);
        assert_eq!(parse_command("help"), Action::ShowHelp);
        assert_eq!(parse_command("tags"), Action::ShowTags);
    }

    #[test]
    fn test_confirm_action() {
        assert_eq!(confirm_action(key(KeyCode::Char('y'))), Action::Confirm);
        assert_eq!(confirm_action(key(KeyCode::Char('n'))), Action::Cancel);
        assert_eq!(confirm_action(key(KeyCode::Enter)), Action::Confirm);
        assert_eq!(confirm_action(key(KeyCode::Esc)), Action::Cancel);
    }

    #[test]
    fn test_normal_mode_j() {
        let (action, _) = normal_mode_action(key(KeyCode::Char('j')), None);
        assert_eq!(action, Action::MoveDown);
    }

    #[test]
    fn test_show_tags() {
        let (action, _) = normal_mode_action(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE), None);
        assert_eq!(action, Action::ShowTags);
    }
}
