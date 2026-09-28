//! Input Modes
//!
//! Modal editing state machine for vim-style interface.

use super::{TextBuffer, TextEditing};

/// Input mode enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Insert,
    Command,
    Search,
    Confirm,
    Help,
    Logs,
    Tags,
    Export,
}

impl InputMode {
    pub fn indicator(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Insert => "INSERT",
            Self::Command => "COMMAND",
            Self::Search => "SEARCH",
            Self::Confirm => "CONFIRM",
            Self::Help => "HELP",
            Self::Logs => "LOG",
            Self::Tags => "TAG",
            Self::Export => "EXPORT",
        }
    }

    pub fn is_text_input(self) -> bool {
        matches!(self, Self::Command | Self::Search)
    }
}

/// Mode state with associated data
#[derive(Debug, Clone)]
pub struct ModeState {
    pub mode: InputMode,
    pub buffer: TextBuffer,
    pub pending: Option<char>,
}

impl Default for ModeState {
    fn default() -> Self {
        Self {
            mode: InputMode::Normal,
            buffer: TextBuffer::new(),
            pending: None,
        }
    }
}

impl ModeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_mode(&mut self, mode: InputMode) {
        self.mode = mode;
        self.buffer.clear();
        self.pending = None;
    }

    pub fn enter_normal_mode(&mut self) {
        self.set_mode(InputMode::Normal);
    }

    pub fn enter_insert_mode(&mut self) {
        self.mode = InputMode::Insert;
    }

    pub fn enter_command_mode(&mut self) {
        self.set_mode(InputMode::Command);
    }

    pub fn enter_search_mode(&mut self) {
        self.set_mode(InputMode::Search);
    }

    pub fn enter_confirm_mode(&mut self) {
        self.set_mode(InputMode::Confirm);
    }

    pub fn enter_help_mode(&mut self) {
        self.set_mode(InputMode::Help);
    }

    pub fn enter_tags_mode(&mut self) {
        self.mode = InputMode::Tags;
    }

    pub fn enter_logs_mode(&mut self) {
        self.mode = InputMode::Logs;
    }

    pub fn enter_export_mode(&mut self) {
        self.set_mode(InputMode::Export);
    }

    // Convenience methods that delegate to buffer
    pub fn insert_char(&mut self, c: char) {
        self.buffer.insert_char(c);
    }

    pub fn delete_char(&mut self) {
        self.buffer.delete_char();
    }

    pub fn delete_word(&mut self) {
        self.buffer.delete_word();
    }

    pub fn cursor_left(&mut self) {
        self.buffer.cursor_left();
    }

    pub fn cursor_right(&mut self) {
        self.buffer.cursor_right();
    }

    pub fn cursor_word_left(&mut self) {
        self.buffer.cursor_word_left();
    }

    pub fn cursor_word_right(&mut self) {
        self.buffer.cursor_word_right();
    }

    pub fn cursor_home(&mut self) {
        self.buffer.cursor_home();
    }

    pub fn cursor_end(&mut self) {
        self.buffer.cursor_end();
    }

    pub fn clear_to_start(&mut self) {
        self.buffer.clear_to_start();
    }

    pub fn get_buffer(&self) -> &str {
        self.buffer.content()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Mode transition basics ---

    #[test]
    fn test_starts_in_normal_mode() {
        let state = ModeState::new();
        assert_eq!(state.mode, InputMode::Normal);
        assert_eq!(state.get_buffer(), "");
        assert!(state.pending.is_none());
    }

    #[test]
    fn test_mode_transitions() {
        let mut state = ModeState::new();

        state.enter_insert_mode();
        assert_eq!(state.mode, InputMode::Insert);

        state.enter_command_mode();
        assert_eq!(state.mode, InputMode::Command);

        state.enter_search_mode();
        assert_eq!(state.mode, InputMode::Search);

        state.enter_confirm_mode();
        assert_eq!(state.mode, InputMode::Confirm);

        state.enter_help_mode();
        assert_eq!(state.mode, InputMode::Help);

        state.enter_tags_mode();
        assert_eq!(state.mode, InputMode::Tags);

        state.enter_logs_mode();
        assert_eq!(state.mode, InputMode::Logs);

        state.enter_export_mode();
        assert_eq!(state.mode, InputMode::Export);

        state.enter_normal_mode();
        assert_eq!(state.mode, InputMode::Normal);
    }

    // --- Buffer clearing semantics ---
    // Some transitions go through set_mode() which clears buffer+pending.
    // Others (insert, tags, logs) set mode directly and preserve buffer.
    // This distinction matters: e.g. switching to tags view shouldn't nuke
    // a search query the user typed.

    #[test]
    fn test_set_mode_transitions_clear_buffer() {
        let mut state = ModeState::new();

        // Populate buffer and pending
        state.enter_command_mode();
        state.insert_char('x');
        state.pending = Some('d');

        // Normal goes through set_mode — should clear everything
        state.enter_normal_mode();
        assert_eq!(state.get_buffer(), "");
        assert!(state.pending.is_none());
    }

    #[test]
    fn test_insert_mode_preserves_buffer() {
        let mut state = ModeState::new();
        state.insert_char('a');
        state.insert_char('b');

        state.enter_insert_mode();
        assert_eq!(state.mode, InputMode::Insert);
        assert_eq!(state.get_buffer(), "ab", "insert should not clear buffer");
    }

    #[test]
    fn test_tags_mode_preserves_buffer() {
        let mut state = ModeState::new();
        state.insert_char('z');

        state.enter_tags_mode();
        assert_eq!(state.mode, InputMode::Tags);
        assert_eq!(state.get_buffer(), "z", "tags should not clear buffer");
    }

    #[test]
    fn test_logs_mode_preserves_buffer() {
        let mut state = ModeState::new();
        state.insert_char('z');

        state.enter_logs_mode();
        assert_eq!(state.mode, InputMode::Logs);
        assert_eq!(state.get_buffer(), "z", "logs should not clear buffer");
    }

    // --- Text input ---

    #[test]
    fn test_command_mode_input() {
        let mut state = ModeState::new();
        state.enter_command_mode();
        for c in "quit".chars() {
            state.insert_char(c);
        }
        assert_eq!(state.get_buffer(), "quit");
        assert_eq!(state.buffer.cursor(), 4);
    }

    #[test]
    fn test_delete_char() {
        let mut state = ModeState::new();
        for c in "hello".chars() {
            state.insert_char(c);
        }

        state.delete_char();
        assert_eq!(state.get_buffer(), "hell");
        assert_eq!(state.buffer.cursor(), 4);
    }

    // --- Cursor movement ---

    #[test]
    fn test_cursor_movement() {
        let mut state = ModeState::new();
        state.buffer.set_content("hello");

        state.cursor_home();
        assert_eq!(state.buffer.cursor(), 0);

        state.cursor_end();
        assert_eq!(state.buffer.cursor(), 5);

        state.cursor_left();
        assert_eq!(state.buffer.cursor(), 4);

        state.cursor_right();
        assert_eq!(state.buffer.cursor(), 5);

        // Right at end should be a no-op
        state.cursor_right();
        assert_eq!(state.buffer.cursor(), 5);

        // Left at 0 should be a no-op
        state.cursor_home();
        state.cursor_left();
        assert_eq!(state.buffer.cursor(), 0);
    }

    // --- InputMode properties ---

    #[test]
    fn test_is_text_input() {
        // Only Command and Search accept freeform text input
        assert!(InputMode::Command.is_text_input());
        assert!(InputMode::Search.is_text_input());

        assert!(!InputMode::Normal.is_text_input());
        assert!(!InputMode::Insert.is_text_input());
        assert!(!InputMode::Confirm.is_text_input());
        assert!(!InputMode::Help.is_text_input());
        assert!(!InputMode::Logs.is_text_input());
        assert!(!InputMode::Tags.is_text_input());
        assert!(!InputMode::Export.is_text_input());
    }

    #[test]
    fn test_indicator_strings() {
        // Sanity check — these show up in the statusline
        assert_eq!(InputMode::Normal.indicator(), "NORMAL");
        assert_eq!(InputMode::Insert.indicator(), "INSERT");
        assert_eq!(InputMode::Command.indicator(), "COMMAND");
    }
}
