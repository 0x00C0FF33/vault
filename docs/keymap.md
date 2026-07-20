# Key handling pipeline

How a keypress travels from the terminal to a text-buffer mutation. This
expands on the dispatch summary in
[architecture.md](architecture.md#modal-input).

The flow starts from `app/input.rs` which is the entry point for all key events:
    1. **`app/input.rs` - `handle_key_event()`** receives the raw `KeyEvent` from crossterm's event loop.
    2. **`app/input.rs` - `resolve_action()`** looks at the current mode and decides which mapper to call. For `Command`/`Search` mode, it calls `resolve_text_action()`.
    3. **`input/keymap.rs` - `text_input_action()`** translates the raw `KeyEvent` into a semantic `Action` enum (e.g., `KeyCode::Left + ALT` → `Action::CursorWordLeft`). This is a pure mapping layer - no state mutation.
    4. **`app/input.rs` - `handle_text_input()`** receives that `Action` and dispatches it. For `CursorWordLeft`, it calls `self.mode_state.cursor_word_left()`.
    5. **`input/modes.rs` - `ModeState::cursor_word_left()`** is a thin delegation wrapper that calls `self.buffer.cursor_word_left()`.
    6. **`input/text_buffer.rs` - `TextBuffer::cursor_word_left()`** does the actual cursor math using `find_word_boundary_back()`.

So the chain for typing `Alt+Left` in command mode:
```
crossterm event loop
    → app/input.rs:    handle_key_event()
    → app/input.rs:    resolve_action() → resolve_text_action()
    → input/keymap.rs: text_input_action()  → Action::CursorWordLeft
    → app/input.rs:    handle_text_input()  → match on CursorWordLeft
    → input/modes.rs:  mode_state.cursor_word_left()
    → input/text_buffer.rs: buffer.cursor_word_left()
    → find_word_boundary_back()
```

**The separation is:** **keymap.rs** only maps keys→actions, **modes.rs** manages modal state and delegates, **text_buffer.rs** does the actual text manipulation. **app/input.rs** orchestrates the whole flow.

**Note** that `handle_text_key` in `text_buffer.rs` is a *separate* path - it's used by the credential form and export dialog, which bypass the `keymap.rs` → `Action` pipeline entirely and go straight to the `TextEditing` trait methods.
