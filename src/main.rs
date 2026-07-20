//! Vault - Encrypted Credential Manager
//!
//! A local-first, vim-style TUI credential manager.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::input::{handle_text_key, SecureTextBuffer, TextEditing};

mod app;
mod crypto;
mod db;
mod input;
mod ui;
mod vault;

use app::{App, AppConfig};

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    harden_process();

    let config = parse_config();
    ensure_vault_dir(&config)?;

    let mut terminal = setup_terminal()?;
    let mut app = App::new(config);

    let result = run_with_auth(&mut terminal, &mut app);

    cleanup_terminal(&mut terminal)?;
    result
}

fn harden_process() {
    #[cfg(unix)]
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0); }
}

fn parse_config() -> AppConfig {
    let mut config = AppConfig::default();
    if let Some(path) = std::env::args().nth(1) {
        config.vault_path = PathBuf::from(path);
    }
    config
}

fn ensure_vault_dir(config: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = config.vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn setup_terminal() -> Result<Term, Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn cleanup_terminal(terminal: &mut Term) -> Result<(), Box<dyn std::error::Error>> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_with_auth(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    if app.needs_init() {
        run_init(terminal, app)?;
    } else if app.is_locked() {
        run_unlock(terminal, app)?;
    }

    if !app.should_quit {
        run_app(terminal, app)?;
    }
    Ok(())
}

enum AppEvent {
    Key(KeyEvent),
    Mouse(crossterm::event::MouseEvent),
}

fn poll_event() -> Result<Option<AppEvent>, Box<dyn std::error::Error>> {
    if !event::poll(Duration::from_millis(100))? {
        return Ok(None);
    }
    match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => Ok(Some(AppEvent::Key(key))),
        Event::Mouse(mouse) => Ok(Some(AppEvent::Mouse(mouse))),
        _ => Ok(None),
    }
}

fn draw_password_dialog(
    terminal: &mut Term,
    title: &str,
    prompt: &str,
    field: &SecureTextBuffer,
    error: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    terminal.draw(|frame| {
        let dialog = build_password_dialog(title, prompt, field, error);
        frame.render_widget(dialog, frame.area());
    })?;
    Ok(())
}

fn build_password_dialog<'a>(
    title: &'a str,
    prompt: &'a str,
    field: &'a SecureTextBuffer,
    error: Option<&'a str>,
) -> ui::PasswordDialog<'a> {
    let dialog = ui::PasswordDialog::new(title, prompt, field.content(), field.cursor());
    match error {
        Some(err) => dialog.error(err),
        None => dialog,
    }
}

fn run_init(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = InitState::default();

    while !state.done {
        init_iteration(terminal, app, &mut state)?;
    }
    Ok(())
}

#[derive(Default)]
struct InitState {
    password: SecureTextBuffer,
    confirm: SecureTextBuffer,
    confirming: bool,
    error: Option<String>,
    done: bool,
}


fn init_iteration(terminal: &mut Term, app: &mut App, state: &mut InitState) -> Result<(), Box<dyn std::error::Error>> {
    let (title, prompt, field) = init_dialog_params(state.confirming, &state.password, &state.confirm);
    draw_password_dialog(terminal, title, prompt, field, state.error.as_deref())?;

    let Some(AppEvent::Key(key)) = poll_event()? else { return Ok(()) };

    handle_init_key(key, state, app);
    Ok(())
}

fn init_dialog_params<'a>(
    confirming: bool,
    password: &'a SecureTextBuffer,
    confirm: &'a SecureTextBuffer,
) -> (&'static str, &'static str, &'a SecureTextBuffer) {
    if confirming {
        (" Confirm Password ", "Confirm password:", confirm)
    } else {
        (" Create Master Password ", "Enter master password:", password)
    }
}

fn handle_init_key(key: KeyEvent, state: &mut InitState, app: &mut App) {
    if key.code == KeyCode::Esc {
        app.should_quit = true;
        state.done = true;
        return;
    }

    if key.code == KeyCode::Enter {
        process_init_submit(state, app);
        return;
    }

    let field = if state.confirming { &mut state.confirm } else { &mut state.password };
    handle_text_key(field, key.code, key.modifiers);
}

fn process_init_submit(state: &mut InitState, app: &mut App) {
    state.error = process_init_enter(state, app);
    state.done = state.error.is_none() && !state.confirming;
}

fn process_init_enter(state: &mut InitState, app: &mut App) -> Option<String> {
    if !state.confirming {
        return validate_init_password(&state.password, &mut state.confirming);
    }
    finalize_init(state, app)
}

fn validate_init_password(password: &SecureTextBuffer, confirming: &mut bool) -> Option<String> {
    if password.len() < 8 {
        return Some("Password must be at least 8 characters".into());
    }
    *confirming = true;
    None
}

fn finalize_init(state: &mut InitState, app: &mut App) -> Option<String> {
    if state.password.content() != state.confirm.content() {
        state.password.clear();
        state.confirm.clear();
        state.confirming = false;
        return Some("Passwords do not match".into());
    }

    if let Err(e) = app.initialize(state.password.content()) {
        state.confirm.clear();
        return Some(format!("Failed to initialize: {e}"));
    }

    state.confirming = false;
    None
}

fn run_unlock(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = UnlockState::default();

    while !state.done {
        unlock_iteration(terminal, app, &mut state)?;
    }
    Ok(())
}

#[derive(Default)]
struct UnlockState {
    password: SecureTextBuffer,
    error: Option<String>,
    attempts: u32,
    done: bool,
}


fn unlock_iteration(terminal: &mut Term, app: &mut App, state: &mut UnlockState) -> Result<(), Box<dyn std::error::Error>> {
    draw_password_dialog(terminal, "  Unlock Vault ", "Enter master password:", &state.password, state.error.as_deref())?;

    let Some(AppEvent::Key(key)) = poll_event()? else { return Ok(()) };

    handle_unlock_key(key, state, app);
    Ok(())
}

fn handle_unlock_key(key: KeyEvent, state: &mut UnlockState, app: &mut App) {
    if key.code == KeyCode::Esc {
        app.should_quit = true;
        state.done = true;
        return;
    }

    if key.code == KeyCode::Enter {
        process_unlock_attempt(state, app);
        return;
    }

    handle_text_key(&mut state.password, key.code, key.modifiers);
}

fn process_unlock_attempt(state: &mut UnlockState, app: &mut App) {
    if app.unlock(state.password.content()).is_ok() {
        state.done = true;
        return;
    }

    state.attempts += 1;
    state.password.clear();
    let _ = app.vault.record_failed_unlock();
    state.error = Some(format!(" Invalid password ({}/5)", state.attempts));

    if state.attempts >= 5 {
        app.should_quit = true;
        state.done = true;
    }
}

#[derive(Default)]
struct PasswordChangeState {
    current: SecureTextBuffer,
    new_pass: SecureTextBuffer,
    confirm: SecureTextBuffer,
    step: u8,
    error: Option<String>,
}


fn change_current_field(state: &mut PasswordChangeState) -> &mut SecureTextBuffer {
    match state.step {
        0 => &mut state.current,
        1 => &mut state.new_pass,
        _ => &mut state.confirm,
    }
}

fn change_prompt_and_field(state: &PasswordChangeState) -> (&'static str, &SecureTextBuffer) {
    match state.step {
        0 => ("Current password:", &state.current),
        1 => ("New password:", &state.new_pass),
        _ => ("Confirm new password:", &state.confirm),
    }
}

fn change_reset(state: &mut PasswordChangeState) {
    state.current.clear();
    state.new_pass.clear();
    state.confirm.clear();
    state.step = 0;
    state.error = None;
}

enum ChangeResult {
    Continue,
    Cancel,
    Success,
}

fn run_password_change(terminal: &mut Term, app: &mut App) -> Result<bool, Box<dyn std::error::Error>> {
    let mut state = PasswordChangeState::default();
    let mut result = ChangeResult::Continue;

    while matches!(result, ChangeResult::Continue) {
        result = change_iteration(terminal, app, &mut state)?;
    }

    Ok(matches!(result, ChangeResult::Success))
}

fn change_iteration(terminal: &mut Term, app: &mut App, state: &mut PasswordChangeState) -> Result<ChangeResult, Box<dyn std::error::Error>> {
    let (prompt, field) = change_prompt_and_field(state);
    draw_password_dialog(terminal, "  Change Master Key ", prompt, field, state.error.as_deref())?;

    let Some(AppEvent::Key(key)) = poll_event()? else { return Ok(ChangeResult::Continue) };

    Ok(handle_change_key(key, state, &mut app.vault))
}

fn handle_change_key(key: KeyEvent, state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    if key.code == KeyCode::Esc {
        return ChangeResult::Cancel;
    }

    if key.code == KeyCode::Enter {
        return process_change_step(state, vault);
    }

    handle_text_key(change_current_field(state), key.code, key.modifiers);
    ChangeResult::Continue
}

fn process_change_step(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    match state.step {
        0 => process_change_verify(state, vault),
        1 => process_change_new(state),
        _ => process_change_confirm(state, vault),
    }
}

fn process_change_verify(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    if let Err(e) = vault.verify_password(state.current.content()) {
        state.current.clear();
        state.error = Some(change_verify_error_msg(&e));
        return ChangeResult::Continue;
    }
    state.step = 1;
    state.error = None;
    ChangeResult::Continue
}

fn change_verify_error_msg(e: &vault::VaultError) -> String {
    match e {
        vault::VaultError::InvalidPassword => "Current password is incorrect",
        vault::VaultError::Locked => "Vault is locked",
        _ => "Verification failed",
    }.into()
}

fn process_change_new(state: &mut PasswordChangeState) -> ChangeResult {
    if state.new_pass.len() < 8 {
        state.new_pass.clear();
        state.error = Some("Password must be at least 8 characters".into());
        return ChangeResult::Continue;
    }

    if state.new_pass.content() == state.current.content() {
        state.new_pass.clear();
        state.error = Some("New password must be different".into());
        return ChangeResult::Continue;
    }

    state.step = 2;
    state.error = None;
    ChangeResult::Continue
}

fn process_change_confirm(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    if state.new_pass.content() != state.confirm.content() {
        state.confirm.clear();
        state.error = Some("Passwords do not match".into());
        return ChangeResult::Continue;
    }

    if let Err(e) = vault.change_password(state.current.content(), state.new_pass.content()) {
        state.error = Some(change_confirm_error_msg(&e));
        change_reset(state);
        return ChangeResult::Continue;
    }

    ChangeResult::Success
}

fn change_confirm_error_msg(e: &vault::VaultError) -> String {
    match e {
        vault::VaultError::InvalidPassword => "Current password is incorrect",
        _ => "Failed to change password",
    }.into()
}

fn run_app(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    while !app.should_quit && !app_iteration(terminal, app)? {}
    Ok(())
}

fn app_iteration(terminal: &mut Term, app: &mut App) -> Result<bool, Box<dyn std::error::Error>> {
    app.tick_totp();
    terminal.draw(|frame| app.render(frame))?;
    if process_app_input(terminal, app)? { return Ok(true); }
    app.check_password_timeout();
    check_auto_lock(terminal, app)?;
    Ok(false)
}

fn process_app_input(terminal: &mut Term, app: &mut App) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(ev) = poll_event()? else { return Ok(false) };

    app.vault.update_activity();

    let quit = match ev {
        AppEvent::Key(key) => app.handle_key_event(key)?,
        AppEvent::Mouse(mouse) => app.handle_mouse_event(mouse),
    };

    if quit { return Ok(true); }

    handle_password_change_request(terminal, app);
    Ok(false)
}

fn handle_password_change_request(terminal: &mut Term, app: &mut App) {
    if !app.wants_password_change {
        return;
    }

    app.wants_password_change = false;
    match run_password_change(terminal, app) {
        Ok(true) => app.set_message("Password changed successfully", ui::MessageType::Success),
        Ok(false) => {}
        Err(e) => app.set_message(&format!("Error: {e}"), ui::MessageType::Error),
    }
}

fn check_auto_lock(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    if app.should_auto_lock() { app.lock(); }
    while app.is_locked() && !app.should_quit {
        run_unlock(terminal, app)?;
    }
    Ok(())
}
