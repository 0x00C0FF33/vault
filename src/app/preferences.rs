//! View preferences kept in the vault's `metadata` table, so they survive a
//! relaunch without introducing a config file.
//!
//! Each preference is written only when the user changes it, so an untouched
//! one keeps following the built-in default if that default ever changes.

use crate::db;
use crate::ui::components::list::DEFAULT_SCROLLOFF;

use super::App;

/// Absent means shown: only an explicit `"false"` hides usernames, so vaults
/// that predate the key keep the default.
const META_SHOW_USERNAMES: &str = "show_usernames";
/// Absent or unparseable means `DEFAULT_SCROLLOFF`.
const META_SCROLLOFF: &str = "scrolloff";

impl App {
    pub(super) fn load_view_preferences(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.vault.db()?.conn();
        let visible = db::get_metadata(conn, META_SHOW_USERNAMES).as_deref() != Some("false");
        let scrolloff = db::get_metadata(conn, META_SCROLLOFF)
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_SCROLLOFF);

        self.list_state.set_usernames_visible(visible);
        self.list_state.set_scrolloff(scrolloff);
        Ok(())
    }

    pub(super) fn save_usernames_visible(&self) -> Result<(), Box<dyn std::error::Error>> {
        let visible = self.list_state.usernames_visible().to_string();
        self.store_preference(META_SHOW_USERNAMES, &visible)
    }

    pub(super) fn save_scrolloff(&self) -> Result<(), Box<dyn std::error::Error>> {
        let lines = self.list_state.scrolloff().to_string();
        self.store_preference(META_SCROLLOFF, &lines)
    }

    fn store_preference(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        db::set_metadata(self.vault.db()?.conn(), key, value)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::app::{App, AppConfig};
    use crate::input::keymap::Action;

    const PASSWORD: &str = "test_password";

    fn app_at(dir: &TempDir) -> App {
        App::new(AppConfig { vault_path: dir.path().join("vault.db"), ..AppConfig::default() })
    }

    fn relaunch(dir: &TempDir) -> App {
        let mut app = app_at(dir);
        app.unlock(PASSWORD).unwrap();
        app
    }

    #[test]
    fn usernames_are_shown_on_a_new_vault() {
        let dir = TempDir::new().unwrap();
        let mut app = app_at(&dir);
        app.initialize(PASSWORD).unwrap();
        assert!(app.list_state.usernames_visible());
    }

    #[test]
    fn hidden_usernames_survive_a_relaunch() {
        let dir = TempDir::new().unwrap();
        let mut first = app_at(&dir);
        first.initialize(PASSWORD).unwrap();
        first.execute_action(Action::ToggleUsernameVisibility).unwrap();
        drop(first);

        let mut relaunched = relaunch(&dir);
        assert!(!relaunched.list_state.usernames_visible());

        relaunched.execute_action(Action::ToggleUsernameVisibility).unwrap();
        drop(relaunched);

        assert!(relaunch(&dir).list_state.usernames_visible());
    }

    #[test]
    fn scrolloff_defaults_to_five() {
        let dir = TempDir::new().unwrap();
        let mut app = app_at(&dir);
        app.initialize(PASSWORD).unwrap();
        assert_eq!(app.list_state.scrolloff(), 5);
    }

    #[test]
    fn scrolloff_survives_a_relaunch() {
        let dir = TempDir::new().unwrap();
        let mut first = app_at(&dir);
        first.initialize(PASSWORD).unwrap();
        first.execute_action(Action::SetScrolloff(2)).unwrap();
        drop(first);

        assert_eq!(relaunch(&dir).list_state.scrolloff(), 2);
    }

    #[test]
    fn toggling_usernames_does_not_pin_the_scrolloff_default() {
        let dir = TempDir::new().unwrap();
        let mut first = app_at(&dir);
        first.initialize(PASSWORD).unwrap();
        first.execute_action(Action::ToggleUsernameVisibility).unwrap();

        let conn = first.vault.db().unwrap().conn();
        assert_eq!(crate::db::get_metadata(conn, super::META_SCROLLOFF), None);
    }

    #[test]
    fn an_out_of_range_scrolloff_is_refused_and_not_saved() {
        let dir = TempDir::new().unwrap();
        let mut first = app_at(&dir);
        first.initialize(PASSWORD).unwrap();
        first.execute_action(Action::SetScrolloff(3)).unwrap();
        first.execute_action(Action::SetScrolloff(1000)).unwrap();
        assert_eq!(first.list_state.scrolloff(), 3);
        drop(first);

        assert_eq!(relaunch(&dir).list_state.scrolloff(), 3);
    }
}
