//! View preferences kept in the vault's `metadata` table, so they survive a
//! relaunch without introducing a config file.

use crate::db;

use super::App;

/// Absent means shown: only an explicit `"false"` hides usernames, so vaults
/// that predate the key keep the default.
const META_SHOW_USERNAMES: &str = "show_usernames";

impl App {
    pub(super) fn load_view_preferences(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.vault.db()?.conn();
        let visible = db::get_metadata(conn, META_SHOW_USERNAMES).as_deref() != Some("false");
        self.list_state.set_usernames_visible(visible);
        Ok(())
    }

    pub(super) fn save_view_preferences(&self) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.vault.db()?.conn();
        let visible = self.list_state.usernames_visible().to_string();
        db::set_metadata(conn, META_SHOW_USERNAMES, &visible)?;
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

        let mut relaunched = app_at(&dir);
        relaunched.unlock(PASSWORD).unwrap();
        assert!(!relaunched.list_state.usernames_visible());

        relaunched.execute_action(Action::ToggleUsernameVisibility).unwrap();
        drop(relaunched);

        let mut again = app_at(&dir);
        again.unlock(PASSWORD).unwrap();
        assert!(again.list_state.usernames_visible());
    }
}
