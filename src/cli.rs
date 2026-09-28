//! Command-line arguments
//!
//! One optional positional argument, the vault path, plus `--help` and
//! `--version`. Anything else that looks like an option is refused, so a
//! mistyped flag cannot be taken as a path and become a new vault file.

use std::path::PathBuf;

use crate::app::AppConfig;

pub enum Command {
    Run(AppConfig),
    Help,
    Version,
}

/// Parse the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut path = None;
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            option if option.starts_with('-') => return Err(format!("unknown option '{option}'")),
            _ if path.is_some() => return Err(format!("unexpected argument '{arg}'")),
            _ => path = Some(PathBuf::from(arg)),
        }
    }

    let mut config = AppConfig::default();
    if let Some(path) = path {
        config.vault_path = path;
    }
    Ok(Command::Run(config))
}

pub fn usage() -> String {
    let default_path = AppConfig::default().vault_path;
    format!(
        "\
{description}

Usage: vault [PATH]

Arguments:
  [PATH]  Vault file to open, or to create if it does not exist
          [default: {default_path}]

Options:
  -h, --help     Print help
  -V, --version  Print version
",
        description = env!("CARGO_PKG_DESCRIPTION"),
        default_path = default_path.display(),
    )
}

pub fn version() -> String {
    format!("vault {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(ToString::to_string))
    }

    fn run_path(args: &[&str]) -> PathBuf {
        match parse_strs(args) {
            Ok(Command::Run(config)) => config.vault_path,
            _ => panic!("{args:?} should run the app"),
        }
    }

    #[test]
    fn no_arguments_uses_the_default_path() {
        assert_eq!(run_path(&[]), AppConfig::default().vault_path);
    }

    #[test]
    fn a_path_argument_selects_that_vault() {
        assert_eq!(run_path(&["/tmp/other.db"]), PathBuf::from("/tmp/other.db"));
    }

    #[test]
    fn help_and_version_flags() {
        for flag in ["-h", "--help"] {
            assert!(matches!(parse_strs(&[flag]), Ok(Command::Help)), "{flag}");
        }
        for flag in ["-V", "--version"] {
            assert!(matches!(parse_strs(&[flag]), Ok(Command::Version)), "{flag}");
        }
    }

    #[test]
    fn help_wins_even_after_a_path() {
        assert!(matches!(parse_strs(&["/tmp/other.db", "--help"]), Ok(Command::Help)));
    }

    /// The bug this module exists for: `vault --hepl` used to offer to
    /// create a vault in a file named `--hepl`.
    #[test]
    fn unknown_options_are_refused_not_taken_as_paths() {
        for option in ["--hepl", "-v", "--vault", "-"] {
            let Err(msg) = parse_strs(&[option]) else { panic!("{option} should be refused") };
            assert!(msg.contains(option), "{msg}");
        }
    }

    #[test]
    fn a_second_path_is_refused() {
        let Err(msg) = parse_strs(&["a.db", "b.db"]) else { panic!("two paths should be refused") };
        assert!(msg.contains("b.db"), "{msg}");
    }

    #[test]
    fn usage_names_the_default_path() {
        let default_path = AppConfig::default().vault_path;
        assert!(usage().contains(&default_path.display().to_string()));
    }
}
