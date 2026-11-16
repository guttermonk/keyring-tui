//! Configuration: `$XDG_CONFIG_HOME/keyring-tui/config.toml`.
//!
//! A missing file is not an error — keyring-tui is usable with no config at
//! all, and every value in `config.example.toml` is the default. A malformed
//! one is an error naming the file, because a config that silently does
//! nothing is worse than one that refuses to load.

pub mod theme;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::keys::{KeymapSection, Keymaps, Mode};
use theme::{Palette, Theme};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub theme: Theme,
    /// `[keys.main]`, `[keys.prompt]`.
    pub keys: BTreeMap<Mode, KeymapSection>,
}

impl Config {
    /// Load from `path`, or return the defaults if it does not exist.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(Error::Read {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        };

        toml::from_str(&text).map_err(|err| Error::Parse {
            path: path.to_path_buf(),
            message: err.to_string(),
        })
    }

    /// Load from the default location, or an explicit override.
    pub fn load_default(override_path: Option<&Path>) -> Result<Self, Error> {
        match override_path {
            Some(path) => Self::load(path),
            None => Self::load(&config_path()),
        }
    }

    /// The keymaps this config resolves to.
    pub fn keymaps(&self) -> Keymaps {
        Keymaps::resolve(&self.keys)
    }

    /// The palette this config resolves to.
    pub fn palette(&self) -> Result<Palette, Error> {
        self.theme.palette().map_err(|err| Error::Theme {
            message: err.to_string(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("{message}")]
    Theme { message: String },
}

/// `$XDG_CONFIG_HOME/keyring-tui`, honouring a dev override so a test or a
/// `direnv` setup can point somewhere else.
pub fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("KEYRING_TUI_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("keyring-tui")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use ratatui::style::Color;

    use super::*;
    use crate::keys::combo::Key;
    use crate::keys::{Action, ModifiedKey, Resolution};

    fn write_config(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn a_missing_file_is_the_defaults() {
        let config = Config::load(Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(config, Config::default());
        assert_eq!(config.keymaps(), Keymaps::default());
    }

    #[test]
    fn an_empty_file_is_the_defaults() {
        let (_dir, path) = write_config("");
        assert_eq!(Config::load(&path).unwrap(), Config::default());
    }

    #[test]
    fn a_malformed_file_names_itself() {
        let (_dir, path) = write_config("[theme\npreset = nope");
        let err = Config::load(&path).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("parsing"), "{message}");
        assert!(message.contains("config.toml"), "{message}");
    }

    #[test]
    fn a_typo_in_a_key_is_rejected_rather_than_ignored() {
        let (_dir, path) = write_config("[theme]\npreset = \"nord\"\npresets = \"nord\"");
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn theme_and_keys_load_together() {
        let (_dir, path) = write_config(
            r##"
            [theme]
            preset = "gruvbox-dark"

            [theme.colors]
            secret = "#ff0000"

            [keys.main]
            set = [["MoveDown", "e"], ["MoveUp", "i"]]
            "##,
        );

        let config = Config::load(&path).unwrap();
        let palette = config.palette().unwrap();
        assert_eq!(palette.secret, Color::Rgb(0xff, 0, 0));
        assert_eq!(palette.accent, Color::Rgb(0xfa, 0xbd, 0x2f));

        let maps = config.keymaps();
        let pressed = [ModifiedKey::plain(Key::Char('e'))];
        assert_eq!(
            maps.get(Mode::Main).resolve(&pressed),
            Resolution::Exact(Action::MoveDown)
        );
    }

    #[test]
    fn an_unknown_colour_slot_surfaces_as_a_config_error() {
        let (_dir, path) = write_config("[theme.colors]\nbackgruond = \"red\"");
        let config = Config::load(&path).unwrap();
        let err = config.palette().unwrap_err().to_string();
        assert!(err.contains("backgruond"), "{err}");
    }

    #[test]
    fn the_config_dir_honours_the_dev_override() {
        // Set and read back in one test to avoid racing other tests over a
        // process-wide variable.
        let previous = std::env::var_os("KEYRING_TUI_CONFIG_DIR");
        unsafe { std::env::set_var("KEYRING_TUI_CONFIG_DIR", "/tmp/keyring-tui-test") };
        assert_eq!(config_dir(), PathBuf::from("/tmp/keyring-tui-test"));
        assert_eq!(
            config_path(),
            PathBuf::from("/tmp/keyring-tui-test/config.toml")
        );
        match previous {
            Some(value) => unsafe { std::env::set_var("KEYRING_TUI_CONFIG_DIR", value) },
            None => unsafe { std::env::remove_var("KEYRING_TUI_CONFIG_DIR") },
        }
    }
}
