// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

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

    /// Slots the overlay supplied, and slots it named that are not slots at
    /// all. Filled in during loading, never read from the file — hence
    /// `skip`, which also means `deny_unknown_fields` rejects anyone writing
    /// them by hand.
    #[serde(skip)]
    pub overlay_applied: Vec<String>,
    #[serde(skip)]
    pub overlay_ignored: Vec<String>,
}

impl Config {
    /// Load from `path`, with no colour overlay. Equivalent to a machine
    /// where no wallpaper tool has ever run. The binary goes through
    /// [`Config::load_default`]; this is the overlay-free form the tests use.
    #[allow(dead_code)]
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::load_with_overlay(path, None)
    }

    /// Load from `path`, merging a colour overlay over `[theme.colors]`.
    ///
    /// The overlay path is a parameter rather than something this function
    /// discovers, so a test is hermetic by construction instead of reading
    /// whatever the developer's own wallpaper tool last wrote.
    pub fn load_with_overlay(path: &Path, overlay: Option<&Path>) -> Result<Self, Error> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            // No config at all is still a machine the overlay can colour.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(err) => {
                return Err(Error::Read {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        };

        // Parsed to a `Value` first so the overlay can be merged before
        // anything is deserialised. Concatenating the two files as text
        // cannot work: TOML rejects a second `[colors]` header as a duplicate
        // key.
        let mut value: toml::Value = toml::from_str(&text).map_err(|err| Error::Parse {
            path: path.to_path_buf(),
            message: err.to_string(),
        })?;

        let merge = overlay.map(|path| merge_colors_overlay(&mut value, path));

        let mut config: Self = value
            .try_into()
            .map_err(|err: toml::de::Error| Error::Parse {
                path: path.to_path_buf(),
                message: err.to_string(),
            })?;

        if let Some(merge) = merge {
            config.overlay_applied = merge.applied;
            config.overlay_ignored = merge.ignored;
        }
        Ok(config)
    }

    /// Load from the default location, or an explicit override, together with
    /// the colour overlay if one has been written.
    pub fn load_default(override_path: Option<&Path>) -> Result<Self, Error> {
        let path = match override_path {
            Some(path) => path.to_path_buf(),
            None => config_path(),
        };
        Self::load_with_overlay(&path, Some(&colors_overlay_path()))
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

/// What a merge did, so `keyring-tui theme` can report it.
#[derive(Debug, Default)]
struct Merge {
    applied: Vec<String>,
    ignored: Vec<String>,
}

/// The optional second colour file, layered over `[theme.colors]`.
///
/// It is for tools that recolour a desktop from the current wallpaper —
/// wallust, pywal — which re-extract a palette on every wallpaper change and
/// have no business owning the file that also holds your keymap. Such a tool
/// renders the overlay; keyring-tui is a fresh process every time it starts,
/// so the next run already has the new colours and nothing here needs a
/// reload hook or a file watcher.
///
/// Set `KEYRING_TUI_COLORS_OVERLAY` to read it from somewhere else.
pub fn colors_overlay_path() -> PathBuf {
    if let Some(path) = std::env::var_os("KEYRING_TUI_COLORS_OVERLAY") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }

    let cache = match std::env::var_os("XDG_CACHE_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => dirs::home_dir().unwrap_or_default().join(".cache"),
    };
    cache.join("wallust").join("colors-keyring-tui.toml")
}

/// Merge the overlay's top-level `[colors]` entries over `[theme.colors]`.
///
/// Per key rather than per file, so an overlay naming only `border` leaves
/// the other thirteen as the config has them. A missing, unreadable or
/// malformed overlay is the normal state — it means "use the config" — and is
/// silently nothing, which is what every theme that is not wallpaper-derived
/// wants.
///
/// The overlay's table is top-level `[colors]`, not `[theme.colors]`, to match
/// the other files a wallust template directory produces. Uniformity across
/// that directory is worth more than matching this app's own nesting, and the
/// shape is written down in `config.example.toml` so the producing side has
/// something to target.
///
/// A key that is not a colour slot is dropped and reported rather than
/// rejected. A hand-written config failing loudly is right — the user can fix
/// it — but this file is machine-written, so the same rule would mean a
/// wallpaper change stopping a key manager from starting. `keyring-tui theme`
/// names what was dropped, which is where that belongs: loud where it can be
/// acted on, quiet where it would only break the app.
fn merge_colors_overlay(config: &mut toml::Value, path: &Path) -> Merge {
    let Ok(text) = fs::read_to_string(path) else {
        return Merge::default();
    };
    // `toml::from_str`, not `str::parse`: `FromStr` for `Value` parses a
    // single value, so a document starting with `[colors]` is read as an
    // array and then errors on the rest of the file. A failed overlay parse
    // is silent by design, so getting this wrong fails invisibly.
    let Ok(overlay) = toml::from_str::<toml::Value>(&text) else {
        return Merge::default();
    };
    let Some(overlay_colors) = overlay.get("colors").and_then(|value| value.as_table()) else {
        return Merge::default();
    };
    let Some(table) = config.as_table_mut() else {
        return Merge::default();
    };

    // Created if absent: a config with no [theme] at all is still themeable
    // by the overlay.
    let theme = table
        .entry("theme".to_string())
        .or_insert_with(|| toml::Value::Table(Default::default()));
    let Some(theme) = theme.as_table_mut() else {
        return Merge::default();
    };
    let colors = theme
        .entry("colors".to_string())
        .or_insert_with(|| toml::Value::Table(Default::default()));
    let Some(colors) = colors.as_table_mut() else {
        return Merge::default();
    };

    let mut merge = Merge::default();
    for (key, value) in overlay_colors.clone() {
        if !Palette::SLOTS.contains(&key.as_str()) {
            merge.ignored.push(key);
            continue;
        }
        merge.applied.push(key.clone());
        colors.insert(key, value);
    }
    merge.applied.sort();
    merge.ignored.sort();
    merge
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

    // --- The colour overlay ----------------------------------------------

    fn write_overlay(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("colors-keyring-tui.toml");
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn an_absent_overlay_leaves_the_config_alone() {
        let (dir, path) = write_config("[theme]\npreset = \"nord\"");
        let missing = dir.path().join("nope.toml");

        let config = Config::load_with_overlay(&path, Some(&missing)).unwrap();
        assert_eq!(config.theme.preset, theme::Preset::Nord);
        assert!(config.overlay_applied.is_empty());
        assert!(config.overlay_ignored.is_empty());
    }

    #[test]
    fn an_overlay_merges_per_key_and_leaves_the_rest() {
        let (dir, path) = write_config(
            r##"
            [theme]
            preset = "nord"

            [theme.colors]
            border = "red"
            secret = "#abcdef"
            "##,
        );
        // Only `border` is named, so `secret` must survive from the config
        // and every unnamed slot from the preset.
        let overlay = write_overlay(dir.path(), "[colors]\nborder = \"blue\"\n");

        let config = Config::load_with_overlay(&path, Some(&overlay)).unwrap();
        let palette = config.palette().unwrap();

        assert_eq!(palette.border, Color::Blue, "the overlay wins its own slot");
        assert_eq!(
            palette.secret,
            Color::Rgb(0xab, 0xcd, 0xef),
            "a slot the overlay did not name keeps the config's value"
        );
        assert_eq!(
            palette.accent,
            Color::Rgb(0x88, 0xc0, 0xd0),
            "and an unset slot still comes from the preset"
        );
        assert_eq!(config.overlay_applied, vec!["border".to_string()]);
    }

    #[test]
    fn an_overlay_works_on_a_config_with_no_theme_table() {
        let (dir, path) = write_config("[keys.main]\nunbind = [\"esc\"]\n");
        let overlay = write_overlay(dir.path(), "[colors]\naccent = \"magenta\"\n");

        let config = Config::load_with_overlay(&path, Some(&overlay)).unwrap();
        assert_eq!(config.palette().unwrap().accent, Color::Magenta);
    }

    #[test]
    fn a_malformed_overlay_is_silently_the_config() {
        let (dir, path) = write_config("[theme]\npreset = \"nord\"");
        let overlay = write_overlay(dir.path(), "[colors\nborder = oops");

        let config = Config::load_with_overlay(&path, Some(&overlay))
            .expect("a broken overlay must not fail the load");
        assert_eq!(
            config.palette().unwrap().border,
            Color::Rgb(0x43, 0x4c, 0x5e)
        );
        assert!(config.overlay_applied.is_empty());
    }

    #[test]
    fn an_overlay_without_a_colors_table_is_ignored() {
        let (dir, path) = write_config("");
        // Right shape for some other app, wrong for this one.
        let overlay = write_overlay(dir.path(), "[theme.colors]\naccent = \"red\"\n");

        let config = Config::load_with_overlay(&path, Some(&overlay)).unwrap();
        assert!(config.overlay_applied.is_empty());
        assert_eq!(config.palette().unwrap().accent, Color::Cyan);
    }

    #[test]
    fn an_unknown_slot_in_the_overlay_is_dropped_and_reported() {
        let (dir, path) = write_config("");
        let overlay = write_overlay(
            dir.path(),
            "[colors]\nbordr = \"blue\"\naccent = \"green\"\n",
        );

        // Machine-written, so a typo must not stop the app starting — but it
        // is reported, which is what `keyring-tui theme` prints.
        let config = Config::load_with_overlay(&path, Some(&overlay))
            .expect("a bad slot in the overlay must not fail the load");
        let palette = config.palette().expect("and must not fail the palette");

        assert_eq!(palette.accent, Color::Green, "the good slot still applies");
        assert_eq!(config.overlay_ignored, vec!["bordr".to_string()]);
        assert_eq!(config.overlay_applied, vec!["accent".to_string()]);
    }

    #[test]
    fn a_bad_slot_in_the_config_still_fails_loudly() {
        // The asymmetry is the point: the config is hand-written and the user
        // can fix it, so it keeps failing at load.
        let (_dir, path) = write_config("[theme.colors]\nbordr = \"blue\"\n");
        let config = Config::load(&path).unwrap();
        assert!(config.palette().is_err());
    }

    #[test]
    fn a_malformed_colour_in_the_overlay_fails_at_the_palette() {
        // Shape is fine, value is not. Deserialising `[theme.colors]` is what
        // rejects it, with the same message a config would get.
        let (dir, path) = write_config("");
        let overlay = write_overlay(dir.path(), "[colors]\naccent = \"nosuchcolour\"\n");

        let err = Config::load_with_overlay(&path, Some(&overlay)).unwrap_err();
        assert!(err.to_string().contains("nosuchcolour"), "{err}");
    }

    #[test]
    fn the_overlay_path_honours_its_override() {
        let previous = std::env::var_os("KEYRING_TUI_COLORS_OVERLAY");
        unsafe { std::env::set_var("KEYRING_TUI_COLORS_OVERLAY", "/tmp/overlay-test.toml") };
        assert_eq!(
            colors_overlay_path(),
            PathBuf::from("/tmp/overlay-test.toml")
        );

        // Unset, it lands under the cache directory with the agreed name.
        unsafe { std::env::remove_var("KEYRING_TUI_COLORS_OVERLAY") };
        let discovered = colors_overlay_path();
        assert!(
            discovered.ends_with("wallust/colors-keyring-tui.toml"),
            "{discovered:?}"
        );

        if let Some(value) = previous {
            unsafe { std::env::set_var("KEYRING_TUI_COLORS_OVERLAY", value) };
        }
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
