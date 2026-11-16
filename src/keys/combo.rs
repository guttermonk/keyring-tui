// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! Key combinations as they appear in config and on screen.
//!
//! The spelling follows lazysync's, so a keymap written for one reads the
//! same in the other: `"q"`, `"esc"`, `{ key = "d", mod = ["Ctrl"] }`, and an
//! array for a chord.

use std::fmt;
use std::str::FromStr;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A key, named the way the config names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    Char(char),
    Enter,
    Space,
    Tab,
    BackTab,
    Backspace,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
    Insert,
    F(u8),
}

impl Key {
    /// The arrow keys, which `set` never retires — see
    /// [`crate::keys::keymap`].
    pub fn is_arrow(self) -> bool {
        matches!(self, Self::Up | Self::Down | Self::Left | Self::Right)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Char(c) => write!(f, "{c}"),
            Self::Enter => f.write_str("enter"),
            Self::Space => f.write_str("space"),
            Self::Tab => f.write_str("tab"),
            Self::BackTab => f.write_str("backtab"),
            Self::Backspace => f.write_str("backspace"),
            Self::Esc => f.write_str("esc"),
            Self::Up => f.write_str("up"),
            Self::Down => f.write_str("down"),
            Self::Left => f.write_str("left"),
            Self::Right => f.write_str("right"),
            Self::Home => f.write_str("home"),
            Self::End => f.write_str("end"),
            Self::PageUp => f.write_str("pageup"),
            Self::PageDown => f.write_str("pagedown"),
            Self::Delete => f.write_str("delete"),
            Self::Insert => f.write_str("insert"),
            Self::F(n) => write!(f, "f{n}"),
        }
    }
}

impl FromStr for Key {
    type Err = ParseKeyError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        // A single character is itself, case-sensitively: `G` is shift+g as
        // far as a keymap is concerned, and lower-casing it first would make
        // `g` and `G` the same binding.
        let mut chars = raw.chars();
        if let (Some(c), None) = (chars.next(), chars.next()) {
            return Ok(Self::Char(c));
        }

        let lowered = raw.to_ascii_lowercase();
        if let Some(digits) = lowered.strip_prefix('f') {
            if let Ok(n) = digits.parse::<u8>() {
                if (1..=12).contains(&n) {
                    return Ok(Self::F(n));
                }
            }
        }

        Ok(match lowered.as_str() {
            "enter" | "return" | "cr" => Self::Enter,
            "space" => Self::Space,
            "tab" => Self::Tab,
            "backtab" | "shifttab" => Self::BackTab,
            "backspace" | "bs" => Self::Backspace,
            "esc" | "escape" => Self::Esc,
            "up" => Self::Up,
            "down" => Self::Down,
            "left" => Self::Left,
            "right" => Self::Right,
            "home" => Self::Home,
            "end" => Self::End,
            "pageup" | "pgup" => Self::PageUp,
            "pagedown" | "pgdn" => Self::PageDown,
            "delete" | "del" => Self::Delete,
            "insert" | "ins" => Self::Insert,
            _ => return Err(ParseKeyError::UnknownKey(raw.to_owned())),
        })
    }
}

/// The modifiers held with a key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mods {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub super_: bool,
}

impl Mods {
    pub const NONE: Self = Self {
        ctrl: false,
        alt: false,
        shift: false,
        super_: false,
    };

    fn parse(raw: &str) -> Result<Self, ParseKeyError> {
        let mut mods = Self::NONE;
        match raw.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => mods.ctrl = true,
            "alt" | "meta" => mods.alt = true,
            "shift" => mods.shift = true,
            "super" | "cmd" | "win" => mods.super_ = true,
            _ => return Err(ParseKeyError::UnknownModifier(raw.to_owned())),
        }
        Ok(mods)
    }

    fn merge(self, other: Self) -> Self {
        Self {
            ctrl: self.ctrl || other.ctrl,
            alt: self.alt || other.alt,
            shift: self.shift || other.shift,
            super_: self.super_ || other.super_,
        }
    }

    fn names(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.ctrl {
            out.push("Ctrl");
        }
        if self.alt {
            out.push("Alt");
        }
        if self.shift {
            out.push("Shift");
        }
        if self.super_ {
            out.push("Super");
        }
        out
    }
}

impl fmt::Display for Mods {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for name in self.names() {
            write!(f, "{}+", name.to_ascii_lowercase())?;
        }
        Ok(())
    }
}

/// One keypress: a key plus whatever was held with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModifiedKey {
    pub key: Key,
    pub mods: Mods,
}

impl ModifiedKey {
    pub const fn plain(key: Key) -> Self {
        Self {
            key,
            mods: Mods::NONE,
        }
    }

    pub const fn ctrl(key: Key) -> Self {
        Self {
            key,
            mods: Mods {
                ctrl: true,
                alt: false,
                shift: false,
                super_: false,
            },
        }
    }

    /// Translate a terminal event. `None` for anything that is not a press,
    /// so a key is not acted on twice on Windows.
    pub fn from_event(event: KeyEvent) -> Option<Self> {
        if event.kind != KeyEventKind::Press {
            return None;
        }

        let key = match event.code {
            KeyCode::Char(' ') => Key::Space,
            KeyCode::Char(c) => Key::Char(c),
            KeyCode::Enter => Key::Enter,
            KeyCode::Tab => Key::Tab,
            KeyCode::BackTab => Key::BackTab,
            KeyCode::Backspace => Key::Backspace,
            KeyCode::Esc => Key::Esc,
            KeyCode::Up => Key::Up,
            KeyCode::Down => Key::Down,
            KeyCode::Left => Key::Left,
            KeyCode::Right => Key::Right,
            KeyCode::Home => Key::Home,
            KeyCode::End => Key::End,
            KeyCode::PageUp => Key::PageUp,
            KeyCode::PageDown => Key::PageDown,
            KeyCode::Delete => Key::Delete,
            KeyCode::Insert => Key::Insert,
            KeyCode::F(n) => Key::F(n),
            _ => return None,
        };

        let mut mods = Mods {
            ctrl: event.modifiers.contains(KeyModifiers::CONTROL),
            alt: event.modifiers.contains(KeyModifiers::ALT),
            shift: event.modifiers.contains(KeyModifiers::SHIFT),
            super_: event.modifiers.contains(KeyModifiers::SUPER),
        };

        // Terminals report `G` as shift+g, and the character already carries
        // the shift. Keeping both would mean `"G"` in a config never matching.
        if let Key::Char(c) = key {
            if c.is_uppercase() {
                mods.shift = false;
            }
        }

        Some(Self { key, mods })
    }
}

impl fmt::Display for ModifiedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.mods, self.key)
    }
}

impl FromStr for ModifiedKey {
    type Err = ParseKeyError;

    /// `"ctrl+c"`, or a bare key. The last `+`-separated part is the key, so
    /// `"ctrl++"` binds ctrl and the plus key.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.is_empty() {
            return Err(ParseKeyError::Empty);
        }
        if raw.chars().count() == 1 {
            return Ok(Self::plain(raw.parse()?));
        }

        let mut parts: Vec<&str> = raw.split('+').collect();
        // A trailing empty part means the key itself was `+`.
        let last = parts.pop().unwrap_or_default();
        let key_text = if last.is_empty() { "+" } else { last };

        let mut mods = Mods::NONE;
        for part in parts {
            if part.is_empty() {
                continue;
            }
            mods = mods.merge(Mods::parse(part)?);
        }

        Ok(Self {
            key: key_text.parse()?,
            mods,
        })
    }
}

/// One binding: a single key, or several pressed in sequence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyCombo(pub Vec<ModifiedKey>);

impl KeyCombo {
    pub fn single(key: ModifiedKey) -> Self {
        Self(vec![key])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Kept for the `len`/`is_empty` pair, and used by the tests.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn starts_with(&self, prefix: &[ModifiedKey]) -> bool {
        self.0.len() >= prefix.len() && self.0[..prefix.len()] == *prefix
    }

    /// True for a lone arrow key, which `set` keeps.
    pub fn is_bare_arrow(&self) -> bool {
        matches!(self.0.as_slice(), [only] if only.key.is_arrow() && only.mods == Mods::NONE)
    }
}

impl fmt::Display for KeyCombo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.0.iter().map(ToString::to_string).collect();
        f.write_str(&parts.join(" "))
    }
}

impl FromStr for KeyCombo {
    type Err = ParseKeyError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Ok(Self::single(raw.parse()?))
    }
}

impl Serialize for KeyCombo {
    /// A single key serialises as a string, a chord as an array, matching
    /// what the config accepts.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [only] => serializer.serialize_str(&only.to_string()),
            many => serializer.collect_seq(many.iter().map(ToString::to_string)),
        }
    }
}

impl<'de> Deserialize<'de> for KeyCombo {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ComboVisitor)
    }
}

struct ComboVisitor;

impl<'de> Visitor<'de> for ComboVisitor {
    type Value = KeyCombo;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a key like \"q\" or \"ctrl+c\", a table like { key = \"d\", mod = [\"Ctrl\"] }, or an array of either for a chord")
    }

    fn visit_str<E: de::Error>(self, raw: &str) -> Result<Self::Value, E> {
        raw.parse().map_err(de::Error::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut keys = Vec::new();
        // Each element of a chord is itself a key in any accepted spelling.
        while let Some(element) = seq.next_element::<KeyCombo>()? {
            keys.extend(element.0);
        }
        if keys.is_empty() {
            return Err(de::Error::custom("a chord needs at least one key"));
        }
        Ok(KeyCombo(keys))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Table {
            key: String,
            #[serde(default, rename = "mod")]
            mods: Vec<String>,
        }

        let table = Table::deserialize(de::value::MapAccessDeserializer::new(map))
            .map_err(de::Error::custom)?;

        let mut mods = Mods::NONE;
        for name in &table.mods {
            mods = mods.merge(Mods::parse(name).map_err(de::Error::custom)?);
        }
        let key: Key = table.key.parse().map_err(de::Error::custom)?;

        Ok(KeyCombo::single(ModifiedKey { key, mods }))
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ParseKeyError {
    #[error("a key cannot be empty")]
    Empty,
    #[error(
        "unknown key {0:?} (expected a single character, or: enter, space, tab, backtab, \
         backspace, esc, up, down, left, right, home, end, pageup, pagedown, delete, insert, \
         f1-f12)"
    )]
    UnknownKey(String),
    #[error("unknown modifier {0:?} (expected Ctrl, Alt, Shift or Super)")]
    UnknownModifier(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_keys() {
        assert_eq!("q".parse::<Key>().unwrap(), Key::Char('q'));
        assert_eq!("esc".parse::<Key>().unwrap(), Key::Esc);
        assert_eq!("ENTER".parse::<Key>().unwrap(), Key::Enter);
        assert_eq!("f5".parse::<Key>().unwrap(), Key::F(5));
    }

    #[test]
    fn case_matters_for_characters() {
        assert_eq!("G".parse::<Key>().unwrap(), Key::Char('G'));
        assert_ne!(
            "G".parse::<Key>().unwrap(),
            "g".parse::<Key>().unwrap(),
            "g and G must be different bindings"
        );
    }

    #[test]
    fn parses_modifiers() {
        let combo: ModifiedKey = "ctrl+c".parse().unwrap();
        assert_eq!(combo.key, Key::Char('c'));
        assert!(combo.mods.ctrl);

        let combo: ModifiedKey = "Ctrl+Alt+delete".parse().unwrap();
        assert_eq!(combo.key, Key::Delete);
        assert!(combo.mods.ctrl && combo.mods.alt);
    }

    #[test]
    fn parses_the_plus_key_itself() {
        let combo: ModifiedKey = "ctrl++".parse().unwrap();
        assert_eq!(combo.key, Key::Char('+'));
        assert!(combo.mods.ctrl);
    }

    #[test]
    fn rejects_nonsense_with_a_useful_message() {
        let err = "wat".parse::<Key>().unwrap_err();
        assert!(err.to_string().contains("unknown key"), "{err}");
        let err = "hyper+c".parse::<ModifiedKey>().unwrap_err();
        assert!(err.to_string().contains("unknown modifier"), "{err}");
    }

    #[test]
    fn an_uppercase_char_does_not_also_demand_shift() {
        // Terminals send `G` as shift+g; a config that says "G" must match.
        let event = KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT);
        let pressed = ModifiedKey::from_event(event).unwrap();
        assert_eq!(pressed, "G".parse::<ModifiedKey>().unwrap());
    }

    #[test]
    fn space_is_named_not_literal() {
        let event = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE);
        let pressed = ModifiedKey::from_event(event).unwrap();
        assert_eq!(pressed.key, Key::Space);
        assert_eq!(pressed, "space".parse::<ModifiedKey>().unwrap());
    }

    #[test]
    fn key_releases_are_not_presses() {
        let mut event = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        event.kind = KeyEventKind::Release;
        assert!(ModifiedKey::from_event(event).is_none());
    }

    #[test]
    fn combos_deserialize_from_every_accepted_spelling() {
        #[derive(Deserialize)]
        struct Wrapper {
            k: KeyCombo,
        }

        let plain: Wrapper = toml::from_str(r#"k = "q""#).unwrap();
        assert_eq!(
            plain.k,
            KeyCombo::single(ModifiedKey::plain(Key::Char('q')))
        );

        let table: Wrapper = toml::from_str(r#"k = { key = "d", mod = ["Ctrl"] }"#).unwrap();
        assert_eq!(table.k, KeyCombo::single(ModifiedKey::ctrl(Key::Char('d'))));

        let chord: Wrapper = toml::from_str(r#"k = ["g", "g"]"#).unwrap();
        assert_eq!(chord.k.len(), 2);
        assert_eq!(chord.k.to_string(), "g g");
    }

    #[test]
    fn combos_round_trip_through_display() {
        for raw in ["q", "esc", "ctrl+c", "G", "f12", "alt+left"] {
            let combo: KeyCombo = raw.parse().unwrap();
            assert_eq!(
                combo.to_string().parse::<KeyCombo>().unwrap(),
                combo,
                "{raw} did not round-trip"
            );
        }
    }

    #[test]
    fn prefix_matching_underpins_chords() {
        let gg = KeyCombo(vec![ModifiedKey::plain(Key::Char('g')); 2]);
        assert!(gg.starts_with(&[ModifiedKey::plain(Key::Char('g'))]));
        assert!(!gg.starts_with(&[ModifiedKey::plain(Key::Char('x'))]));
        assert!(gg.starts_with(&[]), "every combo continues an empty prefix");
    }

    #[test]
    fn bare_arrows_are_recognised() {
        assert!("down".parse::<KeyCombo>().unwrap().is_bare_arrow());
        assert!(!"ctrl+down".parse::<KeyCombo>().unwrap().is_bare_arrow());
        assert!(!"j".parse::<KeyCombo>().unwrap().is_bare_arrow());
    }
}
