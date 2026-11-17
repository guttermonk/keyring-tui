// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! The built-in keymap.
//!
//! vim keys first, with arrows and the obvious named keys alongside, so the
//! app is usable before anyone reads a config file.

use super::action::{Action, Mode};
use super::combo::{Key, KeyCombo, ModifiedKey};
use super::keymap::Keymap;

pub fn for_mode(mode: Mode) -> Keymap {
    match mode {
        Mode::Main => main(),
        Mode::Prompt => prompt(),
        Mode::Input => input(),
    }
}

fn main() -> Keymap {
    Keymap(vec![
        bind(Action::Quit, "q"),
        bind(Action::Quit, "esc"),
        bind(Action::Quit, "ctrl+c"),
        bind(Action::Help, "?"),
        bind(Action::Refresh, "r"),
        bind(Action::NextSection, "tab"),
        bind(Action::PrevSection, "backtab"),
        bind(Action::SectionPasswords, "1"),
        bind(Action::SectionGpgKeys, "2"),
        bind(Action::SectionSshKeys, "3"),
        // h/j/k/l, with the arrows beside them.
        bind(Action::MoveDown, "j"),
        bind(Action::MoveDown, "down"),
        bind(Action::MoveUp, "k"),
        bind(Action::MoveUp, "up"),
        bind(Action::FocusLeft, "h"),
        bind(Action::FocusLeft, "left"),
        bind(Action::FocusRight, "l"),
        bind(Action::FocusRight, "right"),
        bind(Action::FocusRight, "enter"),
        bind(Action::First, "g"),
        bind(Action::First, "home"),
        bind(Action::Last, "G"),
        bind(Action::Last, "end"),
        // Passwords.
        bind(Action::Unlock, "u"),
        bind(Action::Lock, "L"),
        bind(Action::ToggleSecret, "s"),
        // `/` filters here and searches a keyserver in GPG; `x` deletes in
        // all three sections. Section-aware resolution keeps them apart.
        bind(Action::FilterItems, "/"),
        bind(Action::DeleteItem, "x"),
        // `n` is "new" in every section; `D` is the bigger delete, as in SSH.
        bind(Action::NewKeyring, "n"),
        bind(Action::DeleteKeyring, "D"),
        // `y` yanks the useful thing in each section. In GPG that key is
        // already the armoured export, so the fingerprint goes on `Y` — and
        // SSH mirrors it so `Y` means "the identifier" in both.
        bind(Action::CopySecret, "y"),
        // SSH keys.
        bind(Action::AgentAdd, "a"),
        bind(Action::AgentRemove, "x"),
        bind(Action::NewSshKey, "n"),
        bind(Action::SshCopyId, "c"),
        bind(Action::SshPassphrase, "p"),
        bind(Action::CopySshKey, "y"),
        bind(Action::CopySshFingerprint, "Y"),
        // Not `x`: that is the harmless "remove from the agent" in this
        // section, and a near-miss on it should not unlink a private key.
        bind(Action::SshDelete, "D"),
        // GPG keys. `n` and `x` are shared with SSH: each section acts on its
        // own list, and no section has both bindings live at once.
        bind(Action::NewGpgKey, "n"),
        bind(Action::GpgDelete, "x"),
        bind(Action::GpgEdit, "e"),
        bind(Action::GpgExport, "y"),
        bind(Action::GpgPublish, "p"),
        bind(Action::ToggleGpgFilter, "f"),
        // `i` and `/` read as import and search; `c` is free in this section
        // because ssh-copy-id belongs to the other one.
        bind(Action::GpgImport, "i"),
        bind(Action::GpgSearch, "/"),
        bind(Action::CopyGpgFingerprint, "Y"),
    ])
}

fn prompt() -> Keymap {
    Keymap(vec![
        bind(Action::Confirm, "y"),
        bind(Action::Confirm, "enter"),
        bind(Action::Cancel, "n"),
        bind(Action::Cancel, "esc"),
        bind(Action::Cancel, "q"),
        bind(Action::Cancel, "ctrl+c"),
        bind(Action::Choose1, "1"),
        bind(Action::Choose2, "2"),
        bind(Action::Choose3, "3"),
    ])
}

/// The text field.
///
/// Only keys that cannot be typed are bound: everything printable has to stay
/// available as literal text, which is why there is no `q` to quit and no
/// single-letter anything here. The emacs pairs (`ctrl+a`/`ctrl+e`,
/// `ctrl+w`, `ctrl+u`) are the ones a shell has trained everyone on.
fn input() -> Keymap {
    Keymap(vec![
        bind(Action::Confirm, "enter"),
        bind(Action::Cancel, "esc"),
        bind(Action::Cancel, "ctrl+c"),
        bind(Action::Backspace, "backspace"),
        bind(Action::DeleteChar, "delete"),
        bind(Action::CursorLeft, "left"),
        bind(Action::CursorRight, "right"),
        bind(Action::CursorHome, "home"),
        bind(Action::CursorHome, "ctrl+a"),
        bind(Action::CursorEnd, "end"),
        bind(Action::CursorEnd, "ctrl+e"),
        bind(Action::DeleteWord, "ctrl+w"),
        bind(Action::ClearBefore, "ctrl+u"),
    ])
}

/// Panics on a malformed key, which would be a typo in this file rather than
/// in anyone's config — and the tests at the bottom of this module run it.
fn bind(action: Action, keys: &str) -> (Action, KeyCombo) {
    let combo = keys
        .parse::<KeyCombo>()
        .unwrap_or_else(|err| panic!("default binding {keys:?} is malformed: {err}"));
    (action, combo)
}

/// The arrow and named keys that `set` leaves alone, so a user who rebinds
/// movement to their own letters still has arrows that work.
pub fn is_protected(combo: &KeyCombo) -> bool {
    combo.is_bare_arrow()
        || matches!(
            combo.0.as_slice(),
            [only] if only.key == Key::Esc || only.key == Key::Enter
        )
        || combo.0.as_slice() == [ModifiedKey::ctrl(Key::Char('c'))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_default_binding_parses() {
        for mode in Mode::ALL {
            let map = for_mode(mode);
            assert!(!map.is_empty(), "{mode} has no default bindings");
        }
    }

    #[test]
    fn hjkl_is_bound_in_the_main_mode() {
        let map = main();
        for (expected, key) in [
            (Action::FocusLeft, 'h'),
            (Action::MoveDown, 'j'),
            (Action::MoveUp, 'k'),
            (Action::FocusRight, 'l'),
        ] {
            let pressed = [ModifiedKey::plain(Key::Char(key))];
            assert_eq!(
                map.resolve(&pressed),
                super::super::keymap::Resolution::Exact(expected),
                "{key} should be {expected}"
            );
        }
    }

    #[test]
    fn arrows_mirror_hjkl() {
        let map = main();
        for (expected, key) in [
            (Action::FocusLeft, Key::Left),
            (Action::MoveDown, Key::Down),
            (Action::MoveUp, Key::Up),
            (Action::FocusRight, Key::Right),
        ] {
            let pressed = [ModifiedKey::plain(key)];
            assert_eq!(
                map.resolve(&pressed),
                super::super::keymap::Resolution::Exact(expected)
            );
        }
    }

    #[test]
    fn no_default_binding_is_a_prefix_of_another() {
        // Without a chord timeout, a key that completes a binding fires at
        // once — so a default that is also the start of a longer default
        // would make the short one unreachable.
        for mode in Mode::ALL {
            let map = for_mode(mode);
            for (_, a) in map.iter() {
                for (_, b) in map.iter() {
                    if a.len() < b.len() {
                        assert!(
                            !b.starts_with(&a.0),
                            "{mode}: {a} is a prefix of {b}, so {a} could never fire"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn section_actions_may_share_keys_but_global_ones_may_not() {
        let map = main();
        let mut seen: Vec<(&KeyCombo, Action)> = Vec::new();
        for (action, combo) in map.iter() {
            if let Some((_, other)) = seen.iter().find(|(c, _)| *c == combo) {
                let sections = (action.section(), other.section());
                assert!(
                    sections.0.is_some() && sections.1.is_some() && sections.0 != sections.1,
                    "{combo} is bound to both {action} and {other}, which would be ambiguous"
                );
            }
            seen.push((combo, *action));
        }
    }
}
