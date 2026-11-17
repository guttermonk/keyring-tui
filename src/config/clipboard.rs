// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! `[clipboard]` — how to reach the clipboard, and when to wipe it.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The default wipe delay for a copied secret, in seconds.
///
/// Long enough to switch window and paste without rushing, short enough that
/// a forgotten clipboard is not a standing exposure. Public keys and
/// fingerprints are not secret and are never wiped.
const DEFAULT_CLEAR_AFTER: u64 = 45;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Clipboard {
    /// Seconds before a copied *secret* is wiped. `0` disables the wipe.
    pub clear_after: u64,
    /// Argv for the copy command, overriding detection. The text is written
    /// to its standard input.
    pub copy: Vec<String>,
    /// Argv for the read-back command, used to check the clipboard still
    /// holds what we put there before wiping it.
    ///
    /// Leaving it empty alongside a `copy` override is allowed: someone with
    /// an exotic clipboard may only be able to write to it, and a wipe that
    /// occasionally discards a later copy beats a secret that stays put. The
    /// wipe then goes ahead without looking.
    pub paste: Vec<String>,
}

impl Default for Clipboard {
    fn default() -> Self {
        Self {
            clear_after: DEFAULT_CLEAR_AFTER,
            copy: Vec::new(),
            paste: Vec::new(),
        }
    }
}

impl Clipboard {
    /// `None` when the wipe is switched off.
    pub fn clear_after(&self) -> Option<Duration> {
        (self.clear_after > 0).then(|| Duration::from_secs(self.clear_after))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_wipes_after_a_while() {
        let clipboard = Clipboard::default();
        assert_eq!(
            clipboard.clear_after(),
            Some(Duration::from_secs(DEFAULT_CLEAR_AFTER))
        );
        assert!(
            clipboard.copy.is_empty(),
            "no override, so the backend detects a tool"
        );
    }

    #[test]
    fn zero_disables_the_wipe() {
        let clipboard = Clipboard {
            clear_after: 0,
            ..Clipboard::default()
        };
        assert_eq!(clipboard.clear_after(), None);
    }

    #[test]
    fn a_copy_override_may_stand_alone() {
        // Allowed, and the backend wipes without reading back in that case.
        let clipboard = Clipboard {
            copy: vec!["wl-copy".into()],
            ..Clipboard::default()
        };
        assert!(clipboard.paste.is_empty());
    }
}
