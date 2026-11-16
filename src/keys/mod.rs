// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! Keybindings: what a key can do, how a key is spelled, and how a config's
//! tables merge over the built-in map.

pub mod action;
pub mod combo;
pub mod defaults;
pub mod keymap;

pub use action::{Action, Mode};
pub use combo::ModifiedKey;
pub use keymap::{KeymapSection, Keymaps, Resolution};
