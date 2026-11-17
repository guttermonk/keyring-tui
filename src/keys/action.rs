// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! Everything a key can do, and the contexts keys are bound in.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::Section;

/// An input context. Keys are bound per mode, because `y` confirms a prompt
/// and exports a key in the main view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// The lists: navigation, section switching, and per-section operations.
    Main,
    /// A modal question — a confirmation, or the new-key chooser.
    Prompt,
    /// A text field. Printable keys are literal text here, so only keys
    /// that cannot be typed are bound.
    Input,
}

impl Mode {
    pub const ALL: [Self; 3] = [Self::Main, Self::Prompt, Self::Input];

    pub fn name(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Prompt => "prompt",
            Self::Input => "input",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A bindable action.
///
/// Section-specific actions do nothing in the other sections, so one key can
/// carry the same idea in each — `x` removes from the agent in SSH and
/// deletes a key in GPG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Action {
    // Anywhere.
    Quit,
    Help,
    Refresh,
    NextSection,
    PrevSection,
    SectionPasswords,
    SectionGpgKeys,
    SectionSshKeys,

    // Navigation.
    MoveDown,
    MoveUp,
    First,
    Last,
    /// Focus the pane to the left — the keyring list, or back from details.
    FocusLeft,
    /// Focus the pane to the right — items, or the details pane.
    FocusRight,

    // Passwords.
    Unlock,
    Lock,
    ToggleSecret,
    FilterItems,
    DeleteItem,
    NewKeyring,
    DeleteKeyring,
    CopySecret,
    NewItem,
    RenameItem,
    EditAttributes,

    // SSH keys.
    AgentAdd,
    AgentRemove,
    NewSshKey,
    SshCopyId,
    SshPassphrase,
    SshDelete,
    CopySshKey,
    CopySshFingerprint,

    // GPG keys.
    GpgEdit,
    GpgExport,
    GpgPublish,
    GpgDelete,
    NewGpgKey,
    ToggleGpgFilter,
    GpgImport,
    GpgSearch,
    CopyGpgFingerprint,
    GpgSignatures,

    // Prompts.
    Confirm,
    Cancel,
    Choose1,
    Choose2,
    Choose3,

    // Text fields. Only keys that cannot be typed are bound here; anything
    // printable is literal text, so there is no `InsertChar` action.
    Backspace,
    DeleteChar,
    CursorLeft,
    CursorRight,
    CursorHome,
    CursorEnd,
    DeleteWord,
    ClearBefore,
}

impl Action {
    /// One line for the help overlay and for `keyring-tui keys`.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Quit => "quit",
            Self::Help => "toggle this help",
            Self::Refresh => "refresh the current section",
            Self::NextSection => "next section",
            Self::PrevSection => "previous section",
            Self::SectionPasswords => "go to Passwords",
            Self::SectionGpgKeys => "go to GPG Keys",
            Self::SectionSshKeys => "go to SSH Keys",
            Self::MoveDown => "move down",
            Self::MoveUp => "move up",
            Self::First => "first",
            Self::Last => "last",
            Self::FocusLeft => "focus left",
            Self::FocusRight => "focus right",
            Self::Unlock => "unlock the selected keyring",
            Self::Lock => "lock the selected keyring",
            Self::ToggleSecret => "reveal / hide the secret",
            Self::FilterItems => "filter the item list",
            Self::DeleteItem => "delete the stored secret",
            Self::NewKeyring => "new keyring",
            Self::DeleteKeyring => "delete the keyring and everything in it",
            Self::CopySecret => "copy the secret to the clipboard",
            Self::NewItem => "store a new secret (runs secret-tool)",
            Self::RenameItem => "rename the selected item",
            Self::EditAttributes => "edit the selected item's attributes",
            Self::AgentAdd => "add to the ssh-agent (runs ssh-add)",
            Self::AgentRemove => "remove from the ssh-agent",
            Self::NewSshKey => "new SSH key (runs ssh-keygen)",
            Self::SshCopyId => "copy this key to a host (runs ssh-copy-id)",
            Self::SshPassphrase => "change or remove the passphrase (runs ssh-keygen -p)",
            Self::SshDelete => "delete the key files",
            Self::CopySshKey => "copy the public key line to the clipboard",
            Self::CopySshFingerprint => "copy the fingerprint to the clipboard",
            Self::GpgEdit => "edit: trust, expiry, UIDs, revoke, certify",
            Self::GpgExport => "print the armoured public key",
            Self::GpgPublish => "publish to a keyserver",
            Self::GpgDelete => "delete the key",
            Self::NewGpgKey => "new GPG key (runs gpg --full-generate-key)",
            Self::ToggleGpgFilter => "show all keys / only secret keys",
            Self::GpgImport => "import keys from a file",
            Self::GpgSearch => "search a keyserver",
            Self::CopyGpgFingerprint => "copy the fingerprint to the clipboard",
            Self::GpgSignatures => "show / hide who has certified this key",
            Self::Confirm => "confirm",
            Self::Cancel => "cancel",
            Self::Choose1 => "first choice",
            Self::Choose2 => "second choice",
            Self::Choose3 => "third choice",
            Self::Backspace => "delete the character before the cursor",
            Self::DeleteChar => "delete the character under the cursor",
            Self::CursorLeft => "move the cursor left",
            Self::CursorRight => "move the cursor right",
            Self::CursorHome => "start of the line",
            Self::CursorEnd => "end of the line",
            Self::DeleteWord => "delete the word before the cursor",
            Self::ClearBefore => "delete to the start of the line",
        }
    }

    /// Which section an action belongs to. `None` means it works everywhere.
    pub fn section(self) -> Option<Section> {
        match self {
            Self::Unlock
            | Self::Lock
            | Self::ToggleSecret
            | Self::FilterItems
            | Self::DeleteItem
            | Self::NewKeyring
            | Self::DeleteKeyring
            | Self::CopySecret
            | Self::NewItem
            | Self::RenameItem
            | Self::EditAttributes => Some(Section::Keyrings),
            Self::AgentAdd
            | Self::AgentRemove
            | Self::NewSshKey
            | Self::SshCopyId
            | Self::SshPassphrase
            | Self::SshDelete
            | Self::CopySshKey
            | Self::CopySshFingerprint => Some(Section::SshKeys),
            Self::GpgEdit
            | Self::GpgExport
            | Self::GpgPublish
            | Self::GpgDelete
            | Self::NewGpgKey
            | Self::GpgImport
            | Self::GpgSearch
            | Self::ToggleGpgFilter
            | Self::CopyGpgFingerprint
            | Self::GpgSignatures => Some(Section::GpgKeys),
            _ => None,
        }
    }

    /// Whether this action does anything in `section`.
    ///
    /// Used to resolve a key bound in more than one section — `x` is both
    /// "remove from the agent" and "delete this key" — to the one that
    /// applies where the cursor actually is.
    pub fn applies_to(self, section: Section) -> bool {
        match self.section() {
            Some(own) => own == section,
            None => true,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The serde name, which is also the config spelling.
        write!(f, "{self:?}")
    }
}
