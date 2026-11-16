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
}

impl Mode {
    pub const ALL: [Self; 2] = [Self::Main, Self::Prompt];

    pub fn name(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Prompt => "prompt",
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

    // SSH keys.
    AgentAdd,
    AgentRemove,
    NewSshKey,

    // GPG keys.
    GpgEdit,
    GpgExport,
    GpgPublish,
    GpgDelete,
    NewGpgKey,
    ToggleGpgFilter,

    // Prompts.
    Confirm,
    Cancel,
    Choose1,
    Choose2,
    Choose3,
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
            Self::AgentAdd => "add to the ssh-agent (runs ssh-add)",
            Self::AgentRemove => "remove from the ssh-agent",
            Self::NewSshKey => "new SSH key (runs ssh-keygen)",
            Self::GpgEdit => "edit: trust, expiry, UIDs, revoke, certify",
            Self::GpgExport => "print the armoured public key",
            Self::GpgPublish => "publish to a keyserver",
            Self::GpgDelete => "delete the key",
            Self::NewGpgKey => "new GPG key (runs gpg --full-generate-key)",
            Self::ToggleGpgFilter => "show all keys / only secret keys",
            Self::Confirm => "confirm",
            Self::Cancel => "cancel",
            Self::Choose1 => "first choice",
            Self::Choose2 => "second choice",
            Self::Choose3 => "third choice",
        }
    }

    /// Which section an action belongs to. `None` means it works everywhere.
    pub fn section(self) -> Option<Section> {
        match self {
            Self::Unlock | Self::Lock | Self::ToggleSecret => Some(Section::Keyrings),
            Self::AgentAdd | Self::AgentRemove | Self::NewSshKey => Some(Section::SshKeys),
            Self::GpgEdit
            | Self::GpgExport
            | Self::GpgPublish
            | Self::GpgDelete
            | Self::NewGpgKey
            | Self::ToggleGpgFilter => Some(Section::GpgKeys),
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
