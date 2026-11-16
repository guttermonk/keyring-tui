//! Domain types shared between the backends and the UI.
//!
//! Backends translate their native objects (Secret Service items, GPG keys,
//! OpenSSH key files) into these, so the UI never touches a D-Bus proxy or a
//! gpgme context directly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Top-level sections, mirroring Seahorse's sidebar.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Keyrings,
    GpgKeys,
    SshKeys,
}

impl Section {
    pub const ALL: [Self; 3] = [Self::Keyrings, Self::GpgKeys, Self::SshKeys];

    pub fn title(self) -> &'static str {
        match self {
            Self::Keyrings => "Passwords",
            Self::GpgKeys => "GPG Keys",
            Self::SshKeys => "SSH Keys",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// A Secret Service collection — what GNOME calls a keyring.
#[derive(Clone, Debug)]
pub struct KeyringInfo {
    /// Index into the backend's collection table; backends are addressed by it.
    pub id: usize,
    pub label: String,
    pub locked: bool,
    /// True for the collection aliased to `default`.
    pub is_default: bool,
}

/// A single stored secret. The secret value itself is deliberately absent:
/// it is fetched on demand and held only in [`crate::app::App::revealed`].
#[derive(Clone, Debug)]
pub struct ItemInfo {
    /// Index into the owning keyring's item table.
    pub id: usize,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub locked: bool,
    pub created: Option<Duration>,
    pub modified: Option<Duration>,
}

impl ItemInfo {
    /// The `xdg:schema` attribute, which is how applications tag what kind of
    /// secret this is (network password, note, chrome login, ...).
    pub fn schema(&self) -> Option<&str> {
        self.attributes
            .get(crate::backend::secrets::SCHEMA_ATTRIBUTE)
            .map(String::as_str)
    }

    /// A short human label for the schema, for the item list's right column.
    pub fn kind(&self) -> &str {
        match self.schema() {
            Some("org.freedesktop.Secret.Generic") => "generic",
            Some("org.gnome.keyring.NetworkPassword") => "network",
            Some("org.gnome.keyring.Note") => "note",
            Some(s) => s.rsplit('.').next().unwrap_or(s),
            None => "—",
        }
    }
}

/// An SSH key found on disk, in the agent, or both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshKeyInfo {
    /// Index into the backend's key table; the backend is addressed by it.
    pub id: usize,
    /// Display name: the key's file stem, or its comment for agent-only keys.
    pub name: String,
    pub private_path: Option<PathBuf>,
    pub public_path: Option<PathBuf>,
    /// Wire algorithm name, e.g. `ssh-ed25519` or `sk-ssh-ed25519@openssh.com`.
    pub algorithm: String,
    pub bits: Option<u32>,
    pub comment: String,
    /// `SHA256:…`, the same string `ssh-keygen -l` prints.
    pub fingerprint: String,
    /// The private key file is passphrase-protected.
    pub encrypted: bool,
    /// A `*-sk` key, backed by a FIDO2 authenticator.
    pub hardware_backed: bool,
    pub in_agent: bool,
    /// The one-line public key, as it would appear in `authorized_keys`.
    pub public_line: String,
}

impl SshKeyInfo {
    /// Whether this key can be handed to `ssh-add`, which needs a private key
    /// file. Keys that only exist inside the agent cannot.
    pub fn is_addable(&self) -> bool {
        self.private_path.is_some()
    }

    pub fn private_path(&self) -> Option<&Path> {
        self.private_path.as_deref()
    }

    /// Short algorithm label for the list column, e.g. `ed25519 256`.
    pub fn kind(&self) -> String {
        let algorithm = self
            .algorithm
            .trim_start_matches("ssh-")
            .trim_start_matches("sk-ssh-")
            .trim_start_matches("sk-")
            .split('@')
            .next()
            .unwrap_or(&self.algorithm);
        match self.bits {
            Some(bits) => format!("{algorithm} {bits}"),
            None => algorithm.to_owned(),
        }
    }
}

/// A key from the local GnuPG keyring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpgKeyInfo {
    /// Index into the backend's key table; the backend is addressed by it.
    pub id: usize,
    /// Long key ID, as `gpg --list-keys --keyid-format long` prints it.
    pub key_id: String,
    pub fingerprint: String,
    /// First user ID, which GnuPG treats as the primary one.
    pub primary_uid: String,
    pub uids: Vec<GpgUid>,
    pub subkeys: Vec<GpgSubkey>,
    /// Algorithm of the primary key. gpgme spells these the way gpg does and
    /// folds the size in where it matters — `rsa4096`, `ed25519`, `nistp256`
    /// — so there is no separate bit count to report.
    pub algorithm: String,
    pub created: Option<Duration>,
    /// `None` means the key does not expire.
    pub expires: Option<Duration>,
    pub owner_trust: &'static str,
    /// The private key is present in this keyring.
    pub has_secret: bool,
    pub revoked: bool,
    pub expired: bool,
    pub disabled: bool,
    /// Aggregate capability letters across the key, in `escaESCA` style —
    /// lowercase for the primary key, see [`GpgSubkey::capabilities`].
    pub capabilities: String,
    /// At least one subkey lives on a smartcard.
    pub on_card: bool,
}

impl GpgKeyInfo {
    /// Short state label for the list column: the first thing wrong with the
    /// key, or its usability if nothing is.
    pub fn state(&self) -> Option<&'static str> {
        if self.revoked {
            Some("revoked")
        } else if self.expired {
            Some("expired")
        } else if self.disabled {
            Some("disabled")
        } else {
            None
        }
    }
}

/// One user ID on a GPG key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpgUid {
    /// The whole `Name (comment) <email>` string.
    pub uid: String,
    pub validity: &'static str,
    pub revoked: bool,
}

/// One subkey on a GPG key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpgSubkey {
    pub key_id: String,
    pub algorithm: String,
    pub created: Option<Duration>,
    pub expires: Option<Duration>,
    /// Capability letters: `s`ign, `c`ertify, `e`ncrypt, `a`uthenticate.
    pub capabilities: String,
    pub revoked: bool,
    pub expired: bool,
    pub has_secret: bool,
    pub on_card: bool,
}

/// Which keys the GPG section is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpgFilter {
    /// Every key in the local keyring.
    All,
    /// Only keys whose private half we hold.
    Secret,
}

impl GpgFilter {
    pub fn toggled(self) -> Self {
        match self {
            Self::All => Self::Secret,
            Self::Secret => Self::All,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::All => "all keys",
            Self::Secret => "secret keys",
        }
    }
}

/// Whether the ssh-agent could be reached, and how many keys it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentStatus {
    /// `SSH_AUTH_SOCK` is unset.
    NotConfigured,
    /// The socket exists but did not answer.
    Unreachable,
    Ready {
        loaded: usize,
    },
}

impl AgentStatus {
    pub fn describe(self) -> String {
        match self {
            Self::NotConfigured => "no agent (SSH_AUTH_SOCK unset)".into(),
            Self::Unreachable => "agent unreachable".into(),
            Self::Ready { loaded } => format!("agent holds {loaded} key(s)"),
        }
    }
}

/// Format seconds-since-epoch as a local date and time for the detail pane.
pub fn format_timestamp(when: Option<Duration>) -> String {
    let Some(when) = when else {
        return "unknown".into();
    };
    if when.is_zero() {
        return "never".into();
    }
    let seconds = i64::try_from(when.as_secs()).unwrap_or(i64::MAX);
    match jiff::Timestamp::from_second(seconds) {
        Ok(ts) => ts
            .to_zoned_datetime(jiff::tz::TimeZone::system())
            .strftime("%Y-%m-%d %H:%M")
            .to_string(),
        Err(_) => "invalid".into(),
    }
}
