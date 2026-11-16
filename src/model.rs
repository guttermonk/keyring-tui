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
