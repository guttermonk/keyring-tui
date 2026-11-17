// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

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
    /// The collection's D-Bus object path.
    ///
    /// Carried because `secret-tool store --collection` takes a full object
    /// path or the literal `default` alias and nothing else — a label will
    /// not do — and creating an item goes through that tool so the password
    /// is never typed into this process.
    pub path: String,
}

/// Parse a one-line `key=value key=value` attribute list.
///
/// Whitespace-separated pairs, split at the first `=` so a value may contain
/// one. This is the form `secret-tool` itself takes attributes in, and it
/// fits a single text field, which is what the UI has.
///
/// The limitation is real and worth knowing: a value cannot contain a space.
/// Attributes are an item's *identity* in the Secret Service — `service`,
/// `account`, `xdg:schema` — and are near-universally short tokens, so the
/// trade buys a one-field editor at a cost that rarely bites. There is no
/// quoting to learn and none to get wrong.
pub fn parse_attributes(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();

    for token in text.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            return Err(format!("{token:?} is not key=value"));
        };
        if key.is_empty() {
            return Err(format!("{token:?} has no attribute name"));
        }
        if out.iter().any(|(seen, _)| seen == key) {
            // Silently keeping one of them would make the stored item differ
            // from what the line says.
            return Err(format!("{key:?} is given twice"));
        }
        out.push((key.to_owned(), value.to_owned()));
    }

    if out.is_empty() {
        // Not a style rule: the Secret Service identifies an item by its
        // attributes, and `secret-tool store` refuses without at least one.
        return Err("at least one key=value attribute is needed".into());
    }
    Ok(out)
}

/// Render attributes back into the form [`parse_attributes`] accepts, so the
/// edit field starts from what the item actually has.
pub fn format_attributes<'a>(
    attributes: impl IntoIterator<Item = (&'a String, &'a String)>,
) -> String {
    attributes
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
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

/// The certifications on one key, loaded on demand.
///
/// Listing signatures needs `KeyListMode::SIGS`, which makes gpg read every
/// signature packet — affordable for one key, not for a whole keyring. So
/// this is fetched for the selected key when asked for, and is not part of
/// [`GpgKeyInfo`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpgSignatureSet {
    /// Which key these belong to, so a reply for a key the cursor has left
    /// can be discarded.
    pub fingerprint: String,
    pub uids: Vec<GpgUidSignatures>,
}

impl GpgSignatureSet {
    /// Certifications by anyone other than the key itself, which is the
    /// number that says anything about a web of trust.
    pub fn foreign_count(&self) -> usize {
        self.uids
            .iter()
            .flat_map(|uid| uid.signatures.iter())
            .filter(|signature| !signature.self_signature)
            .count()
    }
}

/// The certifications on one user ID.
///
/// Matched to its user ID by string rather than by position: the two come
/// from separate gpg listings, and a keyring that changed in between must not
/// silently attach one UID's signatures to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpgUidSignatures {
    pub uid: String,
    pub signatures: Vec<GpgSignature>,
}

/// One certification: somebody vouching that a user ID belongs to its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpgSignature {
    /// Long key ID of whoever made it.
    pub signer_key_id: String,
    /// The signer's own user ID. `None` when their key is not in this
    /// keyring, which gpg cannot look up — a key ID is all it has.
    pub signer_uid: Option<String>,
    pub created: Option<Duration>,
    pub expires: Option<Duration>,
    /// The key certifying its own user ID. Every UID carries at least one,
    /// and it is not a vote of confidence from anybody.
    pub self_signature: bool,
    /// A revocation of an earlier certification rather than a new one.
    pub revocation: bool,
    pub expired: bool,
    pub invalid: bool,
    /// gpg's certification level: `0x10` generic, `0x11` persona, `0x12`
    /// casual, `0x13` positive.
    pub cert_class: u64,
    /// Whether it travels with an export. A local signature (`lsign`) never
    /// leaves this keyring, so it means nothing to anyone else.
    pub exportable: bool,
}

impl GpgSignature {
    /// How carefully the signer checked, in gpg's own words. `None` for the
    /// classes that are not a certification level at all.
    pub fn level(&self) -> Option<&'static str> {
        match self.cert_class {
            0x10 => Some("generic"),
            0x11 => Some("persona"),
            0x12 => Some("casual"),
            0x13 => Some("positive"),
            _ => None,
        }
    }

    /// The markers for the list, in the order a reader cares about them:
    /// what invalidates it first, then what qualifies it.
    pub fn markers(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.revocation {
            out.push("revocation");
        }
        if self.invalid {
            out.push("invalid");
        }
        if self.expired {
            out.push("expired");
        }
        if !self.exportable {
            out.push("local");
        }
        if self.self_signature {
            out.push("self");
        }
        out
    }
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

#[cfg(test)]
mod attribute_tests {
    use super::*;

    #[test]
    fn parses_space_separated_pairs() {
        assert_eq!(
            parse_attributes("service=github account=greg").unwrap(),
            vec![
                ("service".to_string(), "github".to_string()),
                ("account".to_string(), "greg".to_string()),
            ]
        );
    }

    #[test]
    fn extra_whitespace_is_not_an_error() {
        assert_eq!(
            parse_attributes("  service=github   account=greg  ")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_value_may_contain_an_equals_sign() {
        // Split at the *first* `=`, so a base64 tail or a query string
        // survives rather than being rejected as malformed.
        assert_eq!(
            parse_attributes("token=abc=def==").unwrap(),
            vec![("token".to_string(), "abc=def==".to_string())]
        );
    }

    #[test]
    fn a_colon_in_a_key_is_fine() {
        // `xdg:schema` is the attribute the whole `kind()` column reads.
        assert_eq!(
            parse_attributes("xdg:schema=org.freedesktop.Secret.Generic").unwrap(),
            vec![(
                "xdg:schema".to_string(),
                "org.freedesktop.Secret.Generic".to_string()
            )]
        );
    }

    #[test]
    fn an_empty_value_is_allowed() {
        assert_eq!(
            parse_attributes("service=").unwrap(),
            vec![("service".to_string(), String::new())]
        );
    }

    #[test]
    fn a_token_with_no_equals_is_rejected() {
        let err = parse_attributes("service github").unwrap_err();
        assert!(err.contains("not key=value"), "{err}");
    }

    #[test]
    fn a_missing_key_is_rejected() {
        let err = parse_attributes("=github").unwrap_err();
        assert!(err.contains("no attribute name"), "{err}");
    }

    #[test]
    fn a_repeated_key_is_rejected_rather_than_silently_collapsed() {
        // Keeping one of them would store something other than what the
        // line says.
        let err = parse_attributes("service=a service=b").unwrap_err();
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn nothing_at_all_is_rejected() {
        // Not a style rule: the Secret Service identifies an item by its
        // attributes, and secret-tool store refuses without one.
        for empty in ["", "   "] {
            let err = parse_attributes(empty).unwrap_err();
            assert!(err.contains("at least one"), "{err}");
        }
    }

    #[test]
    fn formatting_round_trips_through_the_parser() {
        let attributes: BTreeMap<String, String> = [
            ("account".to_string(), "greg".to_string()),
            ("service".to_string(), "github".to_string()),
        ]
        .into_iter()
        .collect();

        let line = format_attributes(attributes.iter());
        assert_eq!(line, "account=greg service=github");
        assert_eq!(
            parse_attributes(&line).unwrap(),
            vec![
                ("account".to_string(), "greg".to_string()),
                ("service".to_string(), "github".to_string()),
            ],
            "what the edit field is pre-filled with must parse back"
        );
    }

    #[test]
    fn a_value_with_a_space_is_the_known_limitation() {
        // Documented, not supported: there is no quoting. It surfaces as a
        // parse error on the second word rather than as silent truncation.
        let err = parse_attributes("account=My Name").unwrap_err();
        assert!(err.contains("not key=value"), "{err}");
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;

    fn signature() -> GpgSignature {
        GpgSignature {
            signer_key_id: "ABCD0123".into(),
            signer_uid: Some("Them <them@example>".into()),
            created: None,
            expires: None,
            self_signature: false,
            revocation: false,
            expired: false,
            invalid: false,
            cert_class: 0x13,
            exportable: true,
        }
    }

    #[test]
    fn certification_levels_are_gpgs_four() {
        for (class, name) in [
            (0x10, "generic"),
            (0x11, "persona"),
            (0x12, "casual"),
            (0x13, "positive"),
        ] {
            let signature = GpgSignature {
                cert_class: class,
                ..signature()
            };
            assert_eq!(signature.level(), Some(name));
        }
    }

    #[test]
    fn a_class_that_is_not_a_level_has_no_name() {
        // 0x18 is a subkey binding and 0x30 a revocation: real classes, but
        // not statements about how carefully anyone checked.
        for class in [0x00, 0x18, 0x1f, 0x30] {
            let signature = GpgSignature {
                cert_class: class,
                ..signature()
            };
            assert_eq!(signature.level(), None, "class {class:#x}");
        }
    }

    #[test]
    fn markers_lead_with_what_invalidates_a_signature() {
        let signature = GpgSignature {
            revocation: true,
            expired: true,
            exportable: false,
            self_signature: true,
            ..signature()
        };
        assert_eq!(
            signature.markers(),
            vec!["revocation", "expired", "local", "self"],
            "the disqualifying markers come before the qualifying ones"
        );
    }

    #[test]
    fn an_ordinary_signature_has_no_markers() {
        assert!(signature().markers().is_empty());
    }

    #[test]
    fn the_count_that_matters_excludes_self_signatures() {
        // Every user ID carries a self-signature, so counting them would
        // make an uncertified key look endorsed.
        let set = GpgSignatureSet {
            fingerprint: "FPR".into(),
            uids: vec![
                GpgUidSignatures {
                    uid: "Me <me@example>".into(),
                    signatures: vec![
                        GpgSignature {
                            self_signature: true,
                            ..signature()
                        },
                        signature(),
                    ],
                },
                GpgUidSignatures {
                    uid: "Me <other@example>".into(),
                    signatures: vec![GpgSignature {
                        self_signature: true,
                        ..signature()
                    }],
                },
            ],
        };
        assert_eq!(set.foreign_count(), 1);
    }

    #[test]
    fn a_key_signed_by_nobody_counts_zero() {
        let set = GpgSignatureSet {
            fingerprint: "FPR".into(),
            uids: vec![GpgUidSignatures {
                uid: "Me <me@example>".into(),
                signatures: vec![GpgSignature {
                    self_signature: true,
                    ..signature()
                }],
            }],
        };
        assert_eq!(set.foreign_count(), 0);
    }
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
