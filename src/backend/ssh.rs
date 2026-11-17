// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! SSH backend — the `SSH Keys` section.
//!
//! Three sources of truth, merged into one list:
//!
//! * `~/.ssh`, scanned for public keys and their private counterparts and
//!   parsed with `ssh-key`. Private keys are only parsed far enough to learn
//!   their algorithm, comment and whether they are encrypted — never
//!   decrypted. OpenSSH stores the public half of an encrypted private key in
//!   the clear, which is all the list needs.
//! * The running agent on `$SSH_AUTH_SOCK`, queried over the ssh-agent
//!   protocol. Identities the agent holds but we cannot find on disk are
//!   listed too, since they are often forwarded from elsewhere.
//! * Nothing else. Adding a key to the agent needs a passphrase or a touch on
//!   a security key, so it runs as an external `ssh-add` with the TUI
//!   suspended rather than through this module.
//!
//! Deleting a key is the one write this module does: it unlinks the files,
//! having first asked the agent to forget the key. Everything else that
//! changes a key — generating one, changing a passphrase, deploying a public
//! half to a host — is an external command run with the TUI suspended.
//!
//! Hardware-backed keys (`*-sk`) need no special casing for passphrases, as
//! was once assumed here: the file holds a credential handle rather than a
//! secret scalar, and `ssh-keygen -p` re-encrypts it like any other key file,
//! with no token present and no touch.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, PublicKey};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::{Refresh, Replies, Reply, SshRequest};
use crate::model::{AgentStatus, SshKeyInfo};

/// Spawn the backend actor and return the handle the UI sends requests on.
pub fn spawn(replies: Replies) -> UnboundedSender<SshRequest> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move { run(rx, replies).await });
    tx
}

async fn run(mut rx: UnboundedReceiver<SshRequest>, replies: Replies) {
    // Blobs for the keys we last reported, parallel to the `SshKeyInfo` list
    // the UI is showing. Removing from the agent needs the wire blob, not the
    // file, so that forwarded keys with no file on disk can be removed too.
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    // The same listing, kept because deleting needs the paths and deleting
    // has to agree with what the user was looking at when they confirmed.
    let mut listed: Vec<SshKeyInfo> = Vec::new();

    while let Some(request) = rx.recv().await {
        let reply = match request {
            SshRequest::ListKeys => match list_keys().await {
                Ok((keys, agent, new_blobs)) => {
                    blobs = new_blobs;
                    listed = keys.clone();
                    Reply::SshKeys { keys, agent }
                }
                Err(err) => Reply::Error(err),
            },
            SshRequest::RemoveFromAgent { key } => match blobs.get(key) {
                Some(blob) => match agent::remove(blob).await {
                    Ok(()) => Reply::Status {
                        message: "removed from the agent".into(),
                        refresh: Refresh::SshKeys,
                    },
                    Err(err) => Reply::Error(format!("agent refused the removal: {err}")),
                },
                None => Reply::Error("key is no longer loaded; press r to refresh".into()),
            },
            SshRequest::DeleteKey { key } => {
                match (listed.get(key), blobs.get(key)) {
                    (Some(info), Some(blob)) => delete_key(info, blob).await,
                    // The two vectors are filled together, so this is a stale
                    // index rather than a mismatch.
                    _ => Reply::Error(stale()),
                }
            }
        };
        let _ = replies.send(reply);
    }
}

fn stale() -> String {
    "key is no longer in the list; press r to refresh".into()
}

/// Unlink a key's files, having first asked the agent to forget it.
///
/// The agent step is best-effort: it may legitimately not hold the key, and a
/// refusal there must not stop the files going. The order matters the other
/// way round, though — once the `.pub` is gone the user has no easy way to
/// name the key to `ssh-add -d`.
async fn delete_key(info: &SshKeyInfo, blob: &[u8]) -> Reply {
    let mut notes: Vec<String> = Vec::new();

    if info.in_agent {
        match agent::remove(blob).await {
            Ok(()) => notes.push("dropped from the agent".into()),
            Err(err) => notes.push(format!("agent kept it ({err})")),
        }
    }

    let paths: Vec<PathBuf> = [info.private_path.clone(), info.public_path.clone()]
        .into_iter()
        .flatten()
        .collect();
    if paths.is_empty() {
        return Reply::Error(format!("{} has no files to delete", info.name));
    }

    let dir = match ssh_dir() {
        Ok(dir) => dir,
        Err(err) => return Reply::Error(err),
    };

    let name = info.name.clone();
    let removed = match tokio::task::spawn_blocking(move || unlink_all(&dir, &paths)).await {
        Ok(Ok(removed)) => removed,
        Ok(Err(err)) => return Reply::Error(err),
        Err(err) => return Reply::Error(format!("deleting {name} panicked: {err}")),
    };

    notes.insert(0, format!("deleted {removed} file(s)"));
    Reply::Status {
        message: format!("{}: {}", info.name, notes.join(", ")),
        refresh: Refresh::SshKeys,
    }
}

/// Remove each path, refusing anything that is not a plain file directly
/// inside `dir`.
///
/// The paths come from our own scan of that directory, so the check should
/// never fire — which is exactly why it is cheap to keep. It is the last gate
/// before an unlink, and a stale index or a path that grew a `..` is not
/// something to discover afterwards.
pub(crate) fn unlink_all(dir: &Path, paths: &[PathBuf]) -> Result<usize, String> {
    let mut removed = 0;

    for path in paths {
        if path.parent() != Some(dir) {
            return Err(format!("{} is not in {}", path.display(), dir.display()));
        }
        // `symlink_metadata`, not `metadata`: a symlink is removed as the
        // link it is, and must not be judged by what it points at.
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => {
                return Err(format!("{} is a directory", path.display()));
            }
            // Already gone: someone else deleted it, which is the outcome we
            // wanted anyway.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("{}: {err}", path.display())),
            Ok(_) => {}
        }
        std::fs::remove_file(path).map_err(|err| format!("{}: {err}", path.display()))?;
        removed += 1;
    }

    Ok(removed)
}

type Listing = (Vec<SshKeyInfo>, AgentStatus, Vec<Vec<u8>>);

async fn list_keys() -> Result<Listing, String> {
    let dir = ssh_dir()?;

    // Reading a handful of small files is quick, but it is still blocking
    // syscalls on the runtime, so it goes to the blocking pool.
    let found = tokio::task::spawn_blocking(move || scan_dir(&dir))
        .await
        .map_err(|err| format!("scanning ~/.ssh panicked: {err}"))?;

    let (identities, agent) = match agent::identities().await {
        Ok(identities) => {
            let status = AgentStatus::Ready {
                loaded: identities.len(),
            };
            (identities, status)
        }
        Err(agent::Error::NotConfigured) => (Vec::new(), AgentStatus::NotConfigured),
        // A broken agent must not hide the keys on disk, so this is reported
        // in the status line rather than as a hard error.
        Err(_) => (Vec::new(), AgentStatus::Unreachable),
    };

    let merged = merge(found, identities);
    let keys = merged.iter().map(|(info, _)| info.clone()).collect();
    let blobs = merged.into_iter().map(|(_, blob)| blob).collect();
    Ok((keys, agent, blobs))
}

fn ssh_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".ssh"))
}

/// A key as found on disk, before the agent is consulted.
#[derive(Debug)]
pub(crate) struct Discovered {
    name: String,
    private_path: Option<PathBuf>,
    public_path: Option<PathBuf>,
    key: PublicKey,
    encrypted: bool,
}

/// Scan one directory for key pairs.
///
/// Unparseable files are skipped silently: `~/.ssh` legitimately holds config,
/// `known_hosts`, sockets and editor leftovers, and none of that is an error.
pub(crate) fn scan_dir(dir: &Path) -> Vec<Discovered> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    // Group by the private-key path, so `id_ed25519` and `id_ed25519.pub`
    // become one entry whichever order the directory lists them in.
    let mut pairs: BTreeMap<PathBuf, (Option<PathBuf>, Option<PathBuf>)> = BTreeMap::new();
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let path = entry.path();
        // Owned, so the path can be moved into the map below.
        let Some(name) = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        if is_not_a_key(&name) {
            continue;
        }

        match name.strip_suffix(".pub") {
            Some(stem) => {
                let base = path.with_file_name(stem);
                pairs.entry(base).or_default().1 = Some(path);
            }
            None => {
                let entry = pairs.entry(path.clone()).or_default();
                entry.0 = Some(path);
            }
        }
    }

    let mut found = Vec::new();
    for (base, (private_path, public_path)) in pairs {
        let private = private_path.as_deref().and_then(read_private);
        let public = public_path
            .as_deref()
            .and_then(|path| PublicKey::read_openssh_file(path).ok());

        // Prefer the `.pub` file: it is where the human-set comment lives.
        // Otherwise fall back to the public half of the private key, which is
        // readable even when the key is encrypted.
        let key = match (public, &private) {
            (Some(key), _) => key,
            (None, Some(private)) => private.public_key().clone(),
            (None, None) => continue,
        };

        let encrypted = match &private {
            Some(private) => private.is_encrypted(),
            // A private key we could not parse (a legacy PEM key, say) still
            // advertises its encryption in the clear.
            None => private_path.as_deref().is_some_and(looks_encrypted_pem),
        };

        found.push(Discovered {
            name: base
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("?")
                .to_owned(),
            private_path,
            public_path,
            key,
            encrypted,
        });
    }
    found
}

/// Names in `~/.ssh` that are never keys. Anything else is attempted and
/// skipped if it does not parse.
fn is_not_a_key(name: &str) -> bool {
    const NEVER: &[&str] = &["config", "environment", "rc", "authorized_keys2"];

    NEVER.contains(&name)
        || name.starts_with("known_hosts")
        || name.starts_with("authorized_keys")
        || name.starts_with('.')
        || name.ends_with(".old")
        || name.ends_with(".bak")
        || name.ends_with(".lock")
        || name.ends_with('~')
}

fn read_private(path: &Path) -> Option<PrivateKey> {
    // `from_openssh` on a public key file or on `known_hosts` would fail
    // anyway, but checking the armour first keeps the common case cheap.
    let contents = std::fs::read_to_string(path).ok()?;
    if !contents.contains("PRIVATE KEY-----") {
        return None;
    }
    PrivateKey::from_openssh(&contents).ok()
}

/// Legacy PEM keys (`-----BEGIN RSA PRIVATE KEY-----`) are not OpenSSH format
/// and `ssh-key` will not parse them, but their header still says whether they
/// are encrypted.
fn looks_encrypted_pem(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|contents| contents.contains("ENCRYPTED") || contents.contains("DEK-Info"))
        .unwrap_or(false)
}

/// Combine what is on disk with what the agent holds.
///
/// Keys are returned files-first in name order, then any agent-only
/// identities, with `id` assigned to match the returned order.
pub(crate) fn merge(
    found: Vec<Discovered>,
    identities: Vec<agent::Identity>,
) -> Vec<(SshKeyInfo, Vec<u8>)> {
    let loaded: HashSet<String> = identities
        .iter()
        .map(|identity| identity.fingerprint.clone())
        .collect();

    let mut out: Vec<(SshKeyInfo, Vec<u8>)> = Vec::new();
    let mut on_disk: HashSet<String> = HashSet::new();

    let mut found = found;
    found.sort_by_key(|key| key.name.to_lowercase());

    for key in found {
        let fingerprint = key.key.fingerprint(HashAlg::Sha256).to_string();
        on_disk.insert(fingerprint.clone());

        let algorithm = key.key.algorithm().as_str().to_owned();
        let blob = key.key.to_bytes().unwrap_or_default();
        out.push((
            SshKeyInfo {
                id: 0, // assigned below
                name: key.name,
                private_path: key.private_path,
                public_path: key.public_path,
                bits: bit_len(key.key.key_data()),
                comment: key.key.comment().to_owned(),
                public_line: key.key.to_openssh().unwrap_or_default(),
                hardware_backed: algorithm.starts_with("sk-"),
                algorithm,
                fingerprint: fingerprint.clone(),
                encrypted: key.encrypted,
                in_agent: loaded.contains(&fingerprint),
            },
            blob,
        ));
    }

    // Identities with no file: forwarded agents, keys added from a path we do
    // not scan, or keys whose files have been deleted since.
    for identity in identities {
        if on_disk.contains(&identity.fingerprint) {
            continue;
        }
        let Ok(mut key) = PublicKey::from_bytes(&identity.blob) else {
            continue;
        };
        key.set_comment(&identity.comment);

        let algorithm = key.algorithm().as_str().to_owned();
        let name = if identity.comment.is_empty() {
            format!("(agent) {}", identity.fingerprint)
        } else {
            format!("(agent) {}", identity.comment)
        };
        out.push((
            SshKeyInfo {
                id: 0,
                name,
                private_path: None,
                public_path: None,
                bits: bit_len(key.key_data()),
                comment: identity.comment,
                public_line: key.to_openssh().unwrap_or_default(),
                hardware_backed: algorithm.starts_with("sk-"),
                algorithm,
                fingerprint: identity.fingerprint,
                encrypted: false,
                in_agent: true,
            },
            identity.blob,
        ));
    }

    for (id, (info, _)) in out.iter_mut().enumerate() {
        info.id = id;
    }
    out
}

/// Key size in bits, for the list column. `None` for algorithms we do not
/// recognise, which is better than printing a wrong number.
fn bit_len(key: &KeyData) -> Option<u32> {
    match key {
        KeyData::Ed25519(_) | KeyData::SkEd25519(_) => Some(256),
        KeyData::Ecdsa(key) => Some(match key.curve() {
            ssh_key::EcdsaCurve::NistP256 => 256,
            ssh_key::EcdsaCurve::NistP384 => 384,
            ssh_key::EcdsaCurve::NistP521 => 521,
        }),
        KeyData::SkEcdsaSha2NistP256(_) => Some(256),
        KeyData::Rsa(key) => mpint_bits(key.n.as_positive_bytes()?),
        _ => None,
    }
}

/// Bit length of a big-endian unsigned integer with no leading zero bytes.
fn mpint_bits(bytes: &[u8]) -> Option<u32> {
    let first = *bytes.first()?;
    let whole_bytes = u32::try_from(bytes.len() - 1).ok()? * 8;
    Some(whole_bytes + (8 - first.leading_zeros()))
}

/// A minimal ssh-agent protocol client: list and remove, nothing else.
///
/// Adding a key is deliberately not implemented. It would mean decrypting the
/// private key inside this process; `ssh-add` already does it correctly, with
/// the user's askpass and with support for security keys.
pub(crate) mod agent {
    use std::time::Duration;

    use ssh_key::{HashAlg, PublicKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// <https://www.rfc-editor.org/rfc/rfc4253> framing, message numbers from
    /// OpenSSH's `PROTOCOL.agent`.
    const REQUEST_IDENTITIES: u8 = 11;
    const IDENTITIES_ANSWER: u8 = 12;
    const REMOVE_IDENTITY: u8 = 18;
    const SUCCESS: u8 = 6;
    const FAILURE: u8 = 5;

    /// Generous for any plausible agent (a key blob is well under a kilobyte),
    /// but bounded so a hostile socket cannot make us allocate freely.
    const MAX_FRAME: usize = 1 << 20;
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Debug)]
    pub enum Error {
        /// `SSH_AUTH_SOCK` is unset — no agent is expected to exist.
        NotConfigured,
        Io(String),
        Protocol(String),
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotConfigured => write!(f, "SSH_AUTH_SOCK is not set"),
                Self::Io(message) | Self::Protocol(message) => write!(f, "{message}"),
            }
        }
    }

    /// One identity the agent is holding.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Identity {
        pub blob: Vec<u8>,
        pub comment: String,
        /// `SHA256:…`, derived from the blob so it can be matched against keys
        /// found on disk.
        pub fingerprint: String,
    }

    pub async fn identities() -> Result<Vec<Identity>, Error> {
        let body = request(&[REQUEST_IDENTITIES]).await?;
        let mut reader = Reader::new(&body);

        if reader.u8()? != IDENTITIES_ANSWER {
            return Err(Error::Protocol("unexpected answer to a list".into()));
        }
        let count = reader.u32()?;

        let mut identities = Vec::new();
        for _ in 0..count {
            let blob = reader.string()?.to_vec();
            let comment = String::from_utf8_lossy(reader.string()?).into_owned();
            // An identity whose blob we cannot parse is skipped rather than
            // failing the whole listing.
            let Ok(key) = PublicKey::from_bytes(&blob) else {
                continue;
            };
            identities.push(Identity {
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                blob,
                comment,
            });
        }
        Ok(identities)
    }

    pub async fn remove(blob: &[u8]) -> Result<(), Error> {
        let mut body = vec![REMOVE_IDENTITY];
        let len = u32::try_from(blob.len())
            .map_err(|_| Error::Protocol("key blob is implausibly large".into()))?;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(blob);

        let response = request(&body).await?;
        match response.first() {
            Some(&SUCCESS) => Ok(()),
            Some(&FAILURE) => Err(Error::Protocol("the agent does not hold that key".into())),
            _ => Err(Error::Protocol("unexpected answer to a removal".into())),
        }
    }

    /// One request, one response. The agent protocol is strictly alternating,
    /// so a fresh connection per request keeps this honest and avoids holding
    /// a socket open for the life of the process.
    async fn request(body: &[u8]) -> Result<Vec<u8>, Error> {
        let path = std::env::var_os("SSH_AUTH_SOCK").ok_or(Error::NotConfigured)?;

        tokio::time::timeout(TIMEOUT, async {
            let mut stream = UnixStream::connect(&path)
                .await
                .map_err(|err| Error::Io(format!("cannot reach the agent: {err}")))?;

            let len = u32::try_from(body.len())
                .map_err(|_| Error::Protocol("request too large".into()))?;
            stream
                .write_all(&len.to_be_bytes())
                .await
                .map_err(|err| Error::Io(err.to_string()))?;
            stream
                .write_all(body)
                .await
                .map_err(|err| Error::Io(err.to_string()))?;

            let mut header = [0u8; 4];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|err| Error::Io(err.to_string()))?;
            let len = u32::from_be_bytes(header) as usize;
            if len == 0 || len > MAX_FRAME {
                return Err(Error::Protocol(format!("agent announced {len} bytes")));
            }

            let mut response = vec![0u8; len];
            stream
                .read_exact(&mut response)
                .await
                .map_err(|err| Error::Io(err.to_string()))?;
            Ok(response)
        })
        .await
        .map_err(|_| Error::Io("the agent did not answer in time".into()))?
    }

    /// Cursor over the SSH wire format: big-endian lengths, no alignment.
    struct Reader<'a> {
        bytes: &'a [u8],
    }

    impl<'a> Reader<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self { bytes }
        }

        fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
            if self.bytes.len() < count {
                return Err(Error::Protocol("truncated answer".into()));
            }
            let (head, tail) = self.bytes.split_at(count);
            self.bytes = tail;
            Ok(head)
        }

        fn u8(&mut self) -> Result<u8, Error> {
            Ok(self.take(1)?[0])
        }

        fn u32(&mut self) -> Result<u32, Error> {
            let bytes = self.take(4)?;
            Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }

        fn string(&mut self) -> Result<&'a [u8], Error> {
            let len = self.u32()? as usize;
            if len > MAX_FRAME {
                return Err(Error::Protocol("string too long".into()));
            }
            self.take(len)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn reader_rejects_a_truncated_string() {
            let mut reader = Reader::new(&[0, 0, 0, 8, 1, 2, 3]);
            assert!(reader.string().is_err());
        }

        #[test]
        fn reader_walks_a_well_formed_answer() {
            // type=12, count=1, blob="ab", comment="c"
            let bytes = [12, 0, 0, 0, 1, 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 1, b'c'];
            let mut reader = Reader::new(&bytes);
            assert_eq!(reader.u8().unwrap(), IDENTITIES_ANSWER);
            assert_eq!(reader.u32().unwrap(), 1);
            assert_eq!(reader.string().unwrap(), b"ab");
            assert_eq!(reader.string().unwrap(), b"c");
            assert!(reader.u8().is_err(), "should be exhausted");
        }

        #[tokio::test]
        async fn an_unset_auth_sock_is_not_an_error() {
            // Relies on the test binary's own environment, so it only asserts
            // the mapping when the variable really is absent.
            if std::env::var_os("SSH_AUTH_SOCK").is_none() {
                assert!(matches!(identities().await, Err(Error::NotConfigured)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const ED25519_PRIVATE: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAUHMW97O99RatHnTTNN6XfpqsJEE0nEqf0/rqljv1zCAAAAJji7YM64u2D
OgAAAAtzc2gtZWQyNTUxOQAAACAUHMW97O99RatHnTTNN6XfpqsJEE0nEqf0/rqljv1zCA
AAAEAWmSb8C8lxWrghm70j0FzaAbU4FgZN0vFLBCzeq+k1HxQcxb3s731Fq0edNM03pd+m
qwkQTScSp/T+uqWO/XMIAAAAD2ZpeHR1cmVAZXhhbXBsZQECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
";

    const ED25519_PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBQcxb3s731Fq0edNM03pd+mqwkQTScSp/T+uqWO/XMI fixture@example\n";

    const ECDSA_PUBLIC: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCoh/CJXHXbVFquxKOiXPLnVdAGaRwmpOicKtvC8Y2zZDGE0QXrcIja3ym7h2omYBFKdU3uwTMXHee5pvmjx51Q= enc@example\n";

    /// Encrypted with the passphrase `hunter2`; never decrypted by these tests.
    const ECDSA_PRIVATE_ENCRYPTED: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDIIFL+6P
YLJd0kGPf2AuCJAAAAIAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBCoh/CJXHXbVFquxKOiXPLnVdAGaRwmpOicKtvC8Y2zZDGE0QXrcIja3ym
7h2omYBFKdU3uwTMXHee5pvmjx51QAAACw5EPw/ejM+fygoegAUlj3RulAax+NaFOBLpXV
FFMOeMhDGhtXf82JVaVIzWMIAUBUEJQ/UzLFTrq/HfW+G6vGCHsaenvRWJ8yYW5iJeQol/
kknNDMPAOqFxw7nXHtDDXuDFEYd2EYoOr3b+xQ/JspuWuZbVtrkQLCzr2z95+UJ/o8UP1X
uWwKduVS0HyAGTXOaRlSJ2/86cXDuYr5Dhm0BeWZr8gnjedjHowJsabeoGs=
-----END OPENSSH PRIVATE KEY-----
";

    fn fixture_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path();

        fs::write(path.join("id_ed25519"), ED25519_PRIVATE).unwrap();
        fs::write(path.join("id_ed25519.pub"), ED25519_PUBLIC).unwrap();
        fs::write(path.join("id_ecdsa"), ECDSA_PRIVATE_ENCRYPTED).unwrap();
        fs::write(path.join("id_ecdsa.pub"), ECDSA_PUBLIC).unwrap();

        // Noise that must be ignored.
        fs::write(path.join("config"), "Host *\n  User greg\n").unwrap();
        fs::write(path.join("known_hosts"), "github.com ssh-ed25519 AAAA\n").unwrap();
        fs::write(path.join("authorized_keys"), ED25519_PUBLIC).unwrap();
        fs::write(path.join("id_ed25519.pub.old"), ED25519_PUBLIC).unwrap();
        fs::write(path.join("agent.1234"), "").unwrap();

        dir
    }

    #[test]
    fn finds_both_pairs_and_ignores_the_noise() {
        let dir = fixture_dir();
        let found = scan_dir(dir.path());

        let names: Vec<&str> = found.iter().map(|key| key.name.as_str()).collect();
        assert_eq!(names, vec!["id_ecdsa", "id_ed25519"]);
    }

    #[test]
    fn reports_algorithm_comment_and_encryption() {
        let dir = fixture_dir();
        let keys: Vec<SshKeyInfo> = merge(scan_dir(dir.path()), Vec::new())
            .into_iter()
            .map(|(info, _)| info)
            .collect();

        let ed = keys.iter().find(|key| key.name == "id_ed25519").unwrap();
        assert_eq!(ed.algorithm, "ssh-ed25519");
        assert_eq!(ed.bits, Some(256));
        assert_eq!(ed.comment, "fixture@example");
        assert!(ed.fingerprint.starts_with("SHA256:"));
        assert!(!ed.encrypted, "fixture has an empty passphrase");
        assert!(!ed.hardware_backed);
        assert!(ed.is_addable());
        assert_eq!(ed.kind(), "ed25519 256");

        let ecdsa = keys.iter().find(|key| key.name == "id_ecdsa").unwrap();
        assert_eq!(ecdsa.algorithm, "ecdsa-sha2-nistp256");
        assert_eq!(ecdsa.bits, Some(256));
        assert!(ecdsa.encrypted, "fixture is passphrase-protected");
    }

    #[test]
    fn a_public_key_with_no_private_half_is_not_addable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("id_ed25519.pub"), ED25519_PUBLIC).unwrap();

        let keys = merge(scan_dir(dir.path()), Vec::new());
        assert_eq!(keys.len(), 1);
        let (info, _) = &keys[0];
        assert!(info.private_path.is_none());
        assert!(!info.is_addable());
        assert!(info.public_path.is_some());
    }

    #[test]
    fn a_private_key_with_no_pub_file_is_still_listed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE).unwrap();

        let keys = merge(scan_dir(dir.path()), Vec::new());
        assert_eq!(keys.len(), 1);
        let (info, _) = &keys[0];
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert_eq!(info.comment, "fixture@example");
        assert!(info.is_addable());
    }

    #[test]
    fn a_missing_directory_is_empty_not_an_error() {
        assert!(scan_dir(Path::new("/nonexistent/.ssh")).is_empty());
    }

    fn identity_for(public: &str, comment: &str) -> agent::Identity {
        let key = PublicKey::from_openssh(public).unwrap();
        agent::Identity {
            blob: key.to_bytes().unwrap(),
            comment: comment.to_owned(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        }
    }

    #[test]
    fn marks_the_keys_the_agent_holds() {
        let dir = fixture_dir();
        let keys = merge(
            scan_dir(dir.path()),
            vec![identity_for(ED25519_PUBLIC, "fixture@example")],
        );

        let loaded: Vec<(&str, bool)> = keys
            .iter()
            .map(|(info, _)| (info.name.as_str(), info.in_agent))
            .collect();
        assert_eq!(loaded, vec![("id_ecdsa", false), ("id_ed25519", true)]);
    }

    #[test]
    fn agent_only_identities_are_listed_after_the_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("id_ecdsa.pub"), ECDSA_PUBLIC).unwrap();

        let identity = identity_for(ED25519_PUBLIC, "forwarded@elsewhere");
        let keys = merge(scan_dir(dir.path()), vec![identity.clone()]);

        assert_eq!(keys.len(), 2);
        let (info, blob) = &keys[1];
        assert_eq!(info.name, "(agent) forwarded@elsewhere");
        assert!(info.in_agent);
        assert!(!info.is_addable(), "there is no file to hand to ssh-add");
        assert_eq!(
            blob, &identity.blob,
            "removal needs the blob the agent gave us"
        );
    }

    #[test]
    fn ids_index_the_returned_order() {
        let dir = fixture_dir();
        let keys = merge(
            scan_dir(dir.path()),
            vec![identity_for(ED25519_PUBLIC, "x@y")],
        );
        for (index, (info, _)) in keys.iter().enumerate() {
            assert_eq!(info.id, index);
        }
    }

    /// Smoke test against the developer's real `~/.ssh` and agent. Ignored by
    /// default; run with
    ///
    /// ```console
    /// cargo test ssh::tests::live -- --ignored --nocapture
    /// ```
    ///
    /// Reads metadata only: no private key is decrypted, and the agent is
    /// only asked what it holds.
    #[tokio::test]
    #[ignore = "reads the developer's real ~/.ssh and ssh-agent"]
    async fn live_listing_matches_the_real_environment() {
        let (keys, agent, blobs) = list_keys().await.expect("listing");
        assert_eq!(blobs.len(), keys.len(), "every key needs its blob");

        println!("agent: {}", agent.describe());
        for key in &keys {
            println!(
                "{:<28} {:<12} {:<8} agent={:<5} enc={:<5} {}",
                key.name,
                key.kind(),
                if key.hardware_backed { "sk" } else { "-" },
                key.in_agent,
                key.encrypted,
                key.fingerprint
            );
        }
    }

    /// Exercises the removal request against the real agent using a key it
    /// cannot be holding, so nothing is actually removed. Ignored by default.
    #[tokio::test]
    #[ignore = "talks to the developer's real ssh-agent"]
    async fn live_removal_of_an_unheld_key_is_refused_cleanly() {
        if std::env::var_os("SSH_AUTH_SOCK").is_none() {
            println!("no agent configured; nothing to test");
            return;
        }
        let blob = PublicKey::from_openssh(ED25519_PUBLIC)
            .unwrap()
            .to_bytes()
            .unwrap();

        match agent::remove(&blob).await {
            Err(agent::Error::Protocol(message)) => println!("refused as expected: {message}"),
            Ok(()) => panic!("the agent claimed to hold the test fixture key"),
            Err(other) => panic!("unexpected failure: {other}"),
        }
    }

    #[test]
    fn unlink_removes_the_pair_and_leaves_the_rest_alone() {
        let dir = fixture_dir();
        let path = dir.path();

        let removed = unlink_all(
            path,
            &[path.join("id_ed25519"), path.join("id_ed25519.pub")],
        )
        .unwrap();

        assert_eq!(removed, 2);
        assert!(!path.join("id_ed25519").exists());
        assert!(!path.join("id_ed25519.pub").exists());
        assert!(path.join("id_ecdsa").exists(), "the other pair stays");
        assert!(path.join("config").exists());
        assert!(path.join("known_hosts").exists());
    }

    #[test]
    fn unlink_refuses_a_path_outside_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let victim = elsewhere.path().join("precious");
        fs::write(&victim, "do not touch").unwrap();

        let err = unlink_all(dir.path(), std::slice::from_ref(&victim)).unwrap_err();
        assert!(err.contains("is not in"), "{err}");
        assert!(victim.exists(), "the file must survive the refusal");
    }

    #[test]
    fn unlink_refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();

        let err = unlink_all(dir.path(), std::slice::from_ref(&nested)).unwrap_err();
        assert!(err.contains("is a directory"), "{err}");
        assert!(nested.exists());
    }

    #[test]
    fn unlink_treats_an_already_missing_file_as_done() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE).unwrap();

        // The `.pub` was never there, which is the state after a half-finished
        // delete or a private-key-only setup.
        let removed = unlink_all(
            dir.path(),
            &[
                dir.path().join("id_ed25519"),
                dir.path().join("id_ed25519.pub"),
            ],
        )
        .unwrap();
        assert_eq!(removed, 1, "only the file that existed is counted");
    }

    #[test]
    fn unlink_removes_a_symlink_rather_than_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = elsewhere.path().join("real_key");
        fs::write(&target, ED25519_PRIVATE).unwrap();

        let link = dir.path().join("id_ed25519");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let removed = unlink_all(dir.path(), std::slice::from_ref(&link)).unwrap();
        assert_eq!(removed, 1);
        assert!(!link.exists(), "the link is gone");
        assert!(target.exists(), "what it pointed at is not ours to delete");
    }

    #[test]
    fn rsa_bit_length_is_computed_from_the_modulus() {
        // 0x80 as the leading byte means the top bit is set: 8 bits per byte.
        assert_eq!(mpint_bits(&[0x80]), Some(8));
        assert_eq!(mpint_bits(&[0x01]), Some(1));
        assert_eq!(mpint_bits(&[0xff, 0x00]), Some(16));
        assert_eq!(mpint_bits(&[0x01, 0x00, 0x00]), Some(17));
        assert_eq!(mpint_bits(&[]), None);
    }
}
