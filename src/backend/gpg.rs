// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! GPG backend — the `GPG Keys` section.
//!
//! Reading and writing are split deliberately.
//!
//! **Reading** goes through `gpgme` against the user's real `~/.gnupg`, so
//! keyring-tui never becomes a second source of truth and never parses
//! `--with-colons` output. That gives structured access to user IDs, subkeys,
//! capabilities, validity and expiry.
//!
//! **Writing** is delegated to the `gpg` CLI with the TUI suspended, for the
//! same reason `ssh-add` is: every interesting mutation needs a passphrase
//! through pinentry, a confirmation, or a network round trip, and gpg already
//! does all of that correctly. `gpg --edit-key` in particular covers trust,
//! expiry, user IDs, revocation and certifying other keys — the whole of
//! Seahorse's key-edit surface — with gpg's own prompts and safeguards. See
//! [`crate::app::GpgAction`].
//!
//! Listing is split in two for cost. The key list runs without
//! `KeyListMode::SIGS`, because that mode makes gpg read every signature
//! packet in the keyring; signatures are then fetched for one key at a time,
//! when asked for.
//!
//! Still missing, and worth adding next:
//!
//! - [ ] photo IDs
//! - [ ] S/MIME keys, which gpgme exposes through `Protocol::CMS`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpgme::{Context, Key, KeyListMode, Protocol, UserIdSignature, Validity};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::{GpgRequest, Replies, Reply};
use crate::model::{
    GpgFilter, GpgKeyInfo, GpgSignature, GpgSignatureSet, GpgSubkey, GpgUid, GpgUidSignatures,
};

/// Spawn the backend actor and return the handle the UI sends requests on.
pub fn spawn(replies: Replies) -> UnboundedSender<GpgRequest> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move { run(rx, replies).await });
    tx
}

async fn run(mut rx: UnboundedReceiver<GpgRequest>, replies: Replies) {
    while let Some(request) = rx.recv().await {
        let reply = match request {
            GpgRequest::ListKeys { filter } => {
                // gpgme is synchronous and talks to gpg over a pipe, so it
                // belongs on the blocking pool rather than the reactor.
                match tokio::task::spawn_blocking(move || list_keys(filter)).await {
                    Ok(Ok((keys, engine))) => Reply::GpgKeys {
                        keys,
                        filter,
                        engine,
                    },
                    Ok(Err(err)) => Reply::Error(err),
                    Err(err) => Reply::Error(format!("listing GPG keys panicked: {err}")),
                }
            }
            GpgRequest::ListSignatures { fingerprint } => {
                let wanted = fingerprint.clone();
                match tokio::task::spawn_blocking(move || list_signatures(&wanted)).await {
                    Ok(Ok(uids)) => Reply::GpgSignatures(GpgSignatureSet { fingerprint, uids }),
                    Ok(Err(err)) => Reply::Error(err),
                    Err(err) => Reply::Error(format!("listing signatures panicked: {err}")),
                }
            }
        };
        let _ = replies.send(reply);
    }
}

/// The certifications on one key, user ID by user ID.
///
/// `SIGS` is set only here. On the whole-keyring listing it would make gpg
/// parse every signature packet it owns, which on a keyring with a few
/// well-connected keys is the difference between instant and several seconds.
fn list_signatures(fingerprint: &str) -> Result<Vec<GpgUidSignatures>, String> {
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(|err| format!("cannot talk to gpg: {err}"))?;
    ctx.set_key_list_mode(KeyListMode::LOCAL | KeyListMode::SIGS)
        .map_err(|err| format!("cannot set the key list mode: {err}"))?;

    let key = ctx
        .get_key(fingerprint)
        .map_err(|err| format!("cannot read {fingerprint}: {err}"))?;

    // Every self-signature carries the primary key's ID, but gpg reports the
    // *signing* subkey, so match against all of them rather than just the
    // primary — a key that certifies with a subkey would otherwise look as
    // though a stranger had signed it.
    let own: Vec<String> = std::iter::once(key.id().unwrap_or_default().to_owned())
        .chain(
            key.subkeys()
                .filter_map(|subkey| subkey.id().ok().map(str::to_owned)),
        )
        .filter(|id| !id.is_empty())
        .collect();

    Ok(key
        .user_ids()
        .map(|uid| GpgUidSignatures {
            uid: uid.id().unwrap_or("<unreadable>").to_owned(),
            signatures: uid
                .signatures()
                .map(|signature| describe_signature(&signature, &own))
                .collect(),
        })
        .collect())
}

fn describe_signature(signature: &UserIdSignature<'_>, own: &[String]) -> GpgSignature {
    let signer_key_id = signature.signer_key_id().unwrap_or("?").to_owned();

    GpgSignature {
        self_signature: own.contains(&signer_key_id),
        // An empty user ID is gpg saying "I do not have that key", which is
        // the normal case for a signature from a stranger. `None` says that
        // better than a blank line would.
        signer_uid: signature
            .signer_user_id()
            .ok()
            .map(str::trim)
            .filter(|uid| !uid.is_empty())
            .map(str::to_owned),
        signer_key_id,
        created: epoch_seconds(signature.creation_time()),
        expires: epoch_seconds(signature.expiration_time()),
        revocation: signature.is_revocation(),
        expired: signature.is_expired(),
        // `is_bad` folds in the cases gpgme could not check at all, which for
        // a reader amounts to the same warning as an outright invalid one.
        invalid: signature.is_invalid() || signature.is_bad(),
        cert_class: signature.cert_class(),
        exportable: signature.is_exportable(),
    }
}

type Listing = (Vec<GpgKeyInfo>, String);

fn list_keys(filter: GpgFilter) -> Result<Listing, String> {
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(|err| format!("cannot talk to gpg: {err}"))?;

    // WITH_SECRET makes a public listing report whether we hold the private
    // half, which is the distinction the `f` filter and the `[sec]` marker
    // are built on.
    ctx.set_key_list_mode(KeyListMode::LOCAL | KeyListMode::WITH_SECRET)
        .map_err(|err| format!("cannot set the key list mode: {err}"))?;

    let engine = describe_engine(&ctx);

    let keys: Vec<Key> = match filter {
        GpgFilter::All => ctx
            .keys()
            .map_err(|err| format!("listing keys failed: {err}"))?
            .filter_map(Result::ok)
            .collect(),
        GpgFilter::Secret => ctx
            .secret_keys()
            .map_err(|err| format!("listing secret keys failed: {err}"))?
            .filter_map(Result::ok)
            .collect(),
    };

    let mut infos: Vec<GpgKeyInfo> = keys.iter().map(describe_key).collect();

    // Own keys first, then by primary user ID — the order Seahorse's two
    // panes imply, in one list.
    infos.sort_by(|a, b| {
        (!a.has_secret, a.primary_uid.to_lowercase())
            .cmp(&(!b.has_secret, b.primary_uid.to_lowercase()))
    });
    for (id, info) in infos.iter_mut().enumerate() {
        info.id = id;
    }

    Ok((infos, engine))
}

fn describe_engine(ctx: &Context) -> String {
    let info = ctx.engine_info();
    let version = info.version().unwrap_or("unknown version");
    match info.home_dir() {
        // The default home is uninteresting; a non-default one very much is.
        Ok(home) => format!("gpg {version} ({home})"),
        Err(_) => format!("gpg {version}"),
    }
}

fn describe_key(key: &Key) -> GpgKeyInfo {
    let primary = key.primary_key();

    let uids: Vec<GpgUid> = key
        .user_ids()
        .map(|uid| GpgUid {
            uid: uid.id().unwrap_or("<unreadable>").to_owned(),
            validity: validity_name(uid.validity()),
            revoked: uid.is_revoked(),
        })
        .collect();

    let subkeys: Vec<GpgSubkey> = key
        .subkeys()
        .map(|subkey| GpgSubkey {
            key_id: subkey.id().unwrap_or("?").to_owned(),
            algorithm: subkey
                .algorithm_name()
                .unwrap_or_else(|_| "unknown".to_owned()),
            created: epoch_seconds(subkey.creation_time()),
            expires: epoch_seconds(subkey.expiration_time()),
            capabilities: capabilities(
                subkey.can_sign(),
                subkey.can_certify(),
                subkey.can_encrypt(),
                subkey.can_authenticate(),
            ),
            revoked: subkey.is_revoked(),
            expired: subkey.is_expired(),
            has_secret: subkey.is_secret(),
            on_card: subkey.is_card_key(),
        })
        .collect();

    GpgKeyInfo {
        id: 0, // assigned after sorting
        key_id: key.id().unwrap_or("?").to_owned(),
        fingerprint: key.fingerprint().unwrap_or("?").to_owned(),
        primary_uid: uids
            .first()
            .map(|uid| uid.uid.clone())
            .unwrap_or_else(|| "<no user ID>".to_owned()),
        algorithm: primary
            .as_ref()
            .and_then(|subkey| subkey.algorithm_name().ok())
            .unwrap_or_else(|| "unknown".to_owned()),
        created: primary
            .as_ref()
            .and_then(|subkey| epoch_seconds(subkey.creation_time())),
        expires: primary
            .as_ref()
            .and_then(|subkey| epoch_seconds(subkey.expiration_time())),
        owner_trust: validity_name(key.owner_trust()),
        has_secret: key.has_secret(),
        revoked: key.is_revoked(),
        expired: key.is_expired(),
        disabled: key.is_disabled(),
        capabilities: capabilities(
            key.can_sign(),
            key.can_certify(),
            key.can_encrypt(),
            key.can_authenticate(),
        ),
        on_card: subkeys.iter().any(|subkey| subkey.on_card),
        uids,
        subkeys,
    }
}

/// gpg's capability letters, in gpg's own order.
fn capabilities(sign: bool, certify: bool, encrypt: bool, authenticate: bool) -> String {
    let mut out = String::new();
    for (enabled, letter) in [
        (sign, 's'),
        (certify, 'c'),
        (encrypt, 'e'),
        (authenticate, 'a'),
    ] {
        if enabled {
            out.push(letter);
        }
    }
    out
}

fn validity_name(validity: Validity) -> &'static str {
    match validity {
        Validity::Undefined => "undefined",
        Validity::Never => "never",
        Validity::Marginal => "marginal",
        Validity::Full => "full",
        Validity::Ultimate => "ultimate",
        // `Unknown` and anything gpgme adds later.
        _ => "unknown",
    }
}

/// gpgme reports times as `SystemTime`; the UI formats seconds since the
/// epoch, like the Secret Service timestamps.
fn epoch_seconds(time: Option<SystemTime>) -> Option<Duration> {
    time?.duration_since(UNIX_EPOCH).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_letters_follow_gpgs_order() {
        assert_eq!(capabilities(true, true, false, false), "sc");
        assert_eq!(capabilities(false, false, true, false), "e");
        assert_eq!(capabilities(true, true, true, true), "scea");
        assert_eq!(capabilities(false, false, false, false), "");
    }

    #[test]
    fn validity_covers_every_gpgme_level() {
        assert_eq!(validity_name(Validity::Ultimate), "ultimate");
        assert_eq!(validity_name(Validity::Full), "full");
        assert_eq!(validity_name(Validity::Marginal), "marginal");
        assert_eq!(validity_name(Validity::Never), "never");
        assert_eq!(validity_name(Validity::Undefined), "undefined");
        assert_eq!(validity_name(Validity::Unknown), "unknown");
    }

    #[test]
    fn an_absent_or_pre_epoch_time_is_none() {
        assert_eq!(epoch_seconds(None), None);
        assert_eq!(epoch_seconds(Some(UNIX_EPOCH)), Some(Duration::ZERO));
        assert_eq!(
            epoch_seconds(Some(UNIX_EPOCH - Duration::from_secs(1))),
            None,
            "a time before the epoch is not a usable timestamp"
        );
    }

    /// Build a throwaway keyring with two keys, one certifying the other, and
    /// check the signature listing against it.
    ///
    /// Ignored by default because it shells out to `gpg` and generates keys,
    /// which takes a second or two. Run with
    ///
    /// ```console
    /// cargo test gpg::tests::signatures_against -- --ignored --nocapture
    /// ```
    ///
    /// `set_engine_home_dir` points one gpgme context at the temporary home,
    /// so this never reads or writes the real `~/.gnupg` and does not touch
    /// `GNUPGHOME` — which, being process-wide, would not be safe to set
    /// while other tests run.
    #[test]
    #[ignore = "generates keys in a temporary GnuPG home"]
    fn signatures_against_a_generated_keyring() {
        use std::process::Command;

        let home = tempfile::tempdir().expect("tempdir");
        let home_path = home.path().to_str().expect("utf-8 tempdir");

        // 0700, or gpg refuses the home directory outright.
        std::fs::set_permissions(
            home.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("chmod");

        let gpg = |args: &[&str]| {
            let output = Command::new("gpg")
                .args(["--homedir", home_path, "--batch", "--yes"])
                .args(args)
                .output()
                .expect("run gpg");
            assert!(
                output.status.success(),
                "gpg {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        // Two keys with no passphrase, then one certifies the other.
        for address in ["signed@example.invalid", "signer@example.invalid"] {
            gpg(&[
                "--passphrase",
                "",
                "--quick-generate-key",
                address,
                "ed25519",
                "default",
                "never",
            ]);
        }
        // The fingerprint of the signed key, from gpg's own colon output.
        // `--quick-sign-key` insists on a fingerprint rather than an address,
        // so this has to come first.
        let listing = gpg(&["--with-colons", "--list-keys", "signed@example.invalid"]);
        let fingerprint = listing
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .and_then(|line| line.split(':').nth(9))
            .expect("a fingerprint")
            .to_owned();

        gpg(&[
            "--default-key",
            "signer@example.invalid",
            "--quick-sign-key",
            &fingerprint,
        ]);

        // The same work `list_signatures` does, against the temporary home.
        let mut ctx = Context::from_protocol(Protocol::OpenPgp).expect("context");
        ctx.set_engine_home_dir(home_path).expect("home dir");
        ctx.set_key_list_mode(KeyListMode::LOCAL | KeyListMode::SIGS)
            .expect("key list mode");
        let key = ctx.get_key(&fingerprint).expect("the signed key");
        let own: Vec<String> = std::iter::once(key.id().unwrap_or_default().to_owned())
            .chain(
                key.subkeys()
                    .filter_map(|subkey| subkey.id().ok().map(str::to_owned)),
            )
            .filter(|id| !id.is_empty())
            .collect();

        let uids: Vec<GpgUidSignatures> = key
            .user_ids()
            .map(|uid| GpgUidSignatures {
                uid: uid.id().unwrap_or("<unreadable>").to_owned(),
                signatures: uid
                    .signatures()
                    .map(|signature| describe_signature(&signature, &own))
                    .collect(),
            })
            .collect();

        assert_eq!(uids.len(), 1, "one user ID was generated");
        let signatures = &uids[0].signatures;
        for signature in signatures {
            println!(
                "{:<18} {:<30} self={:<5} {:<9} {}",
                signature.signer_key_id,
                signature.signer_uid.as_deref().unwrap_or("(key not held)"),
                signature.self_signature,
                signature.level().unwrap_or("—"),
                signature.markers().join(" "),
            );
        }

        let own_sigs: Vec<_> = signatures.iter().filter(|s| s.self_signature).collect();
        let foreign: Vec<_> = signatures.iter().filter(|s| !s.self_signature).collect();

        assert!(
            !own_sigs.is_empty(),
            "the key's own self-signature must be recognised as one"
        );
        assert_eq!(
            foreign.len(),
            1,
            "exactly one other key certified this user ID"
        );

        let certification = foreign[0];
        assert!(
            certification
                .signer_uid
                .as_deref()
                .is_some_and(|uid| uid.contains("signer@example.invalid")),
            "the signer is in this keyring, so gpg can name them: {:?}",
            certification.signer_uid
        );
        assert!(
            certification.level().is_some(),
            "a certification carries one of gpg's four levels, got class {:#x}",
            certification.cert_class
        );
        assert!(certification.exportable, "--quick-sign-key is not an lsign");
        assert!(!certification.revocation);
        assert!(!certification.expired);
        assert!(!certification.invalid);
    }

    /// Lists the certifications on every key in the developer's real
    /// keyring. Ignored by default; reads metadata only.
    #[tokio::test]
    #[ignore = "reads the developer's real ~/.gnupg"]
    async fn live_signature_listing() {
        let (keys, _) = list_keys(GpgFilter::All).expect("listing");
        if keys.is_empty() {
            println!("no keys in this keyring; nothing to list signatures for");
            return;
        }

        for key in &keys {
            let uids = list_signatures(&key.fingerprint).expect("signatures");
            assert_eq!(
                uids.len(),
                key.uids.len(),
                "the SIGS listing should report the same user IDs as the plain one"
            );

            println!("{}", key.primary_uid);
            for uid in &uids {
                println!("  {}  ({} signature(s))", uid.uid, uid.signatures.len());
                assert!(
                    uid.signatures.iter().any(|sig| sig.self_signature),
                    "every user ID carries a self-signature, so detecting \
                     none means the key-ID match is wrong"
                );
                for sig in &uid.signatures {
                    println!(
                        "    {:<18} {:<28} {:<9} {}",
                        sig.signer_key_id,
                        sig.signer_uid.as_deref().unwrap_or("(key not held)"),
                        sig.level().unwrap_or("—"),
                        sig.markers().join(" "),
                    );
                }
            }
        }
    }

    /// Smoke test against the developer's real `~/.gnupg`. Ignored by
    /// default; run with
    ///
    /// ```console
    /// cargo test gpg::tests::live -- --ignored --nocapture
    /// ```
    ///
    /// Reads metadata only: no key is exported, modified or decrypted.
    #[tokio::test]
    #[ignore = "reads the developer's real ~/.gnupg"]
    async fn live_listing_matches_the_real_keyring() {
        let (all, engine) = list_keys(GpgFilter::All).expect("listing all keys");
        let (secret, _) = list_keys(GpgFilter::Secret).expect("listing secret keys");

        println!("engine: {engine}");
        println!("{} key(s), {} with a private half", all.len(), secret.len());
        for key in &all {
            println!(
                "{:<40} {:<10} {:<6} trust={:<9} sec={:<5} {}",
                key.primary_uid.chars().take(40).collect::<String>(),
                key.algorithm,
                key.capabilities,
                key.owner_trust,
                key.has_secret,
                key.state().unwrap_or("ok"),
            );
            for subkey in &key.subkeys {
                println!(
                    "    {:<18} {:<10} {:<6} card={}",
                    subkey.key_id, subkey.algorithm, subkey.capabilities, subkey.on_card
                );
            }
        }

        assert!(
            all.len() >= secret.len(),
            "every secret key should also appear in the full listing"
        );
        for key in &secret {
            assert!(key.has_secret, "secret listing returned a public-only key");
        }
    }
}
