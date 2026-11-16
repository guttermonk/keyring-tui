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
//! Still missing, and worth adding next:
//!
//! - [ ] import from a file, and keyserver search (`gpgme` can do the latter
//!   with `KeyListMode::EXTERN`; both need a text input widget first)
//! - [ ] photo IDs
//! - [ ] signature listing per user ID (`KeyListMode::SIGS`), which is what
//!   Seahorse's "Signatures" tab shows
//! - [ ] S/MIME keys, which gpgme exposes through `Protocol::CMS`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpgme::{Context, Key, KeyListMode, Protocol, Validity};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::{GpgRequest, Replies, Reply};
use crate::model::{GpgFilter, GpgKeyInfo, GpgSubkey, GpgUid};

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
        };
        let _ = replies.send(reply);
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
