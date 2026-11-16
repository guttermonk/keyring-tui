//! Secret Service backend — the `Passwords` section.
//!
//! Talks to `org.freedesktop.secrets` (gnome-keyring-daemon, KWallet, or
//! anything else implementing the spec) through `oo7`'s D-Bus layer. We use
//! [`oo7::dbus::Service`] rather than the higher-level [`oo7::Keyring`] because
//! Seahorse shows *every* keyring, not just the default collection.

use std::collections::BTreeMap;

use oo7::dbus::{Collection, Item, Service};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use zeroize::Zeroizing;

use super::{Refresh, Replies, Reply, SecretsRequest};
use crate::model::{ItemInfo, KeyringInfo};

/// Attribute applications use to tag the kind of secret they stored.
pub const SCHEMA_ATTRIBUTE: &str = oo7::XDG_SCHEMA_ATTRIBUTE;

/// Spawn the backend actor and return the handle the UI sends requests on.
pub fn spawn(replies: Replies) -> UnboundedSender<SecretsRequest> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(err) = run(rx, replies.clone()).await {
            let _ = replies.send(Reply::Error(err));
        }
    });
    tx
}

async fn run(mut rx: UnboundedReceiver<SecretsRequest>, replies: Replies) -> Result<(), String> {
    // A failure here is almost always "no secret service on the bus": no
    // gnome-keyring-daemon running, or no D-Bus session at all.
    let service = Service::new()
        .await
        .map_err(|err| format!("cannot reach the secret service: {err}"))?;

    let mut state = State {
        service,
        collections: Vec::new(),
        items: Vec::new(),
    };

    while let Some(request) = rx.recv().await {
        match state.handle(request).await {
            Ok(reply) => {
                let _ = replies.send(reply);
            }
            Err(err) => {
                let _ = replies.send(Reply::Error(err));
            }
        }
    }

    Ok(())
}

struct State {
    service: Service,
    /// Addressed by index; `KeyringInfo::id` is a position in here.
    collections: Vec<Collection>,
    /// Parallel to `collections`: the items last loaded for each keyring, in
    /// the same order the UI is showing them.
    items: Vec<Vec<Item>>,
}

impl State {
    async fn handle(&mut self, request: SecretsRequest) -> Result<Reply, String> {
        match request {
            SecretsRequest::ListKeyrings => self.list_keyrings().await,
            SecretsRequest::ListItems { keyring } => self.list_items(keyring).await,
            SecretsRequest::Unlock { keyring } => self.set_locked(keyring, false).await,
            SecretsRequest::Lock { keyring } => self.set_locked(keyring, true).await,
            SecretsRequest::RevealSecret { keyring, item } => self.reveal(keyring, item).await,
        }
    }

    async fn list_keyrings(&mut self) -> Result<Reply, String> {
        self.collections = self
            .service
            .collections()
            .await
            .map_err(|err| format!("listing keyrings failed: {err}"))?;
        self.items = self.collections.iter().map(|_| Vec::new()).collect();

        // `default` is an alias, so identify it by object path, not by label.
        let default_path = self
            .service
            .default_collection()
            .await
            .ok()
            .map(|collection| collection.path().to_string());

        let mut keyrings = Vec::with_capacity(self.collections.len());
        for (id, collection) in self.collections.iter().enumerate() {
            keyrings.push(KeyringInfo {
                id,
                label: label_or_path(collection).await,
                locked: collection.is_locked().await.unwrap_or(true),
                is_default: default_path
                    .as_deref()
                    .is_some_and(|path| path == collection.path().as_str()),
            });
        }
        Ok(Reply::Keyrings(keyrings))
    }

    async fn list_items(&mut self, keyring: usize) -> Result<Reply, String> {
        let collection = self
            .collections
            .get(keyring)
            .ok_or_else(|| stale("keyring"))?;

        // A locked collection reports an empty item set rather than erroring,
        // which is what we want: the UI shows the lock and offers `u`.
        let items = collection
            .items()
            .await
            .map_err(|err| format!("listing items failed: {err}"))?;

        // Read metadata, then sort info and handle together so that
        // `ItemInfo::id` stays a valid index into `self.items[keyring]`.
        // `Item` is not `Clone`, hence the pair-and-unzip rather than
        // sorting two vectors independently.
        let mut paired: Vec<(ItemInfo, Item)> = Vec::with_capacity(items.len());
        for item in items {
            let attributes: BTreeMap<String, String> = item
                .attributes()
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();
            let info = ItemInfo {
                id: 0, // assigned after sorting
                label: item.label().await.unwrap_or_else(|_| "<unreadable>".into()),
                attributes,
                locked: item.is_locked().await.unwrap_or(true),
                created: item.created().await.ok(),
                modified: item.modified().await.ok(),
            };
            paired.push((info, item));
        }
        paired.sort_by_key(|(info, _)| info.label.to_lowercase());

        let mut infos = Vec::with_capacity(paired.len());
        let mut handles = Vec::with_capacity(paired.len());
        for (id, (mut info, item)) in paired.into_iter().enumerate() {
            info.id = id;
            infos.push(info);
            handles.push(item);
        }

        if let Some(slot) = self.items.get_mut(keyring) {
            *slot = handles;
        }

        Ok(Reply::Items {
            keyring,
            items: infos,
        })
    }

    async fn set_locked(&mut self, keyring: usize, locked: bool) -> Result<Reply, String> {
        let collection = self
            .collections
            .get(keyring)
            .ok_or_else(|| stale("keyring"))?;
        let label = collection.label().await.unwrap_or_default();

        // `None` window identifier: there is no toplevel to parent a prompt
        // to, so the agent prompts on its own (typically via pinentry).
        if locked {
            collection
                .lock(None)
                .await
                .map_err(|err| format!("locking {label} failed: {err}"))?;
        } else {
            collection
                .unlock(None)
                .await
                .map_err(|err| format!("unlocking {label} failed: {err}"))?;
        }

        Ok(Reply::Status {
            message: format!("{label} {}", if locked { "locked" } else { "unlocked" }),
            // Lock state changed, so the keyring list and its items are stale.
            refresh: Refresh::Keyrings,
        })
    }

    async fn reveal(&mut self, keyring: usize, item: usize) -> Result<Reply, String> {
        let handle = self
            .items
            .get(keyring)
            .and_then(|items| items.get(item))
            .ok_or_else(|| stale("item"))?;

        let secret = handle
            .secret()
            .await
            .map_err(|err| format!("reading secret failed: {err}"))?;

        // Non-UTF-8 secrets (binary blobs, certificates) are summarised rather
        // than dumped as mojibake into the terminal.
        let value = match secret.as_str() {
            Some(text) => Zeroizing::new(text.to_owned()),
            None => Zeroizing::new(format!(
                "<{} bytes of binary data>",
                secret.as_bytes().len()
            )),
        };

        Ok(Reply::Secret {
            keyring,
            item,
            value,
        })
    }
}

/// The session keyring is typically unlabelled, so fall back to the last
/// segment of its object path (`…/collection/session`) rather than a blank row.
async fn label_or_path(collection: &Collection) -> String {
    let label = collection.label().await.unwrap_or_default();
    if !label.trim().is_empty() {
        return label;
    }
    collection
        .path()
        .as_str()
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or("unnamed")
        .to_owned()
}

fn stale(what: &str) -> String {
    format!("{what} is no longer available; press r to refresh")
}
