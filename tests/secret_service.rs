//! Smoke test against a real `org.freedesktop.secrets` on the session bus.
//!
//! Ignored by default: it needs a running keyring daemon and reports on the
//! developer's actual keyrings. Run it with
//!
//! ```console
//! cargo test --test secret_service -- --ignored --nocapture
//! ```
//!
//! It reads metadata only — labels, lock state, item counts — and never
//! fetches a secret or unlocks anything.

use oo7::dbus::Service;

#[tokio::test]
#[ignore = "requires a live secret service on the session bus"]
async fn enumerates_keyrings_and_items() {
    let service = Service::new()
        .await
        .expect("no secret service on the session bus");

    let collections = service.collections().await.expect("listing collections");
    let default_path = service
        .default_collection()
        .await
        .ok()
        .map(|collection| collection.path().to_string());

    assert!(
        !collections.is_empty(),
        "service reported no keyrings at all"
    );

    for (index, collection) in collections.iter().enumerate() {
        let label = collection.label().await.unwrap_or_else(|_| "?".into());
        let locked = collection.is_locked().await.unwrap_or(true);
        let items = collection.items().await.map(|i| i.len()).unwrap_or(0);
        let is_default = default_path.as_deref() == Some(collection.path().as_str());

        println!(
            "[{index}] {label:<24} items={items:<4} locked={locked}{}",
            if is_default { "  (default)" } else { "" }
        );
    }
}
