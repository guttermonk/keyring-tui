//! GPG backend — not implemented yet.
//!
//! Design intent, so the shape is settled before the code lands:
//!
//! * Enumerate and inspect keys through the `gpgme` crate against the user's
//!   real `~/.gnupg`, so keyring-tui never becomes a second source of truth.
//!   `sequoia-openpgp` is the better library for *parsing and reasoning about*
//!   certificates (expiry, subkey capabilities, signature validity), so the
//!   likely split is gpgme for keyring access and sequoia for analysis.
//! * Anything that needs a passphrase (signing, certifying, changing expiry,
//!   generating a key) goes through the running `gpg-agent` with its pinentry.
//!   We do not prompt for passphrases ourselves, which keeps secret key
//!   material out of this process entirely.
//! * Keyserver lookup and publish over HKPS, matching Seahorse's "Find Remote
//!   Keys" / "Sync and Publish Keys".
//!
//! Feature parity checklist with Seahorse's PGP pane:
//!
//! - [ ] list secret and public keys, with trust, expiry and capability flags
//! - [ ] key details: UIDs, subkeys, fingerprint, algorithm, photo ID
//! - [ ] generate key (RSA/ECC, expiry, passphrase via pinentry)
//! - [ ] import / export, ASCII-armoured and binary
//! - [ ] sign (certify) another key, set owner trust
//! - [ ] change expiry, add/revoke UID, revoke key, generate revocation cert
//! - [ ] keyserver search, receive, publish
//! - [ ] delete key
//!
//! The section renders [`crate::ui`]'s roadmap placeholder until this module
//! grows a `spawn` mirroring [`crate::backend::secrets::spawn`].
