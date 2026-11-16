# keyring-tui

A terminal replacement for [GNOME Seahorse](https://gitlab.gnome.org/GNOME/seahorse):
one TUI for stored passwords, GPG keys and SSH keys.

> **Status: early.** The Passwords (Secret Service) and SSH Keys sections work;
> both are read-only apart from locking a keyring, managing the ssh-agent, and
> generating a key. The GPG section is a stub that shows its roadmap.

## Running

With Nix:

```console
nix develop        # rustc, cargo, clippy, rust-analyzer, gpgme, nettle, gnupg…
cargo run
```

Without Nix you need a Rust toolchain plus `pkg-config`, and — once the GPG
backend lands — `libgpgme`, `libgpg-error` and `libassuan`.

```console
nix build          # or: cargo build --release
```

## Keys

| Key | Action |
| --- | --- |
| `q`, `Esc` | quit |
| `?` | help |
| `Tab`, `1`/`2`/`3` | switch section |
| `j`/`k`, `↓`/`↑` | move selection |
| `g`/`G` | first / last |
| `r` | refresh the current section |

In **Passwords**:

| Key | Action |
| --- | --- |
| `h`/`l` | focus keyrings / items |
| `u` / `L` | unlock / lock the selected keyring |
| `s` | reveal / hide the selected secret |

In **SSH Keys**:

| Key | Action |
| --- | --- |
| `a` | add the selected key to the agent (runs `ssh-add`) |
| `x` | remove the selected key from the agent |
| `n` | generate a key (runs `ssh-keygen`) |

## Architecture

```
main.rs      terminal lifecycle + the select! event loop
app.rs       all state; synchronous, I/O-free, unit-tested
ui.rs        rendering — a pure function of &App
model.rs     domain types the UI speaks (KeyringInfo, ItemInfo, Section)
backend/     one actor per section, each owning its own I/O
  secrets.rs Secret Service over D-Bus, via oo7
  ssh.rs     ~/.ssh via ssh-key, plus an ssh-agent protocol client
  gpg.rs     planned: gpgme against the real ~/.gnupg
```

Backends are actors: the UI posts a request and never awaits a reply, so a
locked keyring waiting on a pinentry can't block the redraw loop. Replies are
folded into `App` by `on_reply`, which lets the entire interaction model be
tested without a session bus — see the tests in `src/app.rs`.

The event loop is fully event-driven. There is no tick or poll interval, so an
idle keyring-tui costs nothing.

Anything that needs a passphrase or a touch on a security key runs as an
external command with the TUI suspended — `ssh-add` and `ssh-keygen` get the
real terminal, do their own prompting, and the list is re-read when they exit.
That keeps passphrases and private key material out of this process entirely,
and means `-sk` keys, askpass and confirmation all behave exactly as usual.

## Handling secrets

* Secret values are fetched only when explicitly requested with `s`, and are
  held in a `Zeroizing<String>` that wipes on drop.
* Any navigation — moving the cursor, changing pane, changing section, an
  error — drops the revealed secret immediately.
* A reply that arrives after the cursor has moved off its row is discarded
  rather than displayed against the wrong item.
* Passphrases for locking and unlocking are never read by this process; the
  service prompts through its own agent.

## Roadmap

**Passwords** (Secret Service — working unless noted)

- [x] enumerate keyrings, with lock state and the `default` alias
- [x] list items with schema, timestamps and attributes
- [x] reveal a secret on demand
- [x] lock and unlock a keyring
- [ ] create, edit and delete items
- [ ] create and delete keyrings; change a keyring passphrase
- [ ] search and filter
- [ ] copy a secret to the clipboard with a timed clear

**SSH keys**

- [x] list `~/.ssh` with algorithm, size, comment and SHA256 fingerprint
- [x] flag passphrase-protected keys and hardware-backed (`*-sk`) keys
- [x] show which keys the agent holds, including forwarded agent-only keys
- [x] add to the agent (`ssh-add`) and remove from it (agent protocol)
- [x] generate a key (ed25519 / ecdsa p521 / rsa 4096, via `ssh-keygen`)
- [ ] change or remove a key's passphrase
- [ ] deploy a public key to a remote host (`ssh-copy-id`)
- [ ] delete a key
- [ ] copy the public key or fingerprint to the clipboard

**GPG keys** — see `src/backend/gpg.rs` for the full checklist: list with
trust/expiry/capabilities, key details, generate, import/export, certify, set
owner trust, change expiry, revoke, and keyserver search/receive/publish.

## Tests

```console
cargo test                                                  # no D-Bus, agent or disk needed
cargo test --test secret_service -- --ignored --nocapture    # live keyring, metadata only
cargo test ssh::tests::live -- --ignored --nocapture         # live ~/.ssh and agent
```

The default suite covers the state machine against fake backends and the SSH
scanner against key fixtures in a temporary directory.

The ignored tests read from your real environment. They are deliberately
side-effect free: the keyring one reads labels, lock state and item counts
without fetching a secret or unlocking anything; the SSH ones read key
metadata and ask the agent what it holds, and the removal test uses a fixture
key the agent cannot be holding, so nothing is removed.

## License

GPL-3.0-or-later, matching Seahorse.
