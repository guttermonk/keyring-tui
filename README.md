# keyring-tui

A terminal replacement for [GNOME Seahorse](https://gitlab.gnome.org/GNOME/seahorse):
one TUI for stored passwords, GPG keys and SSH keys.

> **Status: early.** All three sections work. Listing and inspection are
> complete; the write operations implemented so far are locking a keyring,
> managing the ssh-agent, generating SSH and GPG keys, and the whole of
> `gpg --edit-key`. See the roadmap for what is still missing.

## Running

With Nix:

```console
nix develop        # rustc, cargo, clippy, rust-analyzer, gpgme, nettle, gnupg…
cargo run
```

Without Nix you need a Rust toolchain, `pkg-config`, and `libgpgme` with its
`libgpg-error` and `libassuan` dependencies — `gpgme` is a C binding, so
`cargo build` outside the dev shell will not find it on its own. At runtime it
wants `gpg`, `ssh-add`/`ssh-keygen`, and a Secret Service on the session bus.

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

In **GPG Keys**:

| Key | Action |
| --- | --- |
| `e` | edit: trust, expiry, user IDs, revocation, certifying (`gpg --edit-key`) |
| `y` | print the armoured public key |
| `n` | generate a key (`gpg --full-generate-key`) |
| `p` | publish to a keyserver — asks first |
| `x` | delete the key — asks first |
| `f` | show all keys / only keys with a private half |

## Architecture

```
main.rs      terminal lifecycle + the select! event loop
app.rs       all state; synchronous, I/O-free, unit-tested
ui.rs        rendering — a pure function of &App
model.rs     domain types the UI speaks (KeyringInfo, ItemInfo, Section)
backend/     one actor per section, each owning its own I/O
  secrets.rs Secret Service over D-Bus, via oo7
  ssh.rs     ~/.ssh via ssh-key, plus an ssh-agent protocol client
  gpg.rs     the GnuPG keyring via gpgme
```

Backends are actors: the UI posts a request and never awaits a reply, so a
locked keyring waiting on a pinentry can't block the redraw loop. Replies are
folded into `App` by `on_reply`, which lets the entire interaction model be
tested without a session bus — see the tests in `src/app.rs`.

The event loop is fully event-driven. There is no tick or poll interval, so an
idle keyring-tui costs nothing.

Anything that needs a passphrase, a touch on a security key, or a network
round trip runs as an external command with the TUI suspended — `ssh-add`,
`ssh-keygen` and `gpg` get the real terminal, do their own prompting, and the
affected list is re-read when they exit. That keeps passphrases and private
key material out of this process entirely, and means `-sk` keys, askpass,
pinentry and gpg's own confirmations all behave exactly as usual.

It also sets the boundary for the GPG section: reading goes through `gpgme`,
because structured access to user IDs, subkeys, capabilities and validity is
worth a library; writing goes through `gpg --edit-key` and friends, because
reimplementing gpg's prompts would be both more code and less safe.

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

**GPG keys**

- [x] list keys with algorithm, owner trust, capabilities and expiry
- [x] flag keys we hold a private half for, and smartcard-backed subkeys
- [x] details: user IDs with validity, subkeys, grouped fingerprint
- [x] filter to only keys with a private half
- [x] generate a key (`gpg --full-generate-key`)
- [x] edit — trust, expiry, user IDs, revocation, certifying (`gpg --edit-key`)
- [x] print the armoured public key
- [x] publish to a keyserver, and delete a key, both behind a confirmation
- [ ] import from a file, and keyserver search (both need a text input widget)
- [ ] per-user-ID signature listing, which is Seahorse's "Signatures" tab
- [ ] photo IDs
- [ ] S/MIME keys, which gpgme exposes through `Protocol::CMS`

## Tests

```console
cargo test                                                  # no D-Bus, agent, gpg or disk needed
cargo test --test secret_service -- --ignored --nocapture    # live keyring, metadata only
cargo test ssh::tests::live -- --ignored --nocapture         # live ~/.ssh and agent
cargo test gpg::tests::live -- --ignored --nocapture         # live ~/.gnupg
```

The default suite covers the state machine against fake backends, the SSH
scanner against key fixtures in a temporary directory, ssh-agent wire-format
parsing, and rendering through ratatui's `TestBackend`.

The ignored tests read from your real environment and are deliberately
side-effect free: the keyring one reads labels, lock state and item counts
without fetching a secret or unlocking anything; the SSH ones read key
metadata and ask the agent what it holds, with the removal test using a
fixture key the agent cannot be holding; the GPG one only lists keys.

To exercise the GPG section — including the operations that write — point it
at a throwaway keyring rather than your own:

```console
export GNUPGHOME=$(mktemp -d) && chmod 700 "$GNUPGHOME"
gpg --batch --passphrase '' --quick-generate-key 'Test <test@example.invalid>' ed25519
cargo run
```

## License

GPL-3.0-or-later, matching Seahorse.
