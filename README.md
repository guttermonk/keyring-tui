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

Every key is rebindable — see [Configuration](#configuration) — and `?` shows
the keymap actually in force rather than this table.

| Key | Action |
| --- | --- |
| `q`, `Esc` | quit |
| `?` | help |
| `Tab`, `1`/`2`/`3` | switch section |
| `j`/`k`, `↓`/`↑` | move selection, or scroll a focused detail pane |
| `h`/`l`, `←`/`→` | focus the pane left / right |
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

## Desktop entry

`keyring-tui.desktop` is installed by the flake into
`$out/share/applications`. It sets `Terminal=true`, so a launcher hands it a
terminal; `Icon=dialog-password` names a *themed* icon — a padlock — so it
follows your icon theme instead of shipping a look of its own.

`dialog-password` is in Papirus, Breeze and the gnome theme, but modern
Adwaita keeps only `dialog-password-symbolic`. If your desktop falls back to
Adwaita and you get a generic icon, `application-certificate` is the name
every theme still carries. Installing by hand:

```console
install -Dm644 keyring-tui.desktop ~/.local/share/applications/keyring-tui.desktop
```

## Configuration

`$XDG_CONFIG_HOME/keyring-tui/config.toml`, or `--config <path>`. Every value
in [`config.example.toml`](config.example.toml) is the default, so an empty
file behaves identically and a missing file is not an error. A malformed one
*is*, reported before the terminal is taken over — and unknown keys are
rejected rather than ignored, so a typo tells you.

**Themes.** A preset plus per-slot overrides, in hex or by ANSI name:

```toml
[theme]
preset = "gruvbox-dark"   # or terminal (default), catppuccin-mocha, nord

[theme.colors]
border_focused = "#fabd2f"
secret = "bright-red"
```

`terminal` uses the terminal's own palette, so a transparent or themed
terminal shows through. The slots are `fg`, `bg`, `dim`, `border`,
`border_focused`, `cursor_fg`/`bg`, `status_fg`/`bg`, `accent`, `ok`, `warn`,
`danger` and `secret`.

It is also the only preset that works on a *light* terminal, because it makes
`dim` and `border` the terminal's own foreground plus the DIM attribute rather
than a colour. No colour can be quiet on both light and dark backgrounds: ANSI
8 is the usual choice and measures about 1.05:1 against the background on a
light theme, where anything under ~3:1 is unreadable, and ANSI 7 is what
`reset` already resolves to. Naming an explicit `dim` or `border` colour
replaces the attribute.

Colour names are normalised the way ratatui normalises its own, so a value
copied from another ratatui app means the same thing here — `bright-red`,
`brightred`, `light_red` and `lightred` are one spelling. Two words are
rejected rather than guessed at, being the only ones where the vocabularies
disagreed *silently*: `white` (ANSI 15 to ratatui, ANSI 7 here — write
`bright-white` or `gray`) and `bright-gray` (folded to ANSI 15 by ratatui
despite the name).

**Colour overlay.** An optional second file, layered over `[theme.colors]`,
for tools that recolour a desktop from the wallpaper — wallust, pywal — which
re-derive a palette on every wallpaper change and shouldn't own the file that
also holds your keymap:

| | |
| --- | --- |
| Path | `$XDG_CACHE_HOME/wallust/colors-keyring-tui.toml`, else `~/.cache/wallust/…`; `$KEYRING_TUI_COLORS_OVERLAY` overrides |
| Shape | a **top-level** `[colors]` table, not `[theme.colors]` |
| Merge | per key over `[theme.colors]`; `[theme]` is created if absent |
| Absent | missing, unreadable or malformed means "use the config", silently |
| Typos | a key that isn't a slot is dropped and reported, not rejected |
| Reload | none — config is read once, so a new overlay applies next run |

A typo in *this* file still fails at load, because you wrote it and can fix
it; the overlay is machine-written, and the same rule would let a wallpaper
change stop a key manager from starting.

```console
keyring-tui theme         # every slot, its resolved value, and where it came from
```

**Keybindings.** Two modes (`main`, `prompt`), four tables each, applied in
order: `base` replaces the defaults, `set` gives actions exactly these keys,
`extra` layers keys on top, `unbind` vetoes. So to navigate with `n`/`e`/`i`/`o`
instead of `h`/`j`/`k`/`l`:

```toml
[keys.main]
set = [
    ["MoveDown",   "e"],
    ["MoveUp",     "i"],
    ["FocusLeft",  "n"],
    ["FocusRight", "o"],
]
# `set` also takes each key from whatever held it, so give the old jobs a home:
extra = [["NewSshKey", "N"], ["NewGpgKey", "N"], ["GpgEdit", "E"]]
```

`set` retires an action's other keys but never the arrows, `Esc`, `Enter` or
`ctrl+c`, so a remapped keymap always leaves a way out. A combo is a key
(`"s"`, `"ctrl+c"`, `{ key = "d", mod = ["Ctrl"] }`) or an array for a chord
(`["z", "z"]`); there is no chord timeout, so `d` and `dd` cannot coexist.

```console
keyring-tui keys          # what a config resolves to, and any action left unbound
keyring-tui theme         # every colour slot, resolved, with its source
```

The format deliberately matches [lazysync](https://github.com/guttermonk/lazysync)'s,
so a keymap written for one reads the same in the other.

## Architecture

```
main.rs      terminal lifecycle + the select! event loop
app.rs       all state; synchronous, I/O-free, unit-tested
ui.rs        rendering — a pure function of &App
model.rs     domain types the UI speaks (KeyringInfo, ItemInfo, Section)
config/      config.toml: the theme and the keymap tables
keys/        actions, key spellings, and how a config merges over the defaults
backend/     one actor per section, each owning its own I/O
  secrets.rs Secret Service over D-Bus, via oo7
  ssh.rs     ~/.ssh via ssh-key, plus an ssh-agent protocol client
  gpg.rs     the GnuPG keyring via gpgme
```

Nothing in the UI hardcodes a key: the footer hints, the help overlay, the
modal choices and even the "press s to reveal" hint are generated from the
keymap in force, so a rebound key can't leave the screen lying.

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
