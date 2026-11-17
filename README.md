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
Copying to the clipboard additionally wants `wl-clipboard`, `xclip` or `xsel`
— see [The clipboard](#the-clipboard) for why it is an external tool. All of
these are looked up on `PATH` when used, so a missing one costs you that one
operation and nothing else.

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
| `/` | filter the item list by label or attribute — empty clears it |
| `x` | delete the selected secret — asks first |
| `n` | new keyring — asks for a name |
| `D` | delete the keyring and everything in it — asks first |
| `y` | copy the secret to the clipboard, wiped after 45s |

In **SSH Keys**:

| Key | Action |
| --- | --- |
| `a` | add the selected key to the agent (runs `ssh-add`) |
| `x` | remove the selected key from the agent |
| `n` | generate a key (runs `ssh-keygen`) |
| `c` | copy the public key to a host — asks for `[user@]host` (`ssh-copy-id`) |
| `p` | change or remove the passphrase (`ssh-keygen -p`) |
| `D` | delete the key files — asks first |
| `y` / `Y` | copy the public key line / the fingerprint |

In **GPG Keys**:

| Key | Action |
| --- | --- |
| `e` | edit: trust, expiry, user IDs, revocation, certifying (`gpg --edit-key`) |
| `y` | print the armoured public key |
| `n` | generate a key (`gpg --full-generate-key`) |
| `p` | publish to a keyserver — asks first |
| `x` | delete the key — asks first |
| `f` | show all keys / only keys with a private half |
| `i` | import keys from a file — asks for a path (`gpg --import`) |
| `/` | search a keyserver — asks for a query (`gpg --search-keys`) |
| `Y` | copy the fingerprint to the clipboard |

A key that opens a text field puts the keymap into **`input` mode**, where
printable keys are literal text rather than bindings — so `q` types a `q`
instead of quitting. Editing uses the shell's keys: `ctrl+w` deletes a word,
`ctrl+u` clears to the start, `ctrl+a`/`ctrl+e` jump to either end. `Enter`
runs, `Esc` cancels, and an empty field just closes — except the item
filter, where an empty field means "show everything again".

The field is deliberately **never** a passphrase box. Everything needing a
secret hands the terminal to pinentry, `ssh-add` or `gpg`, so there is no
masked mode and no buffer a secret could land in.

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

**Keybindings.** Three modes (`main`, `prompt`, `input`), four tables each,
applied in
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

The exception is the operations that need no prompt: deleting a stored secret,
unlinking a key's files, and copying to the clipboard all happen in the
backends, with the TUI left up. The two deletions are gated behind a
confirmation instead.

It also sets the boundary for the GPG section: reading goes through `gpgme`,
because structured access to user IDs, subkeys, capabilities and validity is
worth a library; writing goes through `gpg --edit-key` and friends, because
reimplementing gpg's prompts would be both more code and less safe.

## The clipboard

Copying shells out to `wl-copy`, `xclip`, `xsel` or `pbcopy` instead of
setting the selection directly. That is not laziness: on X11 and Wayland the
clipboard is served by a **live process**, so a selection owned by keyring-tui
would vanish the moment keyring-tui exits — copy a password, quit, paste, get
nothing. Those tools fork a background owner that outlives their parent, which
is what anyone copying a password expects. One of them has to be installed;
`[clipboard] copy` overrides the choice if detection guesses wrong.

A copied **secret** is wiped after 45 seconds by default (`clear_after`, `0`
to disable). A copied public key or fingerprint is not wiped at all: those are
not secret, they are meant to be pasted whenever, and clearing them would only
be annoying.

The wipe reads the clipboard back first and leaves it alone if it no longer
holds what we put there, so a copy you made in the meantime is never
discarded. Quitting with a wipe still pending performs it on the way out,
rather than leaving the secret behind with nothing running to remove it.

The timer lives in the clipboard backend, not the event loop: a copy spawns a
task that sleeps and then posts a wipe request. That is why an idle
keyring-tui still has no tick.

Two things it cannot promise. A clipboard **manager** that archives history
has its own copy, and wiping the selection does not reach into its database.
And `SIGKILL` leaves no opportunity to wipe anything.

## Handling secrets

* Secret values are fetched only when explicitly requested with `s`, and are
  held in a `Zeroizing<String>` that wipes on drop.
* Any navigation — moving the cursor, changing pane, changing section, an
  error — drops the revealed secret immediately.
* A reply that arrives after the cursor has moved off its row is discarded
  rather than displayed against the wrong item — including one fetched for a
  copy, which never reaches the clipboard if the cursor moved.
* Copying a secret fetches it without displaying it. A copy is not a reveal,
  so it does not put the password on screen as a side effect.
* Passphrases for locking, unlocking and creating a keyring are never read by
  this process; the service prompts through its own agent.

## Roadmap

**Passwords** (Secret Service — working unless noted)

- [x] enumerate keyrings, with lock state and the `default` alias
- [x] list items with schema, timestamps and attributes
- [x] reveal a secret on demand
- [x] lock and unlock a keyring
- [x] delete an item, behind a confirmation
- [x] filter the item list by label or attribute
- [x] create a keyring, and delete one behind a confirmation
- [x] copy a secret to the clipboard with a timed clear
- [ ] create and edit items

Changing a keyring's passphrase is not on this list: the Secret Service
spec has no method for it. Seahorse does it through gnome-keyring's own
D-Bus interface, which only gnome-keyring implements — so `gnome-keyring`
or `secret-tool` remains the way to do that.

**SSH keys**

- [x] list `~/.ssh` with algorithm, size, comment and SHA256 fingerprint
- [x] flag passphrase-protected keys and hardware-backed (`*-sk`) keys
- [x] show which keys the agent holds, including forwarded agent-only keys
- [x] add to the agent (`ssh-add`) and remove from it (agent protocol)
- [x] generate a key (ed25519 / ecdsa p521 / rsa 4096, via `ssh-keygen`)
- [x] change or remove a key's passphrase (`ssh-keygen -p`)
- [x] deploy a public key to a remote host (`ssh-copy-id`)
- [x] delete a key, behind a confirmation
- [x] copy the public key or fingerprint to the clipboard

`x` and `D` are deliberately different keys. `x` removes a key from the
agent, which costs you a re-`ssh-add`; `D` unlinks the files, which is
permanent. A near-miss on the harmless one should not be destructive.

**GPG keys**

- [x] list keys with algorithm, owner trust, capabilities and expiry
- [x] flag keys we hold a private half for, and smartcard-backed subkeys
- [x] details: user IDs with validity, subkeys, grouped fingerprint
- [x] filter to only keys with a private half
- [x] generate a key (`gpg --full-generate-key`)
- [x] edit — trust, expiry, user IDs, revocation, certifying (`gpg --edit-key`)
- [x] print the armoured public key
- [x] publish to a keyserver, and delete a key, both behind a confirmation
- [x] import from a file, and keyserver search
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

GPL-3.0-or-later, matching Seahorse. Full text in [LICENSE](LICENSE).
