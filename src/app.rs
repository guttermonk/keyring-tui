// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! Application state and the key handling that mutates it.
//!
//! `App` is deliberately synchronous and I/O-free: every key press either
//! changes local state, posts a request to a backend, or parks an [`External`]
//! command for the event loop to run with the TUI suspended. Every backend
//! [`Reply`] is folded in by [`App::on_reply`]. That keeps the whole UI
//! testable without a D-Bus session, an agent or a subprocess.

use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::KeyEvent;
use ratatui::widgets::ListState;
use tokio::sync::mpsc::UnboundedSender;
use zeroize::Zeroizing;

use crate::backend::{ClipboardRequest, GpgRequest, Refresh, Reply, SecretsRequest, SshRequest};
use crate::input::Input;
use crate::keys::{Action, Key, Keymaps, Mode, ModifiedKey, Resolution};
use crate::model::{
    AgentStatus, GpgFilter, GpgKeyInfo, ItemInfo, KeyringInfo, Section, SshKeyInfo,
};

/// Which pane has the keyboard. `h`/`l` walk this left to right.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    /// The keyring sidebar. Passwords only.
    Keyrings,
    /// The main list: items, SSH keys, or GPG keys.
    List,
    /// The detail pane, which scrolls with `j`/`k` once focused.
    Details,
}

/// The panes a section has, in left-to-right order.
///
/// Only Passwords has a sidebar; the key sections put their list where the
/// item list would be.
pub fn panes_for(section: Section) -> &'static [Pane] {
    match section {
        Section::Keyrings => &[Pane::Keyrings, Pane::List, Pane::Details],
        Section::GpgKeys | Section::SshKeys => &[Pane::List, Pane::Details],
    }
}

/// A modal question. Only ever one at a time, and always dismissable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prompt {
    /// Choose an algorithm for a new SSH key.
    NewSshKey,
    /// Confirm deleting the selected GPG key. gpg asks again, but a stray
    /// keypress should not start a delete flow at all.
    ConfirmGpgDelete,
    /// Confirm publishing the selected GPG key to a keyserver. Keyservers do
    /// not forget, so this one is not undoable.
    ConfirmGpgPublish,
    /// Confirm deleting the selected stored secret. Nothing else asks: the
    /// Secret Service deletes on request, with no trash to recover from.
    ConfirmDeleteItem,
    /// Confirm unlinking the selected SSH key's files. A private key is the
    /// one thing here that no amount of re-running can get back.
    ConfirmSshDelete,
    /// Confirm deleting a keyring, which takes every secret in it.
    ConfirmDeleteKeyring,
    /// A one-line text field. The text itself lives in [`App::input`] so that
    /// this enum stays `Copy`.
    Ask(Question),
}

/// What a text field is being used to ask for.
///
/// Every variant feeds an external command, so none of them ever asks for a
/// secret — see [`crate::input`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Question {
    /// A file to import keys from: `gpg --import <path>`.
    GpgImportPath,
    /// A name or address to look for on a keyserver:
    /// `gpg --search-keys <query>`, which then asks which to import.
    GpgSearch,
    /// Where to install the selected public key: `ssh-copy-id <target>`.
    SshCopyTarget,
    /// A substring to narrow the item list by.
    ItemFilter,
    /// A name for a new keyring. The service asks for its passphrase itself,
    /// so this field only ever holds the label.
    NewKeyringLabel,
}

impl Question {
    /// The modal's title.
    pub fn title(self) -> &'static str {
        match self {
            Self::GpgImportPath => " Import keys from a file ",
            Self::GpgSearch => " Search a keyserver ",
            Self::SshCopyTarget => " Copy this key to a host ",
            Self::ItemFilter => " Filter items ",
            Self::NewKeyringLabel => " New keyring ",
        }
    }

    /// The line above the field, saying what will run.
    pub fn describe(self) -> &'static str {
        match self {
            Self::GpgImportPath => "Runs gpg --import. A file of one or more public keys.",
            Self::GpgSearch => {
                "Runs gpg --search-keys, which lists matches and asks which to import."
            }
            Self::SshCopyTarget => {
                "Runs ssh-copy-id, which appends the public key to the host's\n\
                 authorized_keys. It will ask the host for a password."
            }
            Self::ItemFilter => {
                "Narrows the list to items whose label or attributes contain\n\
                 this text. Empty shows everything again."
            }
            Self::NewKeyringLabel => {
                "Creates an empty keyring. The service asks for its\n\
                 passphrase itself, through its own prompt."
            }
        }
    }

    /// The prompt shown in front of the field.
    pub fn label(self) -> &'static str {
        match self {
            Self::GpgImportPath => "path",
            Self::GpgSearch => "search",
            Self::SshCopyTarget => "[user@]host",
            Self::ItemFilter => "match",
            Self::NewKeyringLabel => "name",
        }
    }
}

/// A `gpg` invocation. Everything that changes a key goes through the CLI so
/// that pinentry, confirmations and keyserver output behave as usual.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GpgAction {
    /// `--full-generate-key`, which prompts for algorithm, identity and
    /// passphrase itself.
    Generate,
    /// `--edit-key`: trust, expiry, user IDs, revocation, certifying.
    Edit,
    /// `--armor --export`, printed to the terminal for copying.
    Export,
    /// `--send-keys`, which publishes to the configured keyserver.
    Publish,
    /// `--delete-key`. gpg refuses when a private key is present and points
    /// at `--delete-secret-keys`, which is the safe default here: losing a
    /// public key is recoverable, losing a private one is not.
    Delete,
    /// `--import <path>`, which reports what it added and skipped.
    Import,
    /// `--search-keys <query>`: gpg lists what the keyserver has and asks
    /// which to import, so the choosing happens in gpg rather than here.
    Search,
}

impl GpgAction {
    fn args(self, fingerprint: Option<&str>) -> Vec<String> {
        let mut args: Vec<String> = match self {
            Self::Generate => vec!["--full-generate-key".into()],
            Self::Edit => vec!["--edit-key".into()],
            Self::Export => vec!["--armor".into(), "--export".into()],
            Self::Publish => vec!["--send-keys".into()],
            Self::Delete => vec!["--delete-key".into()],
            Self::Import => vec!["--import".into()],
            Self::Search => vec!["--search-keys".into()],
        };
        if let Some(fingerprint) = fingerprint {
            args.push(fingerprint.to_owned());
        }
        args
    }
}

/// A command that needs the real terminal: it prompts for a passphrase, or
/// waits for a touch on a security key. The event loop suspends the TUI, runs
/// it with inherited stdio, and resumes.
///
/// Doing it this way means no passphrase ever passes through this process, and
/// `ssh-add`/`ssh-keygen` keep their familiar behaviour — including askpass,
/// confirmation and FIDO2 support.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum External {
    /// `ssh-add <path>`
    SshAdd(PathBuf),
    /// `ssh-keygen -t <algorithm> [-b <bits>]`, which prompts for the
    /// destination path and passphrase itself.
    SshKeygen {
        algorithm: &'static str,
        bits: Option<u32>,
    },
    /// A `gpg` subcommand, optionally against one key.
    Gpg {
        action: GpgAction,
        fingerprint: Option<String>,
    },
    /// `ssh-copy-id -i <public_key> <target>`, which asks the remote host for
    /// a password itself.
    SshCopyId { public_key: PathBuf, target: String },
    /// `ssh-keygen -p -f <path>`, which asks for the old passphrase and then
    /// the new one. An empty new passphrase removes it, so this one command
    /// covers both changing and removing.
    SshPassphrase(PathBuf),
}

impl External {
    pub fn program(&self) -> &'static str {
        match self {
            Self::SshAdd(_) => "ssh-add",
            Self::SshKeygen { .. } | Self::SshPassphrase(_) => "ssh-keygen",
            Self::SshCopyId { .. } => "ssh-copy-id",
            Self::Gpg { .. } => "gpg",
        }
    }

    pub fn args(&self) -> Vec<String> {
        match self {
            Self::SshAdd(path) => vec![path.display().to_string()],
            Self::SshKeygen { algorithm, bits } => {
                let mut args = vec!["-t".to_string(), (*algorithm).to_string()];
                if let Some(bits) = bits {
                    args.push("-b".to_string());
                    args.push(bits.to_string());
                }
                args
            }
            Self::Gpg {
                action,
                fingerprint,
            } => action.args(fingerprint.as_deref()),
            Self::SshCopyId { public_key, target } => {
                vec![
                    "-i".to_string(),
                    public_key.display().to_string(),
                    target.clone(),
                ]
            }
            Self::SshPassphrase(path) => {
                vec![
                    "-p".to_string(),
                    "-f".to_string(),
                    path.display().to_string(),
                ]
            }
        }
    }

    /// Shown while the command runs, so it is obvious what took the terminal.
    pub fn describe(&self) -> String {
        format!("{} {}", self.program(), self.args().join(" "))
    }

    /// What this command may have changed, so the right list is re-read.
    pub fn refresh(&self) -> Refresh {
        match self {
            Self::SshAdd(_)
            | Self::SshKeygen { .. }
            | Self::SshCopyId { .. }
            // The `encrypted` flag in the list changes, so it is re-read.
            | Self::SshPassphrase(_) => Refresh::SshKeys,
            Self::Gpg { .. } => Refresh::GpgKeys,
        }
    }
}

pub struct App {
    pub section: Section,
    pub pane: Pane,

    // Passwords.
    pub keyrings: Vec<KeyringInfo>,
    pub keyring_state: ListState,
    pub items: Vec<ItemInfo>,
    pub item_state: ListState,
    /// A substring the item list is narrowed to, empty when showing
    /// everything. A view over `items` rather than a backend query: keyrings
    /// hold tens of items, not thousands, and filtering locally keeps the
    /// `ItemInfo::id` the backend handed us intact.
    pub item_filter: String,

    /// The currently displayed secret, if the user asked for it. Held in a
    /// `Zeroizing` so it is wiped when cleared, and cleared on *any*
    /// navigation — a revealed password should never outlive the row it
    /// belongs to.
    pub revealed: Option<Zeroizing<String>>,
    /// A fetch that was asked for in order to copy the secret, not to show
    /// it. Copying needs the same round trip as revealing, but putting the
    /// secret on screen as a side effect of a copy is the opposite of what
    /// was asked for.
    copy_on_reveal: bool,

    // SSH keys.
    pub ssh_keys: Vec<SshKeyInfo>,
    pub ssh_state: ListState,
    pub agent: AgentStatus,
    /// The SSH section scans the disk on first visit, not at startup.
    ssh_loaded: bool,

    // GPG keys.
    pub gpg_keys: Vec<GpgKeyInfo>,
    pub gpg_state: ListState,
    pub gpg_filter: GpgFilter,
    /// The gpg engine behind the current listing, for the status line.
    pub gpg_engine: String,
    /// The GPG section reads the keyring on first visit, not at startup.
    gpg_loaded: bool,

    /// How far the detail pane is scrolled, and how many lines it last drew.
    ///
    /// The line count comes back from the renderer, which is the only place
    /// that knows it; without it, `j` in a focused detail pane would scroll
    /// happily past the end.
    pub detail_scroll: u16,
    pub detail_lines: u16,
    pub detail_height: u16,

    pub status: String,
    pub error: Option<String>,
    pub show_help: bool,
    pub prompt: Option<Prompt>,
    /// The text field, live only while `prompt` is `Prompt::Ask`.
    pub input: Input,
    pub should_quit: bool,

    external: Option<External>,

    keymaps: Keymaps,
    /// Keys pressed so far that have not yet completed a binding.
    pending: Vec<ModifiedKey>,

    secrets: UnboundedSender<SecretsRequest>,
    ssh: UnboundedSender<SshRequest>,
    gpg: UnboundedSender<GpgRequest>,
    clipboard: UnboundedSender<ClipboardRequest>,
    /// How long a copied secret survives before the clipboard backend wipes
    /// it. `None` disables the wipe; public keys and fingerprints pass `None`
    /// regardless, as they are not secret.
    clipboard_clear_after: Option<Duration>,
}

impl App {
    pub fn new(
        secrets: UnboundedSender<SecretsRequest>,
        ssh: UnboundedSender<SshRequest>,
        gpg: UnboundedSender<GpgRequest>,
        clipboard: UnboundedSender<ClipboardRequest>,
        clipboard_clear_after: Option<Duration>,
        keymaps: Keymaps,
    ) -> Self {
        let app = Self {
            section: Section::Keyrings,
            pane: Pane::Keyrings,
            keyrings: Vec::new(),
            keyring_state: ListState::default(),
            items: Vec::new(),
            item_state: ListState::default(),
            item_filter: String::new(),
            revealed: None,
            copy_on_reveal: false,
            ssh_keys: Vec::new(),
            ssh_state: ListState::default(),
            agent: AgentStatus::NotConfigured,
            ssh_loaded: false,
            gpg_keys: Vec::new(),
            gpg_state: ListState::default(),
            gpg_filter: GpgFilter::All,
            gpg_engine: String::new(),
            gpg_loaded: false,
            status: "loading keyrings…".into(),
            error: None,
            show_help: false,
            prompt: None,
            input: Input::default(),
            should_quit: false,
            detail_scroll: 0,
            detail_lines: 0,
            detail_height: 0,
            external: None,
            keymaps,
            pending: Vec::new(),
            secrets,
            ssh,
            gpg,
            clipboard,
            clipboard_clear_after,
        };
        app.send(SecretsRequest::ListKeyrings);
        app
    }

    /// A closed channel means that backend's task died; its error reply
    /// already went through the event loop, so these drop silently.
    fn send(&self, request: SecretsRequest) {
        let _ = self.secrets.send(request);
    }

    fn send_ssh(&self, request: SshRequest) {
        let _ = self.ssh.send(request);
    }

    fn send_gpg(&self, request: GpgRequest) {
        let _ = self.gpg.send(request);
    }

    /// Put something on the clipboard.
    ///
    /// `secret` decides whether it is wiped afterwards: a password is, a
    /// public key or a fingerprint is not — those are meant to be pasted
    /// wherever and whenever, and wiping them would only be annoying.
    fn copy(&mut self, text: Zeroizing<String>, what: &str, secret: bool) {
        let _ = self.clipboard.send(ClipboardRequest::Copy {
            text,
            what: what.to_owned(),
            clear_after: secret.then_some(self.clipboard_clear_after).flatten(),
        });
    }

    pub fn selected_keyring(&self) -> Option<&KeyringInfo> {
        self.keyring_state
            .selected()
            .and_then(|i| self.keyrings.get(i))
    }

    /// The items the list is showing, after `item_filter`.
    ///
    /// The filter is a view, not a reload: `items` keeps every row the
    /// backend sent and each `ItemInfo` keeps the `id` that addresses it, so
    /// acting on a filtered row still reaches the right item.
    pub fn visible_items(&self) -> Vec<&ItemInfo> {
        self.items
            .iter()
            .filter(|item| self.item_matches(item))
            .collect()
    }

    /// How many rows the item list is showing. Same predicate as
    /// [`Self::visible_items`], without the allocation — the cursor and the
    /// filtered view have to agree on the length or `G` lands off the end.
    pub fn visible_item_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| self.item_matches(item))
            .count()
    }

    fn item_matches(&self, item: &ItemInfo) -> bool {
        if self.item_filter.is_empty() {
            return true;
        }
        let needle = self.item_filter.to_lowercase();
        item.label.to_lowercase().contains(&needle)
            // Attribute values are where the useful detail hides — a URL, an
            // account name — so they match too.
            || item.attributes.iter().any(|(key, value)| {
                key.to_lowercase().contains(&needle) || value.to_lowercase().contains(&needle)
            })
    }

    /// The cursor indexes the *filtered* list, so this does too.
    pub fn selected_item(&self) -> Option<&ItemInfo> {
        self.item_state
            .selected()
            .and_then(|i| self.visible_items().get(i).copied())
    }

    pub fn selected_ssh_key(&self) -> Option<&SshKeyInfo> {
        self.ssh_state.selected().and_then(|i| self.ssh_keys.get(i))
    }

    /// Whether the first scan has landed. Until it has, an empty key list and
    /// an unset agent mean "not known yet", not "nothing there".
    pub fn ssh_ready(&self) -> bool {
        self.ssh_loaded
    }

    pub fn selected_gpg_key(&self) -> Option<&GpgKeyInfo> {
        self.gpg_state.selected().and_then(|i| self.gpg_keys.get(i))
    }

    /// Whether the keyring has been read at least once.
    pub fn gpg_ready(&self) -> bool {
        self.gpg_loaded
    }

    /// Forget any revealed secret. Called on every navigation.
    fn hide_secret(&mut self) {
        self.revealed = None;
    }

    /// Hand the parked external command to the event loop, if there is one.
    pub fn take_external(&mut self) -> Option<External> {
        self.external.take()
    }

    /// Record how an external command went and re-read whatever it touched.
    pub fn on_external_done(&mut self, external: &External, outcome: Result<String, String>) {
        match outcome {
            Ok(message) => {
                self.error = None;
                self.status = message;
            }
            Err(message) => self.error = Some(message),
        }
        self.refresh_for(external.refresh());
    }

    fn refresh_for(&self, refresh: Refresh) {
        match refresh {
            Refresh::Keyrings => self.send(SecretsRequest::ListKeyrings),
            Refresh::SshKeys => self.send_ssh(SshRequest::ListKeys),
            Refresh::GpgKeys => self.send_gpg(GpgRequest::ListKeys {
                filter: self.gpg_filter,
            }),
            Refresh::Nothing => {}
        }
    }

    /// The keymap in force, so the help overlay can show the user's own keys.
    pub fn keymaps(&self) -> &Keymaps {
        &self.keymaps
    }

    /// Which keymap a keypress is resolved against right now.
    pub fn mode(&self) -> Mode {
        match self.prompt {
            Some(Prompt::Ask(_)) => Mode::Input,
            Some(_) => Mode::Prompt,
            None => Mode::Main,
        }
    }

    pub fn handle_key(&mut self, event: KeyEvent) {
        // Not a press (Windows sends releases too), or a key with no name in
        // the config syntax.
        let Some(pressed) = ModifiedKey::from_event(event) else {
            return;
        };

        // Help is modal: any key dismisses it, including one that would
        // otherwise be bound. Nothing is acted on, so `?` then `x` cannot
        // delete anything.
        if self.show_help {
            self.show_help = false;
            self.pending.clear();
            return;
        }

        let mode = self.mode();
        self.pending.push(pressed);
        let section = self.section;
        let resolution = self
            .keymaps
            .get(mode)
            // In a prompt every action applies; in the main view only the
            // current section's do.
            .resolve_where(&self.pending, |action| {
                mode == Mode::Prompt || action.applies_to(section)
            });
        match resolution {
            // A longer chord starts here; wait for the rest.
            Resolution::Pending => {}
            Resolution::None => {
                self.pending.clear();
                // In a text field anything the keymap does not claim is
                // literal text. Modified keys are excluded: ctrl+j is a
                // binding someone may add, not a `j` to type. Shift is not,
                // since that is how capitals arrive.
                if mode == Mode::Input
                    && !pressed.mods.ctrl
                    && !pressed.mods.alt
                    && !pressed.mods.super_
                {
                    match pressed.key {
                        Key::Char(c) => self.input.insert(c),
                        Key::Space => self.input.insert(' '),
                        _ => {}
                    }
                }
            }
            Resolution::Exact(action) => {
                self.pending.clear();
                self.dispatch(mode, action);
            }
        }
    }

    fn dispatch(&mut self, mode: Mode, action: Action) {
        if mode == Mode::Input {
            self.dispatch_input(action);
            return;
        }
        if mode == Mode::Prompt {
            self.dispatch_prompt(action);
            return;
        }

        match action {
            Action::Quit => self.should_quit = true,
            Action::Help => self.show_help = true,
            Action::Refresh => self.refresh(),

            Action::NextSection => self.set_section(self.section.next()),
            Action::PrevSection => self.set_section(self.section.prev()),
            Action::SectionPasswords => self.set_section(Section::Keyrings),
            Action::SectionGpgKeys => self.set_section(Section::GpgKeys),
            Action::SectionSshKeys => self.set_section(Section::SshKeys),

            Action::MoveDown => self.move_selection(1),
            Action::MoveUp => self.move_selection(-1),
            Action::First => self.jump_selection(true),
            Action::Last => self.jump_selection(false),
            Action::FocusLeft => self.shift_focus(-1),
            Action::FocusRight => self.shift_focus(1),

            Action::Unlock => self.lock_selected(false),
            Action::Lock => self.lock_selected(true),
            Action::ToggleSecret => self.toggle_secret(),
            Action::FilterItems => {
                if self.section == Section::Keyrings {
                    // Pre-filled with the current filter so `/` is also how
                    // you edit or clear one.
                    let current = self.item_filter.clone();
                    self.ask(Question::ItemFilter, &current);
                }
            }
            Action::DeleteItem => self.confirm(Prompt::ConfirmDeleteItem),
            Action::NewKeyring => {
                if self.section == Section::Keyrings {
                    self.ask(Question::NewKeyringLabel, "");
                }
            }
            Action::DeleteKeyring => self.confirm(Prompt::ConfirmDeleteKeyring),
            Action::CopySecret => self.copy_secret(),

            Action::CopySshKey => self.copy_ssh(false),
            Action::CopySshFingerprint => self.copy_ssh(true),
            Action::CopyGpgFingerprint => self.copy_gpg_fingerprint(),

            Action::AgentAdd => self.add_to_agent(),
            Action::SshCopyId => self.copy_key_to_host(),
            Action::AgentRemove => self.remove_from_agent(),
            Action::SshPassphrase => self.change_ssh_passphrase(),
            Action::SshDelete => self.confirm(Prompt::ConfirmSshDelete),
            Action::NewSshKey => {
                if self.section == Section::SshKeys {
                    self.prompt = Some(Prompt::NewSshKey);
                }
            }

            Action::GpgEdit => self.edit_gpg_key(),
            Action::GpgExport => self.export_gpg_key(),
            Action::GpgImport => {
                if self.section == Section::GpgKeys {
                    // Pre-filled with the home directory, which is where a
                    // downloaded key usually lands and saves typing the stem.
                    let home = dirs::home_dir()
                        .map(|path| format!("{}/", path.display()))
                        .unwrap_or_default();
                    self.ask(Question::GpgImportPath, &home);
                }
            }
            Action::GpgSearch => {
                if self.section == Section::GpgKeys {
                    self.ask(Question::GpgSearch, "");
                }
            }
            Action::GpgPublish => self.confirm(Prompt::ConfirmGpgPublish),
            Action::GpgDelete => self.confirm(Prompt::ConfirmGpgDelete),
            // gpg --full-generate-key asks everything itself, so there is
            // nothing for us to ask first.
            Action::NewGpgKey => self.run_gpg(GpgAction::Generate, None),
            Action::ToggleGpgFilter => self.toggle_gpg_filter(),

            // Prompt- and field-only; harmless if someone binds them in the
            // main map, where they have nothing to act on.
            Action::Backspace
            | Action::DeleteChar
            | Action::CursorLeft
            | Action::CursorRight
            | Action::CursorHome
            | Action::CursorEnd
            | Action::DeleteWord
            | Action::ClearBefore
            | Action::Confirm
            | Action::Cancel
            | Action::Choose1
            | Action::Choose2
            | Action::Choose3 => {}
        }
    }

    fn dispatch_prompt(&mut self, action: Action) {
        let Some(prompt) = self.prompt else {
            return;
        };

        match prompt {
            // Handled by `dispatch_input`; this arm keeps the match total.
            Prompt::Ask(_) => {}
            Prompt::NewSshKey => match action {
                // Enter picks the recommended algorithm, like a default
                // button; the numbers pick explicitly.
                Action::Choose1 | Action::Confirm => self.generate_ssh_key("ed25519", None),
                Action::Choose2 => self.generate_ssh_key("ecdsa", Some(521)),
                Action::Choose3 => self.generate_ssh_key("rsa", Some(4096)),
                Action::Cancel => self.cancel_prompt(),
                _ => {}
            },
            Prompt::ConfirmGpgDelete => match action {
                Action::Confirm => {
                    self.prompt = None;
                    let fingerprint = self.selected_gpg_key().map(|key| key.fingerprint.clone());
                    self.run_gpg(GpgAction::Delete, fingerprint);
                }
                Action::Cancel => self.cancel_prompt(),
                _ => {}
            },
            Prompt::ConfirmGpgPublish => match action {
                Action::Confirm => {
                    self.prompt = None;
                    let fingerprint = self.selected_gpg_key().map(|key| key.fingerprint.clone());
                    self.run_gpg(GpgAction::Publish, fingerprint);
                }
                Action::Cancel => self.cancel_prompt(),
                _ => {}
            },
            Prompt::ConfirmDeleteItem => match action {
                Action::Confirm => {
                    self.prompt = None;
                    self.delete_item();
                }
                Action::Cancel => self.cancel_prompt(),
                _ => {}
            },
            Prompt::ConfirmSshDelete => match action {
                Action::Confirm => {
                    self.prompt = None;
                    self.delete_ssh_key();
                }
                Action::Cancel => self.cancel_prompt(),
                _ => {}
            },
            Prompt::ConfirmDeleteKeyring => match action {
                Action::Confirm => {
                    self.prompt = None;
                    self.delete_keyring();
                }
                Action::Cancel => self.cancel_prompt(),
                _ => {}
            },
        }
    }

    /// Editing keys in a text field, plus the two that end it.
    fn dispatch_input(&mut self, action: Action) {
        let Some(Prompt::Ask(question)) = self.prompt else {
            return;
        };

        match action {
            Action::Confirm => self.submit_input(question),
            Action::Cancel => {
                self.input = Input::default();
                self.cancel_prompt();
            }
            Action::Backspace => self.input.backspace(),
            Action::DeleteChar => self.input.delete(),
            Action::CursorLeft => self.input.left(),
            Action::CursorRight => self.input.right(),
            Action::CursorHome => self.input.home(),
            Action::CursorEnd => self.input.end(),
            Action::DeleteWord => self.input.delete_word_before(),
            Action::ClearBefore => self.input.clear_before(),
            _ => {}
        }
    }

    /// Turn the typed answer into the command it was asked for.
    ///
    /// An empty field is a no-op rather than an error: it is what someone
    /// pressing Enter to dismiss the box means, and `gpg --import ""` is not
    /// a thing worth running.
    fn submit_input(&mut self, question: Question) {
        let answer = self.input.value().trim().to_string();

        // The filter is the one answer where empty means something: it clears
        // the filter rather than cancelling the edit.
        if question == Question::ItemFilter {
            self.prompt = None;
            self.input = Input::default();
            self.set_item_filter(answer);
            return;
        }

        if answer.is_empty() {
            self.input = Input::default();
            self.cancel_prompt();
            return;
        }

        self.prompt = None;
        self.input = Input::default();

        match question {
            Question::GpgImportPath => self.run_gpg(GpgAction::Import, Some(answer)),
            Question::GpgSearch => self.run_gpg(GpgAction::Search, Some(answer)),
            Question::SshCopyTarget => {
                // The key to install comes from the cursor, not the field —
                // the field only answers "to where".
                let Some(path) = self
                    .selected_ssh_key()
                    .and_then(|key| key.public_path.clone())
                else {
                    self.status = "that key has no public half to copy".into();
                    return;
                };
                self.external = Some(External::SshCopyId {
                    public_key: path,
                    target: answer,
                });
            }
            Question::NewKeyringLabel => {
                self.status = format!("creating {answer}…");
                self.send(SecretsRequest::CreateKeyring { label: answer });
            }
            // Handled above, before the empty-answer check.
            Question::ItemFilter => {}
        }
    }

    /// Narrow the item list, and put the cursor somewhere that exists.
    ///
    /// A revealed secret is hidden too: the row it belongs to may well have
    /// just been filtered out from under it.
    fn set_item_filter(&mut self, filter: String) {
        self.item_filter = filter;
        self.hide_secret();

        let visible = self.visible_items().len();
        if visible == 0 {
            self.item_state.select(None);
        } else {
            let index = self.item_state.selected().unwrap_or(0).min(visible - 1);
            self.item_state.select(Some(index));
        }

        self.status = if self.item_filter.is_empty() {
            "filter cleared".into()
        } else {
            format!(
                "{visible} of {} items match {:?}",
                self.items.len(),
                self.item_filter
            )
        };
    }

    /// Copy the selected item's secret.
    ///
    /// An already-revealed secret is copied straight from memory; otherwise
    /// this fetches it the way `s` does, and [`Self::copy_on_reveal`] makes
    /// the reply go to the clipboard instead of to the screen.
    fn copy_secret(&mut self) {
        if self.section != Section::Keyrings {
            return;
        }
        let Some(keyring) = self.selected_keyring().map(|keyring| keyring.id) else {
            return;
        };
        let Some((item, label)) = self
            .selected_item()
            .map(|item| (item.id, item.label.clone()))
        else {
            return;
        };

        if let Some(secret) = self.revealed.clone() {
            self.copy(secret, &format!("the secret for {label}"), true);
            return;
        }

        self.copy_on_reveal = true;
        self.send(SecretsRequest::RevealSecret { keyring, item });
        self.status = format!("copying the secret for {label}…");
    }

    /// Copy the selected SSH key's public line, or its fingerprint.
    ///
    /// Neither is secret, so neither is wiped.
    fn copy_ssh(&mut self, fingerprint: bool) {
        if self.section != Section::SshKeys {
            return;
        }
        let Some((text, what)) = self.selected_ssh_key().map(|key| {
            if fingerprint {
                (key.fingerprint.clone(), "the fingerprint")
            } else {
                (key.public_line.trim_end().to_owned(), "the public key")
            }
        }) else {
            return;
        };
        if text.is_empty() {
            self.status = "nothing to copy for that key".into();
            return;
        }
        self.copy(Zeroizing::new(text), what, false);
    }

    fn copy_gpg_fingerprint(&mut self) {
        if self.section != Section::GpgKeys {
            return;
        }
        let Some(fingerprint) = self.selected_gpg_key().map(|key| key.fingerprint.clone()) else {
            return;
        };
        self.copy(Zeroizing::new(fingerprint), "the fingerprint", false);
    }

    /// Ask the backend to delete the keyring under the cursor.
    ///
    /// Everything in it goes too, which is what the confirmation is for. The
    /// cursor is left to the refresh: `Reply::Keyrings` cannot find the old
    /// label any more and falls back to the first row.
    fn delete_keyring(&mut self) {
        let Some(keyring) = self.selected_keyring().map(|keyring| keyring.id) else {
            return;
        };
        self.hide_secret();
        self.send(SecretsRequest::DeleteKeyring { keyring });
        self.status = "deleting…".into();
    }

    /// Ask the backend to delete the item under the cursor.
    ///
    /// `ItemInfo::id` indexes the backend's own table, which is why filtering
    /// is safe to do as a view: the row still knows what it is.
    fn delete_item(&mut self) {
        let Some(keyring) = self.selected_keyring().map(|keyring| keyring.id) else {
            return;
        };
        let Some(item) = self.selected_item().map(|item| item.id) else {
            return;
        };
        self.hide_secret();
        let _ = self
            .secrets
            .send(SecretsRequest::DeleteItem { keyring, item });
        self.status = "deleting…".into();
    }

    /// Open a text field asking `question`, pre-filled with `initial`.
    fn ask(&mut self, question: Question, initial: &str) {
        self.input = Input::new(initial);
        self.prompt = Some(Prompt::Ask(question));
    }

    fn cancel_prompt(&mut self) {
        self.prompt = None;
        self.status = "cancelled".into();
    }

    /// Open a confirmation, but only when there is something to confirm —
    /// in the right section, with a row actually selected.
    fn confirm(&mut self, prompt: Prompt) {
        let ready = match prompt {
            Prompt::ConfirmGpgDelete | Prompt::ConfirmGpgPublish => {
                self.section == Section::GpgKeys && self.selected_gpg_key().is_some()
            }
            Prompt::ConfirmDeleteItem => {
                self.section == Section::Keyrings && self.selected_item().is_some()
            }
            Prompt::ConfirmDeleteKeyring => {
                self.section == Section::Keyrings && self.selected_keyring().is_some()
            }
            Prompt::ConfirmSshDelete if self.section != Section::SshKeys => false,
            Prompt::ConfirmSshDelete => {
                let on_disk = self.selected_ssh_key().map(|key| {
                    (
                        key.name.clone(),
                        key.private_path.is_some() || key.public_path.is_some(),
                    )
                });
                match on_disk {
                    // An agent-only identity has no files to unlink; `x` is
                    // what gets rid of that one, and saying so beats a modal
                    // that would have nothing to delete.
                    Some((name, false)) => {
                        self.status =
                            format!("{name} has no files on disk; x drops it from the agent");
                        false
                    }
                    Some((_, true)) => true,
                    None => false,
                }
            }
            // Neither of these is a confirmation; they are opened directly.
            Prompt::NewSshKey | Prompt::Ask(_) => false,
        };
        if ready {
            self.prompt = Some(prompt);
        }
    }

    fn set_section(&mut self, section: Section) {
        if self.section == section {
            return;
        }
        self.hide_secret();
        self.section = section;
        self.error = None;
        // Each section has its own set of panes, so focus starts at its left.
        self.pane = panes_for(section)[0];
        self.detail_scroll = 0;

        match section {
            Section::Keyrings => self.status = "keyrings".into(),
            Section::SshKeys => {
                if self.ssh_loaded {
                    self.status = self.describe_ssh_keys();
                } else {
                    self.status = "scanning ~/.ssh…".into();
                    self.send_ssh(SshRequest::ListKeys);
                }
            }
            Section::GpgKeys => {
                if self.gpg_loaded {
                    self.status = self.describe_gpg_keys();
                } else {
                    self.status = "reading the GnuPG keyring…".into();
                    self.send_gpg(GpgRequest::ListKeys {
                        filter: self.gpg_filter,
                    });
                }
            }
        }
    }

    /// Move focus one pane left or right, stopping at the ends.
    ///
    /// Which panes exist depends on the section — see [`panes_for`] — so the
    /// same `h`/`l` walks a three-pane Passwords view and a two-pane key view.
    fn shift_focus(&mut self, delta: isize) {
        let panes = panes_for(self.section);
        let current = panes
            .iter()
            .position(|pane| *pane == self.pane)
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, panes.len() as isize - 1) as usize;
        if next == current {
            return;
        }

        self.hide_secret();
        self.pane = panes[next];
        self.detail_scroll = 0;

        // Entering a list that has never had a cursor should put one on the
        // first row rather than looking empty.
        if self.pane == Pane::List
            && self.section == Section::Keyrings
            && self.item_state.selected().is_none()
            && self.visible_item_count() > 0
        {
            self.item_state.select(Some(0));
        }
    }

    fn move_selection(&mut self, delta: isize) {
        // A focused detail pane scrolls instead of moving a cursor, which is
        // the only way to reach the bottom of a long GPG key.
        if self.pane == Pane::Details {
            self.scroll_details(delta);
            return;
        }

        self.hide_secret();
        self.detail_scroll = 0;
        match (self.section, self.pane) {
            (Section::Keyrings, Pane::Keyrings) => {
                if step(&mut self.keyring_state, self.keyrings.len(), delta) {
                    self.select_other_keyring();
                }
            }
            (Section::Keyrings, _) => {
                let len = self.visible_item_count();
                step(&mut self.item_state, len, delta);
            }
            (Section::SshKeys, _) => {
                step(&mut self.ssh_state, self.ssh_keys.len(), delta);
            }
            (Section::GpgKeys, _) => {
                step(&mut self.gpg_state, self.gpg_keys.len(), delta);
            }
        }
    }

    /// Scroll the detail pane, clamped to what it actually drew.
    fn scroll_details(&mut self, delta: isize) {
        let overflow = self.detail_lines.saturating_sub(self.detail_height);
        let next = (i32::from(self.detail_scroll) + delta as i32).clamp(0, i32::from(overflow));
        self.detail_scroll = next as u16;
    }

    fn jump_selection(&mut self, first: bool) {
        if self.pane == Pane::Details {
            self.detail_scroll = if first {
                0
            } else {
                self.detail_lines.saturating_sub(self.detail_height)
            };
            return;
        }

        self.hide_secret();
        self.detail_scroll = 0;
        let (state, len) = match (self.section, self.pane) {
            (Section::Keyrings, Pane::Keyrings) => (&mut self.keyring_state, self.keyrings.len()),
            (Section::Keyrings, _) => {
                let len = self.visible_item_count();
                (&mut self.item_state, len)
            }
            (Section::SshKeys, _) => (&mut self.ssh_state, self.ssh_keys.len()),
            (Section::GpgKeys, _) => (&mut self.gpg_state, self.gpg_keys.len()),
        };
        if len == 0 {
            return;
        }
        let target = if first { 0 } else { len - 1 };
        let changed = state.selected() != Some(target);
        state.select(Some(target));
        if changed && self.section == Section::Keyrings && self.pane == Pane::Keyrings {
            self.select_other_keyring();
        }
    }

    fn refresh(&mut self) {
        self.hide_secret();
        self.error = None;
        match self.section {
            Section::Keyrings => {
                self.status = "refreshing…".into();
                self.send(SecretsRequest::ListKeyrings);
            }
            Section::SshKeys => {
                self.status = "scanning ~/.ssh…".into();
                self.send_ssh(SshRequest::ListKeys);
            }
            Section::GpgKeys => {
                self.status = "reading the GnuPG keyring…".into();
                self.send_gpg(GpgRequest::ListKeys {
                    filter: self.gpg_filter,
                });
            }
        }
    }

    // --- Passwords -------------------------------------------------------

    /// The keyring cursor moved to a different keyring.
    ///
    /// A filter belongs to the list it was typed against, so it goes here —
    /// but *not* in [`Self::load_selected_items`], which also runs on a plain
    /// refresh, where keeping the filter is what the user expects.
    fn select_other_keyring(&mut self) {
        self.item_filter.clear();
        self.load_selected_items();
    }

    fn load_selected_items(&mut self) {
        self.items.clear();
        self.item_state.select(None);
        if let Some(keyring) = self.selected_keyring() {
            self.send(SecretsRequest::ListItems {
                keyring: keyring.id,
            });
        }
    }

    fn lock_selected(&mut self, locked: bool) {
        if self.section != Section::Keyrings {
            return;
        }
        let Some((id, label)) = self
            .selected_keyring()
            .map(|keyring| (keyring.id, keyring.label.clone()))
        else {
            return;
        };
        self.hide_secret();
        self.status = format!("{} {label}…", if locked { "locking" } else { "unlocking" });
        self.send(if locked {
            SecretsRequest::Lock { keyring: id }
        } else {
            SecretsRequest::Unlock { keyring: id }
        });
    }

    fn toggle_secret(&mut self) {
        if self.section != Section::Keyrings {
            return;
        }
        if self.revealed.is_some() {
            self.hide_secret();
            return;
        }
        let Some(keyring) = self.selected_keyring().map(|k| k.id) else {
            return;
        };
        let Some(item) = self.selected_item().map(|i| i.id) else {
            self.status = "no item selected".into();
            return;
        };
        self.send(SecretsRequest::RevealSecret { keyring, item });
    }

    // --- SSH keys --------------------------------------------------------

    fn add_to_agent(&mut self) {
        if self.section != Section::SshKeys {
            return;
        }
        let Some((name, in_agent, path)) = self.selected_ssh_key().map(|key| {
            (
                key.name.clone(),
                key.in_agent,
                key.private_path().map(ToOwned::to_owned),
            )
        }) else {
            return;
        };

        if in_agent {
            self.status = format!("{name} is already in the agent");
            return;
        }
        let Some(path) = path else {
            self.status = format!("{name} has no private key file to add");
            return;
        };
        if matches!(self.agent, AgentStatus::NotConfigured) {
            self.error = Some("no agent to add to (SSH_AUTH_SOCK is unset)".into());
            return;
        }

        // Runs with the TUI suspended: ssh-add may need a passphrase or a
        // touch on a security key.
        self.external = Some(External::SshAdd(path));
    }

    fn remove_from_agent(&mut self) {
        if self.section != Section::SshKeys {
            return;
        }
        let Some((id, name, in_agent)) = self
            .selected_ssh_key()
            .map(|key| (key.id, key.name.clone(), key.in_agent))
        else {
            return;
        };
        if !in_agent {
            self.status = format!("{name} is not in the agent");
            return;
        }
        self.status = format!("removing {name} from the agent…");
        self.send_ssh(SshRequest::RemoveFromAgent { key: id });
    }

    /// Ask where to install the selected key's public half.
    fn copy_key_to_host(&mut self) {
        if self.section != Section::SshKeys {
            return;
        }
        let Some(key) = self.selected_ssh_key() else {
            return;
        };
        // An agent-only identity has no `.pub` on disk for ssh-copy-id to
        // read, so there is nothing to offer.
        if key.public_path.is_none() {
            let name = key.name.clone();
            self.status = format!("{name} has no public key file to copy");
            return;
        }
        self.ask(Question::SshCopyTarget, "");
    }

    /// Hand the key to `ssh-keygen -p`, which asks for the old passphrase and
    /// then the new one.
    ///
    /// No confirmation: it is reversible by running it again, and ssh-keygen
    /// will not get anywhere without the current passphrase anyway. Hardware
    /// keys need no special case — their file holds a credential handle, not
    /// a secret, and re-encrypting it needs no token.
    fn change_ssh_passphrase(&mut self) {
        if self.section != Section::SshKeys {
            return;
        }
        let Some((name, path)) = self
            .selected_ssh_key()
            .map(|key| (key.name.clone(), key.private_path().map(ToOwned::to_owned)))
        else {
            return;
        };
        // A passphrase protects the private half; a lone `.pub` has none, and
        // neither does an identity that only exists in the agent.
        let Some(path) = path else {
            self.status = format!("{name} has no private key file to re-encrypt");
            return;
        };
        self.external = Some(External::SshPassphrase(path));
    }

    /// Ask the backend to unlink the selected key's files.
    fn delete_ssh_key(&mut self) {
        let Some(id) = self.selected_ssh_key().map(|key| key.id) else {
            return;
        };
        self.status = "deleting…".into();
        self.send_ssh(SshRequest::DeleteKey { key: id });
    }

    fn generate_ssh_key(&mut self, algorithm: &'static str, bits: Option<u32>) {
        self.prompt = None;
        // ssh-keygen prompts for the destination path and the passphrase, so
        // no key material or passphrase passes through this process.
        self.external = Some(External::SshKeygen { algorithm, bits });
    }

    fn describe_ssh_keys(&self) -> String {
        format!("{} key(s) · {}", self.ssh_keys.len(), self.agent.describe())
    }

    // --- GPG keys --------------------------------------------------------

    fn edit_gpg_key(&mut self) {
        if self.section != Section::GpgKeys {
            return;
        }
        // --edit-key on a key we have no private half for still works: it is
        // how you certify someone else's key and set owner trust.
        let fingerprint = self.selected_gpg_key().map(|key| key.fingerprint.clone());
        if fingerprint.is_some() {
            self.run_gpg(GpgAction::Edit, fingerprint);
        }
    }

    fn export_gpg_key(&mut self) {
        if self.section != Section::GpgKeys {
            return;
        }
        let fingerprint = self.selected_gpg_key().map(|key| key.fingerprint.clone());
        if fingerprint.is_some() {
            self.run_gpg(GpgAction::Export, fingerprint);
        }
    }

    fn toggle_gpg_filter(&mut self) {
        if self.section != Section::GpgKeys {
            return;
        }
        self.gpg_filter = self.gpg_filter.toggled();
        self.status = format!("showing {}…", self.gpg_filter.describe());
        self.send_gpg(GpgRequest::ListKeys {
            filter: self.gpg_filter,
        });
    }

    /// Park a `gpg` invocation for the event loop to run with the TUI
    /// suspended. Private key operations prompt through pinentry, so no
    /// passphrase passes through this process.
    fn run_gpg(&mut self, action: GpgAction, fingerprint: Option<String>) {
        if self.section != Section::GpgKeys {
            return;
        }
        self.external = Some(External::Gpg {
            action,
            fingerprint,
        });
    }

    fn describe_gpg_keys(&self) -> String {
        format!(
            "{} {} · {}",
            self.gpg_keys.len(),
            self.gpg_filter.describe(),
            self.gpg_engine
        )
    }

    // --- Replies ---------------------------------------------------------

    pub fn on_reply(&mut self, reply: Reply) {
        match reply {
            Reply::Keyrings(keyrings) => {
                // Keep the selected keyring across a refresh where possible.
                let previous = self.selected_keyring().map(|k| k.label.clone());
                self.keyrings = keyrings;
                let restored = previous
                    .as_deref()
                    .and_then(|label| self.keyrings.iter().position(|k| k.label == label))
                    .or_else(|| (!self.keyrings.is_empty()).then_some(0));
                self.keyring_state.select(restored);
                // Landing on a different keyring than before — because this
                // one was just deleted, or renamed elsewhere — means a new
                // list, so a filter typed against the old one goes with it.
                if self.selected_keyring().map(|k| k.label.clone()) != previous {
                    self.item_filter.clear();
                }
                if self.section == Section::Keyrings {
                    self.status = format!("{} keyring(s)", self.keyrings.len());
                }
                self.load_selected_items();
            }

            Reply::Items { keyring, items } => {
                // Ignore a late reply for a keyring the user has left.
                if self.selected_keyring().map(|k| k.id) != Some(keyring) {
                    return;
                }
                self.items = items;
                // A filter can survive a reload — after a delete, say — so
                // the cursor goes on the first *visible* row.
                let visible = self.visible_item_count();
                self.item_state.select((visible > 0).then_some(0));
                let locked = self.selected_keyring().is_some_and(|k| k.locked);
                if self.section == Section::Keyrings {
                    self.status = if self.items.is_empty() && locked {
                        "keyring is locked — press u to unlock".into()
                    } else if self.item_filter.is_empty() {
                        format!("{} item(s)", self.items.len())
                    } else {
                        format!("{visible} of {} item(s) match", self.items.len())
                    };
                }
            }

            Reply::Secret {
                keyring,
                item,
                value,
            } => {
                // Only act on it if the cursor is still on the row we asked
                // for; otherwise this secret belongs to a row the user left.
                let still_current = self.selected_keyring().map(|k| k.id) == Some(keyring)
                    && self.selected_item().map(|i| i.id) == Some(item);
                if !still_current {
                    self.copy_on_reveal = false;
                    return;
                }
                if std::mem::take(&mut self.copy_on_reveal) {
                    let label = self
                        .selected_item()
                        .map(|item| item.label.clone())
                        .unwrap_or_default();
                    // Deliberately not also assigned to `revealed`: a copy
                    // must not put the secret on screen.
                    self.copy(value, &format!("the secret for {label}"), true);
                } else {
                    self.revealed = Some(value);
                }
            }

            Reply::SshKeys { keys, agent } => {
                // Keep the cursor on the same key across a rescan; names are
                // unique within a directory and stable across agent changes.
                let previous = self.selected_ssh_key().map(|key| key.name.clone());
                self.ssh_keys = keys;
                self.agent = agent;
                self.ssh_loaded = true;

                let restored = previous
                    .and_then(|name| self.ssh_keys.iter().position(|key| key.name == name))
                    .or_else(|| (!self.ssh_keys.is_empty()).then_some(0));
                self.ssh_state.select(restored);

                if self.section == Section::SshKeys {
                    self.status = self.describe_ssh_keys();
                }
            }

            Reply::GpgKeys {
                keys,
                filter,
                engine,
            } => {
                // Ignore a listing for a filter the user has since changed.
                if filter != self.gpg_filter {
                    return;
                }
                // Keep the cursor on the same key across a refresh; the
                // fingerprint is the only truly stable handle.
                let previous = self.selected_gpg_key().map(|key| key.fingerprint.clone());
                self.gpg_keys = keys;
                self.gpg_engine = engine;
                self.gpg_loaded = true;

                let restored = previous
                    .and_then(|fingerprint| {
                        self.gpg_keys
                            .iter()
                            .position(|key| key.fingerprint == fingerprint)
                    })
                    .or_else(|| (!self.gpg_keys.is_empty()).then_some(0));
                self.gpg_state.select(restored);

                if self.section == Section::GpgKeys {
                    self.status = self.describe_gpg_keys();
                }
            }

            Reply::Status { message, refresh } => {
                self.error = None;
                self.status = message;
                self.refresh_for(refresh);
            }

            Reply::Error(message) => {
                self.hide_secret();
                self.error = Some(message);
            }
        }
    }
}

/// Move `state` by `delta` within `0..len`, clamping at both ends. Returns
/// whether the selection actually changed.
fn step(state: &mut ListState, len: usize, delta: isize) -> bool {
    if len == 0 {
        if state.selected().is_some() {
            state.select(None);
            return true;
        }
        return false;
    }
    let current = state.selected().unwrap_or(0) as isize;
    let next = (current + delta).clamp(0, len as isize - 1) as usize;
    if state.selected() == Some(next) {
        return false;
    }
    state.select(Some(next));
    true
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use tokio::sync::mpsc::{self, UnboundedReceiver};

    use super::*;

    /// The wipe delay the harness runs with, so a test can assert on the one
    /// the request carries rather than on whatever the default happens to be.
    const TEST_CLEAR_AFTER: Duration = Duration::from_secs(30);

    struct Harness {
        app: App,
        secrets: UnboundedReceiver<SecretsRequest>,
        ssh: UnboundedReceiver<SshRequest>,
        gpg: UnboundedReceiver<GpgRequest>,
        clipboard: UnboundedReceiver<ClipboardRequest>,
    }

    impl Harness {
        fn new() -> Self {
            let (secrets_tx, secrets) = mpsc::unbounded_channel();
            let (ssh_tx, ssh) = mpsc::unbounded_channel();
            let (gpg_tx, gpg) = mpsc::unbounded_channel();
            let (clip_tx, clipboard) = mpsc::unbounded_channel();
            Self {
                app: App::new(
                    secrets_tx,
                    ssh_tx,
                    gpg_tx,
                    clip_tx,
                    Some(TEST_CLEAR_AFTER),
                    Keymaps::default(),
                ),
                secrets,
                ssh,
                gpg,
                clipboard,
            }
        }

        fn press(&mut self, code: KeyCode) {
            self.app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        }

        fn secrets_requests(&mut self) -> Vec<SecretsRequest> {
            let mut out = Vec::new();
            while let Ok(request) = self.secrets.try_recv() {
                out.push(request);
            }
            out
        }

        fn ssh_requests(&mut self) -> Vec<SshRequest> {
            let mut out = Vec::new();
            while let Ok(request) = self.ssh.try_recv() {
                out.push(request);
            }
            out
        }

        fn gpg_requests(&mut self) -> Vec<GpgRequest> {
            let mut out = Vec::new();
            while let Ok(request) = self.gpg.try_recv() {
                out.push(request);
            }
            out
        }

        /// What the clipboard backend was asked to copy, as
        /// `(text, what, clear_after)`. The text is only exposed here so a
        /// test can prove the right bytes were sent.
        fn clipboard_requests(&mut self) -> Vec<(String, String, Option<Duration>)> {
            let mut out = Vec::new();
            while let Ok(request) = self.clipboard.try_recv() {
                if let ClipboardRequest::Copy {
                    text,
                    what,
                    clear_after,
                } = request
                {
                    out.push((text.to_string(), what, clear_after));
                }
            }
            out
        }

        fn drain(&mut self) {
            self.secrets_requests();
            self.ssh_requests();
            self.gpg_requests();
            self.clipboard_requests();
        }

        /// Two keyrings loaded, cursor on the first, its items listed.
        fn loaded() -> Self {
            let mut harness = Self::new();
            harness.app.on_reply(Reply::Keyrings(vec![
                keyring(0, "Login", false),
                keyring(1, "Session", false),
            ]));
            harness.app.on_reply(Reply::Items {
                keyring: 0,
                items: vec![item(0, "alpha"), item(1, "beta")],
            });
            harness.drain();
            harness
        }

        /// In the SSH section with two keys: one on disk and in the agent, one
        /// on disk only.
        fn ssh_loaded() -> Self {
            let mut harness = Self::loaded();
            harness.press(KeyCode::Char('3'));
            harness.app.on_reply(Reply::SshKeys {
                keys: vec![
                    ssh_key(0, "id_ecdsa", true, true),
                    ssh_key(1, "id_rsa", true, false),
                ],
                agent: AgentStatus::Ready { loaded: 1 },
            });
            harness.drain();
            harness
        }

        /// In the GPG section with two keys: one of our own and one public.
        fn gpg_loaded() -> Self {
            let mut harness = Self::loaded();
            harness.press(KeyCode::Char('2'));
            harness.app.on_reply(Reply::GpgKeys {
                keys: vec![
                    gpg_key(0, "Me <me@example>", true),
                    gpg_key(1, "Them <them@example>", false),
                ],
                filter: GpgFilter::All,
                engine: "gpg 2.4.9".into(),
            });
            harness.drain();
            harness
        }
    }

    fn gpg_key(id: usize, uid: &str, has_secret: bool) -> GpgKeyInfo {
        GpgKeyInfo {
            id,
            key_id: format!("KEYID{id}"),
            fingerprint: format!("FPR{id}"),
            primary_uid: uid.into(),
            uids: Vec::new(),
            subkeys: Vec::new(),
            algorithm: "ed25519".into(),
            created: None,
            expires: None,
            owner_trust: "ultimate",
            has_secret,
            revoked: false,
            expired: false,
            disabled: false,
            capabilities: "sc".into(),
            on_card: false,
        }
    }

    fn keyring(id: usize, label: &str, locked: bool) -> KeyringInfo {
        KeyringInfo {
            id,
            label: label.into(),
            locked,
            is_default: id == 0,
        }
    }

    fn item(id: usize, label: &str) -> ItemInfo {
        ItemInfo {
            id,
            label: label.into(),
            attributes: BTreeMap::new(),
            locked: false,
            created: None,
            modified: None,
        }
    }

    fn ssh_key(id: usize, name: &str, has_private: bool, in_agent: bool) -> SshKeyInfo {
        SshKeyInfo {
            id,
            name: name.into(),
            private_path: has_private.then(|| PathBuf::from(format!("/home/u/.ssh/{name}"))),
            public_path: Some(PathBuf::from(format!("/home/u/.ssh/{name}.pub"))),
            algorithm: "ssh-ed25519".into(),
            bits: Some(256),
            comment: "u@host".into(),
            fingerprint: format!("SHA256:{name}"),
            encrypted: false,
            hardware_backed: false,
            in_agent,
            public_line: format!("ssh-ed25519 AAAA {name}"),
        }
    }

    // --- Passwords -------------------------------------------------------

    #[test]
    fn asks_for_keyrings_on_startup() {
        let mut harness = Harness::new();
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::ListKeyrings]
        );
        assert!(
            harness.ssh_requests().is_empty(),
            "the SSH section loads lazily"
        );
    }

    #[test]
    fn first_keyring_is_selected_and_its_items_requested() {
        let mut harness = Harness::new();
        harness.drain();
        harness.app.on_reply(Reply::Keyrings(vec![
            keyring(0, "Login", false),
            keyring(1, "Session", true),
        ]));

        assert_eq!(harness.app.keyring_state.selected(), Some(0));
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::ListItems { keyring: 0 }]
        );
    }

    #[test]
    fn refresh_keeps_the_cursor_on_the_same_keyring_by_label() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('j'));
        assert_eq!(
            harness.app.selected_keyring().map(|k| k.label.as_str()),
            Some("Session")
        );

        // A refresh where the keyring order changed must not move the cursor
        // to a different keyring.
        harness.app.on_reply(Reply::Keyrings(vec![
            keyring(0, "Session", false),
            keyring(1, "Login", false),
        ]));
        assert_eq!(
            harness.app.selected_keyring().map(|k| k.label.as_str()),
            Some("Session")
        );
    }

    #[test]
    fn moving_between_keyrings_reloads_items() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('j'));

        assert!(harness.app.items.is_empty(), "stale items must be cleared");
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::ListItems { keyring: 1 }]
        );
    }

    #[test]
    fn clamps_at_the_ends_without_refetching() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('k')); // already at the top
        assert_eq!(harness.app.keyring_state.selected(), Some(0));
        assert!(
            harness.secrets_requests().is_empty(),
            "no reload for a no-op move"
        );
    }

    #[test]
    fn any_navigation_wipes_a_revealed_secret() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('l')); // focus items
        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });
        assert!(harness.app.revealed.is_some());

        harness.press(KeyCode::Char('j'));
        assert!(harness.app.revealed.is_none(), "secret outlived its row");
    }

    #[test]
    fn toggling_hides_without_a_round_trip() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('l'));
        harness.drain();

        harness.press(KeyCode::Char('s'));
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::RevealSecret {
                keyring: 0,
                item: 0
            }]
        );
        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });

        harness.press(KeyCode::Char('s'));
        assert!(harness.app.revealed.is_none());
        assert!(harness.secrets_requests().is_empty());
    }

    #[test]
    fn a_secret_for_a_row_we_left_is_dropped() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('l'));
        harness.press(KeyCode::Char('j')); // now on item 1
        harness.drain();

        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });
        assert!(harness.app.revealed.is_none());
    }

    #[test]
    fn items_for_a_keyring_we_left_are_dropped() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('j')); // moved to keyring 1
        harness.drain();

        harness.app.on_reply(Reply::Items {
            keyring: 0,
            items: vec![item(0, "late")],
        });
        assert!(harness.app.items.is_empty());
    }

    #[test]
    fn locked_and_empty_explains_itself() {
        let mut harness = Harness::new();
        harness
            .app
            .on_reply(Reply::Keyrings(vec![keyring(0, "Login", true)]));
        harness.app.on_reply(Reply::Items {
            keyring: 0,
            items: Vec::new(),
        });
        assert!(
            harness.app.status.contains("locked"),
            "status was {:?}",
            harness.app.status
        );
    }

    #[test]
    fn unlock_only_acts_in_the_keyrings_section() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('2')); // GPG section
        harness.drain();
        harness.press(KeyCode::Char('u'));
        assert!(harness.secrets_requests().is_empty());

        harness.press(KeyCode::Char('1'));
        harness.press(KeyCode::Char('u'));
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::Unlock { keyring: 0 }]
        );
    }

    #[test]
    fn a_status_refreshes_only_what_it_names() {
        let mut harness = Harness::loaded();
        harness.app.on_reply(Reply::Status {
            message: "Login unlocked".into(),
            refresh: Refresh::Keyrings,
        });
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::ListKeyrings]
        );
        assert!(harness.ssh_requests().is_empty());

        harness.app.on_reply(Reply::Status {
            message: "removed from the agent".into(),
            refresh: Refresh::SshKeys,
        });
        assert!(harness.secrets_requests().is_empty());
        assert_eq!(harness.ssh_requests(), vec![SshRequest::ListKeys]);
    }

    /// Four items whose labels and attributes overlap in different ways, so
    /// that a filter can be shown to match on each.
    fn filterable() -> Harness {
        let mut harness = Harness::new();
        harness
            .app
            .on_reply(Reply::Keyrings(vec![keyring(0, "Login", false)]));

        let mut gitlab = item(2, "GitLab token");
        gitlab
            .attributes
            .insert("service".into(), "gitlab.com".into());
        let mut mail = item(3, "Mail");
        mail.attributes
            .insert("username".into(), "greg@example".into());

        harness.app.on_reply(Reply::Items {
            keyring: 0,
            items: vec![item(0, "alpha"), item(1, "GitHub token"), gitlab, mail],
        });
        harness.drain();
        harness
    }

    fn visible_labels(app: &App) -> Vec<String> {
        app.visible_items()
            .iter()
            .map(|item| item.label.clone())
            .collect()
    }

    #[test]
    fn a_filter_narrows_the_item_list_by_label() {
        let mut harness = filterable();
        harness.press(KeyCode::Char('/'));
        assert_eq!(harness.app.prompt, Some(Prompt::Ask(Question::ItemFilter)));

        type_text(&mut harness, "git");
        harness.press(KeyCode::Enter);

        assert_eq!(
            visible_labels(&harness.app),
            vec!["GitHub token", "GitLab token"],
            "the match is case-insensitive"
        );
        assert_eq!(
            harness.app.items.len(),
            4,
            "filtering is a view; nothing is dropped"
        );
    }

    #[test]
    fn a_filter_matches_attributes_too() {
        let mut harness = filterable();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "greg@");
        harness.press(KeyCode::Enter);

        assert_eq!(
            visible_labels(&harness.app),
            vec!["Mail"],
            "an address stored as an attribute is findable"
        );
    }

    #[test]
    fn an_empty_filter_clears_rather_than_cancels() {
        let mut harness = filterable();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "git");
        harness.press(KeyCode::Enter);

        // `/` re-opens pre-filled, so this is also how a filter is edited.
        harness.press(KeyCode::Char('/'));
        assert_eq!(harness.app.input.value(), "git");

        harness
            .app
            .handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        harness.press(KeyCode::Enter);

        assert!(harness.app.item_filter.is_empty());
        assert_eq!(visible_labels(&harness.app).len(), 4);
    }

    #[test]
    fn a_filter_keeps_the_cursor_on_a_row_that_exists() {
        let mut harness = filterable();
        harness.press(KeyCode::Char('l')); // focus the item list
        harness.press(KeyCode::Char('G')); // last row, index 3

        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "alpha");
        harness.press(KeyCode::Enter);

        assert_eq!(
            harness.app.item_state.selected(),
            Some(0),
            "the cursor is clamped to the one remaining row"
        );
        assert_eq!(
            harness.app.selected_item().map(|item| item.label.as_str()),
            Some("alpha")
        );
    }

    #[test]
    fn a_filter_that_matches_nothing_leaves_no_selection() {
        let mut harness = filterable();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "nothing here");
        harness.press(KeyCode::Enter);

        assert!(harness.app.visible_items().is_empty());
        assert_eq!(harness.app.item_state.selected(), None);
        assert!(
            harness.app.selected_item().is_none(),
            "nothing is selected, so nothing can be acted on"
        );
    }

    #[test]
    fn moving_to_another_keyring_clears_the_filter() {
        let mut harness = Harness::loaded(); // two keyrings
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "alpha");
        harness.press(KeyCode::Enter);
        assert_eq!(harness.app.item_filter, "alpha");

        harness.press(KeyCode::Char('j')); // the Session keyring
        assert!(
            harness.app.item_filter.is_empty(),
            "a filter belongs to the list it was typed against"
        );
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::ListItems { keyring: 1 }]
        );
    }

    #[test]
    fn a_refresh_keeps_the_filter() {
        let mut harness = filterable();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "git");
        harness.press(KeyCode::Enter);

        // What a delete triggers: the keyring is re-read, same keyring.
        harness.app.on_reply(Reply::Items {
            keyring: 0,
            items: vec![item(0, "alpha"), item(1, "GitHub token")],
        });

        assert_eq!(harness.app.item_filter, "git");
        assert_eq!(visible_labels(&harness.app), vec!["GitHub token"]);
        assert_eq!(
            harness.app.item_state.selected(),
            Some(0),
            "the cursor lands on the first visible row, not the first row"
        );
    }

    #[test]
    fn deleting_an_item_asks_first() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('x'));
        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmDeleteItem));
        assert!(
            harness.secrets_requests().is_empty(),
            "nothing is sent until it is confirmed"
        );

        harness.press(KeyCode::Char('y'));
        assert_eq!(harness.app.prompt, None);
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::DeleteItem {
                keyring: 0,
                item: 0
            }]
        );
    }

    #[test]
    fn cancelling_the_delete_sends_nothing() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('x'));
        harness.press(KeyCode::Char('n'));
        assert_eq!(harness.app.prompt, None);
        assert!(harness.secrets_requests().is_empty());
    }

    #[test]
    fn deleting_a_filtered_row_deletes_that_row() {
        // The reason the filter is a view: a row the user picked out of a
        // narrowed list still carries the id the backend indexes by.
        let mut harness = filterable();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "git");
        harness.press(KeyCode::Enter);

        harness.press(KeyCode::Char('l')); // focus the item list
        harness.press(KeyCode::Char('j')); // second visible row: GitLab, id 2
        assert_eq!(
            harness.app.selected_item().map(|item| item.label.as_str()),
            Some("GitLab token")
        );

        harness.press(KeyCode::Char('x'));
        harness.press(KeyCode::Char('y'));
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::DeleteItem {
                keyring: 0,
                item: 2
            }],
            "not index 1, which is where the row sits in the filtered view"
        );
    }

    #[test]
    fn delete_does_nothing_without_a_selected_item() {
        let mut harness = Harness::new();
        harness
            .app
            .on_reply(Reply::Keyrings(vec![keyring(0, "Login", true)]));
        harness.app.on_reply(Reply::Items {
            keyring: 0,
            items: Vec::new(),
        });
        harness.drain();

        harness.press(KeyCode::Char('x'));
        assert_eq!(
            harness.app.prompt, None,
            "an empty list has nothing to confirm deleting"
        );
        assert!(harness.secrets_requests().is_empty());
    }

    #[test]
    fn delete_and_filter_only_act_in_the_keyrings_section() {
        let mut harness = Harness::ssh_loaded();
        // `x` is the agent key here, and `/` is unbound outside GPG.
        harness.press(KeyCode::Char('x'));
        assert_eq!(harness.app.prompt, None);
        assert!(
            harness.secrets_requests().is_empty(),
            "x in the SSH section must not reach the secret service"
        );
        assert_eq!(
            harness.ssh_requests(),
            vec![SshRequest::RemoveFromAgent { key: 0 }]
        );
    }

    #[test]
    fn n_asks_for_a_name_and_creates_a_keyring() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('n'));
        assert_eq!(
            harness.app.prompt,
            Some(Prompt::Ask(Question::NewKeyringLabel))
        );

        type_text(&mut harness, "Work");
        harness.press(KeyCode::Enter);

        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::CreateKeyring {
                label: "Work".into()
            }],
            "the passphrase is the service's to ask for; we only send a name"
        );
    }

    #[test]
    fn creating_a_keyring_with_no_name_does_nothing() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('n'));
        harness.press(KeyCode::Enter);
        assert_eq!(harness.app.prompt, None);
        assert!(harness.secrets_requests().is_empty());
    }

    #[test]
    fn n_creates_a_keyring_in_passwords_but_a_key_elsewhere() {
        // `n` is "new" in all three sections; the section picks which new.
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('n'));
        assert_eq!(
            harness.app.prompt,
            Some(Prompt::Ask(Question::NewKeyringLabel))
        );

        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('n'));
        assert_eq!(harness.app.prompt, Some(Prompt::NewSshKey));

        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('n'));
        assert!(harness.app.take_external().is_some(), "gpg asks everything");
    }

    #[test]
    fn deleting_a_keyring_asks_first() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('D'));
        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmDeleteKeyring));
        assert!(harness.secrets_requests().is_empty());

        harness.press(KeyCode::Char('y'));
        assert_eq!(harness.app.prompt, None);
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::DeleteKeyring { keyring: 0 }]
        );
    }

    #[test]
    fn cancelling_the_keyring_delete_sends_nothing() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('D'));
        harness.press(KeyCode::Char('n'));
        assert_eq!(harness.app.prompt, None);
        assert!(harness.secrets_requests().is_empty());
    }

    #[test]
    fn x_deletes_an_item_but_d_deletes_the_whole_keyring() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('x'));
        harness.press(KeyCode::Char('y'));
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::DeleteItem {
                keyring: 0,
                item: 0
            }]
        );

        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('D'));
        harness.press(KeyCode::Char('y'));
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::DeleteKeyring { keyring: 0 }]
        );
    }

    #[test]
    fn d_acts_on_the_keyring_even_from_the_item_pane() {
        // `u` and `L` already work on the selected keyring from any pane, and
        // this follows them rather than inventing a pane rule.
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('l'));
        assert_eq!(harness.app.pane, Pane::List);

        harness.press(KeyCode::Char('D'));
        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmDeleteKeyring));
    }

    #[test]
    fn losing_the_selected_keyring_clears_the_filter() {
        let mut harness = filterable();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "git");
        harness.press(KeyCode::Enter);
        harness.drain();

        // What a delete looks like coming back: the keyring the cursor was on
        // is simply not in the new listing.
        harness
            .app
            .on_reply(Reply::Keyrings(vec![keyring(0, "Session", false)]));

        assert!(
            harness.app.item_filter.is_empty(),
            "the cursor landed on a different keyring, so the filter is stale"
        );
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::ListItems { keyring: 0 }]
        );
    }

    #[test]
    fn copying_a_secret_fetches_it_without_showing_it() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('y'));

        // Same round trip as revealing: the secret is not in the list reply.
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::RevealSecret {
                keyring: 0,
                item: 0
            }]
        );

        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });

        assert_eq!(
            harness.clipboard_requests(),
            vec![(
                "hunter2".to_string(),
                "the secret for alpha".to_string(),
                Some(TEST_CLEAR_AFTER)
            )]
        );
        assert!(
            harness.app.revealed.is_none(),
            "a copy must not put the secret on screen as a side effect"
        );
    }

    #[test]
    fn an_already_revealed_secret_is_copied_without_a_second_fetch() {
        let mut harness = Harness::loaded();
        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });
        harness.drain();
        assert!(harness.app.revealed.is_some());

        harness.press(KeyCode::Char('y'));
        assert!(
            harness.secrets_requests().is_empty(),
            "it is already in memory"
        );
        assert_eq!(harness.clipboard_requests().len(), 1);
        assert!(
            harness.app.revealed.is_some(),
            "and copying does not hide what was already shown"
        );
    }

    #[test]
    fn a_secret_fetched_for_a_copy_is_dropped_if_the_cursor_moved() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('y'));
        harness.drain();

        // The reply names item 0, but the cursor is on item 1 by the time it
        // lands — so it belongs to a row the user has left.
        harness.press(KeyCode::Char('l'));
        harness.press(KeyCode::Char('j'));
        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });

        assert!(
            harness.clipboard_requests().is_empty(),
            "a stale secret must not reach the clipboard"
        );
        assert!(harness.app.revealed.is_none());

        // And the dropped copy must not leave the flag armed, or the next
        // plain reveal would silently copy instead of displaying.
        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 1,
            value: Zeroizing::new("correct horse".into()),
        });
        assert!(harness.clipboard_requests().is_empty());
        assert!(
            harness.app.revealed.is_some(),
            "this one was a plain reveal"
        );
    }

    #[test]
    fn copying_a_public_key_is_not_wiped_afterwards() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('y'));

        let copied = harness.clipboard_requests();
        assert_eq!(copied.len(), 1);
        let (text, what, clear_after) = &copied[0];
        assert!(text.starts_with("ssh-"), "the openssh line: {text}");
        assert_eq!(what, "the public key");
        assert_eq!(
            *clear_after, None,
            "a public key is not secret, and wiping it would only annoy"
        );
    }

    #[test]
    fn capital_y_copies_a_fingerprint_in_both_key_sections() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('Y'));
        let copied = harness.clipboard_requests();
        assert_eq!(copied[0].0, "SHA256:id_ecdsa");
        assert_eq!(copied[0].2, None);

        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('Y'));
        let copied = harness.clipboard_requests();
        assert_eq!(copied[0].0, "FPR0");
        assert_eq!(copied[0].2, None);
    }

    #[test]
    fn y_exports_in_gpg_but_copies_in_the_other_sections() {
        // `y` is the armoured export in GPG, so the fingerprint went to `Y`
        // and `y` keeps its old meaning there.
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('y'));
        assert!(harness.clipboard_requests().is_empty());
        let external = harness.app.take_external().expect("gpg --export");
        assert!(external.args().contains(&"--export".to_string()));

        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('y'));
        assert!(harness.app.take_external().is_none());
        assert_eq!(
            harness.secrets_requests(),
            vec![SecretsRequest::RevealSecret {
                keyring: 0,
                item: 0
            }]
        );
    }

    #[test]
    fn a_copy_reports_nothing_to_refresh() {
        // Re-reading a list after a copy would move the cursor for no reason.
        let mut harness = Harness::loaded();
        harness.app.on_reply(Reply::Status {
            message: "copied the secret for alpha — clearing in 30s".into(),
            refresh: Refresh::Nothing,
        });
        assert!(harness.secrets_requests().is_empty());
        assert!(harness.ssh_requests().is_empty());
        assert!(harness.gpg_requests().is_empty());
    }

    #[test]
    fn copy_does_nothing_without_a_selection() {
        let mut harness = Harness::new();
        harness
            .app
            .on_reply(Reply::Keyrings(vec![keyring(0, "Login", true)]));
        harness.app.on_reply(Reply::Items {
            keyring: 0,
            items: Vec::new(),
        });
        harness.drain();

        harness.press(KeyCode::Char('y'));
        assert!(harness.secrets_requests().is_empty());
        assert!(harness.clipboard_requests().is_empty());
    }

    #[test]
    fn revealing_a_secret_is_dropped_when_the_filter_changes() {
        let mut harness = filterable();
        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });
        assert!(harness.app.revealed.is_some());

        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "git");
        harness.press(KeyCode::Enter);

        assert!(
            harness.app.revealed.is_none(),
            "the row it belonged to may no longer be on screen"
        );
    }

    // --- SSH keys --------------------------------------------------------

    #[test]
    fn the_ssh_section_scans_on_first_visit_only() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('3'));
        assert_eq!(harness.ssh_requests(), vec![SshRequest::ListKeys]);

        harness.app.on_reply(Reply::SshKeys {
            keys: vec![ssh_key(0, "id_ed25519", true, false)],
            agent: AgentStatus::Ready { loaded: 0 },
        });

        harness.press(KeyCode::Char('1'));
        harness.press(KeyCode::Char('3'));
        assert!(
            harness.ssh_requests().is_empty(),
            "a revisit must not rescan"
        );
        assert!(harness.app.status.contains("1 key(s)"));
    }

    #[test]
    fn navigation_moves_the_ssh_cursor_not_the_keyring_one() {
        let mut harness = Harness::ssh_loaded();
        assert_eq!(harness.app.ssh_state.selected(), Some(0));

        harness.press(KeyCode::Char('j'));
        assert_eq!(harness.app.ssh_state.selected(), Some(1));
        assert_eq!(
            harness.app.keyring_state.selected(),
            Some(0),
            "the Passwords cursor must not move"
        );
        assert!(
            harness.secrets_requests().is_empty(),
            "no secret service traffic from SSH navigation"
        );
    }

    #[test]
    fn adding_to_the_agent_parks_an_external_ssh_add() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('j')); // id_rsa, on disk but not loaded
        harness.press(KeyCode::Char('a'));

        let external = harness.app.take_external().expect("external parked");
        assert_eq!(external.program(), "ssh-add");
        assert_eq!(external.args(), vec!["/home/u/.ssh/id_rsa".to_string()]);
        assert!(
            harness.ssh_requests().is_empty(),
            "the backend must not be asked to add a key"
        );
    }

    #[test]
    fn adding_a_key_already_in_the_agent_does_nothing() {
        let mut harness = Harness::ssh_loaded(); // cursor on id_ecdsa, loaded
        harness.press(KeyCode::Char('a'));

        assert!(harness.app.take_external().is_none());
        assert!(harness.app.status.contains("already in the agent"));
    }

    #[test]
    fn a_key_with_no_private_file_cannot_be_added() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('3'));
        harness.app.on_reply(Reply::SshKeys {
            keys: vec![ssh_key(0, "pub_only", false, false)],
            agent: AgentStatus::Ready { loaded: 0 },
        });
        harness.drain();

        harness.press(KeyCode::Char('a'));
        assert!(harness.app.take_external().is_none());
        assert!(
            harness.app.status.contains("no private key file"),
            "status was {:?}",
            harness.app.status
        );
    }

    #[test]
    fn adding_without_an_agent_is_an_error_not_a_prompt() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('3'));
        harness.app.on_reply(Reply::SshKeys {
            keys: vec![ssh_key(0, "id_ed25519", true, false)],
            agent: AgentStatus::NotConfigured,
        });

        harness.press(KeyCode::Char('a'));
        assert!(harness.app.take_external().is_none());
        assert!(harness.app.error.is_some());
    }

    #[test]
    fn removing_from_the_agent_goes_through_the_backend() {
        let mut harness = Harness::ssh_loaded(); // cursor on id_ecdsa, loaded
        harness.press(KeyCode::Char('x'));

        assert_eq!(
            harness.ssh_requests(),
            vec![SshRequest::RemoveFromAgent { key: 0 }]
        );
        assert!(harness.app.take_external().is_none());
    }

    #[test]
    fn removing_a_key_the_agent_does_not_hold_does_nothing() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('j')); // id_rsa, not loaded
        harness.drain();
        harness.press(KeyCode::Char('x'));

        assert!(harness.ssh_requests().is_empty());
        assert!(harness.app.status.contains("not in the agent"));
    }

    #[test]
    fn generating_a_key_asks_for_the_algorithm_first() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('n'));
        assert_eq!(harness.app.prompt, Some(Prompt::NewSshKey));
        assert!(harness.app.take_external().is_none(), "not yet");

        harness.press(KeyCode::Char('1'));
        assert_eq!(harness.app.prompt, None);
        let external = harness.app.take_external().expect("external parked");
        assert_eq!(external.program(), "ssh-keygen");
        assert_eq!(external.args(), vec!["-t".to_string(), "ed25519".into()]);
    }

    #[test]
    fn the_rsa_choice_passes_a_bit_length() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('n'));
        harness.press(KeyCode::Char('3'));

        let external = harness.app.take_external().expect("external parked");
        assert_eq!(
            external.describe(),
            "ssh-keygen -t rsa -b 4096",
            "the banner should name the exact command"
        );
    }

    #[test]
    fn a_prompt_swallows_unrecognised_keys() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('n'));

        // `q` cancels, but a stray `j` must not navigate underneath the modal.
        harness.press(KeyCode::Char('j'));
        assert_eq!(harness.app.prompt, Some(Prompt::NewSshKey));
        assert_eq!(harness.app.ssh_state.selected(), Some(0));

        harness.press(KeyCode::Esc);
        assert_eq!(harness.app.prompt, None);
        assert!(!harness.app.should_quit, "Esc dismissed the prompt only");
    }

    #[test]
    fn an_external_command_is_followed_by_a_rescan() {
        let mut harness = Harness::ssh_loaded();
        let external = External::SshAdd("/home/u/.ssh/id_rsa".into());
        harness
            .app
            .on_external_done(&external, Ok("ssh-add finished".into()));

        assert_eq!(harness.ssh_requests(), vec![SshRequest::ListKeys]);
        assert_eq!(harness.app.status, "ssh-add finished");
        assert!(harness.app.error.is_none());
    }

    #[test]
    fn a_failed_external_command_reports_and_still_rescans() {
        let mut harness = Harness::ssh_loaded();
        let external = External::SshAdd("/home/u/.ssh/id_rsa".into());
        harness
            .app
            .on_external_done(&external, Err("ssh-add exited with status 1".into()));

        assert_eq!(harness.ssh_requests(), vec![SshRequest::ListKeys]);
        assert_eq!(
            harness.app.error.as_deref(),
            Some("ssh-add exited with status 1")
        );
    }

    #[test]
    fn an_external_command_only_refreshes_its_own_section() {
        let mut harness = Harness::gpg_loaded();
        let external = External::Gpg {
            action: GpgAction::Edit,
            fingerprint: Some("FPR0".into()),
        };
        harness
            .app
            .on_external_done(&external, Ok("gpg done".into()));

        assert_eq!(
            harness.gpg_requests(),
            vec![GpgRequest::ListKeys {
                filter: GpgFilter::All
            }]
        );
        assert!(harness.ssh_requests().is_empty());
        assert!(harness.secrets_requests().is_empty());
    }

    #[test]
    fn a_rescan_keeps_the_cursor_on_the_same_key_by_name() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('j')); // id_rsa

        // A new key sorts in ahead of it; the cursor should follow the name.
        harness.app.on_reply(Reply::SshKeys {
            keys: vec![
                ssh_key(0, "id_dsa", true, false),
                ssh_key(1, "id_ecdsa", true, true),
                ssh_key(2, "id_rsa", true, false),
            ],
            agent: AgentStatus::Ready { loaded: 1 },
        });
        assert_eq!(
            harness.app.selected_ssh_key().map(|k| k.name.as_str()),
            Some("id_rsa")
        );
    }

    #[test]
    fn ssh_bindings_do_nothing_in_the_passwords_section() {
        let mut harness = Harness::loaded();
        for code in [KeyCode::Char('a'), KeyCode::Char('x'), KeyCode::Char('n')] {
            harness.press(code);
        }
        assert!(harness.app.take_external().is_none());
        assert!(harness.app.prompt.is_none());
        assert!(harness.ssh_requests().is_empty());
    }

    #[test]
    fn the_agent_status_is_reported_in_the_status_line() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('3'));
        harness.app.on_reply(Reply::SshKeys {
            keys: vec![ssh_key(0, "id_ed25519", true, false)],
            agent: AgentStatus::NotConfigured,
        });
        assert!(
            harness.app.status.contains("SSH_AUTH_SOCK"),
            "status was {:?}",
            harness.app.status
        );
    }

    // --- GPG keys --------------------------------------------------------

    #[test]
    fn the_gpg_section_reads_the_keyring_on_first_visit_only() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('2'));
        assert_eq!(
            harness.gpg_requests(),
            vec![GpgRequest::ListKeys {
                filter: GpgFilter::All
            }]
        );

        harness.app.on_reply(Reply::GpgKeys {
            keys: vec![gpg_key(0, "Me <me@example>", true)],
            filter: GpgFilter::All,
            engine: "gpg 2.4.9".into(),
        });

        harness.press(KeyCode::Char('1'));
        harness.press(KeyCode::Char('2'));
        assert!(
            harness.gpg_requests().is_empty(),
            "a revisit must not re-read"
        );
        assert!(harness.app.status.contains("gpg 2.4.9"));
    }

    #[test]
    fn editing_runs_gpg_edit_key_on_the_selected_key() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('j')); // Them
        harness.press(KeyCode::Char('e'));

        let external = harness.app.take_external().expect("external parked");
        assert_eq!(external.program(), "gpg");
        assert_eq!(external.describe(), "gpg --edit-key FPR1");
        assert_eq!(external.refresh(), Refresh::GpgKeys);
    }

    #[test]
    fn exporting_prints_an_armoured_key() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('y'));

        let external = harness.app.take_external().expect("external parked");
        assert_eq!(external.describe(), "gpg --armor --export FPR0");
    }

    #[test]
    fn generating_needs_no_prompt_because_gpg_asks() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('n'));

        assert!(harness.app.prompt.is_none());
        let external = harness.app.take_external().expect("external parked");
        assert_eq!(external.describe(), "gpg --full-generate-key");
    }

    #[test]
    fn deleting_asks_first_and_then_runs_gpg() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('x'));

        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmGpgDelete));
        assert!(harness.app.take_external().is_none(), "not without a yes");

        harness.press(KeyCode::Char('y'));
        assert_eq!(harness.app.prompt, None);
        let external = harness.app.take_external().expect("external parked");
        assert_eq!(external.describe(), "gpg --delete-key FPR0");
    }

    #[test]
    fn declining_a_delete_does_nothing() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('x'));
        harness.press(KeyCode::Char('n'));

        assert_eq!(harness.app.prompt, None);
        assert!(harness.app.take_external().is_none());
        assert_eq!(harness.app.status, "cancelled");
    }

    #[test]
    fn publishing_asks_first_because_keyservers_do_not_forget() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('p'));

        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmGpgPublish));
        assert!(harness.app.take_external().is_none());

        harness.press(KeyCode::Esc);
        assert_eq!(harness.app.prompt, None);
        assert!(
            harness.app.take_external().is_none(),
            "Esc must not publish"
        );
        assert!(!harness.app.should_quit);
    }

    #[test]
    fn a_confirmation_is_not_offered_without_a_selected_key() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('2'));
        harness.app.on_reply(Reply::GpgKeys {
            keys: Vec::new(),
            filter: GpgFilter::All,
            engine: "gpg 2.4.9".into(),
        });

        harness.press(KeyCode::Char('x'));
        assert!(harness.app.prompt.is_none());
        harness.press(KeyCode::Char('p'));
        assert!(harness.app.prompt.is_none());
    }

    #[test]
    fn the_filter_toggle_re_reads_with_the_new_filter() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('f'));

        assert_eq!(harness.app.gpg_filter, GpgFilter::Secret);
        assert_eq!(
            harness.gpg_requests(),
            vec![GpgRequest::ListKeys {
                filter: GpgFilter::Secret
            }]
        );
    }

    #[test]
    fn a_listing_for_a_superseded_filter_is_dropped() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('f')); // now expecting Secret
        harness.drain();

        harness.app.on_reply(Reply::GpgKeys {
            keys: vec![gpg_key(0, "Stale <stale@example>", false)],
            filter: GpgFilter::All,
            engine: "gpg 2.4.9".into(),
        });
        assert_eq!(
            harness.app.gpg_keys.len(),
            2,
            "the pre-toggle listing should still be on screen"
        );

        harness.app.on_reply(Reply::GpgKeys {
            keys: vec![gpg_key(0, "Me <me@example>", true)],
            filter: GpgFilter::Secret,
            engine: "gpg 2.4.9".into(),
        });
        assert_eq!(harness.app.gpg_keys.len(), 1);
    }

    #[test]
    fn a_re_read_keeps_the_cursor_on_the_same_key_by_fingerprint() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('j')); // FPR1

        harness.app.on_reply(Reply::GpgKeys {
            keys: vec![
                gpg_key(0, "New <new@example>", true),
                gpg_key(1, "Me <me@example>", true),
                gpg_key(2, "Them <them@example>", false),
            ],
            filter: GpgFilter::All,
            engine: "gpg 2.4.9".into(),
        });
        assert_eq!(
            harness.app.selected_gpg_key().map(|key| key.id),
            Some(1),
            "FPR1 moved to index 1 and the cursor should have followed"
        );
    }

    #[test]
    fn gpg_bindings_do_nothing_in_the_other_sections() {
        let mut harness = Harness::ssh_loaded();
        // Not `p`: that is shared with SshPassphrase, and
        // `p_publishes_in_gpg_but_re_encrypts_in_ssh` covers the split.
        for code in [KeyCode::Char('e'), KeyCode::Char('y'), KeyCode::Char('f')] {
            harness.press(code);
        }
        assert!(harness.app.take_external().is_none());
        assert!(harness.app.prompt.is_none());
        assert!(harness.gpg_requests().is_empty());
    }

    #[test]
    fn x_removes_from_the_agent_in_ssh_but_deletes_in_gpg() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('x'));
        assert_eq!(
            harness.ssh_requests(),
            vec![SshRequest::RemoveFromAgent { key: 0 }]
        );
        assert!(harness.app.prompt.is_none());

        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('x'));
        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmGpgDelete));
    }

    #[test]
    fn p_changes_the_passphrase_without_asking_first() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('p'));

        assert_eq!(
            harness.app.prompt, None,
            "ssh-keygen gets nowhere without the current passphrase, so \
             there is nothing to guard against"
        );
        let external = harness.app.take_external().expect("an external command");
        assert_eq!(external.program(), "ssh-keygen");
        assert_eq!(
            external.args(),
            vec!["-p", "-f", "/home/u/.ssh/id_ecdsa"],
            "the private half is what carries the passphrase"
        );
        assert_eq!(external.refresh(), Refresh::SshKeys);
    }

    #[test]
    fn a_key_with_no_private_half_cannot_be_re_encrypted() {
        let mut harness = Harness::new();
        harness.press(KeyCode::Char('3'));
        harness.app.on_reply(Reply::SshKeys {
            keys: vec![ssh_key(0, "id_ed25519", false, false)],
            agent: AgentStatus::Ready { loaded: 0 },
        });
        harness.drain();

        harness.press(KeyCode::Char('p'));
        assert!(harness.app.take_external().is_none());
        assert!(
            harness.app.status.contains("no private key file"),
            "{}",
            harness.app.status
        );
    }

    #[test]
    fn p_publishes_in_gpg_but_re_encrypts_in_ssh() {
        // Both are bound to `p`; the section decides which one fires.
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('p'));
        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmGpgPublish));
        assert!(harness.app.take_external().is_none());

        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('p'));
        assert_eq!(harness.app.prompt, None);
        assert!(harness.app.take_external().is_some());
    }

    #[test]
    fn deleting_an_ssh_key_asks_first() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('D'));
        assert_eq!(harness.app.prompt, Some(Prompt::ConfirmSshDelete));
        assert!(
            harness.ssh_requests().is_empty(),
            "nothing is unlinked until it is confirmed"
        );

        harness.press(KeyCode::Char('y'));
        assert_eq!(harness.app.prompt, None);
        assert_eq!(
            harness.ssh_requests(),
            vec![SshRequest::DeleteKey { key: 0 }]
        );
    }

    #[test]
    fn cancelling_the_ssh_delete_unlinks_nothing() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('D'));
        harness.press(KeyCode::Char('n'));
        assert_eq!(harness.app.prompt, None);
        assert!(harness.ssh_requests().is_empty());
    }

    #[test]
    fn an_agent_only_identity_has_no_files_to_delete() {
        let mut harness = Harness::new();
        harness.press(KeyCode::Char('3'));
        let mut forwarded = ssh_key(0, "(agent) forwarded@elsewhere", false, true);
        forwarded.public_path = None;
        harness.app.on_reply(Reply::SshKeys {
            keys: vec![forwarded],
            agent: AgentStatus::Ready { loaded: 1 },
        });
        harness.drain();

        harness.press(KeyCode::Char('D'));
        assert_eq!(
            harness.app.prompt, None,
            "there is nothing on disk to confirm deleting"
        );
        assert!(harness.ssh_requests().is_empty());
        assert!(
            harness.app.status.contains("x drops it from the agent"),
            "the status should point at the thing that does work: {}",
            harness.app.status
        );
    }

    #[test]
    fn deleting_the_second_key_sends_its_own_id() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('j'));
        harness.drain();

        harness.press(KeyCode::Char('D'));
        harness.press(KeyCode::Enter); // Enter confirms, like y
        assert_eq!(
            harness.ssh_requests(),
            vec![SshRequest::DeleteKey { key: 1 }]
        );
    }

    // --- Navigation and keybindings --------------------------------------

    #[test]
    fn hl_walks_the_three_passwords_panes() {
        let mut harness = Harness::loaded();
        assert_eq!(harness.app.pane, Pane::Keyrings);

        harness.press(KeyCode::Char('l'));
        assert_eq!(harness.app.pane, Pane::List);
        harness.press(KeyCode::Char('l'));
        assert_eq!(harness.app.pane, Pane::Details);
        harness.press(KeyCode::Char('l'));
        assert_eq!(harness.app.pane, Pane::Details, "stops at the right edge");

        harness.press(KeyCode::Char('h'));
        assert_eq!(harness.app.pane, Pane::List);
        harness.press(KeyCode::Char('h'));
        assert_eq!(harness.app.pane, Pane::Keyrings);
        harness.press(KeyCode::Char('h'));
        assert_eq!(harness.app.pane, Pane::Keyrings, "stops at the left edge");
    }

    #[test]
    fn hl_walks_two_panes_in_the_key_sections() {
        for section in [KeyCode::Char('2'), KeyCode::Char('3')] {
            let mut harness = Harness::loaded();
            harness.press(section);
            assert_eq!(
                harness.app.pane,
                Pane::List,
                "a key section starts on its list, not a sidebar"
            );

            harness.press(KeyCode::Char('l'));
            assert_eq!(harness.app.pane, Pane::Details);
            harness.press(KeyCode::Char('h'));
            assert_eq!(harness.app.pane, Pane::List);
            harness.press(KeyCode::Char('h'));
            assert_eq!(harness.app.pane, Pane::List, "no third pane to the left");
        }
    }

    #[test]
    fn arrows_do_the_same_as_hjkl() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Right);
        assert_eq!(harness.app.pane, Pane::List);
        harness.press(KeyCode::Down);
        assert_eq!(harness.app.item_state.selected(), Some(1));
        harness.press(KeyCode::Up);
        assert_eq!(harness.app.item_state.selected(), Some(0));
        harness.press(KeyCode::Left);
        assert_eq!(harness.app.pane, Pane::Keyrings);
    }

    #[test]
    fn a_focused_detail_pane_scrolls_instead_of_moving_the_cursor() {
        let mut harness = Harness::ssh_loaded();
        harness.app.detail_lines = 40;
        harness.app.detail_height = 10;

        harness.press(KeyCode::Char('l')); // focus details
        assert_eq!(harness.app.pane, Pane::Details);

        harness.press(KeyCode::Char('j'));
        assert_eq!(harness.app.detail_scroll, 1);
        assert_eq!(
            harness.app.ssh_state.selected(),
            Some(0),
            "the list cursor must not move while the details have focus"
        );

        harness.press(KeyCode::Char('k'));
        assert_eq!(harness.app.detail_scroll, 0);
        harness.press(KeyCode::Char('k'));
        assert_eq!(harness.app.detail_scroll, 0, "clamped at the top");
    }

    #[test]
    fn detail_scrolling_stops_at_the_last_line() {
        let mut harness = Harness::ssh_loaded();
        harness.app.detail_lines = 12;
        harness.app.detail_height = 10;
        harness.press(KeyCode::Char('l'));

        for _ in 0..10 {
            harness.press(KeyCode::Char('j'));
        }
        assert_eq!(
            harness.app.detail_scroll, 2,
            "only the overflow is scrollable"
        );

        harness.press(KeyCode::Char('G'));
        assert_eq!(harness.app.detail_scroll, 2);
        harness.press(KeyCode::Char('g'));
        assert_eq!(harness.app.detail_scroll, 0);
    }

    #[test]
    fn changing_section_resets_focus_and_scroll() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('l'));
        harness.press(KeyCode::Char('l'));
        harness.app.detail_scroll = 5;

        harness.press(KeyCode::Char('3'));
        assert_eq!(harness.app.pane, Pane::List);
        assert_eq!(harness.app.detail_scroll, 0);
    }

    #[test]
    fn a_shared_key_resolves_to_the_section_it_is_in() {
        // `x` is AgentRemove in SSH and GpgDelete in GPG; `n` is NewSshKey and
        // NewGpgKey. Both are bound to one key, and the section decides.
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('n'));
        assert_eq!(harness.app.prompt, Some(Prompt::NewSshKey));
        harness.press(KeyCode::Esc);

        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('n'));
        assert!(harness.app.prompt.is_none(), "gpg asks for itself");
        assert_eq!(
            harness.app.take_external().map(|e| e.describe()),
            Some("gpg --full-generate-key".to_string())
        );
    }

    #[test]
    fn a_custom_keymap_moves_navigation_onto_neio() {
        use std::collections::BTreeMap;

        use crate::keys::KeymapSection;

        // The layout from the example config: n/e/i/o instead of h/j/k/l.
        #[derive(serde::Deserialize)]
        struct Wrapper {
            keys: BTreeMap<Mode, KeymapSection>,
        }
        let wrapper: Wrapper = toml::from_str(
            r#"
            [keys.main]
            set = [
                ["MoveDown",   "e"],
                ["MoveUp",     "i"],
                ["FocusLeft",  "n"],
                ["FocusRight", "o"],
            ]
            "#,
        )
        .unwrap();

        let (secrets_tx, secrets) = mpsc::unbounded_channel();
        let (ssh_tx, ssh) = mpsc::unbounded_channel();
        let (gpg_tx, gpg) = mpsc::unbounded_channel();
        let (clip_tx, clipboard) = mpsc::unbounded_channel();
        let mut harness = Harness {
            app: App::new(
                secrets_tx,
                ssh_tx,
                gpg_tx,
                clip_tx,
                Some(TEST_CLEAR_AFTER),
                Keymaps::resolve(&wrapper.keys),
            ),
            secrets,
            ssh,
            gpg,
            clipboard,
        };
        harness.app.on_reply(Reply::Keyrings(vec![
            keyring(0, "Login", false),
            keyring(1, "Session", false),
        ]));
        harness.drain();

        harness.press(KeyCode::Char('e'));
        assert_eq!(
            harness.app.keyring_state.selected(),
            Some(1),
            "e moves down"
        );
        harness.press(KeyCode::Char('i'));
        assert_eq!(harness.app.keyring_state.selected(), Some(0), "i moves up");
        harness.press(KeyCode::Char('o'));
        assert_eq!(harness.app.pane, Pane::List, "o focuses right");
        harness.press(KeyCode::Char('n'));
        assert_eq!(harness.app.pane, Pane::Keyrings, "n focuses left");

        // The keys those actions used to own are retired, and the ones they
        // took are no longer doing their old jobs.
        harness.press(KeyCode::Char('j'));
        assert_eq!(
            harness.app.keyring_state.selected(),
            Some(0),
            "j is retired"
        );
        harness.press(KeyCode::Char('3'));
        harness.drain();
        harness.press(KeyCode::Char('n'));
        assert!(
            harness.app.prompt.is_none(),
            "n is navigation now, not new-key"
        );
    }

    // --- Text fields -----------------------------------------------------

    /// Type a string into whatever field is open.
    fn type_text(harness: &mut Harness, text: &str) {
        for c in text.chars() {
            harness.press(KeyCode::Char(c));
        }
    }

    #[test]
    fn opening_a_field_switches_the_keymap_to_input_mode() {
        let mut harness = Harness::gpg_loaded();
        assert_eq!(harness.app.mode(), Mode::Main);

        harness.press(KeyCode::Char('/'));
        assert_eq!(harness.app.prompt, Some(Prompt::Ask(Question::GpgSearch)));
        assert_eq!(
            harness.app.mode(),
            Mode::Input,
            "a field resolves keys against its own map"
        );
    }

    #[test]
    fn printable_keys_are_text_not_bindings() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));

        // Every one of these is a binding in the main map: q quits, x deletes,
        // n generates, 1/2/3 switch section. In a field they are just letters.
        type_text(&mut harness, "qxn123 greg@example");

        assert_eq!(harness.app.input.value(), "qxn123 greg@example");
        assert!(!harness.app.should_quit, "q must not quit while typing");
        assert_eq!(
            harness.app.section,
            Section::GpgKeys,
            "digits must not switch"
        );
        assert!(harness.app.take_external().is_none());
    }

    #[test]
    fn a_space_is_typed_rather_than_swallowed() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "two words");
        assert_eq!(harness.app.input.value(), "two words");
    }

    #[test]
    fn editing_keys_still_work_inside_a_field() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "greg@exampel");

        harness.press(KeyCode::Backspace);
        harness.press(KeyCode::Backspace);
        type_text(&mut harness, "le");
        assert_eq!(harness.app.input.value(), "greg@example");

        harness
            .app
            .handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(harness.app.input.value(), "", "ctrl+u clears to the start");
    }

    #[test]
    fn a_modified_key_is_a_binding_not_a_letter() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "abc def");

        harness
            .app
            .handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert_eq!(
            harness.app.input.value(),
            "abc ",
            "ctrl+w deleted a word rather than typing a w"
        );
    }

    #[test]
    fn submitting_runs_the_command_with_what_was_typed() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "greg@example.com");
        harness.press(KeyCode::Enter);

        assert_eq!(harness.app.prompt, None);
        let external = harness.app.take_external().expect("external parked");
        assert_eq!(
            external.describe(),
            "gpg --search-keys greg@example.com",
            "the typed text becomes the argument"
        );
        assert!(
            harness.app.input.value().is_empty(),
            "the field is cleared for next time"
        );
    }

    #[test]
    fn the_import_field_is_prefilled_and_editable() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('i'));
        assert_eq!(
            harness.app.prompt,
            Some(Prompt::Ask(Question::GpgImportPath))
        );

        // Offered a default with the cursor at the end, so typing extends it.
        let offered = harness.app.input.value().to_string();
        assert!(
            offered.ends_with('/'),
            "a directory to continue from: {offered:?}"
        );
        type_text(&mut harness, "key.asc");
        harness.press(KeyCode::Enter);

        let external = harness.app.take_external().expect("external parked");
        assert_eq!(
            external.describe(),
            format!("gpg --import {offered}key.asc")
        );
    }

    #[test]
    fn an_empty_field_closes_without_running_anything() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));
        harness.press(KeyCode::Enter);

        assert_eq!(harness.app.prompt, None);
        assert!(
            harness.app.take_external().is_none(),
            "gpg --search-keys \"\" is not worth running"
        );
    }

    #[test]
    fn whitespace_only_counts_as_empty() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "   ");
        harness.press(KeyCode::Enter);
        assert!(harness.app.take_external().is_none());
    }

    #[test]
    fn cancelling_discards_the_text() {
        let mut harness = Harness::gpg_loaded();
        harness.press(KeyCode::Char('/'));
        type_text(&mut harness, "half typed");
        harness.press(KeyCode::Esc);

        assert_eq!(harness.app.prompt, None);
        assert_eq!(harness.app.mode(), Mode::Main);
        assert!(harness.app.input.value().is_empty());
        assert!(harness.app.take_external().is_none());

        // And the main keymap is live again.
        harness.press(KeyCode::Char('q'));
        assert!(harness.app.should_quit);
    }

    #[test]
    fn ssh_copy_id_takes_the_target_from_the_field_and_the_key_from_the_cursor() {
        let mut harness = Harness::ssh_loaded();
        harness.press(KeyCode::Char('c'));
        assert_eq!(
            harness.app.prompt,
            Some(Prompt::Ask(Question::SshCopyTarget))
        );

        type_text(&mut harness, "greg@nas");
        harness.press(KeyCode::Enter);

        let external = harness.app.take_external().expect("external parked");
        assert_eq!(
            external.describe(),
            "ssh-copy-id -i /home/u/.ssh/id_ecdsa.pub greg@nas"
        );
        assert_eq!(external.refresh(), Refresh::SshKeys);
    }

    #[test]
    fn a_key_with_no_public_half_cannot_be_copied() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('3'));
        let mut key = ssh_key(0, "forwarded", false, true);
        key.public_path = None;
        harness.app.on_reply(Reply::SshKeys {
            keys: vec![key],
            agent: AgentStatus::Ready { loaded: 1 },
        });

        harness.press(KeyCode::Char('c'));
        assert!(harness.app.prompt.is_none(), "nothing to ask about");
        assert!(harness.app.status.contains("no public key file"));
    }

    #[test]
    fn field_keys_do_nothing_in_the_main_view() {
        let mut harness = Harness::gpg_loaded();
        // No field open: these must not be swallowed or crash.
        harness.press(KeyCode::Backspace);
        harness.press(KeyCode::Delete);
        harness
            .app
            .handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert!(harness.app.input.value().is_empty());
        assert!(harness.app.prompt.is_none());
    }

    // --- Shared chrome ---------------------------------------------------

    #[test]
    fn help_swallows_the_next_key_only() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('?'));
        assert!(harness.app.show_help);

        harness.press(KeyCode::Char('j'));
        assert!(!harness.app.show_help);
        assert!(
            !harness.app.should_quit,
            "dismissing help must not act on the key"
        );
    }

    #[test]
    fn errors_hide_any_revealed_secret() {
        let mut harness = Harness::loaded();
        harness.press(KeyCode::Char('l'));
        harness.app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });
        harness
            .app
            .on_reply(Reply::Error("service went away".into()));

        assert!(harness.app.revealed.is_none());
        assert_eq!(harness.app.error.as_deref(), Some("service went away"));
    }

    #[test]
    fn key_releases_are_ignored() {
        let mut harness = Harness::loaded();
        let mut release = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        harness.app.handle_key(release);
        assert!(!harness.app.should_quit);
    }
}
