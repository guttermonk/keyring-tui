//! Application state and the key handling that mutates it.
//!
//! `App` is deliberately synchronous and I/O-free: every key press either
//! changes local state, posts a request to a backend, or parks an [`External`]
//! command for the event loop to run with the TUI suspended. Every backend
//! [`Reply`] is folded in by [`App::on_reply`]. That keeps the whole UI
//! testable without a D-Bus session, an agent or a subprocess.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::ListState;
use tokio::sync::mpsc::UnboundedSender;
use zeroize::Zeroizing;

use crate::backend::{Refresh, Reply, SecretsRequest, SshRequest};
use crate::model::{AgentStatus, ItemInfo, KeyringInfo, Section, SshKeyInfo};

/// Which of the two list panes has the keyboard, in the Passwords section.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    Keyrings,
    Items,
}

/// A modal question. Only ever one at a time, and always dismissable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prompt {
    /// Choose an algorithm for a new SSH key.
    NewSshKey,
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
}

impl External {
    pub fn program(&self) -> &'static str {
        match self {
            Self::SshAdd(_) => "ssh-add",
            Self::SshKeygen { .. } => "ssh-keygen",
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
        }
    }

    /// Shown while the command runs, so it is obvious what took the terminal.
    pub fn describe(&self) -> String {
        format!("{} {}", self.program(), self.args().join(" "))
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

    /// The currently displayed secret, if the user asked for it. Held in a
    /// `Zeroizing` so it is wiped when cleared, and cleared on *any*
    /// navigation — a revealed password should never outlive the row it
    /// belongs to.
    pub revealed: Option<Zeroizing<String>>,

    // SSH keys.
    pub ssh_keys: Vec<SshKeyInfo>,
    pub ssh_state: ListState,
    pub agent: AgentStatus,
    /// The SSH section scans the disk on first visit, not at startup.
    ssh_loaded: bool,

    pub status: String,
    pub error: Option<String>,
    pub show_help: bool,
    pub prompt: Option<Prompt>,
    pub should_quit: bool,

    external: Option<External>,

    secrets: UnboundedSender<SecretsRequest>,
    ssh: UnboundedSender<SshRequest>,
}

impl App {
    pub fn new(secrets: UnboundedSender<SecretsRequest>, ssh: UnboundedSender<SshRequest>) -> Self {
        let app = Self {
            section: Section::Keyrings,
            pane: Pane::Keyrings,
            keyrings: Vec::new(),
            keyring_state: ListState::default(),
            items: Vec::new(),
            item_state: ListState::default(),
            revealed: None,
            ssh_keys: Vec::new(),
            ssh_state: ListState::default(),
            agent: AgentStatus::NotConfigured,
            ssh_loaded: false,
            status: "loading keyrings…".into(),
            error: None,
            show_help: false,
            prompt: None,
            should_quit: false,
            external: None,
            secrets,
            ssh,
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

    pub fn selected_keyring(&self) -> Option<&KeyringInfo> {
        self.keyring_state
            .selected()
            .and_then(|i| self.keyrings.get(i))
    }

    pub fn selected_item(&self) -> Option<&ItemInfo> {
        self.item_state.selected().and_then(|i| self.items.get(i))
    }

    pub fn selected_ssh_key(&self) -> Option<&SshKeyInfo> {
        self.ssh_state.selected().and_then(|i| self.ssh_keys.get(i))
    }

    /// Whether the first scan has landed. Until it has, an empty key list and
    /// an unset agent mean "not known yet", not "nothing there".
    pub fn ssh_ready(&self) -> bool {
        self.ssh_loaded
    }

    /// Forget any revealed secret. Called on every navigation.
    fn hide_secret(&mut self) {
        self.revealed = None;
    }

    /// Hand the parked external command to the event loop, if there is one.
    pub fn take_external(&mut self) -> Option<External> {
        self.external.take()
    }

    /// Both external commands change what the agent or `~/.ssh` holds, so the
    /// SSH list is always re-read afterwards.
    pub fn on_external_done(&mut self, outcome: Result<String, String>) {
        match outcome {
            Ok(message) => {
                self.error = None;
                self.status = message;
            }
            Err(message) => self.error = Some(message),
        }
        self.send_ssh(SshRequest::ListKeys);
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Windows sends both press and release; only act once.
        if key.kind != KeyEventKind::Press {
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        // Help is modal: any key dismisses it.
        if self.show_help {
            self.show_help = false;
            return;
        }

        // A prompt consumes the key, so an unrecognised press cannot fall
        // through to a binding underneath it.
        if let Some(prompt) = self.prompt {
            self.handle_prompt_key(prompt, key.code);
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('?') => self.show_help = true,

            KeyCode::Tab => self.set_section(self.section.next()),
            KeyCode::BackTab => self.set_section(self.section.prev()),
            KeyCode::Char('1') => self.set_section(Section::Keyrings),
            KeyCode::Char('2') => self.set_section(Section::GpgKeys),
            KeyCode::Char('3') => self.set_section(Section::SshKeys),

            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('g') | KeyCode::Home => self.jump_selection(true),
            KeyCode::Char('G') | KeyCode::End => self.jump_selection(false),

            KeyCode::Char('r') => self.refresh(),

            // Passwords only.
            KeyCode::Char('h') | KeyCode::Left => self.focus(Pane::Keyrings),
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => self.focus(Pane::Items),
            KeyCode::Char('u') => self.lock_selected(false),
            KeyCode::Char('L') => self.lock_selected(true),
            KeyCode::Char('s') => self.toggle_secret(),

            // SSH only.
            KeyCode::Char('a') => self.add_to_agent(),
            KeyCode::Char('x') => self.remove_from_agent(),
            KeyCode::Char('n') => self.begin_new_ssh_key(),

            _ => {}
        }
    }

    fn handle_prompt_key(&mut self, prompt: Prompt, code: KeyCode) {
        match prompt {
            Prompt::NewSshKey => match code {
                KeyCode::Char('1') => self.generate_ssh_key("ed25519", None),
                KeyCode::Char('2') => self.generate_ssh_key("ecdsa", Some(521)),
                KeyCode::Char('3') => self.generate_ssh_key("rsa", Some(4096)),
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.prompt = None;
                    self.status = "cancelled".into();
                }
                _ => {}
            },
        }
    }

    fn set_section(&mut self, section: Section) {
        if self.section == section {
            return;
        }
        self.hide_secret();
        self.section = section;
        self.error = None;

        match section {
            Section::Keyrings => self.status = "keyrings".into(),
            Section::GpgKeys => self.status = "GPG backend not implemented yet".into(),
            Section::SshKeys => {
                if self.ssh_loaded {
                    self.status = self.describe_ssh_keys();
                } else {
                    self.status = "scanning ~/.ssh…".into();
                    self.send_ssh(SshRequest::ListKeys);
                }
            }
        }
    }

    fn focus(&mut self, pane: Pane) {
        if self.section != Section::Keyrings || self.pane == pane {
            return;
        }
        self.hide_secret();
        self.pane = pane;
        if pane == Pane::Items && self.item_state.selected().is_none() && !self.items.is_empty() {
            self.item_state.select(Some(0));
        }
    }

    fn move_selection(&mut self, delta: isize) {
        self.hide_secret();
        match self.section {
            Section::Keyrings => match self.pane {
                Pane::Keyrings => {
                    if step(&mut self.keyring_state, self.keyrings.len(), delta) {
                        self.load_selected_items();
                    }
                }
                Pane::Items => {
                    step(&mut self.item_state, self.items.len(), delta);
                }
            },
            Section::SshKeys => {
                step(&mut self.ssh_state, self.ssh_keys.len(), delta);
            }
            Section::GpgKeys => {}
        }
    }

    fn jump_selection(&mut self, first: bool) {
        self.hide_secret();
        let (state, len) = match self.section {
            Section::Keyrings => match self.pane {
                Pane::Keyrings => (&mut self.keyring_state, self.keyrings.len()),
                Pane::Items => (&mut self.item_state, self.items.len()),
            },
            Section::SshKeys => (&mut self.ssh_state, self.ssh_keys.len()),
            Section::GpgKeys => return,
        };
        if len == 0 {
            return;
        }
        let target = if first { 0 } else { len - 1 };
        let changed = state.selected() != Some(target);
        state.select(Some(target));
        if changed && self.section == Section::Keyrings && self.pane == Pane::Keyrings {
            self.load_selected_items();
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
            Section::GpgKeys => {}
        }
    }

    // --- Passwords -------------------------------------------------------

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

    fn begin_new_ssh_key(&mut self) {
        if self.section != Section::SshKeys {
            return;
        }
        self.prompt = Some(Prompt::NewSshKey);
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

    // --- Replies ---------------------------------------------------------

    pub fn on_reply(&mut self, reply: Reply) {
        match reply {
            Reply::Keyrings(keyrings) => {
                // Keep the selected keyring across a refresh where possible.
                let previous = self.selected_keyring().map(|k| k.label.clone());
                self.keyrings = keyrings;
                let restored = previous
                    .and_then(|label| self.keyrings.iter().position(|k| k.label == label))
                    .or_else(|| (!self.keyrings.is_empty()).then_some(0));
                self.keyring_state.select(restored);
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
                self.item_state
                    .select((!self.items.is_empty()).then_some(0));
                let locked = self.selected_keyring().is_some_and(|k| k.locked);
                if self.section == Section::Keyrings {
                    self.status = if self.items.is_empty() && locked {
                        "keyring is locked — press u to unlock".into()
                    } else {
                        format!("{} item(s)", self.items.len())
                    };
                }
            }

            Reply::Secret {
                keyring,
                item,
                value,
            } => {
                // Only show it if the cursor is still on the row we asked for.
                let still_current = self.selected_keyring().map(|k| k.id) == Some(keyring)
                    && self.selected_item().map(|i| i.id) == Some(item);
                if still_current {
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

            Reply::Status { message, refresh } => {
                self.error = None;
                self.status = message;
                match refresh {
                    Refresh::Keyrings => self.send(SecretsRequest::ListKeyrings),
                    Refresh::SshKeys => self.send_ssh(SshRequest::ListKeys),
                }
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

    use tokio::sync::mpsc::{self, UnboundedReceiver};

    use super::*;

    struct Harness {
        app: App,
        secrets: UnboundedReceiver<SecretsRequest>,
        ssh: UnboundedReceiver<SshRequest>,
    }

    impl Harness {
        fn new() -> Self {
            let (secrets_tx, secrets) = mpsc::unbounded_channel();
            let (ssh_tx, ssh) = mpsc::unbounded_channel();
            Self {
                app: App::new(secrets_tx, ssh_tx),
                secrets,
                ssh,
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

        fn drain(&mut self) {
            self.secrets_requests();
            self.ssh_requests();
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
        harness.app.on_external_done(Ok("ssh-add finished".into()));

        assert_eq!(harness.ssh_requests(), vec![SshRequest::ListKeys]);
        assert_eq!(harness.app.status, "ssh-add finished");
        assert!(harness.app.error.is_none());
    }

    #[test]
    fn a_failed_external_command_reports_and_still_rescans() {
        let mut harness = Harness::ssh_loaded();
        harness
            .app
            .on_external_done(Err("ssh-add exited with status 1".into()));

        assert_eq!(harness.ssh_requests(), vec![SshRequest::ListKeys]);
        assert_eq!(
            harness.app.error.as_deref(),
            Some("ssh-add exited with status 1")
        );
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
