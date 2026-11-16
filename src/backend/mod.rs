//! Backends own all I/O and run off the UI task.
//!
//! Each backend is an actor: it receives a request, does the blocking or async
//! work (D-Bus round trips, reading `~/.ssh`, talking to the agent), and
//! pushes a [`Reply`] back to the event loop. The UI never awaits a backend,
//! so a locked keyring prompting for a passphrase can't wedge the redraw loop.
//!
//! Requests are per-backend; replies share one channel so the event loop has a
//! single place to wait.

pub mod gpg;
pub mod secrets;
pub mod ssh;

use tokio::sync::mpsc::UnboundedSender;
use zeroize::Zeroizing;

use crate::model::{AgentStatus, ItemInfo, KeyringInfo, SshKeyInfo};

/// Commands for the Secret Service backend.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretsRequest {
    /// Re-enumerate collections.
    ListKeyrings,
    /// Load the items of one keyring, unlocking nothing.
    ListItems {
        keyring: usize,
    },
    Unlock {
        keyring: usize,
    },
    Lock {
        keyring: usize,
    },
    /// Fetch one item's secret value for display.
    RevealSecret {
        keyring: usize,
        item: usize,
    },
}

/// Commands for the SSH backend.
///
/// Adding a key to the agent is deliberately absent: it needs a passphrase or
/// a touch on a security key, so it runs as an external command with the TUI
/// suspended. See [`crate::app::External`].
#[derive(Debug, PartialEq, Eq)]
pub enum SshRequest {
    /// Re-scan `~/.ssh` and re-read the agent.
    ListKeys,
    RemoveFromAgent {
        key: usize,
    },
}

/// Results flowing back from a backend to the event loop.
#[derive(Debug)]
pub enum Reply {
    Keyrings(Vec<KeyringInfo>),
    Items {
        keyring: usize,
        items: Vec<ItemInfo>,
    },
    Secret {
        keyring: usize,
        item: usize,
        /// Wiped when dropped; never logged.
        value: Zeroizing<String>,
    },
    SshKeys {
        keys: Vec<SshKeyInfo>,
        agent: AgentStatus,
    },
    /// Transient message for the status line, plus whatever the operation
    /// invalidated. A backend says what to re-read rather than the UI
    /// guessing, so a lock in one section cannot trigger a reload in another.
    Status {
        message: String,
        refresh: Refresh,
    },
    Error(String),
}

/// What a completed operation invalidated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refresh {
    Keyrings,
    SshKeys,
}

/// The channel a backend uses to report back. Send failures mean the UI is
/// already gone, so they are ignored at every call site.
pub type Replies = UnboundedSender<Reply>;
