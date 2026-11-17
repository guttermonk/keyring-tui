// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! Clipboard backend — copying, and wiping afterwards.
//!
//! Copying shells out to `wl-copy`, `xclip`, `xsel` or `pbcopy` rather than
//! setting the selection from this process. That is not a shortcut: on X11 and
//! Wayland the clipboard is served by a *live process*, so a selection owned
//! by keyring-tui would vanish the moment keyring-tui exits — copy a password,
//! quit, paste, get nothing. Those tools fork a background owner that outlives
//! their parent, which is the behaviour anyone copying a password expects.
//!
//! The timed wipe lives here rather than in the event loop. A copy spawns a
//! task that sleeps and then sends this actor a wipe request, so the UI stays
//! purely event-driven with no tick and no idle wakeups.
//!
//! A wipe reads the clipboard back and only clears it if it still holds what
//! we put there, so a later copy by the user is never discarded. Secrets are
//! held in [`Zeroizing`] throughout and never appear in a status message —
//! only the label does.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use zeroize::Zeroizing;

use super::{ClipboardRequest, Refresh, Replies, Reply};
use crate::config::clipboard::Clipboard;

/// Long enough for a loaded machine, short enough that a missing clipboard
/// tool does not look like a hang.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn the backend actor and return the handle the UI sends requests on.
pub fn spawn(replies: Replies, settings: Clipboard) -> UnboundedSender<ClipboardRequest> {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = tx.clone();
    tokio::spawn(async move { run(rx, handle, replies, settings).await });
    tx
}

async fn run(
    mut rx: UnboundedReceiver<ClipboardRequest>,
    self_handle: UnboundedSender<ClipboardRequest>,
    replies: Replies,
    settings: Clipboard,
) {
    let tool = Tool::resolve(&settings);

    // What we last put on the clipboard and are still willing to wipe. The
    // generation makes a sleeping wipe harmless once a newer copy has
    // replaced it: the stale task finds a number that no longer matches and
    // does nothing.
    let mut pending: Option<Zeroizing<String>> = None;
    let mut generation: u64 = 0;

    while let Some(request) = rx.recv().await {
        match request {
            ClipboardRequest::Copy {
                text,
                what,
                clear_after,
            } => {
                let Some(tool) = tool.as_ref() else {
                    let _ = replies.send(Reply::Error(no_tool()));
                    continue;
                };

                if let Err(err) = tool.copy(&text).await {
                    let _ = replies.send(Reply::Error(err));
                    continue;
                }

                generation = generation.wrapping_add(1);
                let message = match clear_after {
                    Some(delay) => {
                        pending = Some(text);
                        let after = generation;
                        let handle = self_handle.clone();
                        // The sleep lives in its own task so the actor stays
                        // free to answer the next request.
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = handle.send(ClipboardRequest::WipeIfOurs { generation: after });
                        });
                        format!("copied {what} — clearing in {}s", delay.as_secs().max(1))
                    }
                    None => {
                        // Nothing to wipe later, so nothing is remembered.
                        pending = None;
                        format!("copied {what}")
                    }
                };

                let _ = replies.send(Reply::Status {
                    message,
                    // Copying changes nothing about any list.
                    refresh: Refresh::Nothing,
                });
            }

            ClipboardRequest::WipeIfOurs { generation: asked } => {
                if asked != generation {
                    // A newer copy has happened; that one owns the wipe.
                    continue;
                }
                let Some(ours) = pending.take() else { continue };
                let Some(tool) = tool.as_ref() else { continue };

                match tool.wipe(&ours).await {
                    Ok(true) => {
                        let _ = replies.send(Reply::Status {
                            message: "clipboard cleared".into(),
                            refresh: Refresh::Nothing,
                        });
                    }
                    // Something else is on the clipboard now, so it was not
                    // ours to take. Silent: the user replaced it deliberately.
                    Ok(false) => {}
                    Err(err) => {
                        let _ = replies.send(Reply::Error(err));
                    }
                }
            }

            ClipboardRequest::WipeNow { done } => {
                // Quitting with a wipe still pending: do it now rather than
                // leave the secret on the clipboard with nobody left to
                // remove it.
                if let (Some(ours), Some(tool)) = (pending.take(), tool.as_ref()) {
                    let _ = tool.wipe(&ours).await;
                }
                let _ = done.send(());
            }
        }
    }
}

fn no_tool() -> String {
    "no clipboard tool found — install wl-clipboard or xclip, or set \
     [clipboard] copy in the config"
        .into()
}

/// The commands that reach this machine's clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tool {
    copy: Vec<String>,
    /// Empty when the clipboard can be written but not read, which makes a
    /// wipe unconditional.
    paste: Vec<String>,
}

impl Tool {
    /// A configured command wins outright; otherwise pick by what the session
    /// looks like, then by what is installed.
    fn resolve(settings: &Clipboard) -> Option<Self> {
        if !settings.copy.is_empty() {
            return Some(Self {
                copy: settings.copy.clone(),
                paste: settings.paste.clone(),
            });
        }
        Self::detect(
            std::env::var_os("WAYLAND_DISPLAY").is_some(),
            std::env::var_os("DISPLAY").is_some(),
            |program| which(program).is_some(),
        )
    }

    /// Detection, with the environment and the `PATH` lookup passed in so a
    /// test can describe a machine it is not running on.
    pub(crate) fn detect(
        wayland: bool,
        x11: bool,
        installed: impl Fn(&str) -> bool,
    ) -> Option<Self> {
        let candidates: &[(&str, &[&str], &[&str])] = &[
            // Wayland and X11 first, in session order, so an XWayland-capable
            // machine running Wayland does not get handed xclip.
            (
                "wl-copy",
                &["--type", "text/plain"],
                &["wl-paste", "--no-newline", "--type", "text/plain"],
            ),
            (
                "xclip",
                &["-selection", "clipboard"],
                &["xclip", "-selection", "clipboard", "-o"],
            ),
            (
                "xsel",
                &["--clipboard", "--input"],
                &["xsel", "--clipboard", "--output"],
            ),
            // macOS, where there is no session variable to key off.
            ("pbcopy", &[], &["pbpaste"]),
        ];

        let eligible = |program: &str| match program {
            "wl-copy" => wayland,
            "xclip" | "xsel" => x11,
            _ => true,
        };

        for (program, args, paste) in candidates {
            if eligible(program) && installed(program) {
                return Some(Self {
                    copy: std::iter::once(*program)
                        .chain(args.iter().copied())
                        .map(str::to_owned)
                        .collect(),
                    paste: paste.iter().map(|part| (*part).to_string()).collect(),
                });
            }
        }
        None
    }

    async fn copy(&self, text: &str) -> Result<(), String> {
        let (program, args) = self.copy.split_first().ok_or_else(|| {
            "[clipboard] copy is empty; it needs at least a program name".to_string()
        })?;

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            // wl-copy forks a background owner and chatters on stderr; none
            // of it belongs on a terminal the TUI is drawing to.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| format!("could not run {program}: {err}"))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("{program} gave us no stdin"))?;

        // The write and the wait are both bounded: a clipboard tool that
        // never drains stdin would otherwise wedge this actor for good.
        tokio::time::timeout(TIMEOUT, async {
            stdin
                .write_all(text.as_bytes())
                .await
                .map_err(|err| format!("writing to {program} failed: {err}"))?;
            // Closing stdin is what tells the tool the selection is complete.
            drop(stdin);
            child
                .wait()
                .await
                .map_err(|err| format!("{program} failed: {err}"))
        })
        .await
        .map_err(|_| format!("{program} did not finish in time"))??;

        Ok(())
    }

    /// Clear the clipboard if it still holds `ours`. Returns whether it did.
    async fn wipe(&self, ours: &str) -> Result<bool, String> {
        if !self.paste.is_empty() {
            match self.read().await {
                // Someone has copied something else since; leave it alone.
                Ok(current) if current.as_str() != ours => return Ok(false),
                Ok(_) => {}
                // A clipboard we cannot read is wiped anyway: failing to
                // remove a secret is the worse outcome of the two.
                Err(_) => {}
            }
        }
        self.copy("").await?;
        Ok(true)
    }

    async fn read(&self) -> Result<Zeroizing<String>, String> {
        let (program, args) = self
            .paste
            .split_first()
            .ok_or_else(|| "[clipboard] paste is empty".to_string())?;

        let output = tokio::time::timeout(
            TIMEOUT,
            Command::new(program)
                .args(args)
                .stderr(Stdio::null())
                .output(),
        )
        .await
        .map_err(|_| format!("{program} did not finish in time"))?
        .map_err(|err| format!("could not run {program}: {err}"))?;

        Ok(Zeroizing::new(
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }
}

/// `PATH` lookup, so detection can say "installed" without running anything.
fn which(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wayland_is_preferred_where_both_displays_exist() {
        // An XWayland-capable session has both variables set, and wl-copy is
        // the one that talks to the compositor actually in charge.
        let tool = Tool::detect(true, true, |_| true).unwrap();
        assert_eq!(tool.copy.first().unwrap(), "wl-copy");
        assert_eq!(tool.paste.first().unwrap(), "wl-paste");
    }

    #[test]
    fn x11_falls_back_through_xclip_to_xsel() {
        let tool = Tool::detect(false, true, |program| program != "xclip").unwrap();
        assert_eq!(tool.copy.first().unwrap(), "xsel");

        let tool = Tool::detect(false, true, |_| true).unwrap();
        assert_eq!(tool.copy.first().unwrap(), "xclip");
    }

    #[test]
    fn a_wayland_tool_is_not_chosen_without_a_wayland_session() {
        // wl-copy installed but no compositor: it would fail at runtime, so
        // it must not be picked over the X11 tool that will work.
        let tool = Tool::detect(false, true, |_| true).unwrap();
        assert_ne!(tool.copy.first().unwrap(), "wl-copy");
    }

    #[test]
    fn pbcopy_needs_no_session_variable() {
        let tool = Tool::detect(false, false, |program| program == "pbcopy").unwrap();
        assert_eq!(tool.copy, vec!["pbcopy"]);
        assert_eq!(tool.paste, vec!["pbpaste"]);
    }

    #[test]
    fn nothing_installed_is_none_rather_than_a_command_that_fails() {
        assert!(Tool::detect(true, true, |_| false).is_none());
    }

    #[test]
    fn a_configured_command_wins_over_detection() {
        let settings = Clipboard {
            copy: vec!["tmux".into(), "load-buffer".into(), "-".into()],
            paste: vec!["tmux".into(), "save-buffer".into(), "-".into()],
            ..Clipboard::default()
        };
        let tool = Tool::resolve(&settings).unwrap();
        assert_eq!(tool.copy.first().unwrap(), "tmux");
    }

    /// Exercises the real copy/read/wipe round trip against whatever
    /// clipboard this machine has. Ignored by default: it writes to the
    /// developer's actual clipboard.
    #[tokio::test]
    #[ignore = "writes to the developer's real clipboard"]
    async fn live_round_trip() {
        let Some(tool) = Tool::resolve(&Clipboard::default()) else {
            println!("no clipboard tool on this machine");
            return;
        };
        println!("using {:?}", tool.copy);

        tool.copy("keyring-tui-test-value").await.expect("copy");
        let read = tool.read().await.expect("read");
        assert_eq!(read.as_str(), "keyring-tui-test-value");

        // A value that is not ours must survive the wipe.
        assert!(
            !tool.wipe("something-else-entirely").await.expect("wipe"),
            "the wipe should decline to clear a clipboard it does not own"
        );
        assert_eq!(
            tool.read().await.expect("read").as_str(),
            "keyring-tui-test-value"
        );

        assert!(tool.wipe("keyring-tui-test-value").await.expect("wipe"));
        assert!(tool.read().await.expect("read").is_empty());
    }
}
