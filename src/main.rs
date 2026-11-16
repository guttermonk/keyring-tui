//! keyring-tui — a terminal replacement for GNOME Seahorse.

mod app;
mod backend;
mod config;
mod keys;
mod model;
mod ui;

use std::io;
use std::path::PathBuf;
use std::process::Command;

use color_eyre::Result;
use color_eyre::eyre::WrapErr;
use crossterm::event::{Event as TermEvent, EventStream};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures_util::StreamExt;
use tokio::sync::mpsc;

use crate::app::{App, External};
use crate::backend::Reply;

const USAGE: &str = concat!(
    env!("CARGO_PKG_NAME"),
    " ",
    env!("CARGO_PKG_VERSION"),
    "\n",
    env!("CARGO_PKG_DESCRIPTION"),
    "\n
Usage: keyring-tui [options]
       keyring-tui keys [options]      print the resolved keymap and exit

Options:
  -c, --config <path>   config file (default: $XDG_CONFIG_HOME/keyring-tui/config.toml)
  -h, --help
  -V, --version
",
);

#[tokio::main]
async fn main() -> Result<()> {
    // Two flags and one subcommand, so no argument parser.
    let mut config_path: Option<PathBuf> = None;
    let mut dump_keys = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "keys" => dump_keys = true,
            "-c" | "--config" => match args.next() {
                Some(path) => config_path = Some(PathBuf::from(path)),
                None => {
                    eprintln!("{arg} needs a path\n");
                    print!("{USAGE}");
                    std::process::exit(2);
                }
            },
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(());
            }
            "-V" | "--version" => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}\n");
                print!("{USAGE}");
                std::process::exit(2);
            }
        }
    }

    // A broken config is reported here, before the terminal is taken over,
    // where the message can actually be read.
    let settings = config::Config::load_default(config_path.as_deref())
        .wrap_err("failed to load the configuration")?;
    let palette = settings.palette().wrap_err("failed to build the theme")?;
    let keymaps = settings.keymaps();

    if dump_keys {
        print_keymap(&keymaps);
        return Ok(());
    }

    color_eyre::install()?;

    let terminal = ratatui::try_init().wrap_err("failed to set up the terminal")?;
    // Restore the terminal even if `run` returns an error or panics upstream of
    // the report being printed.
    let outcome = run(terminal, palette, keymaps).await;
    ratatui::restore();
    outcome
}

/// What `keyring-tui keys` prints: the keymap a config resolves to, and any
/// action a config has left with no key at all — which `base`, `set`, `extra`
/// and `unbind` can all cause, and which is otherwise silent.
fn print_keymap(keymaps: &keys::Keymaps) {
    for (mode, map) in keymaps.iter() {
        println!("[keys.{mode}]");
        for action in map.actions() {
            let combos: Vec<String> = map
                .combos_for(action)
                .into_iter()
                .map(ToString::to_string)
                .collect();
            println!(
                "  {:<18} {:<24} {}",
                action.to_string(),
                combos.join(", "),
                action.describe()
            );
        }

        let unreachable = keymaps.unreachable(mode);
        if !unreachable.is_empty() {
            println!("  (no key bound):");
            for action in unreachable {
                println!(
                    "  {:<18} {:<24} {}",
                    action.to_string(),
                    "-",
                    action.describe()
                );
            }
        }
        println!();
    }
}

async fn run(
    mut terminal: ratatui::DefaultTerminal,
    palette: config::theme::Palette,
    keymaps: keys::Keymaps,
) -> Result<()> {
    let (reply_tx, mut replies) = mpsc::unbounded_channel::<Reply>();
    let secrets = backend::secrets::spawn(reply_tx.clone());
    let ssh = backend::ssh::spawn(reply_tx.clone());
    let gpg = backend::gpg::spawn(reply_tx);
    let mut app = App::new(secrets, ssh, gpg, keymaps);

    let mut input = EventStream::new();

    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, &mut app, &palette))?;

        // Redraw only when something happened — no polling, no idle wakeups.
        tokio::select! {
            Some(event) = input.next() => match event {
                Ok(TermEvent::Key(key)) => app.handle_key(key),
                // Resize and focus events just need the redraw above.
                Ok(_) => {}
                Err(err) => return Err(err).wrap_err("reading terminal input failed"),
            },
            Some(reply) = replies.recv() => {
                app.on_reply(reply);
                // Drain anything else already queued so one redraw covers it.
                while let Ok(reply) = replies.try_recv() {
                    app.on_reply(reply);
                }
            },
            else => break,
        }

        if let Some(external) = app.take_external() {
            // The stream's reader thread must stop before the child gets the
            // terminal, or the two would race for stdin.
            drop(input);
            let outcome = suspended(&mut terminal, || run_external(&external))?;
            input = EventStream::new();
            app.on_external_done(&external, outcome);
        }
    }

    Ok(())
}

/// Leave the TUI, run `body` with the terminal in its original state, then
/// come back and repaint from scratch.
///
/// Raw mode and the alternate screen are toggled by hand rather than through
/// `ratatui::restore`/`init`, and the repaint goes through `resize` rather
/// than `clear`. Both avoid asking the terminal for its cursor position over
/// stdin — a round trip that hangs if the child left stdin drained — and
/// keeping the existing `Terminal` keeps ratatui's panic hook installed.
fn suspended<T>(terminal: &mut ratatui::DefaultTerminal, body: impl FnOnce() -> T) -> Result<T> {
    disable_raw_mode().wrap_err("failed to leave raw mode")?;
    execute!(io::stdout(), LeaveAlternateScreen)
        .wrap_err("failed to leave the alternate screen")?;

    let outcome = body();

    enable_raw_mode().wrap_err("failed to re-enter raw mode")?;
    execute!(io::stdout(), EnterAlternateScreen)
        .wrap_err("failed to re-enter the alternate screen")?;

    // Re-entering the alternate screen gives us a blank one, so reset the
    // buffer ratatui diffs against; otherwise the next frame paints nothing.
    let area = terminal
        .size()
        .wrap_err("failed to read the terminal size")?;
    terminal
        .resize(area.into())
        .wrap_err("failed to repaint after the external command")?;
    Ok(outcome)
}

/// Run an external command with inherited stdio, so it can prompt for a
/// passphrase or wait for a touch on a security key.
///
/// Returns the message for the status line, or the failure for the error line.
fn run_external(external: &External) -> Result<String, String> {
    let command = external.describe();
    println!("\n\x1b[1m› {command}\x1b[0m\n");

    let status = Command::new(external.program())
        .args(external.args())
        .status();

    let outcome = match status {
        Ok(status) if status.success() => Ok(format!("{} finished", external.program())),
        Ok(status) => Err(match status.code() {
            Some(code) => format!("{command} exited with status {code}"),
            None => format!("{command} was killed"),
        }),
        Err(err) => Err(format!("could not run {}: {err}", external.program())),
    };

    // The output is about to be hidden by the redraw, so let it be read first.
    println!("\n\x1b[2m[press Enter to return]\x1b[0m");
    let mut discard = String::new();
    let _ = io::stdin().read_line(&mut discard);

    outcome
}
