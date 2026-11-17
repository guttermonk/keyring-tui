// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! Rendering.
//!
//! A function of the app state and the resolved [`Palette`], with one
//! exception: the detail panes report how many lines they drew back into
//! `App`, because scrolling has to know where the content ends and only the
//! renderer knows.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, List, ListItem, Paragraph, Tabs, Wrap};

use crate::app::{App, Pane, Prompt, Question};
use crate::config::theme::Palette;
use crate::keys::{Action, Mode};
use crate::model::{AgentStatus, Section, format_timestamp};

pub fn draw(frame: &mut Frame, app: &mut App, p: &Palette) {
    // The base layer, so a preset's background covers the whole screen and
    // the `terminal` preset's `Reset` lets the real terminal show through.
    frame.render_widget(
        Block::default().style(Style::default().fg(p.fg).bg(p.bg)),
        frame.area(),
    );

    let [tabs_area, body_area, status_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_tabs(frame, tabs_area, app, p);

    match app.section {
        Section::Keyrings => draw_keyrings(frame, body_area, app, p),
        Section::GpgKeys => draw_gpg_keys(frame, body_area, app, p),
        Section::SshKeys => draw_ssh_keys(frame, body_area, app, p),
    }

    draw_status(frame, status_area, app, p);

    match app.prompt {
        Some(Prompt::Ask(question)) => draw_input(frame, frame.area(), app, question, p),
        Some(prompt) => draw_prompt(frame, frame.area(), app, prompt, p),
        None => {}
    }
    if app.show_help {
        draw_help(frame, frame.area(), app, p);
    }
}

fn draw_tabs(frame: &mut Frame, area: Rect, app: &App, p: &Palette) {
    let titles = Section::ALL.map(|section| {
        let index = section.index() + 1;
        Line::from(format!(" {index} {} ", section.title()))
    });
    let tabs = Tabs::new(titles)
        .select(app.section.index())
        .divider("")
        .highlight_style(
            Style::default()
                .fg(p.cursor_fg)
                .bg(p.accent)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn draw_keyrings(frame: &mut Frame, area: Rect, app: &mut App, p: &Palette) {
    let [left, right] =
        Layout::horizontal([Constraint::Length(30), Constraint::Min(30)]).areas(area);
    let [items_area, detail_area] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Min(9)]).areas(right);

    // Keyrings.
    let rows: Vec<ListItem> = app
        .keyrings
        .iter()
        .map(|keyring| {
            let mut spans = vec![Span::raw(keyring.label.clone())];
            if keyring.is_default {
                spans.push(Span::styled(" (default)", p.dim_style()));
            }
            if keyring.locked {
                spans.push(Span::styled(" [locked]", Style::default().fg(p.warn)));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let keyrings = List::new(rows)
        .block(pane_block("Keyrings", app.pane == Pane::Keyrings, p))
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(p.cursor_bg)
                .fg(p.cursor_fg),
        );
    frame.render_stateful_widget(keyrings, left, &mut app.keyring_state);

    // Items, as narrowed by the filter.
    let visible = app.visible_items();
    let rows: Vec<ListItem> = visible
        .iter()
        .map(|item| {
            let mut spans = vec![Span::raw(item.label.clone())];
            if item.locked {
                spans.push(Span::styled(" [locked]", Style::default().fg(p.warn)));
            }
            spans.push(Span::styled(format!("  {}", item.kind()), p.dim_style()));
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut title = match app.selected_keyring() {
        Some(keyring) => format!("Items — {}", keyring.label),
        None => "Items".to_string(),
    };
    // An active filter is the reason rows are missing, so say so in the one
    // place someone looking at a short list will read.
    if !app.item_filter.is_empty() {
        title.push_str(&format!(
            " — /{} ({} of {})",
            app.item_filter,
            visible.len(),
            app.items.len()
        ));
    }
    let items = List::new(rows)
        .block(pane_block(&title, app.pane == Pane::List, p))
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(p.cursor_bg)
                .fg(p.cursor_fg),
        );
    frame.render_stateful_widget(items, items_area, &mut app.item_state);

    draw_detail(frame, detail_area, app, p);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &mut App, p: &Palette) {
    let Some(item) = app.selected_item() else {
        let hint = Paragraph::new("No item selected.")
            .style(p.dim_style())
            .block(pane_block("Details", app.pane == Pane::Details, p));
        frame.render_widget(hint, area);
        return;
    };

    let mut lines = vec![
        field("Label", &item.label, p),
        field("Schema", item.schema().unwrap_or("—"), p),
        field("Created", &format_timestamp(item.created), p),
        field("Modified", &format_timestamp(item.modified), p),
    ];

    // The reveal hint names the bound key, which may not be `s`.
    let reveal_hint = match app
        .keymaps()
        .get(Mode::Main)
        .combos_for(Action::ToggleSecret)
        .first()
    {
        Some(combo) => format!("•••••••••  ({combo} to reveal)"),
        None => "•••••••••".to_string(),
    };
    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "Secret"), p.dim_style()),
        match &app.revealed {
            Some(secret) => Span::styled(secret.to_string(), Style::default().fg(p.secret).bold()),
            None => Span::styled(reveal_hint, p.dim_style()),
        },
    ]));

    if !item.attributes.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "Attributes",
            Style::default().fg(p.accent),
        )));
        for (key, value) in &item.attributes {
            lines.push(Line::from(vec![
                Span::styled(format!("  {key}: "), p.dim_style()),
                Span::raw(value.clone()),
            ]));
        }
    }

    // Record what was drawn so a focused detail pane knows where to stop
    // scrolling; only the renderer knows how many lines there are.
    app.detail_lines = lines.len() as u16;
    app.detail_height = area.height.saturating_sub(2);
    let scroll = app
        .detail_scroll
        .min(app.detail_lines.saturating_sub(app.detail_height));

    let detail = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(pane_block("Details", app.pane == Pane::Details, p));
    frame.render_widget(detail, area);
}

fn draw_ssh_keys(frame: &mut Frame, area: Rect, app: &mut App, p: &Palette) {
    // Wide enough for a long name plus both markers — `ssh-copy-id`-era names
    // like `id_ed25519_sk_nas_backup [agent] [sk]` are 37 columns. The
    // algorithm and size live in the detail pane rather than being truncated
    // off the end of every row.
    let [left, right] =
        Layout::horizontal([Constraint::Length(40), Constraint::Min(30)]).areas(area);

    let rows: Vec<ListItem> = app
        .ssh_keys
        .iter()
        .map(|key| {
            let mut spans = vec![Span::raw(key.name.clone())];
            if key.in_agent {
                spans.push(Span::styled(" [agent]", Style::default().fg(p.ok)));
            }
            if key.hardware_backed {
                spans.push(Span::styled(" [sk]", Style::default().fg(p.accent)));
            } else if key.encrypted {
                spans.push(Span::styled(" [enc]", p.dim_style()));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    // Before the first scan lands, say so rather than reporting the empty
    // defaults as fact.
    let title = match (app.ssh_ready(), app.agent) {
        (false, _) => "Keys — scanning…".to_string(),
        (true, AgentStatus::Ready { .. }) => "Keys".to_string(),
        (true, agent) => format!("Keys — {}", agent.describe()),
    };
    let keys = List::new(rows)
        .block(pane_block(&title, app.pane == Pane::List, p))
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(p.cursor_bg)
                .fg(p.cursor_fg),
        );
    frame.render_stateful_widget(keys, left, &mut app.ssh_state);

    draw_ssh_detail(frame, right, app, p);
}

fn draw_ssh_detail(frame: &mut Frame, area: Rect, app: &mut App, p: &Palette) {
    let Some(key) = app.selected_ssh_key() else {
        let message = if app.ssh_ready() {
            "No keys found in ~/.ssh."
        } else {
            "Scanning ~/.ssh…"
        };
        let hint = Paragraph::new(message)
            .style(p.dim_style())
            .block(pane_block("Details", app.pane == Pane::Details, p));
        frame.render_widget(hint, area);
        return;
    };

    let mut lines = vec![
        field("Name", &key.name, p),
        // The compact form is what the list used to show; the wire name is
        // what `ssh-keygen -l` and `authorized_keys` use.
        field(
            "Algorithm",
            &format!("{}  ({})", key.kind(), key.algorithm),
            p,
        ),
        field(
            "Comment",
            if key.comment.is_empty() {
                "—"
            } else {
                &key.comment
            },
            p,
        ),
        field("Fingerprint", &key.fingerprint, p),
    ];

    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "In agent"), p.dim_style()),
        match (key.in_agent, key.is_addable()) {
            (true, _) => Span::styled("yes", Style::default().fg(p.ok)),
            (false, true) => Span::styled("no  (a to add)", p.dim_style()),
            // No private key file, so ssh-add has nothing to work with.
            (false, false) => Span::styled("no", p.dim_style()),
        },
    ]));

    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "Private key"), p.dim_style()),
        match key.private_path() {
            Some(path) => Span::raw(path.display().to_string()),
            None => Span::styled("none on disk", p.dim_style()),
        },
    ]));
    if key.private_path().is_some() {
        lines.push(field(
            "Passphrase",
            if key.hardware_backed {
                "held by the security key"
            } else if key.encrypted {
                "yes, encrypted"
            } else {
                "none — the file is unencrypted"
            },
            p,
        ));
    }
    if let Some(path) = &key.public_path {
        lines.push(field("Public key", &path.display().to_string(), p));
    }

    if !key.public_line.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "authorized_keys line",
            Style::default().fg(p.accent),
        )));
        lines.push(Line::raw(key.public_line.clone()));
    }

    // Record what was drawn so a focused detail pane knows where to stop
    // scrolling; only the renderer knows how many lines there are.
    app.detail_lines = lines.len() as u16;
    app.detail_height = area.height.saturating_sub(2);
    let scroll = app
        .detail_scroll
        .min(app.detail_lines.saturating_sub(app.detail_height));

    let detail = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(pane_block("Details", app.pane == Pane::Details, p));
    frame.render_widget(detail, area);
}

fn draw_gpg_keys(frame: &mut Frame, area: Rect, app: &mut App, p: &Palette) {
    let [left, right] =
        Layout::horizontal([Constraint::Length(44), Constraint::Min(30)]).areas(area);

    let rows: Vec<ListItem> = app
        .gpg_keys
        .iter()
        .map(|key| {
            let mut spans = vec![Span::raw(key.primary_uid.clone())];
            if key.has_secret {
                spans.push(Span::styled(" [sec]", Style::default().fg(p.ok)));
            }
            if key.on_card {
                spans.push(Span::styled(" [card]", Style::default().fg(p.accent)));
            }
            if let Some(state) = key.state() {
                spans.push(Span::styled(
                    format!(" [{state}]"),
                    Style::default().fg(p.warn),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let title = if app.gpg_ready() {
        format!("Keys — {}", app.gpg_filter.describe())
    } else {
        "Keys — reading…".to_string()
    };
    let keys = List::new(rows)
        .block(pane_block(&title, app.pane == Pane::List, p))
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(p.cursor_bg)
                .fg(p.cursor_fg),
        );
    frame.render_stateful_widget(keys, left, &mut app.gpg_state);

    draw_gpg_detail(frame, right, app, p);
}

fn draw_gpg_detail(frame: &mut Frame, area: Rect, app: &mut App, p: &Palette) {
    let Some(key) = app.selected_gpg_key() else {
        let message = if app.gpg_ready() {
            match app.gpg_filter {
                crate::model::GpgFilter::Secret => "No keys with a private half.",
                crate::model::GpgFilter::All => "No keys in the GnuPG keyring.",
            }
        } else {
            "Reading the GnuPG keyring…"
        };
        let hint = Paragraph::new(message)
            .style(p.dim_style())
            .block(pane_block("Details", app.pane == Pane::Details, p));
        frame.render_widget(hint, area);
        return;
    };

    let mut lines = vec![
        field("Key ID", &key.key_id, p),
        field("Fingerprint", &group_fingerprint(&key.fingerprint), p),
        field("Algorithm", &key.algorithm, p),
        field("Created", &format_timestamp(key.created), p),
        field(
            "Expires",
            &match key.expires {
                Some(expires) => format_timestamp(Some(expires)),
                None => "never".into(),
            },
            p,
        ),
        field("Owner trust", key.owner_trust, p),
        field("Capabilities", &describe_capabilities(&key.capabilities), p),
        field(
            "Private key",
            if key.has_secret {
                "present in this keyring"
            } else {
                "not held"
            },
            p,
        ),
    ];

    if let Some(state) = key.state() {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<12}", "State"), p.dim_style()),
            Span::styled(state.to_string(), Style::default().fg(p.warn)),
        ]));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "User IDs",
        Style::default().fg(p.accent),
    )));
    for uid in &key.uids {
        let mut spans = vec![
            Span::styled("  ", Style::default()),
            Span::raw(uid.uid.clone()),
            Span::styled(format!("  ({})", uid.validity), p.dim_style()),
        ];
        if uid.revoked {
            spans.push(Span::styled(" [revoked]", Style::default().fg(p.warn)));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Subkeys",
        Style::default().fg(p.accent),
    )));
    for subkey in &key.subkeys {
        let mut spans = vec![
            Span::styled("  ", Style::default()),
            Span::raw(subkey.key_id.clone()),
            Span::styled(
                format!(
                    "  {}  [{}]  {}",
                    subkey.algorithm,
                    subkey.capabilities,
                    format_timestamp(subkey.created)
                ),
                p.dim_style(),
            ),
        ];
        if subkey.on_card {
            spans.push(Span::styled(" [card]", Style::default().fg(p.accent)));
        }
        if subkey.revoked {
            spans.push(Span::styled(" [revoked]", Style::default().fg(p.warn)));
        } else if subkey.expired {
            spans.push(Span::styled(" [expired]", Style::default().fg(p.warn)));
        }
        lines.push(Line::from(spans));
    }

    // Record what was drawn so a focused detail pane knows where to stop
    // scrolling; only the renderer knows how many lines there are.
    app.detail_lines = lines.len() as u16;
    app.detail_height = area.height.saturating_sub(2);
    let scroll = app
        .detail_scroll
        .min(app.detail_lines.saturating_sub(app.detail_height));

    let detail = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(pane_block("Details", app.pane == Pane::Details, p));
    frame.render_widget(detail, area);
}

/// Spell out gpg's capability letters, which are otherwise folklore.
fn describe_capabilities(letters: &str) -> String {
    if letters.is_empty() {
        return "none".into();
    }
    let names: Vec<&str> = letters
        .chars()
        .filter_map(|letter| match letter {
            's' => Some("sign"),
            'c' => Some("certify"),
            'e' => Some("encrypt"),
            'a' => Some("authenticate"),
            _ => None,
        })
        .collect();
    format!("{letters}  ({})", names.join(", "))
}

/// Fingerprints are read aloud and compared by eye, so group them the way gpg
/// does rather than printing 40 unbroken characters.
fn group_fingerprint(fingerprint: &str) -> String {
    if fingerprint.len() != 40 {
        return fingerprint.to_owned();
    }
    fingerprint
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App, p: &Palette) {
    let hints = format!("{} ", hint_line(app));
    let [message_area, keys_area] = Layout::horizontal([
        Constraint::Min(10),
        // Measured in characters, not bytes: a rebound key may be anything.
        Constraint::Length(hints.chars().count() as u16 + 1),
    ])
    .areas(area);

    let bar = Style::default().fg(p.status_fg).bg(p.status_bg);
    let message = match &app.error {
        Some(error) => Span::styled(format!(" {error}"), Style::default().fg(p.fg).bg(p.danger)),
        None => Span::styled(format!(" {}", app.status), p.dim_style()),
    };
    frame.render_widget(Paragraph::new(Line::from(message)).style(bar), message_area);

    let keys = Paragraph::new(Line::from(Span::styled(hints, p.dim_style())))
        .style(bar)
        .alignment(Alignment::Right);
    frame.render_widget(keys, keys_area);
}

/// The footer hints, built from the keymap in force rather than hardcoded —
/// otherwise a rebound key would leave the footer lying.
fn hint_line(app: &App) -> String {
    let map = app.keymaps().get(Mode::Main);
    let key = |action: Action| -> Option<String> {
        let combos = map.combos_for(action);
        // Prefer a named key over an arrow. `set` keeps the arrows, and they
        // keep their original position, so the arrow would otherwise be what
        // a rebound keymap advertises — less useful than the key the user
        // actually chose.
        combos
            .iter()
            .find(|combo| !combo.is_bare_arrow())
            .or_else(|| combos.first())
            .map(|combo| combo.to_string())
    };

    // Movement reads as a pair, since the two keys are always learned
    // together: `j/k move`, or `e/i move` for a rebound keymap.
    let mut parts = Vec::new();
    if let (Some(down), Some(up)) = (key(Action::MoveDown), key(Action::MoveUp)) {
        parts.push(format!("{down}/{up} move"));
    }

    let section_actions: &[(Action, &str)] = match app.section {
        Section::Keyrings => &[
            (Action::Unlock, "unlock"),
            (Action::ToggleSecret, "secret"),
            (Action::FilterItems, "filter"),
            (Action::NewKeyring, "new"),
            (Action::CopySecret, "copy"),
        ],
        Section::SshKeys => &[
            (Action::AgentAdd, "add"),
            (Action::AgentRemove, "remove"),
            (Action::NewSshKey, "new"),
            (Action::SshPassphrase, "passphrase"),
            (Action::CopySshKey, "copy"),
        ],
        Section::GpgKeys => &[
            (Action::GpgEdit, "edit"),
            (Action::GpgExport, "export"),
            (Action::NewGpgKey, "new"),
            (Action::CopyGpgFingerprint, "copy fpr"),
        ],
    };
    for (action, label) in section_actions {
        if let Some(combo) = key(*action) {
            parts.push(format!("{combo} {label}"));
        }
    }

    if let Some(combo) = key(Action::Help) {
        parts.push(format!("{combo} help"));
    }

    parts.join("  ")
}

/// A one-line text field, with a real terminal cursor in it.
///
/// `set_cursor_position` rather than a drawn block, so the cursor blinks and
/// behaves the way the terminal's own does — including for anyone reading the
/// screen with a tool that tracks it.
fn draw_input(frame: &mut Frame, area: Rect, app: &App, question: Question, p: &Palette) {
    let prose: Vec<&str> = question.describe().lines().collect();
    let label = question.label();

    // Prose, a blank line, the field, a blank line, the keys.
    let height = (prose.len() as u16 + 5).min(area.height);
    let popup = centered(area, 72, height);
    frame.render_widget(Clear, popup);

    let block = Block::bordered()
        .title(question.title())
        .border_style(Style::default().fg(p.accent));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let [prose_area, field_area, keys_area] = Layout::vertical([
        Constraint::Length(prose.len() as u16 + 1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(inner);

    let prose_lines: Vec<Line> = prose
        .iter()
        .map(|line| Line::styled((*line).to_string(), p.dim_style()))
        .collect();
    frame.render_widget(Paragraph::new(Text::from(prose_lines)), prose_area);

    // `label: ` sits in front of the field, so the text starts after it.
    let prefix = format!("{label}: ");
    let prefix_width = prefix.chars().count() as u16;
    let field_width = field_area.width.saturating_sub(prefix_width);
    let (text, cursor) = app.input.visible(field_width);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(prefix, p.dim_style()),
            Span::raw(text.to_string()),
        ])),
        field_area,
    );
    frame.set_cursor_position((field_area.x + prefix_width + cursor, field_area.y));

    let map = app.keymaps().get(Mode::Input);
    let keys = |action: Action| -> String {
        map.combos_for(action)
            .first()
            .map(ToString::to_string)
            .unwrap_or_else(|| "-".into())
    };
    // An empty field has nothing to run, and Enter just closes the box —
    // say so rather than offering an action that will not happen.
    let confirm = if app.input.is_empty() {
        format!(" {} close", keys(Action::Confirm))
    } else {
        format!(" {} run", keys(Action::Confirm))
    };
    frame.render_widget(
        Paragraph::new(Line::styled(
            format!("{confirm}   {} cancel", keys(Action::Cancel)),
            p.dim_style(),
        )),
        keys_area,
    );
}

fn draw_prompt(frame: &mut Frame, area: Rect, app: &App, prompt: Prompt, p: &Palette) {
    // Confirmations name the key they are about, so there is no doubt which
    // one is about to be deleted or published.
    let subject = app
        .selected_gpg_key()
        .map(|key| format!("{}\n{}", key.primary_uid, key.key_id))
        .unwrap_or_default();

    let (title, body) = match prompt {
        // Routed to `draw_input` before this is called.
        Prompt::Ask(_) => return,
        Prompt::NewSshKey => (" New SSH key ".to_string(), NEW_SSH_KEY_PROMPT.to_string()),
        Prompt::ConfirmGpgDelete => (
            " Delete key ".to_string(),
            format!("{subject}\n\n{DELETE_GPG_KEY_PROMPT}"),
        ),
        Prompt::ConfirmGpgPublish => (
            " Publish key ".to_string(),
            format!("{subject}\n\n{PUBLISH_GPG_KEY_PROMPT}"),
        ),
        Prompt::ConfirmDeleteItem => {
            let item = app
                .selected_item()
                .map(|item| item.label.clone())
                .unwrap_or_default();
            (
                " Delete secret ".to_string(),
                format!("{item}\n\n{DELETE_ITEM_PROMPT}"),
            )
        }
        Prompt::ConfirmDeleteKeyring => {
            let mut body = String::new();
            if let Some(keyring) = app.selected_keyring() {
                body.push_str(&keyring.label);
                if keyring.is_default {
                    body.push_str("  (the default keyring)");
                }
                body.push('\n');
                // A locked keyring reports no items, so counting them would
                // read as "this one is empty" when it is only shut.
                body.push_str(&if keyring.locked {
                    "locked — what is in it cannot be counted from here\n".to_string()
                } else {
                    format!("{} item(s)\n", app.items.len())
                });
            }
            (
                " Delete keyring ".to_string(),
                format!("{body}\n{DELETE_KEYRING_PROMPT}"),
            )
        }
        Prompt::ConfirmSshDelete => {
            // The files are the whole point of the question, so they are
            // listed rather than summarised.
            let mut body = String::new();
            if let Some(key) = app.selected_ssh_key() {
                for path in [&key.private_path, &key.public_path].into_iter().flatten() {
                    body.push_str(&format!("{}\n", path.display()));
                }
                if key.in_agent {
                    body.push_str("\nThe agent is holding it, and will be asked to forget it.\n");
                }
            }
            (
                " Delete SSH key ".to_string(),
                format!("{body}\n{DELETE_SSH_KEY_PROMPT}"),
            )
        }
    };

    // The prose is written out; the keys come from the prompt keymap, so a
    // rebound confirmation does not leave the modal advertising `y`.
    let choices: &[(Action, &str)] = match prompt {
        // Routed to `draw_input` before this is called.
        Prompt::Ask(_) => return,
        Prompt::NewSshKey => &[
            (Action::Choose1, "ed25519        (recommended)"),
            (Action::Choose2, "ecdsa p521"),
            (Action::Choose3, "rsa 4096"),
            (Action::Cancel, "cancel"),
        ],
        Prompt::ConfirmGpgDelete => &[(Action::Confirm, "delete"), (Action::Cancel, "cancel")],
        Prompt::ConfirmGpgPublish => &[(Action::Confirm, "publish"), (Action::Cancel, "cancel")],
        Prompt::ConfirmDeleteItem | Prompt::ConfirmSshDelete | Prompt::ConfirmDeleteKeyring => {
            &[(Action::Confirm, "delete"), (Action::Cancel, "cancel")]
        }
    };

    let map = app.keymaps().get(Mode::Prompt);
    let mut lines: Vec<Line> = body.lines().map(|line| annotate_key(line, p)).collect();
    lines.push(Line::raw(""));
    for (action, label) in choices {
        let combos: Vec<String> = map
            .combos_for(*action)
            .into_iter()
            .map(ToString::to_string)
            .collect();
        if combos.is_empty() {
            continue;
        }
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<10}", combos.join(", ")),
                Style::default().fg(p.accent).bold(),
            ),
            Span::raw((*label).to_string()),
        ]));
    }
    let popup = centered(area, 62, lines.len() as u16 + 2);
    frame.render_widget(Clear, popup);

    let widget = Paragraph::new(Text::from(lines)).block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(p.warn)),
    );
    frame.render_widget(widget, popup);
}

/// The help overlay, generated from the keymap in force.
///
/// Built rather than written out, so a rebound key shows the user's key and
/// an unbound action disappears instead of being advertised.
fn draw_help(frame: &mut Frame, area: Rect, app: &App, p: &Palette) {
    let map = app.keymaps().get(Mode::Main);

    let mut lines: Vec<Line> = Vec::new();
    let mut current_group = None;

    // Only what works here: the other sections' keys would be noise, and two
    // sections can share a key with different meanings.
    for action in map
        .actions()
        .into_iter()
        .filter(|action| action.applies_to(app.section))
    {
        let group = action.section();
        if group != current_group {
            if let Some(section) = group {
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    section.title().to_string(),
                    Style::default().fg(p.accent).bold(),
                ));
            }
            current_group = group;
        }

        let combos: Vec<String> = map
            .combos_for(action)
            .into_iter()
            .map(ToString::to_string)
            .collect();
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<12}", combos.join(", ")),
                Style::default().fg(p.accent).bold(),
            ),
            Span::raw(action.describe().to_string()),
        ]));
    }

    // The widest key column decides the width; the longest description is
    // about 44 columns, and the border adds two.
    let height = (lines.len() as u16 + 2).min(area.height);
    let popup = centered(area, 62, height);
    frame.render_widget(Clear, popup);

    let help = Paragraph::new(Text::from(lines)).block(
        Block::bordered()
            .title(format!(" Keys — {} ", app.section.title()))
            .border_style(Style::default().fg(p.accent)),
    );
    frame.render_widget(help, popup);
}

/// Style a `keys  description` line, highlighting the key column. Lines
/// without that shape (blank lines, group headings) are left alone.
fn annotate_key(line: &str, p: &Palette) -> Line<'static> {
    match line.split_once("  ") {
        Some((keys, description)) if !keys.is_empty() => Line::from(vec![
            Span::styled(format!(" {keys:<10}"), Style::default().fg(p.accent).bold()),
            Span::raw(description.trim().to_string()),
        ]),
        _ => Line::styled(line.to_string(), p.dim_style()),
    }
}

fn pane_block(title: &str, focused: bool, p: &Palette) -> Block<'static> {
    Block::bordered()
        .title(format!(" {title} "))
        .border_style(p.border_style(focused))
}

fn field(name: &str, value: &str, p: &Palette) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{name:<12}"), p.dim_style()),
        Span::raw(value.to_string()),
    ])
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

// The help overlay is generated from the keymap in force — see `draw_help`.
// Only prose lives here; every key the UI mentions comes from the keymap, so
// a rebound key never leaves the screen lying.

const NEW_SSH_KEY_PROMPT: &str = "\
ssh-keygen will ask for the path and passphrase.
";

const DELETE_GPG_KEY_PROMPT: &str = "\
Runs gpg --delete-key, which asks again. A key whose private
half you hold is refused, as gpg wants --delete-secret-keys.
";

const PUBLISH_GPG_KEY_PROMPT: &str = "\
Runs gpg --send-keys. Keyservers do not forget: a published
key, and every user ID on it, stays public.
";

const DELETE_ITEM_PROMPT: &str = "\
Deletes this secret from the keyring. There is no trash and no
undo, and whatever stored it will have to be told again.
";

const DELETE_KEYRING_PROMPT: &str = "\
Deletes the keyring and every secret in it. There is no trash
and no undo. Unlocking it first is not required and would not
help: the service removes the store either way.
";

const DELETE_SSH_KEY_PROMPT: &str = "\
Unlinks the files above. A private key cannot be regenerated:
anything still trusting it — authorized_keys on a host, a
deploy key, a signed commit — has to be reissued.
";

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use tokio::sync::mpsc;
    use zeroize::Zeroizing;

    use super::*;
    use crate::backend::Reply;
    use crate::keys::Keymaps;
    use crate::model::{
        AgentStatus, GpgFilter, GpgKeyInfo, GpgSubkey, GpgUid, ItemInfo, KeyringInfo, SshKeyInfo,
    };

    /// The rendered screen as one string per row, joined — enough to assert
    /// that a label is present without pinning the exact layout.
    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
        let palette = Palette::default();
        terminal.draw(|frame| draw(frame, app, &palette)).unwrap();

        let buffer = terminal.backend().buffer().clone();
        let area = buffer.area;
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn app() -> App {
        let (secrets, _secrets_rx) = mpsc::unbounded_channel();
        let (ssh, _ssh_rx) = mpsc::unbounded_channel();
        let (gpg, _gpg_rx) = mpsc::unbounded_channel();
        let (clipboard, _clip_rx) = mpsc::unbounded_channel();
        // The receivers are dropped, so requests go nowhere: these tests only
        // care about what a given state renders as.
        App::new(secrets, ssh, gpg, clipboard, None, Keymaps::default())
    }

    fn ssh_key(name: &str, in_agent: bool) -> SshKeyInfo {
        SshKeyInfo {
            id: 0,
            name: name.into(),
            private_path: Some(format!("/home/u/.ssh/{name}").into()),
            public_path: Some(format!("/home/u/.ssh/{name}.pub").into()),
            algorithm: "sk-ssh-ed25519@openssh.com".into(),
            bits: Some(256),
            comment: "u@host".into(),
            fingerprint: "SHA256:abcdef".into(),
            encrypted: false,
            hardware_backed: true,
            in_agent,
            public_line: "sk-ssh-ed25519@openssh.com AAAA u@host".into(),
        }
    }

    #[test]
    fn the_ssh_section_says_it_is_scanning_before_the_first_reply() {
        let mut app = app();
        app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(screen.contains("scanning"), "screen was:\n{screen}");
        assert!(
            !screen.contains("No keys found"),
            "must not claim an empty ~/.ssh before scanning:\n{screen}"
        );
        assert!(
            !screen.contains("SSH_AUTH_SOCK"),
            "must not claim there is no agent before asking:\n{screen}"
        );
    }

    #[test]
    fn an_ssh_key_renders_its_markers_and_details() {
        let mut app = app();
        app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
        app.on_reply(Reply::SshKeys {
            keys: vec![ssh_key("id_ed25519_sk", true)],
            agent: AgentStatus::Ready { loaded: 1 },
        });

        let screen = render(&mut app);
        assert!(screen.contains("id_ed25519_sk"), "{screen}");
        assert!(screen.contains("[agent]"), "{screen}");
        assert!(screen.contains("[sk]"), "{screen}");
        assert!(screen.contains("ed25519 256"), "{screen}");
        assert!(screen.contains("SHA256:abcdef"), "{screen}");
        assert!(
            screen.contains("held by the security key"),
            "an sk key has no file passphrase:\n{screen}"
        );
        assert!(!screen.contains("scanning"), "{screen}");
    }

    #[test]
    fn a_secret_is_masked_until_revealed() {
        let mut app = app();
        app.on_reply(Reply::Keyrings(vec![KeyringInfo {
            id: 0,
            label: "Login".into(),
            locked: false,
            is_default: true,
        }]));
        app.on_reply(Reply::Items {
            keyring: 0,
            items: vec![ItemInfo {
                id: 0,
                label: "github token".into(),
                attributes: Default::default(),
                locked: false,
                created: None,
                modified: None,
            }],
        });

        let screen = render(&mut app);
        assert!(screen.contains("•••"), "{screen}");
        assert!(!screen.contains("hunter2"), "{screen}");

        app.on_reply(Reply::Secret {
            keyring: 0,
            item: 0,
            value: Zeroizing::new("hunter2".into()),
        });
        let screen = render(&mut app);
        assert!(screen.contains("hunter2"), "{screen}");
    }

    #[test]
    fn a_filtered_item_list_says_so_in_its_title() {
        let mut app = app();
        app.on_reply(Reply::Keyrings(vec![KeyringInfo {
            id: 0,
            label: "Login".into(),
            locked: false,
            is_default: true,
        }]));
        app.on_reply(Reply::Items {
            keyring: 0,
            items: vec![item("github token"), item("mail")],
        });

        // `/` then "git", the way the keymap drives it.
        for code in [KeyCode::Char('/'), KeyCode::Char('g'), KeyCode::Char('i')] {
            app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(
            screen.contains("/git"),
            "the title has to explain the short list:\n{screen}"
        );
        assert!(screen.contains("1 of 2"), "{screen}");
        assert!(
            !screen.contains("mail"),
            "the filtered row is gone:\n{screen}"
        );
    }

    #[test]
    fn a_delete_confirmation_names_the_secret() {
        let mut app = app();
        app.on_reply(Reply::Keyrings(vec![KeyringInfo {
            id: 0,
            label: "Login".into(),
            locked: false,
            is_default: true,
        }]));
        app.on_reply(Reply::Items {
            keyring: 0,
            items: vec![item("github token")],
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(screen.contains("Delete secret"), "{screen}");
        assert!(
            screen.contains("github token"),
            "the modal must name what goes:\n{screen}"
        );
        assert!(screen.contains("no trash"), "{screen}");
    }

    #[test]
    fn the_keyring_delete_confirmation_counts_what_goes() {
        let mut app = app();
        app.on_reply(Reply::Keyrings(vec![KeyringInfo {
            id: 0,
            label: "Login".into(),
            locked: false,
            is_default: true,
        }]));
        app.on_reply(Reply::Items {
            keyring: 0,
            items: vec![item("github token"), item("mail")],
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(screen.contains("Delete keyring"), "{screen}");
        assert!(
            screen.contains("the default keyring"),
            "deleting the default is worth saying out loud:\n{screen}"
        );
        assert!(screen.contains("2 item(s)"), "{screen}");
    }

    #[test]
    fn a_locked_keyring_is_not_reported_as_empty() {
        let mut app = app();
        app.on_reply(Reply::Keyrings(vec![KeyringInfo {
            id: 0,
            label: "Archive".into(),
            locked: true,
            is_default: false,
        }]));
        // A locked collection answers with no items, which must not be
        // rendered as "this one is empty".
        app.on_reply(Reply::Items {
            keyring: 0,
            items: Vec::new(),
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(screen.contains("cannot be counted"), "{screen}");
        assert!(!screen.contains("0 item(s)"), "{screen}");
    }

    #[test]
    fn the_ssh_delete_confirmation_lists_the_files() {
        let mut app = app();
        app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
        app.on_reply(Reply::SshKeys {
            keys: vec![SshKeyInfo {
                id: 0,
                name: "id_ed25519".into(),
                private_path: Some("/home/u/.ssh/id_ed25519".into()),
                public_path: Some("/home/u/.ssh/id_ed25519.pub".into()),
                algorithm: "ssh-ed25519".into(),
                bits: Some(256),
                comment: "u@host".into(),
                public_line: "ssh-ed25519 AAAA u@host".into(),
                fingerprint: "SHA256:abc".into(),
                encrypted: true,
                hardware_backed: false,
                in_agent: true,
            }],
            agent: AgentStatus::Ready { loaded: 1 },
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(screen.contains("Delete SSH key"), "{screen}");
        assert!(
            screen.contains("id_ed25519.pub"),
            "both files have to be named:\n{screen}"
        );
        assert!(
            screen.contains("forget it"),
            "and the agent copy mentioned:\n{screen}"
        );
        assert!(screen.contains("cannot be regenerated"), "{screen}");
    }

    fn item(label: &str) -> ItemInfo {
        ItemInfo {
            id: 0,
            label: label.into(),
            attributes: Default::default(),
            locked: false,
            created: None,
            modified: None,
        }
    }

    #[test]
    fn a_gpg_key_renders_its_uids_subkeys_and_grouped_fingerprint() {
        let mut app = app();
        app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        app.on_reply(Reply::GpgKeys {
            keys: vec![GpgKeyInfo {
                id: 0,
                key_id: "A9F0DB57379512B0".into(),
                fingerprint: "A9F0DB57379512B0DFBFA6CDE18D94492C20F0FC".into(),
                primary_uid: "Greg <greg@example>".into(),
                uids: vec![GpgUid {
                    uid: "Greg <greg@example>".into(),
                    validity: "ultimate",
                    revoked: false,
                }],
                subkeys: vec![GpgSubkey {
                    key_id: "DEADBEEFCAFE0001".into(),
                    algorithm: "cv25519".into(),
                    created: None,
                    expires: None,
                    capabilities: "e".into(),
                    revoked: false,
                    expired: false,
                    has_secret: true,
                    on_card: true,
                }],
                algorithm: "ed25519".into(),
                created: None,
                expires: None,
                owner_trust: "ultimate",
                has_secret: true,
                revoked: false,
                expired: false,
                disabled: false,
                capabilities: "sc".into(),
                on_card: true,
            }],
            filter: GpgFilter::All,
            engine: "gpg 2.4.9".into(),
        });

        let screen = render(&mut app);
        assert!(screen.contains("Greg <greg@example>"), "{screen}");
        assert!(screen.contains("[sec]"), "{screen}");
        assert!(screen.contains("[card]"), "{screen}");
        assert!(
            screen.contains("A9F0 DB57 3795 12B0"),
            "fingerprint should be grouped:\n{screen}"
        );
        assert!(
            screen.contains("sc  (sign, certify)"),
            "capabilities should be spelled out:\n{screen}"
        );
        assert!(
            screen.contains("never"),
            "expiry should read never:\n{screen}"
        );
        assert!(screen.contains("DEADBEEFCAFE0001"), "{screen}");
        assert!(screen.contains("cv25519"), "{screen}");
    }

    #[test]
    fn a_delete_confirmation_names_the_key() {
        let mut app = app();
        app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        app.on_reply(Reply::GpgKeys {
            keys: vec![gpg_key("Greg <greg@example>")],
            filter: GpgFilter::All,
            engine: "gpg 2.4.9".into(),
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(screen.contains("Delete key"), "{screen}");
        assert!(
            screen.contains("Greg <greg@example>"),
            "the modal must name the key:\n{screen}"
        );
        assert!(screen.contains("delete-secret-key"), "{screen}");
    }

    #[test]
    fn the_gpg_section_says_it_is_reading_before_the_first_reply() {
        let mut app = app();
        app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));

        let screen = render(&mut app);
        assert!(screen.contains("reading"), "{screen}");
        assert!(!screen.contains("No keys in the GnuPG keyring"), "{screen}");
    }

    fn gpg_key(uid: &str) -> GpgKeyInfo {
        GpgKeyInfo {
            id: 0,
            key_id: "A9F0DB57379512B0".into(),
            fingerprint: "A9F0DB57379512B0DFBFA6CDE18D94492C20F0FC".into(),
            primary_uid: uid.into(),
            uids: Vec::new(),
            subkeys: Vec::new(),
            algorithm: "ed25519".into(),
            created: None,
            expires: None,
            owner_trust: "ultimate",
            has_secret: true,
            revoked: false,
            expired: false,
            disabled: false,
            capabilities: "sc".into(),
            on_card: false,
        }
    }

    #[test]
    fn the_new_key_prompt_covers_the_list() {
        let mut app = app();
        for code in [KeyCode::Char('3'), KeyCode::Char('n')] {
            app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        }

        let screen = render(&mut app);
        assert!(screen.contains("New SSH key"), "{screen}");
        assert!(screen.contains("ed25519"), "{screen}");
        assert!(
            screen.contains("esc"),
            "the cancel key comes from the keymap, lower-cased:\n{screen}"
        );
    }
}
