//! Rendering. Pure function of `&App` — no state of its own.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, List, ListItem, Paragraph, Tabs, Wrap};

use crate::app::{App, Pane, Prompt};
use crate::model::{AgentStatus, Section, format_timestamp};

const ACCENT: Color = Color::Cyan;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [tabs_area, body_area, status_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_tabs(frame, tabs_area, app);

    match app.section {
        Section::Keyrings => draw_keyrings(frame, body_area, app),
        Section::GpgKeys => draw_placeholder(frame, body_area, GPG_ROADMAP),
        Section::SshKeys => draw_ssh_keys(frame, body_area, app),
    }

    draw_status(frame, status_area, app);

    if let Some(prompt) = app.prompt {
        draw_prompt(frame, frame.area(), prompt);
    }
    if app.show_help {
        draw_help(frame, frame.area());
    }
}

fn draw_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let titles = Section::ALL.map(|section| {
        let index = section.index() + 1;
        Line::from(format!(" {index} {} ", section.title()))
    });
    let tabs = Tabs::new(titles)
        .select(app.section.index())
        .divider("")
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn draw_keyrings(frame: &mut Frame, area: Rect, app: &mut App) {
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
                spans.push(Span::styled(" (default)", Style::default().dim()));
            }
            if keyring.locked {
                spans.push(Span::styled(
                    " [locked]",
                    Style::default().fg(Color::Yellow),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let keyrings = List::new(rows)
        .block(pane_block("Keyrings", app.pane == Pane::Keyrings))
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        );
    frame.render_stateful_widget(keyrings, left, &mut app.keyring_state);

    // Items.
    let rows: Vec<ListItem> = app
        .items
        .iter()
        .map(|item| {
            let mut spans = vec![Span::raw(item.label.clone())];
            if item.locked {
                spans.push(Span::styled(
                    " [locked]",
                    Style::default().fg(Color::Yellow),
                ));
            }
            spans.push(Span::styled(
                format!("  {}", item.kind()),
                Style::default().dim(),
            ));
            ListItem::new(Line::from(spans))
        })
        .collect();

    let title = match app.selected_keyring() {
        Some(keyring) => format!("Items — {}", keyring.label),
        None => "Items".to_string(),
    };
    let items = List::new(rows)
        .block(pane_block(&title, app.pane == Pane::Items))
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        );
    frame.render_stateful_widget(items, items_area, &mut app.item_state);

    draw_detail(frame, detail_area, app);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let Some(item) = app.selected_item() else {
        let hint = Paragraph::new("No item selected.")
            .style(Style::default().dim())
            .block(pane_block("Details", false));
        frame.render_widget(hint, area);
        return;
    };

    let mut lines = vec![
        field("Label", &item.label),
        field("Schema", item.schema().unwrap_or("—")),
        field("Created", &format_timestamp(item.created)),
        field("Modified", &format_timestamp(item.modified)),
    ];

    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "Secret"), Style::default().dim()),
        match &app.revealed {
            Some(secret) => Span::styled(
                secret.to_string(),
                Style::default().fg(Color::LightRed).bold(),
            ),
            None => Span::styled("•••••••••  (s to reveal)", Style::default().dim()),
        },
    ]));

    if !item.attributes.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "Attributes",
            Style::default().fg(ACCENT),
        )));
        for (key, value) in &item.attributes {
            lines.push(Line::from(vec![
                Span::styled(format!("  {key}: "), Style::default().dim()),
                Span::raw(value.clone()),
            ]));
        }
    }

    let detail = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .block(pane_block("Details", false));
    frame.render_widget(detail, area);
}

fn draw_ssh_keys(frame: &mut Frame, area: Rect, app: &mut App) {
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
                spans.push(Span::styled(" [agent]", Style::default().fg(Color::Green)));
            }
            if key.hardware_backed {
                spans.push(Span::styled(" [sk]", Style::default().fg(ACCENT)));
            } else if key.encrypted {
                spans.push(Span::styled(" [enc]", Style::default().dim()));
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
        .block(pane_block(&title, true))
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        );
    frame.render_stateful_widget(keys, left, &mut app.ssh_state);

    draw_ssh_detail(frame, right, app);
}

fn draw_ssh_detail(frame: &mut Frame, area: Rect, app: &App) {
    let Some(key) = app.selected_ssh_key() else {
        let message = if app.ssh_ready() {
            "No keys found in ~/.ssh."
        } else {
            "Scanning ~/.ssh…"
        };
        let hint = Paragraph::new(message)
            .style(Style::default().dim())
            .block(pane_block("Details", false));
        frame.render_widget(hint, area);
        return;
    };

    let mut lines = vec![
        field("Name", &key.name),
        // The compact form is what the list used to show; the wire name is
        // what `ssh-keygen -l` and `authorized_keys` use.
        field("Algorithm", &format!("{}  ({})", key.kind(), key.algorithm)),
        field(
            "Comment",
            if key.comment.is_empty() {
                "—"
            } else {
                &key.comment
            },
        ),
        field("Fingerprint", &key.fingerprint),
    ];

    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "In agent"), Style::default().dim()),
        match (key.in_agent, key.is_addable()) {
            (true, _) => Span::styled("yes", Style::default().fg(Color::Green)),
            (false, true) => Span::styled("no  (a to add)", Style::default().dim()),
            // No private key file, so ssh-add has nothing to work with.
            (false, false) => Span::styled("no", Style::default().dim()),
        },
    ]));

    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "Private key"), Style::default().dim()),
        match key.private_path() {
            Some(path) => Span::raw(path.display().to_string()),
            None => Span::styled("none on disk", Style::default().dim()),
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
        ));
    }
    if let Some(path) = &key.public_path {
        lines.push(field("Public key", &path.display().to_string()));
    }

    if !key.public_line.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "authorized_keys line",
            Style::default().fg(ACCENT),
        )));
        lines.push(Line::raw(key.public_line.clone()));
    }

    let detail = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .block(pane_block("Details", false));
    frame.render_widget(detail, area);
}

fn draw_placeholder(frame: &mut Frame, area: Rect, body: &str) {
    let mut lines = vec![
        Line::from(Span::styled(
            "Not implemented yet.",
            Style::default().fg(Color::Yellow).bold(),
        )),
        Line::raw(""),
    ];
    lines.extend(body.lines().map(Line::raw));

    let paragraph = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .block(pane_block("Roadmap", false));
    frame.render_widget(paragraph, area);
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    // The hints are section-specific, so the width follows the longest one.
    let hints = match app.section {
        Section::Keyrings => "j/k move  u unlock  s secret  ? help ",
        Section::SshKeys => "j/k move  a add  x remove  n new  ? help ",
        Section::GpgKeys => "? help ",
    };
    let [message_area, keys_area] = Layout::horizontal([
        Constraint::Min(10),
        Constraint::Length(hints.len() as u16 + 1),
    ])
    .areas(area);

    let message = match &app.error {
        Some(error) => Span::styled(
            format!(" {error}"),
            Style::default().fg(Color::White).bg(Color::Red),
        ),
        None => Span::styled(format!(" {}", app.status), Style::default().dim()),
    };
    frame.render_widget(Paragraph::new(Line::from(message)), message_area);

    let keys = Paragraph::new(Line::from(Span::styled(hints, Style::default().dim())))
        .alignment(Alignment::Right);
    frame.render_widget(keys, keys_area);
}

fn draw_prompt(frame: &mut Frame, area: Rect, prompt: Prompt) {
    let (title, body) = match prompt {
        Prompt::NewSshKey => (" New SSH key ", NEW_SSH_KEY_PROMPT),
    };

    let lines: Vec<Line> = body.lines().map(annotate_key).collect();
    let popup = centered(area, 58, lines.len() as u16 + 2);
    frame.render_widget(Clear, popup);

    let widget = Paragraph::new(Text::from(lines)).block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(widget, popup);
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let popup = centered(area, 58, HELP.lines().count() as u16 + 2);
    frame.render_widget(Clear, popup);

    let lines: Vec<Line> = HELP.lines().map(annotate_key).collect();

    let help = Paragraph::new(Text::from(lines)).block(
        Block::bordered()
            .title(" Keys ")
            .border_style(Style::default().fg(ACCENT)),
    );
    frame.render_widget(help, popup);
}

/// Style a `keys  description` line, highlighting the key column. Lines
/// without that shape (blank lines, group headings) are left alone.
fn annotate_key(line: &str) -> Line<'static> {
    match line.split_once("  ") {
        Some((keys, description)) if !keys.is_empty() => Line::from(vec![
            Span::styled(format!(" {keys:<10}"), Style::default().fg(ACCENT).bold()),
            Span::raw(description.trim().to_string()),
        ]),
        _ => Line::styled(line.to_string(), Style::default().dim()),
    }
}

fn pane_block(title: &str, focused: bool) -> Block<'static> {
    let border = if focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().dim()
    };
    Block::bordered()
        .title(format!(" {title} "))
        .border_style(border)
}

fn field(name: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{name:<12}"), Style::default().dim()),
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

const HELP: &str = "\
q, Esc  quit
?  toggle this help
Tab  next section
1/2/3  jump to section
j/k  move selection
g/G  first / last
r  refresh the current section

Passwords
h/l  focus keyrings / items
u  unlock selected keyring
L  lock selected keyring
s  reveal / hide the secret

SSH keys
a  add to the agent (runs ssh-add)
x  remove from the agent
n  new key (runs ssh-keygen)
";

const NEW_SSH_KEY_PROMPT: &str = "\
ssh-keygen will ask for the path and passphrase.

1  ed25519        (recommended)
2  ecdsa p521
3  rsa 4096
Esc  cancel
";

const GPG_ROADMAP: &str = "\
Planned, via gpgme against the real ~/.gnupg (passphrases stay in gpg-agent):

  • list secret and public keys, with trust, expiry and capabilities
  • key details: UIDs, subkeys, fingerprint, algorithm
  • generate, import, export
  • sign (certify) a key, set owner trust
  • change expiry, revoke UID or key
  • keyserver search, receive, publish
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
    use crate::model::{AgentStatus, ItemInfo, KeyringInfo, SshKeyInfo};

    /// The rendered screen as one string per row, joined — enough to assert
    /// that a label is present without pinning the exact layout.
    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();

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
        // The receivers are dropped, so requests go nowhere: these tests only
        // care about what a given state renders as.
        App::new(secrets, ssh)
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
    fn the_new_key_prompt_covers_the_list() {
        let mut app = app();
        for code in [KeyCode::Char('3'), KeyCode::Char('n')] {
            app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        }

        let screen = render(&mut app);
        assert!(screen.contains("New SSH key"), "{screen}");
        assert!(screen.contains("ed25519"), "{screen}");
        assert!(screen.contains("Esc"), "{screen}");
    }
}
