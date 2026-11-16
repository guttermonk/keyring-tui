//! Colour themes.
//!
//! The syntax matches lazysync's: a `preset`, plus per-slot overrides in hex
//! or by ANSI name. The slots differ because the UI does — there are no
//! directories or symlinks here, but there are locks, agents and secrets.

use std::collections::BTreeMap;

use ratatui::style::Color;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `[theme]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Theme {
    pub preset: Preset,
    /// Per-slot overrides applied over the preset.
    pub colors: BTreeMap<String, ColorSpec>,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            preset: Preset::Terminal,
            colors: BTreeMap::new(),
        }
    }
}

impl Theme {
    /// The resolved palette: the preset, with `[theme.colors]` applied.
    ///
    /// An unknown slot is an error naming it, rather than a silently ignored
    /// line in a config someone expected to do something.
    pub fn palette(&self) -> Result<Palette, UnknownColorSlot> {
        let mut palette = self.preset.palette();
        for (slot, spec) in &self.colors {
            palette.set(slot, spec.0)?;
        }
        Ok(palette)
    }
}

/// A built-in palette.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    /// Follow the terminal's own colours, so a transparent or themed
    /// terminal shows through.
    #[default]
    Terminal,
    CatppuccinMocha,
    GruvboxDark,
    Nord,
}

/// Every colour the UI uses.
///
/// A flat struct rather than a map, so a missing slot is a compile error
/// instead of a black-on-black surprise at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub fg: Color,
    pub bg: Color,
    /// Secondary text: field labels, schemas, timestamps, hints.
    pub dim: Color,

    pub border: Color,
    pub border_focused: Color,

    /// The selected row, and the selected tab.
    pub cursor_fg: Color,
    pub cursor_bg: Color,

    pub status_fg: Color,
    pub status_bg: Color,

    /// Headings, `[sk]`/`[card]` markers, the active pane's title.
    pub accent: Color,
    /// `[agent]`, "in agent: yes" — a thing that is loaded and ready.
    pub ok: Color,
    /// `[locked]`, `[expired]`, `[revoked]`, and a modal's border.
    pub warn: Color,
    /// Errors, and anything irreversible.
    pub danger: Color,
    /// A revealed secret. Deliberately loud: it is on screen, and should
    /// look like it.
    pub secret: Color,
}

impl Palette {
    /// Slot names accepted in `[theme.colors]`, for the error message and the
    /// example config.
    pub const SLOTS: &'static [&'static str] = &[
        "fg",
        "bg",
        "dim",
        "border",
        "border_focused",
        "cursor_fg",
        "cursor_bg",
        "status_fg",
        "status_bg",
        "accent",
        "ok",
        "warn",
        "danger",
        "secret",
    ];

    fn set(&mut self, slot: &str, color: Color) -> Result<(), UnknownColorSlot> {
        let target = match slot {
            "fg" => &mut self.fg,
            "bg" => &mut self.bg,
            "dim" => &mut self.dim,
            "border" => &mut self.border,
            "border_focused" => &mut self.border_focused,
            "cursor_fg" => &mut self.cursor_fg,
            "cursor_bg" => &mut self.cursor_bg,
            "status_fg" => &mut self.status_fg,
            "status_bg" => &mut self.status_bg,
            "accent" => &mut self.accent,
            "ok" => &mut self.ok,
            "warn" => &mut self.warn,
            "danger" => &mut self.danger,
            "secret" => &mut self.secret,
            other => return Err(UnknownColorSlot(other.to_owned())),
        };
        *target = color;
        Ok(())
    }
}

impl Default for Palette {
    fn default() -> Self {
        Preset::Terminal.palette()
    }
}

/// A `[theme.colors]` key that is not a real colour slot.
#[derive(Debug, Clone)]
pub struct UnknownColorSlot(pub String);

impl std::error::Error for UnknownColorSlot {}

impl std::fmt::Display for UnknownColorSlot {
    /// The expected list comes from [`Palette::SLOTS`], so the message
    /// cannot drift from what `set` actually accepts.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown theme colour {:?} (expected one of: {})",
            self.0,
            Palette::SLOTS.join(", ")
        )
    }
}

impl Preset {
    fn palette(self) -> Palette {
        match self {
            Self::Terminal => Palette {
                // Reset, not a concrete colour: it is what lets a transparent
                // or themed terminal background show through.
                fg: Color::Reset,
                bg: Color::Reset,
                dim: Color::DarkGray,
                border: Color::DarkGray,
                border_focused: Color::Cyan,
                cursor_fg: Color::Black,
                cursor_bg: Color::Cyan,
                status_fg: Color::Reset,
                status_bg: Color::Reset,
                accent: Color::Cyan,
                ok: Color::Green,
                warn: Color::Yellow,
                danger: Color::Red,
                secret: Color::LightRed,
            },
            Self::CatppuccinMocha => Palette {
                fg: rgb(0xcdd6f4),
                bg: rgb(0x1e1e2e),
                dim: rgb(0x6c7086),
                border: rgb(0x45475a),
                border_focused: rgb(0x89b4fa),
                cursor_fg: rgb(0x1e1e2e),
                cursor_bg: rgb(0x89b4fa),
                status_fg: rgb(0xcdd6f4),
                status_bg: rgb(0x181825),
                accent: rgb(0x89b4fa),
                ok: rgb(0xa6e3a1),
                warn: rgb(0xf9e2af),
                danger: rgb(0xf38ba8),
                secret: rgb(0xf38ba8),
            },
            Self::GruvboxDark => Palette {
                fg: rgb(0xebdbb2),
                bg: rgb(0x282828),
                dim: rgb(0x928374),
                border: rgb(0x504945),
                border_focused: rgb(0xfabd2f),
                cursor_fg: rgb(0x282828),
                cursor_bg: rgb(0xfabd2f),
                status_fg: rgb(0xebdbb2),
                status_bg: rgb(0x3c3836),
                accent: rgb(0xfabd2f),
                ok: rgb(0xb8bb26),
                warn: rgb(0xfe8019),
                danger: rgb(0xfb4934),
                secret: rgb(0xfb4934),
            },
            Self::Nord => Palette {
                fg: rgb(0xd8dee9),
                bg: rgb(0x2e3440),
                dim: rgb(0x616e88),
                border: rgb(0x434c5e),
                border_focused: rgb(0x88c0d0),
                cursor_fg: rgb(0x2e3440),
                cursor_bg: rgb(0x88c0d0),
                status_fg: rgb(0xd8dee9),
                status_bg: rgb(0x3b4252),
                accent: rgb(0x88c0d0),
                ok: rgb(0xa3be8c),
                warn: rgb(0xebcb8b),
                danger: rgb(0xbf616a),
                secret: rgb(0xbf616a),
            },
        }
    }
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb(
        ((hex >> 16) & 0xff) as u8,
        ((hex >> 8) & 0xff) as u8,
        (hex & 0xff) as u8,
    )
}

/// A colour in config: `"#89b4fa"`, `"0x89b4fa"`, or an ANSI name like
/// `"red"` / `"bright-blue"` / `"reset"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorSpec(pub Color);

impl<'de> Deserialize<'de> for ColorSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        parse_color(&raw)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for ColorSpec {
    /// Hex for true colour, the ANSI name otherwise, so a dump round-trips
    /// through [`parse_color`].
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = match self.0 {
            Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
            Color::Reset => "reset".into(),
            Color::Black => "black".into(),
            Color::Red => "red".into(),
            Color::Green => "green".into(),
            Color::Yellow => "yellow".into(),
            Color::Blue => "blue".into(),
            Color::Magenta => "magenta".into(),
            Color::Cyan => "cyan".into(),
            Color::Gray => "gray".into(),
            Color::DarkGray => "dark-gray".into(),
            Color::LightRed => "bright-red".into(),
            Color::LightGreen => "bright-green".into(),
            Color::LightYellow => "bright-yellow".into(),
            Color::LightBlue => "bright-blue".into(),
            Color::LightMagenta => "bright-magenta".into(),
            Color::LightCyan => "bright-cyan".into(),
            Color::White => "bright-white".into(),
            // Indexed colours have no spelling in the config syntax; the
            // number keeps a dump honest rather than inventing a name.
            Color::Indexed(n) => format!("indexed-{n}"),
        };
        serializer.serialize_str(&text)
    }
}

fn parse_color(raw: &str) -> Result<Color, String> {
    let hex = raw
        .strip_prefix('#')
        .or_else(|| raw.strip_prefix("0x"))
        .or_else(|| raw.strip_prefix("0X"));

    if let Some(hex) = hex {
        if hex.len() != 6 {
            return Err(format!(
                "colour {raw:?} should have six hex digits, e.g. \"#89b4fa\""
            ));
        }
        let value =
            u32::from_str_radix(hex, 16).map_err(|_| format!("colour {raw:?} is not valid hex"))?;
        return Ok(rgb(value));
    }

    Ok(match raw.to_ascii_lowercase().replace('_', "-").as_str() {
        "reset" | "default" => Color::Reset,
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" | "white" => Color::Gray,
        "dark-gray" | "dark-grey" => Color::DarkGray,
        "bright-red" => Color::LightRed,
        "bright-green" => Color::LightGreen,
        "bright-yellow" => Color::LightYellow,
        "bright-blue" => Color::LightBlue,
        "bright-magenta" => Color::LightMagenta,
        "bright-cyan" => Color::LightCyan,
        "bright-white" => Color::White,
        other => {
            return Err(format!(
                "unknown colour {other:?} (expected a hex value like \"#89b4fa\", or an ANSI \
                 name: reset, black, red, green, yellow, blue, magenta, cyan, gray, dark-gray, \
                 bright-red, bright-green, bright-yellow, bright-blue, bright-magenta, \
                 bright-cyan, bright-white)"
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_preset_follows_the_terminal() {
        let palette = Theme::default().palette().unwrap();
        assert_eq!(
            palette.bg,
            Color::Reset,
            "a themed terminal must show through"
        );
        assert_eq!(palette.fg, Color::Reset);
    }

    #[test]
    fn presets_parse_from_kebab_case() {
        #[derive(Deserialize)]
        struct Wrapper {
            theme: Theme,
        }
        let parsed: Wrapper = toml::from_str("[theme]\npreset = \"catppuccin-mocha\"").unwrap();
        assert_eq!(parsed.theme.preset, Preset::CatppuccinMocha);
        assert_eq!(parsed.theme.palette().unwrap().accent, rgb(0x89b4fa));
    }

    #[test]
    fn overrides_apply_over_the_preset() {
        // `r##` because the hex colours contain `"#`, which would end an
        // `r#` literal early.
        let parsed: Theme = toml::from_str(
            r##"
            preset = "nord"
            [colors]
            border_focused = "#fabd2f"
            danger = "bright-red"
            "##,
        )
        .unwrap();

        let palette = parsed.palette().unwrap();
        assert_eq!(palette.border_focused, rgb(0xfabd2f));
        assert_eq!(palette.danger, Color::LightRed);
        // Untouched slots keep the preset's value.
        assert_eq!(palette.accent, rgb(0x88c0d0));
    }

    #[test]
    fn hex_accepts_both_prefixes() {
        assert_eq!(parse_color("#89b4fa").unwrap(), rgb(0x89b4fa));
        assert_eq!(parse_color("0x89b4fa").unwrap(), rgb(0x89b4fa));
    }

    #[test]
    fn a_bad_colour_names_itself() {
        let err = parse_color("#12345").unwrap_err();
        assert!(err.contains("six hex digits"), "{err}");
        let err = parse_color("burnt-sienna").unwrap_err();
        assert!(err.contains("unknown colour"), "{err}");
    }

    #[test]
    fn an_unknown_slot_is_an_error_not_a_shrug() {
        let theme: Theme = toml::from_str("[colors]\nborder_focsed = \"red\"").unwrap();
        let err = theme.palette().unwrap_err();
        assert!(err.to_string().contains("border_focsed"), "{err}");
    }

    #[test]
    fn every_slot_in_the_list_is_settable() {
        for slot in Palette::SLOTS {
            let mut palette = Palette::default();
            palette
                .set(slot, Color::Magenta)
                .unwrap_or_else(|err| panic!("{slot} is advertised but rejected: {err}"));
        }
    }

    #[test]
    fn colours_round_trip_through_serialisation() {
        // Through a table, because TOML has no document whose root is a bare
        // value — and a `[theme.colors]` table is how these are written anyway.
        for raw in ["#89b4fa", "red", "dark-gray", "bright-white", "reset"] {
            let color = parse_color(raw).unwrap();
            let theme = Theme {
                preset: Preset::Terminal,
                colors: BTreeMap::from([("accent".to_string(), ColorSpec(color))]),
            };

            let text = toml::to_string(&theme).expect("a theme serialises");
            let back: Theme = toml::from_str(&text).expect("and parses back");
            assert_eq!(
                back.palette().unwrap().accent,
                color,
                "{raw} did not round-trip through {text:?}"
            );
        }
    }
}
