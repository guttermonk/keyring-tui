//! Keymaps, and how a config's four tables merge over the defaults.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::action::{Action, Mode};
use super::combo::{KeyCombo, ModifiedKey};
use super::defaults;

/// One mode's bindings, in the order they were added. Order matters: the
/// first match wins, so a later duplicate is shadowed rather than fighting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keymap(pub Vec<(Action, KeyCombo)>);

/// What the keys pressed so far mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Nothing starts with these keys. Drop them.
    None,
    /// A longer chord starts with these keys, so wait for more.
    Pending,
    /// A complete binding.
    Exact(Action),
}

impl Keymap {
    pub fn iter(&self) -> std::slice::Iter<'_, (Action, KeyCombo)> {
        self.0.iter()
    }

    /// Kept for the `len`/`is_empty` pair, and used by the tests.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Decide what `pressed` means.
    ///
    /// A complete binding fires immediately, even if a longer chord also
    /// starts with it. There is no chord timeout to wait out, which is a
    /// deliberate trade: `d` and `dd` cannot coexist, and
    /// [`defaults::is_protected`] plus the default-keymap test keep that
    /// situation out of the built-ins.
    ///
    /// The app itself uses [`Keymap::resolve_where`], since a key's meaning
    /// can depend on the section; this is the unfiltered form the tests and
    /// any future non-sectioned caller want.
    #[allow(dead_code)]
    pub fn resolve(&self, pressed: &[ModifiedKey]) -> Resolution {
        self.resolve_where(pressed, |_| true)
    }

    /// Resolve, skipping actions that do not apply right now.
    ///
    /// One key can carry the same idea in several sections — `x` removes from
    /// the agent in SSH and deletes a key in GPG — so the first *applicable*
    /// binding wins rather than simply the first. Without this, the SSH
    /// binding would shadow the GPG one everywhere and `x` would silently do
    /// nothing in the GPG section.
    pub fn resolve_where(
        &self,
        pressed: &[ModifiedKey],
        applies: impl Fn(Action) -> bool,
    ) -> Resolution {
        if pressed.is_empty() {
            return Resolution::None;
        }

        let mut pending = false;
        let mut inapplicable: Option<Action> = None;

        for (action, combo) in &self.0 {
            if !combo.starts_with(pressed) {
                continue;
            }
            if combo.len() == pressed.len() {
                if applies(*action) {
                    return Resolution::Exact(*action);
                }
                // Remembered so the key still reports as bound; dispatching
                // it is a no-op, which is what "not here" should look like.
                inapplicable = inapplicable.or(Some(*action));
            } else {
                pending = true;
            }
        }

        match (inapplicable, pending) {
            (Some(action), _) => Resolution::Exact(action),
            (None, true) => Resolution::Pending,
            (None, false) => Resolution::None,
        }
    }

    /// Every combo bound to `action`, for the help overlay.
    pub fn combos_for(&self, action: Action) -> Vec<&KeyCombo> {
        self.0
            .iter()
            .filter(|(bound, _)| *bound == action)
            .map(|(_, combo)| combo)
            .collect()
    }

    /// The actions in this map, in the order they are first bound.
    pub fn actions(&self) -> Vec<Action> {
        let mut seen = Vec::new();
        for (action, _) in &self.0 {
            if !seen.contains(action) {
                seen.push(*action);
            }
        }
        seen
    }
}

/// One `[keys.<mode>]` table.
///
/// Four tables, applied in the order listed, because "change one key" and
/// "change every key" are different jobs — and so is "change which key does
/// X" versus "change what X's key does":
///
/// - `base` — start from nothing but this, replacing the defaults entirely.
/// - `set` — these actions get exactly these keys, losing the ones they had.
/// - `extra` — these keys get these actions, on top of whatever is there.
/// - `unbind` — these keys do nothing. Applied last, so it is a veto.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeymapSection {
    pub base: Option<Keymap>,
    /// Rebinds whole actions. This is the difference from `extra`: `extra`
    /// resolves collisions by *key*, so moving `MoveDown` to `e` with it
    /// would leave `j` moving down too. `set` resolves by *action*, which is
    /// what "I moved this to `e`" actually means.
    pub set: Option<Keymap>,
    pub extra: Option<Keymap>,
    pub unbind: Option<Vec<KeyCombo>>,
}

/// The resolved keymap for every mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keymaps(BTreeMap<Mode, Keymap>);

impl Default for Keymaps {
    fn default() -> Self {
        Self(
            Mode::ALL
                .into_iter()
                .map(|mode| (mode, defaults::for_mode(mode)))
                .collect(),
        )
    }
}

impl Keymaps {
    /// Merge user config over the defaults, per mode.
    ///
    /// `unbind` is last on purpose. It is the only one of the four that
    /// subtracts, and a veto another table could reinstate would be no veto
    /// at all — the reason to reach for it is to guarantee a key reaches the
    /// terminal, or a multiplexer, instead of keyring-tui.
    pub fn resolve(sections: &BTreeMap<Mode, KeymapSection>) -> Self {
        let mut maps = BTreeMap::new();

        for mode in Mode::ALL {
            let section = sections.get(&mode);
            let mut map = section
                .and_then(|s| s.base.clone())
                .unwrap_or_else(|| defaults::for_mode(mode));

            if let Some(set) = section.and_then(|s| s.set.as_ref()) {
                apply_set(&mut map, set);
            }
            if let Some(extra) = section.and_then(|s| s.extra.as_ref()) {
                apply_extra(&mut map, extra);
            }
            if let Some(unbind) = section.and_then(|s| s.unbind.as_ref()) {
                apply_unbind(&mut map, unbind);
            }

            maps.insert(mode, map);
        }

        Self(maps)
    }

    pub fn get(&self, mode: Mode) -> &Keymap {
        self.0
            .get(&mode)
            .expect("Keymaps is built with an entry for every Mode")
    }

    pub fn iter(&self) -> impl Iterator<Item = (Mode, &Keymap)> {
        self.0.iter().map(|(mode, map)| (*mode, map))
    }

    /// Actions that ended up with no key at all, which `base`, `set`, `extra`
    /// and `unbind` can all cause and which is otherwise silent.
    pub fn unreachable(&self, mode: Mode) -> Vec<Action> {
        let bound = self.get(mode).actions();
        defaults::for_mode(mode)
            .actions()
            .into_iter()
            .filter(|action| !bound.contains(action))
            .collect()
    }
}

/// Give each listed action exactly the listed keys.
fn apply_set(map: &mut Keymap, set: &Keymap) {
    let rebound: Vec<Action> = set.iter().map(|(action, _)| *action).collect();

    // The action loses its old keys — except the protected ones, so someone
    // who moves movement onto their own letters keeps working arrows.
    map.0
        .retain(|(action, combo)| !rebound.contains(action) || defaults::is_protected(combo));

    // And the new keys are taken from whoever else had them, or the binding
    // would be ambiguous.
    for (_, new_combo) in set.iter() {
        map.0.retain(|(_, combo)| !combo.starts_with(&new_combo.0));
    }

    map.0.extend(set.0.iter().cloned());
}

/// Layer `extra` over the map, dropping anything it makes unreachable.
///
/// The prefix test is the subtle part: binding `d` has to remove an existing
/// `dd`, or `d` would resolve to `Pending` and never fire.
fn apply_extra(map: &mut Keymap, extra: &Keymap) {
    for (_, extra_combo) in extra.iter() {
        map.0
            .retain(|(_, combo)| !combo.starts_with(&extra_combo.0));
    }
    map.0.extend(extra.0.iter().cloned());
}

/// Remove every binding a listed combo would reach.
///
/// Prefix-based for the same reason: `unbind = ["s"]` has to take any `s…`
/// chord with it, or `s` would still be swallowed waiting for the rest.
fn apply_unbind(map: &mut Keymap, combos: &[KeyCombo]) {
    for dead in combos {
        map.0.retain(|(_, combo)| !combo.starts_with(&dead.0));
    }
}

#[cfg(test)]
mod tests {
    use super::super::combo::Key;
    use super::*;

    fn key(c: char) -> ModifiedKey {
        ModifiedKey::plain(Key::Char(c))
    }

    fn section(toml: &str) -> BTreeMap<Mode, KeymapSection> {
        #[derive(Deserialize)]
        struct Wrapper {
            keys: BTreeMap<Mode, KeymapSection>,
        }
        toml::from_str::<Wrapper>(toml)
            .expect("config should parse")
            .keys
    }

    #[test]
    fn defaults_resolve_hjkl() {
        let maps = Keymaps::default();
        let main = maps.get(Mode::Main);
        assert_eq!(
            main.resolve(&[key('j')]),
            Resolution::Exact(Action::MoveDown)
        );
        assert_eq!(
            main.resolve(&[key('h')]),
            Resolution::Exact(Action::FocusLeft)
        );
    }

    #[test]
    fn set_moves_an_action_and_retires_its_old_key() {
        // The n/e/i/o layout, exactly as the example config documents it.
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            set = [
                ["MoveDown",   "e"],
                ["MoveUp",     "i"],
                ["FocusLeft",  "n"],
                ["FocusRight", "o"],
            ]
            "#,
        ));
        let main = maps.get(Mode::Main);

        assert_eq!(
            main.resolve(&[key('e')]),
            Resolution::Exact(Action::MoveDown)
        );
        assert_eq!(main.resolve(&[key('i')]), Resolution::Exact(Action::MoveUp));
        assert_eq!(
            main.resolve(&[key('n')]),
            Resolution::Exact(Action::FocusLeft)
        );
        assert_eq!(
            main.resolve(&[key('o')]),
            Resolution::Exact(Action::FocusRight)
        );

        // j and k are gone, because `set` is by action.
        assert_eq!(main.resolve(&[key('j')]), Resolution::None);
        assert_eq!(main.resolve(&[key('k')]), Resolution::None);

        // And the keys were taken from what previously held them.
        assert_ne!(
            main.resolve(&[key('n')]),
            Resolution::Exact(Action::NewSshKey)
        );
        assert_ne!(
            main.resolve(&[key('e')]),
            Resolution::Exact(Action::GpgEdit)
        );
    }

    #[test]
    fn set_keeps_the_arrows_and_the_escape_hatches() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            set = [["MoveDown", "e"], ["Quit", "Z"]]
            "#,
        ));
        let main = maps.get(Mode::Main);

        assert_eq!(
            main.resolve(&[ModifiedKey::plain(Key::Down)]),
            Resolution::Exact(Action::MoveDown),
            "an arrow should survive a set"
        );
        assert_eq!(
            main.resolve(&[ModifiedKey::ctrl(Key::Char('c'))]),
            Resolution::Exact(Action::Quit),
            "ctrl+c should always quit"
        );
        assert_eq!(main.resolve(&[key('Z')]), Resolution::Exact(Action::Quit));
        assert_eq!(main.resolve(&[key('q')]), Resolution::None, "q was retired");
    }

    #[test]
    fn extra_adds_without_retiring() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            extra = [["MoveDown", "e"]]
            "#,
        ));
        let main = maps.get(Mode::Main);

        assert_eq!(
            main.resolve(&[key('e')]),
            Resolution::Exact(Action::MoveDown)
        );
        assert_eq!(
            main.resolve(&[key('j')]),
            Resolution::Exact(Action::MoveDown),
            "extra leaves the old key working"
        );
    }

    #[test]
    fn extra_takes_a_key_from_whoever_had_it() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            extra = [["MoveDown", "e"]]
            "#,
        ));
        // `e` was GpgEdit by default; the new binding wins.
        assert_eq!(
            maps.get(Mode::Main).resolve(&[key('e')]),
            Resolution::Exact(Action::MoveDown)
        );
    }

    #[test]
    fn base_replaces_everything() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            base = [["Quit", "Q"]]
            "#,
        ));
        let main = maps.get(Mode::Main);

        assert_eq!(main.resolve(&[key('Q')]), Resolution::Exact(Action::Quit));
        assert_eq!(main.resolve(&[key('j')]), Resolution::None);
        assert_eq!(main.0.len(), 1);
    }

    #[test]
    fn unbind_wins_over_everything_and_is_prefix_based() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            extra = [["Refresh", ["s", "r"]]]
            unbind = ["s", "esc"]
            "#,
        ));
        let main = maps.get(Mode::Main);

        assert_eq!(
            main.resolve(&[key('s')]),
            Resolution::None,
            "unbinding s must also take the s-r chord, or s stays swallowed"
        );
        assert_eq!(
            main.resolve(&[ModifiedKey::plain(Key::Esc)]),
            Resolution::None
        );
        assert_eq!(
            main.resolve(&[ModifiedKey::ctrl(Key::Char('c'))]),
            Resolution::Exact(Action::Quit),
            "ctrl+c was not unbound, so it still quits"
        );
    }

    #[test]
    fn chords_report_pending_until_complete() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            extra = [["Refresh", ["g", "r"]]]
            unbind = ["g"]
            "#,
        ));
        let main = maps.get(Mode::Main);
        // `unbind = ["g"]` removed the default First binding, then... the
        // chord was added before the unbind, so it is gone too.
        assert_eq!(main.resolve(&[key('g')]), Resolution::None);

        // Without the unbind, the chord is reachable and `g` is pending-free
        // because the plain `g` binding completes first.
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            set = [["Refresh", ["g", "r"]]]
            "#,
        ));
        let main = maps.get(Mode::Main);
        assert_eq!(
            main.resolve(&[key('g')]),
            Resolution::Exact(Action::First),
            "the plain binding fires rather than waiting"
        );
        assert_eq!(main.resolve(&[key('r')]), Resolution::None, "r was retired");
    }

    #[test]
    fn a_chord_on_a_free_key_waits_for_its_second_press() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            extra = [["Refresh", ["z", "z"]]]
            "#,
        ));
        let main = maps.get(Mode::Main);
        assert_eq!(main.resolve(&[key('z')]), Resolution::Pending);
        assert_eq!(
            main.resolve(&[key('z'), key('z')]),
            Resolution::Exact(Action::Refresh)
        );
        assert_eq!(main.resolve(&[key('z'), key('x')]), Resolution::None);
    }

    #[test]
    fn unreachable_actions_are_reported() {
        let maps = Keymaps::resolve(&section(
            r#"
            [keys.main]
            unbind = ["s"]
            "#,
        ));
        let lost = maps.unreachable(Mode::Main);
        assert!(
            lost.contains(&Action::ToggleSecret),
            "unbinding s should report ToggleSecret as unreachable, got {lost:?}"
        );
        assert!(maps.unreachable(Mode::Prompt).is_empty());
    }

    #[test]
    fn an_empty_config_equals_the_defaults() {
        let maps = Keymaps::resolve(&BTreeMap::new());
        assert_eq!(maps, Keymaps::default());
    }

    #[test]
    fn unknown_tables_are_rejected_not_ignored() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[allow(dead_code)]
            keys: BTreeMap<Mode, KeymapSection>,
        }
        let err = toml::from_str::<Wrapper>(
            r#"
            [keys.main]
            sett = [["Quit", "Z"]]
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("sett"), "{err}");
    }
}
