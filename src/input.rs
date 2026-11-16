// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 guttermonk <guttermonk@protonmail.com>

//! A one-line text field.
//!
//! Deliberately not a passphrase box. Everything in keyring-tui that needs a
//! secret — unlocking a keyring, adding a key to the agent, changing a
//! passphrase, signing — hands the terminal to pinentry, `ssh-add` or `gpg`
//! and lets them ask. Nothing here should ever hold one, so there is no
//! masked mode to reach for and no buffer a secret could land in. This field
//! is for paths, hostnames and search terms.
//!
//! Editing works in grapheme clusters rather than `char`s, so backspace over
//! `é` written as `e` + U+0301 removes the whole thing rather than stranding
//! a floating accent, and an emoji with a zero-width joiner behaves as one
//! character. The cursor is tracked as a byte offset that is always on a
//! cluster boundary.

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Input {
    value: String,
    /// Byte offset into `value`, always on a grapheme boundary.
    cursor: usize,
}

impl Input {
    /// A field pre-filled with `initial`, cursor at the end — the useful
    /// place when a default is offered for editing rather than retyping.
    pub fn new(initial: impl Into<String>) -> Self {
        let value = initial.into();
        Self {
            cursor: value.len(),
            value,
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn insert(&mut self, c: char) {
        self.value.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Delete the cluster before the cursor.
    pub fn backspace(&mut self) {
        if let Some(start) = self.prev_boundary() {
            self.value.replace_range(start..self.cursor, "");
            self.cursor = start;
        }
    }

    /// Delete the cluster under the cursor.
    pub fn delete(&mut self) {
        if let Some(end) = self.next_boundary() {
            self.value.replace_range(self.cursor..end, "");
        }
    }

    pub fn left(&mut self) {
        if let Some(start) = self.prev_boundary() {
            self.cursor = start;
        }
    }

    pub fn right(&mut self) {
        if let Some(end) = self.next_boundary() {
            self.cursor = end;
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.value.len();
    }

    /// Delete the word before the cursor, as `ctrl+w` does in a shell:
    /// trailing whitespace first, then back to the preceding whitespace.
    pub fn delete_word_before(&mut self) {
        let head = &self.value[..self.cursor];
        let trimmed = head.trim_end();
        let start = match trimmed.rfind(char::is_whitespace) {
            // `rfind` gives the byte index of the space itself; the word
            // begins after it.
            Some(index) => index + head[index..].chars().next().map_or(1, char::len_utf8),
            None => 0,
        };
        self.value.replace_range(start..self.cursor, "");
        self.cursor = start;
    }

    /// Delete everything before the cursor, as `ctrl+u` does.
    pub fn clear_before(&mut self) {
        self.value.replace_range(..self.cursor, "");
        self.cursor = 0;
    }

    /// The text to draw and how many columns into it the cursor sits, for a
    /// field `width` columns wide.
    ///
    /// Scrolls horizontally only as far as it must: the window is pinned to
    /// the start until the cursor would run past the right edge, so a short
    /// value never jitters and a long one keeps the cursor in view.
    pub fn visible(&self, width: u16) -> (&str, u16) {
        let width = width.max(1) as usize;
        let before = self.value[..self.cursor].width();

        if before < width {
            // The cursor still fits with the text anchored at the start.
            let mut end = self.value.len();
            let mut shown = 0;
            for (offset, cluster) in self.value.grapheme_indices(true) {
                shown += cluster.width();
                if shown > width {
                    end = offset;
                    break;
                }
            }
            return (&self.value[..end], before as u16);
        }

        // Scroll so the cursor sits on the last usable column.
        let mut start = self.cursor;
        let mut shown = 0;
        for (offset, cluster) in self.value[..self.cursor].grapheme_indices(true).rev() {
            let next = shown + cluster.width();
            if next > width.saturating_sub(1) {
                break;
            }
            shown = next;
            start = offset;
        }
        (&self.value[start..self.cursor], shown as u16)
    }

    fn prev_boundary(&self) -> Option<usize> {
        self.value[..self.cursor]
            .grapheme_indices(true)
            .next_back()
            .map(|(offset, _)| offset)
    }

    fn next_boundary(&self) -> Option<usize> {
        self.value[self.cursor..]
            .graphemes(true)
            .next()
            .map(|cluster| self.cursor + cluster.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(text: &str) -> Input {
        let mut input = Input::default();
        for c in text.chars() {
            input.insert(c);
        }
        input
    }

    #[test]
    fn new_puts_the_cursor_after_the_default() {
        let input = Input::new("/home/greg/key.asc");
        assert_eq!(input.value(), "/home/greg/key.asc");
        // Typing appends rather than overwriting the offered default.
        let mut input = input;
        input.insert('!');
        assert_eq!(input.value(), "/home/greg/key.asc!");
    }

    #[test]
    fn typing_and_backspacing() {
        let mut input = typed("abc");
        assert_eq!(input.value(), "abc");
        input.backspace();
        assert_eq!(input.value(), "ab");
        input.backspace();
        input.backspace();
        input.backspace();
        assert_eq!(input.value(), "", "backspace on an empty field is a no-op");
    }

    #[test]
    fn cursor_movement_inserts_in_the_middle() {
        let mut input = typed("ac");
        input.left();
        input.insert('b');
        assert_eq!(input.value(), "abc");

        input.home();
        input.insert('>');
        assert_eq!(input.value(), ">abc");

        input.end();
        input.insert('<');
        assert_eq!(input.value(), ">abc<");
    }

    #[test]
    fn delete_removes_forwards() {
        let mut input = typed("abc");
        input.home();
        input.delete();
        assert_eq!(input.value(), "bc");
        input.end();
        input.delete();
        assert_eq!(input.value(), "bc", "delete at the end is a no-op");
    }

    #[test]
    fn a_combining_accent_is_one_character_to_the_user() {
        // "e" + U+0301 renders as é; backspace should take both.
        let mut input = typed("cafe\u{301}");
        assert_eq!(
            input.value().chars().count(),
            5,
            "two chars for the last glyph"
        );
        input.backspace();
        assert_eq!(input.value(), "caf");
    }

    #[test]
    fn a_joined_emoji_is_one_character_too() {
        // Family emoji: several code points joined by U+200D.
        let mut input = typed("hi\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}");
        input.backspace();
        assert_eq!(input.value(), "hi");
    }

    #[test]
    fn moving_over_clusters_does_not_split_them() {
        let mut input = typed("a\u{1F468}\u{200D}\u{1F469}b");
        input.home();
        input.right();
        input.right();
        input.insert('|');
        assert_eq!(input.value(), "a\u{1F468}\u{200D}\u{1F469}|b");
    }

    #[test]
    fn delete_word_before_behaves_like_a_shell() {
        let mut input = typed("ssh-copy-id greg@nas  ");
        input.delete_word_before();
        assert_eq!(
            input.value(),
            "ssh-copy-id ",
            "trailing spaces go with the word"
        );
        input.delete_word_before();
        assert_eq!(input.value(), "");
        input.delete_word_before();
        assert_eq!(input.value(), "", "on an empty field it is a no-op");
    }

    #[test]
    fn delete_word_before_only_touches_what_is_behind_the_cursor() {
        let mut input = typed("one two");
        input.home();
        input.delete_word_before();
        assert_eq!(input.value(), "one two");
    }

    #[test]
    fn clear_before_leaves_the_tail() {
        let mut input = typed("/etc/nixos/flake.nix");
        input.home();
        for _ in 0..5 {
            input.right();
        }
        input.clear_before();
        assert_eq!(input.value(), "nixos/flake.nix");
    }

    #[test]
    fn a_short_value_is_shown_whole_with_no_scrolling() {
        let input = typed("key.asc");
        let (text, column) = input.visible(40);
        assert_eq!(text, "key.asc");
        assert_eq!(column, 7, "cursor sits after the last character");
    }

    #[test]
    fn a_long_value_scrolls_to_keep_the_cursor_visible() {
        let input = typed("/home/greg/Documents/keys/very-long-name.asc");
        let (text, column) = input.visible(20);

        assert!(text.len() <= input.value().len());
        assert!(column < 20, "the cursor must land inside the field");
        assert!(
            input.value().ends_with(text),
            "scrolled to the end, where the cursor is: {text:?}"
        );
    }

    #[test]
    fn scrolling_back_to_the_start_shows_the_head_again() {
        let mut input = typed("/home/greg/Documents/keys/very-long-name.asc");
        input.home();
        let (text, column) = input.visible(20);
        assert_eq!(column, 0);
        assert!(
            input.value().starts_with(text),
            "anchored at the start: {text:?}"
        );
    }

    #[test]
    fn wide_characters_count_as_two_columns() {
        // CJK glyphs are double-width; the cursor column is measured in
        // columns, not characters, or it would drift on screen.
        let input = typed("日本語");
        let (_, column) = input.visible(40);
        assert_eq!(column, 6);
    }

    #[test]
    fn a_zero_width_field_does_not_panic() {
        let input = typed("something");
        let (_, column) = input.visible(0);
        assert!(column <= 1);
    }
}
