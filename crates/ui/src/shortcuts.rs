//! Settings → Keyboard Shortcuts…: see and change every action's keys.
//!
//! The dialog edits a draft, one list of keys per action in
//! [`SHORTCUTS`] order. Save puts it in effect at once and writes it to the
//! settings' `[keys]`; Cancel (or Esc) drops it. Adding a key waits for the
//! next one pressed: that's caught before anything it's bound to runs, so
//! pressing `t` names the key rather than toggling the tree, and Esc gives
//! up. A key another action has is only moved after asking.

use std::path::PathBuf;

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::{ActiveTheme as _, Sizable as _, WindowExt as _};
use gpui_kit::prelude::*;
use gpui_kit::*;

use crate::actions::{SHORTCUTS, display_key, works_while_typing};
use crate::app::AppState;
use crate::icons::{IconName, icon};
use crate::keymap::{Keymap, from_keystroke};
use crate::widgets::Highlighted as _;

/// A key pressed for one action that another already has.
struct Conflict {
    row: usize,
    key: String,
    owner: usize,
}

pub struct ShortcutsView {
    app: WeakEntity<AppState>,
    /// Each action's keys, as they'll be on Save.
    draft: Vec<Vec<String>>,
    filter: Entity<InputState>,
    /// The action picked, by its place in [`SHORTCUTS`].
    selected: Option<usize>,
    /// The action waiting for a key to be pressed.
    recording: Option<usize>,
    conflict: Option<Conflict>,
    /// Where Save writes; none when the settings file couldn't be read.
    save_to: Option<PathBuf>,
    /// Catches the next key while [`Self::recording`].
    intercept: Option<Subscription>,
    _subscription: Subscription,
}

impl ShortcutsView {
    pub fn new(
        app: WeakEntity<AppState>,
        keymap: &Keymap,
        save_to: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let filter =
            cx.new(|cx| InputState::new(window, cx).placeholder("Filter by action or key"));
        let subscription = cx.subscribe(&filter, |this: &mut Self, _, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Change) {
                this.keep_selection_visible(cx);
                cx.notify();
            }
        });
        Self {
            app,
            draft: keymap.draft(),
            filter,
            selected: Some(0),
            recording: None,
            conflict: None,
            save_to,
            intercept: None,
            _subscription: subscription,
        }
    }

    pub fn filter(&self) -> &Entity<InputState> {
        &self.filter
    }

    /// The actions the filter lets through: by description, name or key.
    fn visible(&self, cx: &App) -> Vec<usize> {
        let needle = self.filter.read(cx).value().trim().to_lowercase();
        let needle_key = crate::keymap::canonical(&needle).ok();
        (0..SHORTCUTS.len())
            .filter(|&i| {
                let s = &SHORTCUTS[i];
                needle.is_empty()
                    || s.description.to_lowercase().contains(&needle)
                    || s.name().contains(&needle)
                    || self.draft[i].iter().any(|k| {
                        Some(k) == needle_key.as_ref() || display_key(k).to_lowercase() == needle
                    })
            })
            .collect()
    }

    fn keep_selection_visible(&mut self, cx: &App) {
        let visible = self.visible(cx);
        if !self.selected.is_some_and(|s| visible.contains(&s)) {
            self.selected = visible.first().copied();
        }
    }

    fn step(&mut self, down: bool, cx: &mut Context<Self>) {
        let visible = self.visible(cx);
        let at = self
            .selected
            .and_then(|s| visible.iter().position(|&v| v == s));
        let next = match at {
            None => 0,
            Some(i) if down => (i + 1).min(visible.len().saturating_sub(1)),
            Some(i) => i.saturating_sub(1),
        };
        self.selected = visible.get(next).copied();
        cx.notify();
    }

    /// Wait for a key for the action at `row`: the next one pressed, caught
    /// before any binding (the app's, the dialog's Enter and Esc) runs.
    pub fn start_recording(&mut self, row: usize, cx: &mut Context<Self>) {
        self.selected = Some(row);
        self.recording = Some(row);
        self.conflict = None;
        let me = cx.entity().downgrade();
        self.intercept = Some(cx.intercept_keystrokes(move |ev, _, cx| {
            let Some(me) = me.upgrade() else {
                return;
            };
            cx.stop_propagation();
            let keystroke = ev.keystroke.clone();
            me.update(cx, |this, cx| this.pressed(&keystroke, cx));
        }));
        cx.notify();
    }

    /// Enter, with no key being waited for: add one to the picked action.
    pub fn start_recording_selected(&mut self, cx: &mut Context<Self>) {
        if self.recording.is_none()
            && let Some(row) = self.selected
        {
            self.start_recording(row, cx);
        }
    }

    fn stop_recording(&mut self, cx: &mut Context<Self>) {
        self.recording = None;
        // Dropped later: this can run inside the interceptor itself.
        if let Some(sub) = self.intercept.take() {
            cx.defer(move |_| drop(sub));
        }
        cx.notify();
    }

    fn pressed(&mut self, keystroke: &Keystroke, cx: &mut Context<Self>) {
        let Some(row) = self.recording else {
            return;
        };
        let m = &keystroke.modifiers;
        if keystroke.key == "escape" && !m.control && !m.alt && !m.shift && !m.platform {
            self.stop_recording(cx);
            return;
        }
        // A modifier on its own: wait for the key with it.
        let Some(key) = from_keystroke(keystroke) else {
            return;
        };
        self.stop_recording(cx);
        if self.draft[row].contains(&key) {
            return;
        }
        match (0..self.draft.len()).find(|&j| j != row && self.draft[j].contains(&key)) {
            Some(owner) => self.conflict = Some(Conflict { row, key, owner }),
            None => self.draft[row].push(key),
        }
    }

    /// Answer the question about a key another action has: move it here
    /// (`take`), or leave things as they were.
    fn settle_conflict(&mut self, take: bool, cx: &mut Context<Self>) {
        if let Some(c) = self.conflict.take()
            && take
        {
            self.draft[c.owner].retain(|k| *k != c.key);
            self.draft[c.row].push(c.key);
        }
        cx.notify();
    }

    fn remove_key(&mut self, row: usize, key: &str, cx: &mut Context<Self>) {
        self.draft[row].retain(|k| k != key);
        cx.notify();
    }

    fn defaults(row: usize) -> Vec<String> {
        SHORTCUTS[row].keys.iter().map(|k| k.to_string()).collect()
    }

    /// Back to its default keys, taking them from any action that has
    /// one of them now.
    fn reset(&mut self, row: usize, cx: &mut Context<Self>) {
        let keys = Self::defaults(row);
        for (j, other) in self.draft.iter_mut().enumerate() {
            if j != row {
                other.retain(|k| !keys.contains(k));
            }
        }
        self.draft[row] = keys;
        self.conflict = None;
        cx.notify();
    }

    pub fn reset_all(&mut self, cx: &mut Context<Self>) {
        self.draft = Keymap::defaults().draft();
        self.conflict = None;
        cx.notify();
    }

    /// Put the draft in effect, write it to the settings, and close.
    pub fn save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let keymap = Keymap::from_draft(self.draft.clone());
        let saved = self
            .save_to
            .as_ref()
            .map(|path| crate::config::save_keys(path, &keymap.entries()));
        let _ = self.app.update(cx, |app, cx| {
            app.apply_keymap(keymap, cx);
            match saved {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    app.set_error(format!("The new shortcuts are in effect, but couldn't be saved: {e}"))
                }
                None => app.set_error(
                    "The new shortcuts are in effect until you quit: the settings file couldn't be \
                     read, so it isn't changed"
                        .into(),
                ),
            }
        });
        window.close_dialog(cx);
    }

    fn render_row(&self, row: usize, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let s = &SHORTCUTS[row];
        let keys = &self.draft[row];
        let recording = self.recording == Some(row);
        let mut chips = div().flex().flex_wrap().items_center().gap_1().flex_1();
        for key in keys {
            let shown = display_key(key);
            let typed = !works_while_typing(key);
            let k = key.clone();
            chips = chips.child(
                div()
                    .id(SharedString::from(format!("key-{row}-{key}")))
                    .test_support()
                    .flex()
                    .items_center()
                    .gap_1()
                    .pl_2()
                    .pr_1()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.secondary)
                    .font_family(theme.mono_font_family.clone())
                    .aria_description(shown.clone())
                    .when(typed, |d| {
                        d.tooltip(|window, cx| {
                            Tooltip::new(
                                "Can be typed, so it's off while a filter box has the keyboard",
                            )
                            .build(window, cx)
                        })
                    })
                    .child(shown)
                    .child(
                        div()
                            .id(SharedString::from(format!("key-remove-{row}-{key}")))
                            .test_support()
                            .cursor_pointer()
                            .text_color(theme.muted_foreground)
                            .aria_description("Remove this key")
                            .child(icon(IconName::X))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                this.remove_key(row, &k, cx);
                            })),
                    ),
            );
        }
        if recording {
            chips = chips.child(
                div()
                    .id(("shortcut-recording", row))
                    .test_support()
                    .px_2()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.primary)
                    .text_color(theme.primary)
                    .child("Press a key… (Esc gives up)"),
            );
        } else if keys.is_empty() {
            chips = chips.child(div().text_color(theme.muted_foreground).child("No key"));
        }
        let changed = *keys != Self::defaults(row);
        let line = div()
            .id(("shortcut-row", row))
            .test_support()
            .flex()
            .items_center()
            .gap_2()
            .px_2()
            .py_1()
            .rounded_md()
            .highlighted(self.selected == Some(row), &theme)
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected = Some(row);
                cx.notify();
            }))
            .child(
                div()
                    .flex_none()
                    .w(px(300.))
                    .truncate()
                    .child(s.description)
                    .when(changed, |d| d.font_weight(FontWeight::SEMIBOLD)),
            )
            .child(chips)
            .child(
                Button::new(("shortcut-add", row))
                    .icon(icon(IconName::Plus))
                    .tooltip("Add a key: press it next (Enter does this too)")
                    .accessibility_label("Add a key")
                    .small()
                    .ghost()
                    .on_click(cx.listener(move |this, _, _, cx| this.start_recording(row, cx))),
            )
            .child(div().flex_none().w(px(64.)).when(changed, |d| {
                d.child(
                    Button::new(("shortcut-reset", row))
                        .label("Reset")
                        .tooltip("Back to the default keys")
                        .small()
                        .ghost()
                        .on_click(cx.listener(move |this, _, _, cx| this.reset(row, cx))),
                )
            }));
        let conflict = self.conflict.as_ref().filter(|c| c.row == row).map(|c| {
            let text = format!(
                "{} is used by \u{201c}{}\u{201d}.",
                display_key(&c.key),
                SHORTCUTS[c.owner].description
            );
            div()
                .id(("shortcut-conflict", row))
                .test_support()
                .flex()
                .items_center()
                .gap_2()
                .ml(px(310.))
                .mb_1()
                .text_color(theme.warning)
                .aria_description(text.clone())
                .child(icon(IconName::TriangleAlert))
                .child(text)
                .child(
                    Button::new("conflict-take")
                        .label("Use it here")
                        .small()
                        .on_click(cx.listener(|this, _, _, cx| this.settle_conflict(true, cx))),
                )
                .child(
                    Button::new("conflict-cancel")
                        .label("Cancel")
                        .small()
                        .ghost()
                        .on_click(cx.listener(|this, _, _, cx| this.settle_conflict(false, cx))),
                )
        });
        div().flex().flex_col().child(line).children(conflict)
    }
}

impl Render for ShortcutsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let visible = self.visible(cx);
        let mut list = div()
            .id("shortcuts-list")
            .test_support()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .border_1()
            .border_color(theme.border)
            .rounded_md()
            .p_1();
        let mut group = "";
        for &row in &visible {
            let g = SHORTCUTS[row].group;
            if g != group {
                group = g;
                list = list.child(
                    div()
                        .px_2()
                        .pt_2()
                        .pb_1()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(g),
                );
            }
            list = list.child(self.render_row(row, cx));
        }
        if visible.is_empty() {
            list = list.child(
                div()
                    .p_3()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("No action or key matches."),
            );
        }
        div()
            .id("shortcuts-editor")
            .test_support()
            .flex()
            .flex_col()
            .gap_3()
            .h(px(520.))
            .text_sm()
            // ↑/↓ pick an action; Delete takes the last key off it.
            .capture_key_down(cx.listener(|this, ev: &KeyDownEvent, window, cx| {
                if this.recording.is_some() {
                    return;
                }
                match ev.keystroke.key.as_str() {
                    "up" => this.step(false, cx),
                    "down" => this.step(true, cx),
                    "delete" if !this.filter.focus_handle(cx).is_focused(window) => {
                        if let Some(row) = this.selected
                            && let Some(last) = this.draft[row].last().cloned()
                        {
                            this.remove_key(row, &last, cx);
                        }
                    }
                    _ => return,
                }
                cx.stop_propagation();
            }))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div().w(px(260.)).child(
                            Input::new(&self.filter)
                                .small()
                                .prefix(icon(IconName::Search))
                                .cleanable(true),
                        ),
                    )
                    .child(div().text_xs().text_color(theme.muted_foreground).child(
                        "↑/↓ pick an action, Enter or + adds a key, Delete removes its last.",
                    )),
            )
            .child(list)
    }
}
