//! The keyboard shortcuts in effect: the defaults in
//! [`crate::actions::SHORTCUTS`], with the user's `[keys]` settings over
//! them.
//!
//! A setting names an action in snake_case (`toggle_graph`) and gives the
//! keys for it, which replace its defaults; an empty list leaves it with
//! none. A key given to one action is taken off any other that had it by
//! default. Two settings can't share a key: the first in the file keeps it.

use std::any::TypeId;
use std::rc::Rc;

use gpui_kit::*;

use crate::actions::{CONTEXT, NOT_TYPING, SHORTCUTS, Shortcut, works_while_typing};

/// One action and its keys, in gpui syntax and canonical form.
pub struct Binding {
    pub shortcut: &'static Shortcut,
    pub keys: Vec<String>,
}

/// Every shortcut, in [`SHORTCUTS`] order, with the keys in effect.
pub struct Keymap {
    bindings: Vec<Binding>,
}

impl Global for Keymap {}

impl Default for Keymap {
    fn default() -> Self {
        Self::defaults()
    }
}

impl Keymap {
    /// The keys sysmon ships with.
    pub fn defaults() -> Self {
        Self {
            bindings: SHORTCUTS
                .iter()
                .map(|s| Binding {
                    shortcut: s,
                    keys: s.keys.iter().map(|k| k.to_string()).collect(),
                })
                .collect(),
        }
    }

    /// The defaults with `overrides` — `(action name, keys)` in the order
    /// the settings file gives them — applied, and what was wrong with them,
    /// as lines to show.
    pub fn resolve(overrides: &[(String, Vec<String>)]) -> (Self, Vec<String>) {
        let mut problems = Vec::new();
        // The keys each overridden action ends up with, in file order.
        let mut set: Vec<(usize, Vec<String>)> = Vec::new();
        for (name, keys) in overrides {
            let Some(i) = SHORTCUTS.iter().position(|s| s.name() == *name) else {
                problems.push(format!(
                    "[keys] {name}: no such action (sysmon-ui --print-keys lists them)"
                ));
                continue;
            };
            let mut mine = Vec::new();
            for key in keys {
                let key = match canonical(key) {
                    Ok(k) => k,
                    Err(why) => {
                        problems.push(format!("[keys] {name}: {why}"));
                        continue;
                    }
                };
                let taken = set
                    .iter()
                    .find(|(_, ks)| ks.contains(&key))
                    .map(|(j, _)| SHORTCUTS[*j].name());
                match taken {
                    Some(other) => problems.push(format!(
                        "[keys] {name}: \"{key}\" is already set for {other}"
                    )),
                    None if !mine.contains(&key) => mine.push(key),
                    None => {}
                }
            }
            match set.iter_mut().find(|(j, _)| *j == i) {
                Some((_, ks)) => ks.extend(mine),
                None => set.push((i, mine)),
            }
        }
        let claimed: Vec<&String> = set.iter().flat_map(|(_, ks)| ks).collect();
        let bindings = SHORTCUTS
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let keys = match set.iter().find(|(j, _)| *j == i) {
                    Some((_, ks)) => ks.clone(),
                    // Defaults, less any key a setting gave another action.
                    None => s
                        .keys
                        .iter()
                        .map(|k| k.to_string())
                        .filter(|k| !claimed.contains(&k))
                        .collect(),
                };
                Binding { shortcut: s, keys }
            })
            .collect();
        (Self { bindings }, problems)
    }

    /// The keys in effect as a `[keys]` table, every action with its
    /// description, grouped as the shortcuts list groups them: for
    /// `sysmon-ui --print-keys`, to copy into the settings and edit.
    pub fn to_toml(&self) -> String {
        let mut out = String::from(
            "# sysmon-ui keyboard shortcuts. Put this in config.toml and edit it:\n\
             # an action's keys replace its defaults, [] leaves it without any, and\n\
             # one you leave out keeps its defaults. Keys are written ctrl-g, shift-p,\n\
             # f5, pagedown, … (Ctrl+G works too).\n[keys]\n",
        );
        let mut group = "";
        for b in &self.bindings {
            if b.shortcut.group != group {
                group = b.shortcut.group;
                out.push_str(&format!("\n# {group}\n"));
            }
            let keys: Vec<String> = b.keys.iter().map(|k| format!("{k:?}")).collect();
            let entry = format!("{} = [{}]", b.shortcut.name(), keys.join(", "));
            out.push_str(&format!("{entry:<40} # {}\n", b.shortcut.description));
        }
        out
    }

    /// Each action's keys, in [`SHORTCUTS`] order: what the shortcut
    /// editor edits.
    pub fn draft(&self) -> Vec<Vec<String>> {
        self.bindings.iter().map(|b| b.keys.clone()).collect()
    }

    /// The keymap with `draft`'s keys, one list per action in
    /// [`SHORTCUTS`] order (as [`Self::draft`] gives them).
    pub fn from_draft(draft: Vec<Vec<String>>) -> Self {
        Self {
            bindings: SHORTCUTS
                .iter()
                .zip(draft)
                .map(|(shortcut, keys)| Binding { shortcut, keys })
                .collect(),
        }
    }

    /// What `[keys]` must say for this keymap: every action whose keys
    /// differ from its defaults with them, and the rest as `None` (no
    /// entry). An action that only lost a key to another is written out
    /// too, so the file says plainly what each key does.
    pub fn entries(&self) -> Vec<(String, Option<Vec<String>>)> {
        self.bindings
            .iter()
            .map(|b| {
                let default = b.shortcut.keys.iter().map(|k| k.to_string());
                let same = b.keys.iter().cloned().eq(default);
                (b.shortcut.name(), (!same).then(|| b.keys.clone()))
            })
            .collect()
    }

    /// The keys bound to the action `A`.
    pub fn keys<A: Action>(&self) -> &[String] {
        self.bindings
            .iter()
            .find(|b| (b.shortcut.type_id)() == TypeId::of::<A>())
            .map_or(&[], |b| &b.keys)
    }

    /// The first key bound to `A` as people read it (`g`, `Ctrl+O`), if
    /// it has one: for hints like "Graph this process (g)".
    pub fn label<A: Action>(&self) -> Option<String> {
        self.keys::<A>()
            .first()
            .map(|k| crate::actions::display_key(k))
    }

    /// gpui key bindings for all of it. A key that can be typed isn't
    /// bound while a text box has the keyboard.
    pub fn key_bindings(&self, cx: &App) -> Vec<KeyBinding> {
        let typing: Rc<KeyBindingContextPredicate> =
            Rc::new(KeyBindingContextPredicate::parse(CONTEXT).expect("context"));
        let not_typing: Rc<KeyBindingContextPredicate> =
            Rc::new(KeyBindingContextPredicate::parse(NOT_TYPING).expect("context"));
        let mut out = Vec::new();
        for b in &self.bindings {
            for k in &b.keys {
                let ctx = if works_while_typing(k) {
                    typing.clone()
                } else {
                    not_typing.clone()
                };
                match KeyBinding::load(k, (b.shortcut.action)(), Some(ctx), false, None, cx) {
                    Ok(binding) => out.push(binding.with_meta(OURS)),
                    // `canonical` let it through, so this is a bug; skip
                    // the key rather than lose them all.
                    Err(e) => tracing::warn!(key = %k, error = %e, "can't bind key"),
                }
            }
        }
        out
    }
}

/// `text` with the first key for `A` after it, as tooltips write it:
/// "Graph this process (g)". Just `text` when `A` has no key.
pub fn hinted<A: Action>(cx: &App, text: &str) -> SharedString {
    match cx.global::<Keymap>().label::<A>() {
        Some(key) => format!("{text} ({key})").into(),
        None => SharedString::from(text.to_string()),
    }
}

/// Marks sysmon's own bindings in gpui's keymap, so they can be told from
/// gpui-kit's (text editing, menus, dialogs) when the keys change.
const OURS: KeyBindingMetaIndex = KeyBindingMetaIndex(0x5359_534d);

/// Put `keymap` in effect while running: sysmon's bindings are replaced,
/// everyone else's kept, and the global the shortcuts list and hints read
/// is updated. gpui can only clear the whole keymap, so the others are
/// taken out first and put back. Menus that show keys must be rebuilt by
/// the caller.
pub fn apply(cx: &mut App, keymap: Keymap) {
    let others: Vec<KeyBinding> = cx
        .key_bindings()
        .borrow()
        .bindings()
        .filter(|b| b.meta() != Some(OURS))
        .cloned()
        .collect();
    let ours = keymap.key_bindings(cx);
    cx.clear_key_bindings();
    cx.bind_keys(others);
    cx.bind_keys(ours);
    cx.set_global(keymap);
}

/// Keys that aren't a single character.
const NAMED_KEYS: &[&str] = &[
    "escape",
    "enter",
    "space",
    "tab",
    "backspace",
    "delete",
    "insert",
    "up",
    "down",
    "left",
    "right",
    "home",
    "end",
    "pageup",
    "pagedown",
];

/// `key` in the one spelling the keymap uses: lower case, modifiers in a
/// fixed order (`ctrl-alt-shift-super-`), `+` accepted between parts
/// (`ctrl+g`). A capital letter on its own means Shift with it (`P` is
/// `shift-p`); after a modifier it's just the letter, as menus write it
/// (`Ctrl+X` is `ctrl-x`).
/// An error says what's wrong, for the settings file's reader.
pub fn canonical(key: &str) -> Result<String, String> {
    let key = key.trim();
    let bad = |why: &str| Err(format!("\"{key}\" {why}"));
    if key.is_empty() {
        return bad("is empty");
    }
    if key.contains(' ') {
        return bad("is several keys; only single keystrokes can be bound");
    }
    let sep = if !key.contains('-') && key.len() > 1 && key.contains('+') {
        '+'
    } else {
        '-'
    };
    let mut parts: Vec<&str> = key.split(sep).collect();
    // A trailing "-" or "+" key: "ctrl--" splits into ["ctrl", "", ""].
    let last = match parts.as_slice() {
        [.., "", ""] => {
            parts.truncate(parts.len() - 2);
            sep.to_string()
        }
        _ => parts.pop().unwrap_or_default().to_string(),
    };
    let (mut ctrl, mut alt, mut shift, mut sup) = (false, false, false, false);
    for m in &parts {
        match m.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => ctrl = true,
            "alt" => alt = true,
            "shift" => shift = true,
            "super" | "cmd" | "win" => sup = true,
            "" => return bad("has an empty part"),
            other => {
                return Err(format!(
                    "\"{key}\": \"{other}\" isn't a modifier (ctrl, alt, shift or super)"
                ));
            }
        }
    }
    let mut name = last;
    if name.chars().count() == 1 {
        let c = name.chars().next().unwrap_or_default();
        if c.is_ascii_uppercase() && parts.is_empty() {
            shift = true;
        }
        name = c.to_ascii_lowercase().to_string();
        if c.is_whitespace() || c.is_control() {
            return bad("isn't a key");
        }
    } else {
        name.make_ascii_lowercase();
        let f_key = name.strip_prefix('f').and_then(|n| n.parse::<u8>().ok());
        if !NAMED_KEYS.contains(&name.as_str()) && !f_key.is_some_and(|n| (1..=24).contains(&n)) {
            return bad(
                "isn't a key: use a character, f1 to f24, or one of escape, enter, space, tab, backspace, delete, insert, up, down, left, right, home, end, pageup, pagedown",
            );
        }
    }
    let mut out = String::new();
    for (on, m) in [
        (ctrl, "ctrl"),
        (alt, "alt"),
        (shift, "shift"),
        (sup, "super"),
    ] {
        if on {
            out.push_str(m);
            out.push('-');
        }
    }
    out.push_str(&name);
    Ok(out)
}

/// The key that `keystroke`, as pressed, is bound as; `None` for a
/// modifier on its own. A shifted symbol is the symbol it types: Shift
/// with / is `?`, as the defaults write it, while Shift with a letter stays
/// `shift-p`.
pub fn from_keystroke(keystroke: &Keystroke) -> Option<String> {
    let key = keystroke.key.as_str();
    if matches!(
        key,
        "shift"
            | "control"
            | "ctrl"
            | "alt"
            | "platform"
            | "super"
            | "cmd"
            | "function"
            | "fn"
            | "capslock"
    ) {
        return None;
    }
    let m = &keystroke.modifiers;
    let mut shift = m.shift;
    let mut name = key.to_string();
    if shift && !m.control && !m.alt && !m.platform {
        let typed = keystroke
            .key_char
            .as_deref()
            .filter(|c| c.chars().count() == 1);
        if let Some(c) = typed
            && c.chars().all(|c| !c.is_alphabetic() && !c.is_whitespace())
        {
            name = c.to_string();
            shift = false;
        }
    }
    let mut out = String::new();
    for (on, part) in [
        (m.control, "ctrl-"),
        (m.alt, "alt-"),
        (shift, "shift-"),
        (m.platform, "super-"),
    ] {
        if on {
            out.push_str(part);
        }
    }
    out.push_str(&name);
    canonical(&out).ok()
}

/// `ToggleGraph` → `toggle_graph`: how an action is named in the settings.
pub fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    // Explicit imports: the gpui glob would shadow `#[test]`.
    use super::{Keymap, canonical, snake_case};
    use crate::actions::{CursorDown, ExpandAll, SHORTCUTS, ToggleGraph, ToggleTree};

    fn set(entries: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        entries
            .iter()
            .map(|(n, ks)| (n.to_string(), ks.iter().map(|k| k.to_string()).collect()))
            .collect()
    }

    #[test]
    fn the_printed_table_reads_back_as_the_same_keys() {
        let (keymap, _) = Keymap::resolve(&set(&[("toggle_graph", &["x"]), ("toggle_tree", &[])]));
        let text = keymap.to_toml();
        assert!(text.contains("toggle_graph = [\"x\"]"), "{text}");
        assert!(text.contains("toggle_tree = []"), "{text}");
        let doc: toml_edit::DocumentMut = text.parse().expect("valid TOML");
        let keys = doc["keys"].as_table().unwrap();
        assert_eq!(keys.len(), SHORTCUTS.len(), "every action");
        let again: Vec<(String, Vec<String>)> = keys
            .iter()
            .map(|(n, v)| {
                let ks = v
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| k.as_str().unwrap().to_string());
                (n.to_string(), ks.collect())
            })
            .collect();
        let (round, problems) = Keymap::resolve(&again);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(round.to_toml(), text);
    }

    #[test]
    fn a_key_press_is_named_as_the_keymap_writes_it() {
        use super::from_keystroke;
        use gpui_kit::Keystroke;
        // Every default, pressed, comes back as itself.
        for s in SHORTCUTS {
            for k in s.keys {
                let pressed = Keystroke::parse(k).unwrap();
                assert_eq!(from_keystroke(&pressed).as_deref(), Some(*k), "{k}");
            }
        }
        // ? as a keyboard reports it: Shift with /, typing "?".
        let question = Keystroke {
            key_char: Some("?".into()),
            ..Keystroke::parse("shift-/").unwrap()
        };
        assert_eq!(from_keystroke(&question).as_deref(), Some("?"));
        let shifted_p = Keystroke {
            key_char: Some("P".into()),
            ..Keystroke::parse("shift-p").unwrap()
        };
        assert_eq!(from_keystroke(&shifted_p).as_deref(), Some("shift-p"));
        assert_eq!(from_keystroke(&Keystroke::parse("shift").unwrap()), None);
        assert_eq!(
            from_keystroke(&Keystroke::parse("ctrl-shift-g").unwrap()).as_deref(),
            Some("ctrl-shift-g")
        );
    }

    #[test]
    fn a_draft_saves_as_entries_that_read_back_the_same() {
        let mut draft = Keymap::defaults().draft();
        let graph = SHORTCUTS
            .iter()
            .position(|s| s.name() == "toggle_graph")
            .unwrap();
        let expand = SHORTCUTS
            .iter()
            .position(|s| s.name() == "expand_all")
            .unwrap();
        draft[graph] = vec!["e".into()];
        draft[expand] = vec![];
        let keymap = Keymap::from_draft(draft.clone());
        let entries = keymap.entries();
        let written: Vec<(String, Vec<String>)> = entries
            .iter()
            .filter_map(|(n, ks)| ks.clone().map(|ks| (n.clone(), ks)))
            .collect();
        assert_eq!(written.len(), 2, "{written:?}");
        let (again, problems) = Keymap::resolve(&written);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(again.draft(), draft);
        assert!(
            Keymap::defaults()
                .entries()
                .iter()
                .all(|(_, ks)| ks.is_none())
        );
    }

    #[test]
    fn actions_are_named_in_snake_case() {
        assert_eq!(snake_case("ToggleGraph"), "toggle_graph");
        assert_eq!(snake_case("SeekForwardLong"), "seek_forward_long");
        assert_eq!(snake_case("Quit"), "quit");
        let mut names: Vec<_> = SHORTCUTS.iter().map(|s| s.name()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), SHORTCUTS.len(), "one entry per action");
    }

    #[test]
    fn keys_have_one_spelling() {
        assert_eq!(canonical("ctrl-g").as_deref(), Ok("ctrl-g"));
        assert_eq!(canonical("Ctrl+Shift+G").as_deref(), Ok("ctrl-shift-g"));
        assert_eq!(canonical("shift-ctrl-g").as_deref(), Ok("ctrl-shift-g"));
        assert_eq!(canonical("P").as_deref(), Ok("shift-p"));
        assert_eq!(canonical(" F5 ").as_deref(), Ok("f5"));
        assert_eq!(canonical("cmd-k").as_deref(), Ok("super-k"));
        assert_eq!(canonical("PageDown").as_deref(), Ok("pagedown"));
        assert_eq!(canonical("/").as_deref(), Ok("/"));
        assert_eq!(canonical("-").as_deref(), Ok("-"));
        assert_eq!(canonical("ctrl--").as_deref(), Ok("ctrl--"));
        assert_eq!(canonical("+").as_deref(), Ok("+"));
        for bad in ["", "g g", "ctrl-", "hyper-g", "f25", "pgdn", "ctrl-shift"] {
            assert!(canonical(bad).is_err(), "{bad:?}");
        }
        // Every default is already in that spelling.
        for s in SHORTCUTS {
            for k in s.keys {
                assert_eq!(canonical(k).as_deref(), Ok(*k));
            }
        }
    }

    #[test]
    fn no_settings_is_the_defaults() {
        let (keymap, problems) = Keymap::resolve(&[]);
        assert!(problems.is_empty());
        assert_eq!(keymap.keys::<ToggleGraph>(), ["g"]);
        assert_eq!(keymap.label::<CursorDown>().as_deref(), Some("↓"));
    }

    #[test]
    fn a_setting_replaces_the_defaults_and_takes_its_keys_from_others() {
        let (keymap, problems) = Keymap::resolve(&set(&[
            ("toggle_graph", &["x", "Ctrl+X"]),
            ("toggle_tree", &[]),
            ("cursor_down", &["e"]),
        ]));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(keymap.keys::<ToggleGraph>(), ["x", "ctrl-x"], "g is gone");
        assert!(keymap.keys::<ToggleTree>().is_empty(), "unbound");
        assert_eq!(keymap.label::<ToggleTree>(), None);
        assert_eq!(keymap.keys::<CursorDown>(), ["e"]);
        assert!(
            keymap.keys::<ExpandAll>().is_empty(),
            "e went to cursor_down"
        );
    }

    #[test]
    fn mistakes_are_reported_and_the_rest_applies() {
        let (keymap, problems) = Keymap::resolve(&set(&[
            ("toggel_tree", &["x"]),
            ("toggle_graph", &["hyper-x", "y"]),
            ("toggle_tree", &["y", "z"]),
        ]));
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(
            problems[0].contains("toggel_tree: no such action"),
            "{}",
            problems[0]
        );
        assert!(
            problems[1].contains("\"hyper\" isn't a modifier"),
            "{}",
            problems[1]
        );
        assert!(
            problems[2].contains("\"y\" is already set for toggle_graph"),
            "{}",
            problems[2]
        );
        assert_eq!(keymap.keys::<ToggleGraph>(), ["y"]);
        assert_eq!(keymap.keys::<ToggleTree>(), ["z"]);
    }
}
