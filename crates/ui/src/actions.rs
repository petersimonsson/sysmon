//! Actions, their keyboard shortcuts and the application menus.
//!
//! [`SHORTCUTS`] is the single source for key bindings and for the
//! shortcuts overlay. The menus use the same actions, so they show the
//! bindings next to each item.

use std::any::TypeId;
use std::collections::HashSet;

use gpui_kit::*;

actions!(
    sysmon,
    [
        Quit,
        OpenRecording,
        ShowLive,
        ShowRecording,
        TogglePause,
        Faster,
        Slower,
        SeekBackward,
        SeekForward,
        SeekBackwardLong,
        SeekForwardLong,
        SeekStart,
        SeekEnd,
        ToggleTree,
        ExpandAll,
        CollapseAll,
        FocusFilter,
        Dismiss,
        NextHost,
        PreviousHost,
        SortByCpu,
        SortByMemory,
        SortByVirt,
        SortByShr,
        SortByPid,
        SortByUser,
        SortByCommand,
        ToggleShortcuts,
        CursorUp,
        CursorDown,
        CursorPageUp,
        CursorPageDown,
        ToggleGraph,
        ClearGraph,
        ToggleGraphPanel,
        GraphCpu,
        GraphVirt,
        GraphRss,
        GraphShr,
        GraphMem,
        GraphThreads,
        CycleGraphWindow,
        About,
        EditShortcuts,
        ToggleKernelThreads,
        ToggleThreads,
        ToggleLogs,
        ToggleDetails,
        ThemeSystem,
        ThemeLight,
        ThemeDark,
    ]
);

/// Key context of the app's root element.
pub const CONTEXT: &str = "SysmonApp";
/// Shortcuts without a modifier must not fire while typing in the filter.
pub const NOT_TYPING: &str = "SysmonApp && !Input";

/// Seek step for ←/→ and ⇧←/⇧→, in seconds.
pub const SEEK_SHORT_S: u64 = 10;
pub const SEEK_LONG_S: u64 = 60;
/// Rows moved by Page Up / Page Down.
pub const PAGE_ROWS: isize = 20;

/// "Back 10 s", "Forward 1 min": a seek step as the menus show it. The
/// shortcuts list says the same in literals (a `const` table can't format);
/// a test keeps the two in step.
fn seek_label(direction: &str, s: u64) -> String {
    if s.is_multiple_of(60) {
        format!("{direction} {} min", s / 60)
    } else {
        format!("{direction} {s} s")
    }
}

pub struct Shortcut {
    pub group: &'static str,
    /// The default keystrokes, in gpui syntax and the keymap's spelling
    /// ([`crate::keymap::canonical`]); the first is shown in the overlay.
    pub keys: &'static [&'static str],
    pub description: &'static str,
    /// The action's type name (`ToggleGraph`).
    action_name: &'static str,
    pub type_id: fn() -> TypeId,
    pub action: fn() -> Box<dyn Action>,
}

impl Shortcut {
    /// What the settings call it: `toggle_graph`.
    pub fn name(&self) -> String {
        crate::keymap::snake_case(self.action_name)
    }
}

macro_rules! shortcut {
    ($group:literal, [$($key:literal),*], $action:ident, $desc:literal) => {
        Shortcut {
            group: $group,
            keys: &[$($key),*],
            description: $desc,
            action_name: stringify!($action),
            type_id: TypeId::of::<$action>,
            action: || Box::new($action),
        }
    };
}

pub const SHORTCUTS: &[Shortcut] = &[
    shortcut!("General", ["ctrl-o"], OpenRecording, "Open a recording"),
    shortcut!("General", ["ctrl-q"], Quit, "Quit"),
    shortcut!(
        "General",
        ["f1", "?"],
        ToggleShortcuts,
        "Show or hide this list"
    ),
    shortcut!(
        "General",
        ["escape"],
        Dismiss,
        "Close this list, or clear the filter"
    ),
    // No key by default, but one can be set ([keys] in the settings);
    // the shortcuts list leaves out actions without one.
    shortcut!("General", [], About, "About sysmon"),
    shortcut!("View", ["ctrl-1"], ShowLive, "Live view"),
    shortcut!("View", ["ctrl-2"], ShowRecording, "Recording view"),
    shortcut!("View", ["ctrl-up"], PreviousHost, "Previous host"),
    shortcut!("View", ["ctrl-down"], NextHost, "Next host"),
    shortcut!(
        "View",
        ["l"],
        ToggleLogs,
        "Show the host's logs, or the graph again"
    ),
    shortcut!(
        "View",
        ["d", "enter"],
        ToggleDetails,
        "Show the cursor row's process details, or the graph again"
    ),
    shortcut!(
        "Processes",
        ["ctrl-f", "/"],
        FocusFilter,
        "Filter processes (Enter returns)"
    ),
    shortcut!("Processes", ["t"], ToggleTree, "Toggle tree view"),
    shortcut!(
        "Processes",
        ["ctrl-k"],
        ToggleKernelThreads,
        "Show / hide kernel threads"
    ),
    shortcut!(
        "Processes",
        ["ctrl-h"],
        ToggleThreads,
        "Show / hide threads"
    ),
    shortcut!("Processes", ["e"], ExpandAll, "Expand all (tree)"),
    shortcut!("Processes", ["c"], CollapseAll, "Collapse all (tree)"),
    shortcut!("Processes", ["up", "k"], CursorUp, "Previous row"),
    shortcut!("Processes", ["down", "j"], CursorDown, "Next row"),
    shortcut!("Processes", ["pageup"], CursorPageUp, "Up 20 rows"),
    shortcut!("Processes", ["pagedown"], CursorPageDown, "Down 20 rows"),
    shortcut!("Processes", ["shift-p"], SortByCpu, "Sort by CPU"),
    shortcut!("Processes", ["shift-v"], SortByVirt, "Sort by VIRT"),
    shortcut!("Processes", ["shift-m"], SortByMemory, "Sort by RES"),
    shortcut!("Processes", ["shift-s"], SortByShr, "Sort by SHR"),
    shortcut!("Processes", ["shift-n"], SortByPid, "Sort by PID"),
    shortcut!("Processes", ["shift-u"], SortByUser, "Sort by user"),
    shortcut!("Processes", ["shift-c"], SortByCommand, "Sort by command"),
    shortcut!(
        "Graph",
        ["g"],
        ToggleGraph,
        "Graph the row (collapsed: its subtree)"
    ),
    shortcut!("Graph", ["ctrl-g"], ClearGraph, "Remove all lines"),
    shortcut!("Graph", ["v"], ToggleGraphPanel, "Show / hide the graph"),
    shortcut!("Graph", ["1"], GraphCpu, "Graph %CPU"),
    shortcut!("Graph", ["2"], GraphVirt, "Graph VIRT"),
    shortcut!("Graph", ["3"], GraphRss, "Graph RES"),
    shortcut!("Graph", ["4"], GraphShr, "Graph SHR"),
    shortcut!("Graph", ["5"], GraphMem, "Graph %MEM"),
    shortcut!("Graph", ["6"], GraphThreads, "Graph threads"),
    shortcut!(
        "Graph",
        ["w"],
        CycleGraphWindow,
        "Time window: 1 / 5 / 10 min"
    ),
    shortcut!(
        "Playback (recordings)",
        ["space"],
        TogglePause,
        "Play / pause"
    ),
    shortcut!("Playback (recordings)", ["]"], Faster, "Faster"),
    shortcut!("Playback (recordings)", ["["], Slower, "Slower"),
    shortcut!("Playback (recordings)", ["left"], SeekBackward, "Back 10 s"),
    shortcut!(
        "Playback (recordings)",
        ["right"],
        SeekForward,
        "Forward 10 s"
    ),
    shortcut!(
        "Playback (recordings)",
        ["shift-left"],
        SeekBackwardLong,
        "Back 1 min"
    ),
    shortcut!(
        "Playback (recordings)",
        ["shift-right"],
        SeekForwardLong,
        "Forward 1 min"
    ),
    shortcut!("Playback (recordings)", ["home"], SeekStart, "Go to start"),
    shortcut!("Playback (recordings)", ["end"], SeekEnd, "Go to end"),
    shortcut!("Settings", [], EditShortcuts, "Change keyboard shortcuts"),
    shortcut!("Settings", [], ThemeSystem, "Theme: as the system"),
    shortcut!("Settings", [], ThemeLight, "Theme: light"),
    shortcut!("Settings", [], ThemeDark, "Theme: dark"),
];

/// What the mouse does, for the shortcuts overlay: gestures there are no
/// keys for, or that do more than their key.
pub const MOUSE: &[(&str, &str)] = &[
    ("Click a row", "Move the cursor to it"),
    ("Ctrl+click", "Graph the row, or stop"),
    ("Shift+click", "Graph the rows from the last one picked"),
    ("Click a column", "Sort by it, again to reverse"),
    (
        "Click a log line",
        "Highlight it (in a recording, go there)",
    ),
    ("Click a unit", "Show only its log lines"),
    ("Click a log's PID", "Find the process in the table"),
    ("Click a timeline mark", "Go to the error, logs open"),
    (
        "Click a parent or child",
        "Move the cursor to it (Details tab)",
    ),
    ("Drag the divider", "Resize the bottom panel"),
];

/// The actions that can do something right now, in the view on screen
/// with the data it has. Only these get handlers, so the others' keys do
/// nothing, and their menu items are greyed out.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Available {
    on: HashSet<TypeId>,
    /// Shown ticked in the menus: the option in effect.
    checked: HashSet<TypeId>,
}

impl Available {
    pub fn set<A: Action>(&mut self, on: bool) {
        self.set_type(TypeId::of::<A>(), on);
    }

    pub fn set_type(&mut self, action: TypeId, on: bool) {
        if on {
            self.on.insert(action);
        }
    }

    pub fn has<A: Action>(&self) -> bool {
        self.on.contains(&TypeId::of::<A>())
    }

    pub fn check<A: Action>(&mut self, checked: bool) {
        if checked {
            self.checked.insert(TypeId::of::<A>());
        }
    }

    pub fn is_checked<A: Action>(&self) -> bool {
        self.checked.contains(&TypeId::of::<A>())
    }
}

/// Handle an action only while it's [`Available`].
pub trait OnAvailable: InteractiveElement + Sized {
    fn on_available<A: Action>(
        self,
        available: &Available,
        listener: impl Fn(&A, &mut Window, &mut App) + 'static,
    ) -> Self {
        if available.has::<A>() {
            self.on_action(listener)
        } else {
            self
        }
    }
}

impl<E: InteractiveElement> OnAvailable for E {}

/// Register `keymap`'s key bindings and the menus. Call once, after
/// `gpui_kit::init`. The keymap is kept as a global, for the shortcuts
/// list and hints to show the keys in effect.
pub fn init(cx: &mut App, keymap: crate::keymap::Keymap) {
    let bindings = keymap.key_bindings(cx);
    cx.bind_keys(bindings);
    cx.set_global(keymap);
    cx.on_action(|_: &Quit, cx| cx.quit());
    // The window sets the menus up for what it shows once it draws.
    set_menus(&Available::default(), cx);
}

/// Put up the menus, with what isn't `available` greyed out. macOS draws
/// the native menu bar; elsewhere `AppMenuBar` renders these inside the
/// window, once it's reloaded.
pub fn set_menus(available: &Available, cx: &mut App) {
    cx.set_menus(menus(available));
    gpui_kit::component::GlobalState::global_mut(cx)
        .set_app_menus(menus(available).into_iter().map(Menu::owned).collect());
}

fn menus(available: &Available) -> Vec<Menu> {
    macro_rules! action {
        ($name:expr, $action:ident) => {
            MenuItem::action($name, $action)
                .disabled(!available.has::<$action>())
                .checked(available.is_checked::<$action>())
        };
    }
    vec![
        Menu::new("File").items([
            action!("Open Recording…", OpenRecording),
            MenuItem::separator(),
            action!("Quit", Quit),
        ]),
        Menu::new("View").items([
            action!("Live", ShowLive),
            action!("Recording", ShowRecording),
            MenuItem::separator(),
            action!("Previous Host", PreviousHost),
            action!("Next Host", NextHost),
            MenuItem::separator(),
            action!("Logs", ToggleLogs),
            action!("Process Details", ToggleDetails),
        ]),
        Menu::new("Processes").items([
            action!("Filter…", FocusFilter),
            MenuItem::separator(),
            action!("Tree View", ToggleTree),
            action!("Kernel Threads", ToggleKernelThreads),
            action!("Threads", ToggleThreads),
            action!("Expand All", ExpandAll),
            action!("Collapse All", CollapseAll),
            MenuItem::separator(),
            MenuItem::submenu(Menu::new("Sort By").items([
                action!("CPU", SortByCpu),
                action!("VIRT", SortByVirt),
                action!("RES", SortByMemory),
                action!("SHR", SortByShr),
                action!("PID", SortByPid),
                action!("User", SortByUser),
                action!("Command", SortByCommand),
            ])),
        ]),
        Menu::new("Graph").items([
            action!("Graph Selected Row", ToggleGraph),
            action!("Clear Graph", ClearGraph),
            MenuItem::separator(),
            action!("Show / Hide Graph", ToggleGraphPanel),
            MenuItem::submenu(Menu::new("Metric").items([
                action!("%CPU", GraphCpu),
                action!("VIRT", GraphVirt),
                action!("RES", GraphRss),
                action!("SHR", GraphShr),
                action!("%MEM", GraphMem),
                action!("Threads", GraphThreads),
            ])),
            action!("Cycle Time Window", CycleGraphWindow),
        ]),
        Menu::new("Playback").items([
            action!("Play / Pause", TogglePause),
            action!("Faster", Faster),
            action!("Slower", Slower),
            MenuItem::separator(),
            action!(seek_label("Back", SEEK_SHORT_S), SeekBackward),
            action!(seek_label("Forward", SEEK_SHORT_S), SeekForward),
            action!(seek_label("Back", SEEK_LONG_S), SeekBackwardLong),
            action!(seek_label("Forward", SEEK_LONG_S), SeekForwardLong),
            MenuItem::separator(),
            action!("Go to Start", SeekStart),
            action!("Go to End", SeekEnd),
        ]),
        Menu::new("Settings").items([
            action!("Keyboard Shortcuts…", EditShortcuts),
            MenuItem::separator(),
            MenuItem::submenu(Menu::new("Theme").items([
                action!("System", ThemeSystem),
                action!("Light", ThemeLight),
                action!("Dark", ThemeDark),
            ])),
        ]),
        Menu::new("Help").items([
            action!("Keyboard Shortcuts", ToggleShortcuts),
            MenuItem::separator(),
            action!("About sysmon", About),
        ]),
    ]
}

/// Whether the keystroke `k` (gpui syntax) may fire while a text box has
/// the keyboard: only if it can't be typed. That's a key with Ctrl, Alt or
/// Super, or Esc or an F-key; a plain or shifted key is text. Decided per
/// key, not per action: `/` beside Ctrl+F once inherited Ctrl+F's "yes"
/// and couldn't be typed into the filter.
pub fn works_while_typing(k: &str) -> bool {
    if k == "-" || k == "+" {
        return false;
    }
    let mut parts: Vec<&str> = k.split('-').collect();
    let key = parts.pop().unwrap_or_default();
    parts
        .iter()
        .any(|m| matches!(*m, "ctrl" | "alt" | "cmd" | "super" | "platform" | "fn"))
        || key == "escape"
        || (key.len() > 1 && key.starts_with('f') && key[1..].parse::<u8>().is_ok())
}

/// How a gpui keystroke string is shown to people, e.g. `ctrl-o` → `Ctrl+O`.
pub fn display_key(k: &str) -> String {
    if k == "-" || k == "+" {
        return k.to_string();
    }
    // A lone letter is shown as typed: "G" read as Shift+G beside the
    // real Shift+P. With a modifier it's capitalised, as menus do (Ctrl+O).
    if k.chars().count() == 1 {
        return k.to_string();
    }
    k.split('-')
        .map(|part| match part {
            "ctrl" => "Ctrl".to_string(),
            "shift" => "Shift".to_string(),
            "alt" => "Alt".to_string(),
            "cmd" | "super" => "Super".to_string(),
            "left" => "←".to_string(),
            "right" => "→".to_string(),
            "up" => "↑".to_string(),
            "down" => "↓".to_string(),
            "space" => "Space".to_string(),
            "escape" => "Esc".to_string(),
            "home" => "Home".to_string(),
            "pageup" => "PgUp".to_string(),
            "pagedown" => "PgDn".to_string(),
            "end" => "End".to_string(),
            "enter" => "Enter".to_string(),
            "tab" => "Tab".to_string(),
            "backspace" => "Backspace".to_string(),
            "delete" => "Delete".to_string(),
            "insert" => "Insert".to_string(),
            p => p.to_uppercase(),
        })
        .collect::<Vec<_>>()
        .join("+")
}

#[cfg(test)]
mod tests {
    // Not `super::*`: the gpui glob would shadow `#[test]`.
    use super::{
        PAGE_ROWS, SEEK_LONG_S, SEEK_SHORT_S, SHORTCUTS, display_key, seek_label,
        works_while_typing,
    };

    #[test]
    fn only_keys_that_cant_be_typed_work_while_typing() {
        for k in [
            "ctrl-f",
            "ctrl-shift-g",
            "alt-x",
            "escape",
            "f1",
            "f12",
            "ctrl-up",
        ] {
            assert!(works_while_typing(k), "{k}");
        }
        for k in [
            "/", "?", "g", "shift-p", "up", "space", "enter", "1", "]", "-", "f", "fn",
        ] {
            assert!(!works_while_typing(k), "{k}");
        }
    }

    #[test]
    fn displays_keys() {
        assert_eq!(display_key("ctrl-o"), "Ctrl+O");
        assert_eq!(display_key("shift-left"), "Shift+←");
        assert_eq!(display_key("f1"), "F1");
        assert_eq!(display_key("enter"), "Enter");
        assert_eq!(display_key("?"), "?");
        assert_eq!(display_key("]"), "]");
        assert_eq!(display_key("g"), "g", "not G, which reads as Shift+G");
        assert_eq!(display_key("shift-p"), "Shift+P");
    }

    #[test]
    fn groups_are_contiguous() {
        let mut seen: Vec<&str> = Vec::new();
        for s in SHORTCUTS {
            if seen.last() != Some(&s.group) {
                assert!(!seen.contains(&s.group), "{} appears twice", s.group);
                seen.push(s.group);
            }
        }
    }

    /// The descriptions that state a number say the one in use.
    #[test]
    fn descriptions_match_the_constants() {
        let desc = |key: &str| {
            SHORTCUTS
                .iter()
                .find(|s| s.keys.first() == Some(&key))
                .unwrap()
                .description
        };
        assert_eq!(desc("left"), seek_label("Back", SEEK_SHORT_S));
        assert_eq!(desc("right"), seek_label("Forward", SEEK_SHORT_S));
        assert_eq!(desc("shift-left"), seek_label("Back", SEEK_LONG_S));
        assert_eq!(desc("shift-right"), seek_label("Forward", SEEK_LONG_S));
        assert_eq!(desc("pageup"), format!("Up {PAGE_ROWS} rows"));
        assert_eq!(desc("pagedown"), format!("Down {PAGE_ROWS} rows"));
        let windows: Vec<String> = crate::graph::WINDOWS_S
            .iter()
            .map(|w| (w / 60).to_string())
            .collect();
        assert_eq!(
            desc("w"),
            format!("Time window: {} min", windows.join(" / "))
        );
    }

    #[test]
    fn no_duplicate_keys() {
        let mut keys: Vec<_> = SHORTCUTS.iter().flat_map(|s| s.keys.iter()).collect();
        keys.sort();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len());
    }
}
