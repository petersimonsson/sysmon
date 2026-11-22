//! Actions, their keyboard shortcuts and the application menus.
//!
//! [`SHORTCUTS`] is the single source for key bindings and for the
//! shortcuts overlay. The menus use the same actions, so they show the
//! bindings next to each item.

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
    ]
);

/// Key context of the app's root element.
pub const CONTEXT: &str = "SysmonApp";
/// Shortcuts without a modifier must not fire while typing in the filter.
const NOT_TYPING: &str = "SysmonApp && !Input";

/// Seek step for ←/→ and ⇧←/⇧→, in seconds.
pub const SEEK_SHORT_S: u64 = 10;
pub const SEEK_LONG_S: u64 = 60;

pub struct Shortcut {
    pub group: &'static str,
    /// Keystrokes in gpui syntax; the first is shown in the overlay.
    pub keys: &'static [&'static str],
    pub description: &'static str,
    /// Bindable while the filter input has focus.
    pub while_typing: bool,
    bind: fn(&'static str, Option<&str>) -> KeyBinding,
}

macro_rules! shortcut {
    ($group:literal, [$($key:literal),+], $action:expr, $typing:expr, $desc:literal) => {
        Shortcut {
            group: $group,
            keys: &[$($key),+],
            description: $desc,
            while_typing: $typing,
            bind: |k, c| KeyBinding::new(k, $action, c),
        }
    };
}

pub const SHORTCUTS: &[Shortcut] = &[
    shortcut!(
        "General",
        ["ctrl-o"],
        OpenRecording,
        true,
        "Open a recording"
    ),
    shortcut!("General", ["ctrl-q"], Quit, true, "Quit"),
    shortcut!(
        "General",
        ["f1", "?"],
        ToggleShortcuts,
        false,
        "Show or hide this list"
    ),
    shortcut!(
        "General",
        ["escape"],
        Dismiss,
        false,
        "Close this list, or clear the filter"
    ),
    shortcut!("View", ["ctrl-1"], ShowLive, true, "Live view"),
    shortcut!("View", ["ctrl-2"], ShowRecording, true, "Recording view"),
    shortcut!("View", ["ctrl-down"], NextHost, true, "Next host"),
    shortcut!("View", ["ctrl-up"], PreviousHost, true, "Previous host"),
    shortcut!(
        "Processes",
        ["ctrl-f", "/"],
        FocusFilter,
        true,
        "Filter processes (Enter returns)"
    ),
    shortcut!("Processes", ["t"], ToggleTree, false, "Toggle tree view"),
    shortcut!("Processes", ["e"], ExpandAll, false, "Expand all (tree)"),
    shortcut!(
        "Processes",
        ["c"],
        CollapseAll,
        false,
        "Collapse all (tree)"
    ),
    shortcut!("Processes", ["up", "k"], CursorUp, false, "Previous row"),
    shortcut!("Processes", ["down", "j"], CursorDown, false, "Next row"),
    shortcut!("Processes", ["pageup"], CursorPageUp, false, "Up 20 rows"),
    shortcut!(
        "Processes",
        ["pagedown"],
        CursorPageDown,
        false,
        "Down 20 rows"
    ),
    shortcut!(
        "Graph",
        ["g"],
        ToggleGraph,
        false,
        "Graph the row (collapsed: its subtree)"
    ),
    shortcut!("Graph", ["ctrl-g"], ClearGraph, true, "Remove all lines"),
    shortcut!("Processes", ["shift-p"], SortByCpu, false, "Sort by CPU"),
    shortcut!(
        "Processes",
        ["shift-m"],
        SortByMemory,
        false,
        "Sort by memory"
    ),
    shortcut!("Processes", ["shift-n"], SortByPid, false, "Sort by PID"),
    shortcut!("Processes", ["shift-u"], SortByUser, false, "Sort by user"),
    shortcut!(
        "Processes",
        ["shift-c"],
        SortByCommand,
        false,
        "Sort by command"
    ),
    shortcut!("Playback", ["space"], TogglePause, false, "Play / pause"),
    shortcut!("Playback", ["]"], Faster, false, "Faster"),
    shortcut!("Playback", ["["], Slower, false, "Slower"),
    shortcut!("Playback", ["left"], SeekBackward, false, "Back 10 s"),
    shortcut!("Playback", ["right"], SeekForward, false, "Forward 10 s"),
    shortcut!(
        "Playback",
        ["shift-left"],
        SeekBackwardLong,
        false,
        "Back 1 min"
    ),
    shortcut!(
        "Playback",
        ["shift-right"],
        SeekForwardLong,
        false,
        "Forward 1 min"
    ),
    shortcut!("Playback", ["home"], SeekStart, false, "Go to start"),
    shortcut!("Playback", ["end"], SeekEnd, false, "Go to end"),
];

/// Register key bindings and menus. Call once, after `gpui_kit::init`.
pub fn init(cx: &mut App) {
    cx.bind_keys(SHORTCUTS.iter().flat_map(|s| {
        let ctx = if s.while_typing { CONTEXT } else { NOT_TYPING };
        s.keys.iter().map(move |k| (s.bind)(k, Some(ctx)))
    }));
    cx.on_action(|_: &Quit, cx| cx.quit());

    // macOS draws the native menu bar; elsewhere `AppMenuBar` renders these
    // inside the window.
    cx.set_menus(menus());
    gpui_kit::component::GlobalState::global_mut(cx)
        .set_app_menus(menus().into_iter().map(Menu::owned).collect());
}

fn menus() -> Vec<Menu> {
    vec![
        Menu::new("File").items([
            MenuItem::action("Open Recording…", OpenRecording),
            MenuItem::separator(),
            MenuItem::action("Quit", Quit),
        ]),
        Menu::new("View").items([
            MenuItem::action("Live", ShowLive),
            MenuItem::action("Recording", ShowRecording),
            MenuItem::separator(),
            MenuItem::action("Next Host", NextHost),
            MenuItem::action("Previous Host", PreviousHost),
        ]),
        Menu::new("Processes").items([
            MenuItem::action("Filter…", FocusFilter),
            MenuItem::separator(),
            MenuItem::action("Tree View", ToggleTree),
            MenuItem::action("Expand All", ExpandAll),
            MenuItem::action("Collapse All", CollapseAll),
            MenuItem::separator(),
            MenuItem::submenu(Menu::new("Sort By").items([
                MenuItem::action("CPU", SortByCpu),
                MenuItem::action("Memory", SortByMemory),
                MenuItem::action("PID", SortByPid),
                MenuItem::action("User", SortByUser),
                MenuItem::action("Command", SortByCommand),
            ])),
        ]),
        Menu::new("Graph").items([
            MenuItem::action("Graph Selected Row", ToggleGraph),
            MenuItem::action("Clear Graph", ClearGraph),
        ]),
        Menu::new("Playback").items([
            MenuItem::action("Play / Pause", TogglePause),
            MenuItem::action("Faster", Faster),
            MenuItem::action("Slower", Slower),
            MenuItem::separator(),
            MenuItem::action("Back 10 s", SeekBackward),
            MenuItem::action("Forward 10 s", SeekForward),
            MenuItem::action("Back 1 min", SeekBackwardLong),
            MenuItem::action("Forward 1 min", SeekForwardLong),
            MenuItem::separator(),
            MenuItem::action("Go to Start", SeekStart),
            MenuItem::action("Go to End", SeekEnd),
        ]),
        Menu::new("Help").items([MenuItem::action("Keyboard Shortcuts", ToggleShortcuts)]),
    ]
}

/// How a gpui keystroke string is shown to people, e.g. `ctrl-o` → `Ctrl+O`.
pub fn display_key(k: &str) -> String {
    if k == "-" || k == "+" {
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
            p if p.len() == 1 => p.to_uppercase(),
            p => p.to_uppercase(),
        })
        .collect::<Vec<_>>()
        .join("+")
}

#[cfg(test)]
mod tests {
    // Not `super::*`: the gpui glob would shadow `#[test]`.
    use super::{SHORTCUTS, display_key};

    #[test]
    fn displays_keys() {
        assert_eq!(display_key("ctrl-o"), "Ctrl+O");
        assert_eq!(display_key("shift-left"), "Shift+←");
        assert_eq!(display_key("f1"), "F1");
        assert_eq!(display_key("?"), "?");
        assert_eq!(display_key("]"), "]");
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
