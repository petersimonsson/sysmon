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
        ToggleKernelThreads,
        ToggleThreads,
        ToggleLogs,
        ToggleDarkTheme,
    ]
);

/// Key context of the app's root element.
pub const CONTEXT: &str = "SysmonApp";
/// Shortcuts without a modifier must not fire while typing in the filter.
const NOT_TYPING: &str = "SysmonApp && !Input";

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
        true,
        "Close this list, or clear the filter"
    ),
    shortcut!("View", ["ctrl-1"], ShowLive, true, "Live view"),
    shortcut!("View", ["ctrl-2"], ShowRecording, true, "Recording view"),
    shortcut!("View", ["ctrl-down"], NextHost, true, "Next host"),
    shortcut!("View", ["ctrl-up"], PreviousHost, true, "Previous host"),
    shortcut!(
        "View",
        ["l"],
        ToggleLogs,
        false,
        "Show the host's logs, or the graph again"
    ),
    shortcut!(
        "Processes",
        ["ctrl-f", "/"],
        FocusFilter,
        true,
        "Filter processes (Enter returns)"
    ),
    shortcut!("Processes", ["t"], ToggleTree, false, "Toggle tree view"),
    shortcut!(
        "Processes",
        ["ctrl-k"],
        ToggleKernelThreads,
        false,
        "Show / hide kernel threads"
    ),
    shortcut!(
        "Processes",
        ["ctrl-h"],
        ToggleThreads,
        false,
        "Show / hide threads"
    ),
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
    shortcut!("Processes", ["shift-p"], SortByCpu, false, "Sort by CPU"),
    shortcut!("Processes", ["shift-v"], SortByVirt, false, "Sort by VIRT"),
    shortcut!("Processes", ["shift-m"], SortByMemory, false, "Sort by RES"),
    shortcut!("Processes", ["shift-s"], SortByShr, false, "Sort by SHR"),
    shortcut!("Processes", ["shift-n"], SortByPid, false, "Sort by PID"),
    shortcut!("Processes", ["shift-u"], SortByUser, false, "Sort by user"),
    shortcut!(
        "Processes",
        ["shift-c"],
        SortByCommand,
        false,
        "Sort by command"
    ),
    shortcut!(
        "Graph",
        ["g"],
        ToggleGraph,
        false,
        "Graph the row (collapsed: its subtree)"
    ),
    shortcut!("Graph", ["ctrl-g"], ClearGraph, true, "Remove all lines"),
    shortcut!(
        "Graph",
        ["v"],
        ToggleGraphPanel,
        false,
        "Show / hide the graph"
    ),
    shortcut!("Graph", ["1"], GraphCpu, false, "Graph %CPU"),
    shortcut!("Graph", ["2"], GraphVirt, false, "Graph VIRT"),
    shortcut!("Graph", ["3"], GraphRss, false, "Graph RES"),
    shortcut!("Graph", ["4"], GraphShr, false, "Graph SHR"),
    shortcut!("Graph", ["5"], GraphMem, false, "Graph %MEM"),
    shortcut!("Graph", ["6"], GraphThreads, false, "Graph threads"),
    shortcut!(
        "Graph",
        ["w"],
        CycleGraphWindow,
        false,
        "Time window: 1 / 5 / 10 min"
    ),
    shortcut!(
        "Playback (recordings)",
        ["space"],
        TogglePause,
        false,
        "Play / pause"
    ),
    shortcut!("Playback (recordings)", ["]"], Faster, false, "Faster"),
    shortcut!("Playback (recordings)", ["["], Slower, false, "Slower"),
    shortcut!(
        "Playback (recordings)",
        ["left"],
        SeekBackward,
        false,
        "Back 10 s"
    ),
    shortcut!(
        "Playback (recordings)",
        ["right"],
        SeekForward,
        false,
        "Forward 10 s"
    ),
    shortcut!(
        "Playback (recordings)",
        ["shift-left"],
        SeekBackwardLong,
        false,
        "Back 1 min"
    ),
    shortcut!(
        "Playback (recordings)",
        ["shift-right"],
        SeekForwardLong,
        false,
        "Forward 1 min"
    ),
    shortcut!(
        "Playback (recordings)",
        ["home"],
        SeekStart,
        false,
        "Go to start"
    ),
    shortcut!(
        "Playback (recordings)",
        ["end"],
        SeekEnd,
        false,
        "Go to end"
    ),
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
    ("Drag the divider", "Resize the graph or log panel"),
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
            MenuItem::separator(),
            MenuItem::action("Logs", ToggleLogs),
            MenuItem::separator(),
            MenuItem::action("Dark Theme", ToggleDarkTheme),
        ]),
        Menu::new("Processes").items([
            MenuItem::action("Filter…", FocusFilter),
            MenuItem::separator(),
            MenuItem::action("Tree View", ToggleTree),
            MenuItem::action("Kernel Threads", ToggleKernelThreads),
            MenuItem::action("Threads", ToggleThreads),
            MenuItem::action("Expand All", ExpandAll),
            MenuItem::action("Collapse All", CollapseAll),
            MenuItem::separator(),
            MenuItem::submenu(Menu::new("Sort By").items([
                MenuItem::action("CPU", SortByCpu),
                MenuItem::action("VIRT", SortByVirt),
                MenuItem::action("RES", SortByMemory),
                MenuItem::action("SHR", SortByShr),
                MenuItem::action("PID", SortByPid),
                MenuItem::action("User", SortByUser),
                MenuItem::action("Command", SortByCommand),
            ])),
        ]),
        Menu::new("Graph").items([
            MenuItem::action("Graph Selected Row", ToggleGraph),
            MenuItem::action("Clear Graph", ClearGraph),
            MenuItem::separator(),
            MenuItem::action("Show / Hide Graph", ToggleGraphPanel),
            MenuItem::submenu(Menu::new("Metric").items([
                MenuItem::action("%CPU", GraphCpu),
                MenuItem::action("VIRT", GraphVirt),
                MenuItem::action("RES", GraphRss),
                MenuItem::action("SHR", GraphShr),
                MenuItem::action("%MEM", GraphMem),
                MenuItem::action("Threads", GraphThreads),
            ])),
            MenuItem::action("Cycle Time Window", CycleGraphWindow),
        ]),
        Menu::new("Playback").items([
            MenuItem::action("Play / Pause", TogglePause),
            MenuItem::action("Faster", Faster),
            MenuItem::action("Slower", Slower),
            MenuItem::separator(),
            MenuItem::action(seek_label("Back", SEEK_SHORT_S), SeekBackward),
            MenuItem::action(seek_label("Forward", SEEK_SHORT_S), SeekForward),
            MenuItem::action(seek_label("Back", SEEK_LONG_S), SeekBackwardLong),
            MenuItem::action(seek_label("Forward", SEEK_LONG_S), SeekForwardLong),
            MenuItem::separator(),
            MenuItem::action("Go to Start", SeekStart),
            MenuItem::action("Go to End", SeekEnd),
        ]),
        Menu::new("Help").items([
            MenuItem::action("Keyboard Shortcuts", ToggleShortcuts),
            MenuItem::separator(),
            MenuItem::action("About sysmon", About),
        ]),
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
            p => p.to_uppercase(),
        })
        .collect::<Vec<_>>()
        .join("+")
}

#[cfg(test)]
mod tests {
    // Not `super::*`: the gpui glob would shadow `#[test]`.
    use super::{PAGE_ROWS, SEEK_LONG_S, SEEK_SHORT_S, SHORTCUTS, display_key, seek_label};

    #[test]
    fn displays_keys() {
        assert_eq!(display_key("ctrl-o"), "Ctrl+O");
        assert_eq!(display_key("shift-left"), "Shift+←");
        assert_eq!(display_key("f1"), "F1");
        assert_eq!(display_key("?"), "?");
        assert_eq!(display_key("]"), "]");
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
                .find(|s| s.keys[0] == key)
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
