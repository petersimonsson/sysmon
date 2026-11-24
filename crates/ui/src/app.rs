//! Top-level gpui entity: owns the live and replay host models and renders
//! the toolbar, host list, header, process table and replay timeline.

use std::any::TypeId;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::ops::Range;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::dialog::DialogFooter;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::menu::AppMenuBar;
use gpui_kit::component::slider::{Slider, SliderEvent, SliderState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Sizable as _, WindowExt as _};
use gpui_kit::prelude::*;
use gpui_kit::*;
use sysmon_ingest::{Event, Rejected, Rejections};
use sysmon_model::{
    Control, Feed, HISTORY_LEN, HostModel, LogKind, Metric, ProcRow, ReplayHandle, ReplayStatus,
    SeriesTarget, ThreadRow, TreeLine, tree::Guide,
};
use sysmon_proto::ProcKey;

use crate::actions::{self, OnAvailable as _, *};
use crate::format;
use crate::graph;
use crate::icons::{IconName, icon};
use crate::selection::{self, Selection};
use crate::widgets::{Chosen as _, Highlighted as _, bar, sparkline};

mod details;
mod parts;
mod plot;

const ROW_HEIGHT: f32 = 20.;
/// The tree's ▾/▸ column; guide lines run down its middle.
const TWISTY_W: f32 = 14.;
/// Where a guide line leaves a ▾: just below the chevron's stroke, which
/// is centred in the row.
const TWISTY_STUB_TOP: f32 = ROW_HEIGHT / 2. + 3.;
/// Widths of the process table's fixed columns, shared by the header and
/// the rows so they stay lined up.
/// The graph checkbox: 10 px with 2 px either side.
const PICK_COL: f32 = 14.;
const PID_COL: f32 = 64.;
const STATE_COL: f32 = 16.;
const CPU_COL: f32 = 60.;
/// VIRT, RES and SHR; fits "1023.9 MiB".
const SIZE_COL: f32 = 80.;
const MEM_PCT_COL: f32 = 44.;
const THREADS_COL: f32 = 48.;
/// The graph's y-axis labels, and the x labels' indent to line up with it.
const AXIS_LABELS_W: f32 = 64.;
/// The USER column fits the longest name shown, within these many characters;
/// longer names are shortened in the middle.
const USER_MIN_CHARS: usize = 4;
const USER_MAX_CHARS: usize = 16;
const MENU_BAR_HEIGHT: f32 = 30.;
/// A per-core bar with its number and figure (28 + 70 + 36 px and gaps),
/// and the space between them.
const CORE_W: f32 = 142.;
const CORE_GAP: f32 = 12.;
/// Width of the host list.
const SIDEBAR_W: f32 = 190.;
/// The CPU and memory bars under each host's name.
const SIDEBAR_BAR_W: f32 = 84.;
/// Samples shown in the header's sparklines.
const SPARK_POINTS: usize = 240;
/// Smallest initial height of the graph panel below the process list.
const GRAPH_HEIGHT: f32 = 260.;
/// Share of the window the panel takes until you drag its divider: a
/// fixed 260 px was a sliver of a tall window.
const GRAPH_SHARE: f32 = 0.3;
/// Smallest graph panel, and room always left for the rest of the window.
const GRAPH_MIN: f32 = 140.;
const GRAPH_MIN_LIST: f32 = 300.;
/// Slider resolution: positions are mapped onto 0..TIMELINE_STEPS.
const TIMELINE_STEPS: f32 = 10_000.;
const SPEEDS: [f64; 5] = [1., 4., 16., 64., 256.];
/// Longest stretch of replay catch-up applied between two frames.
const REPLAY_SLICE: Duration = Duration::from_millis(8);
/// How often the sidebar is brought up to date for hosts not shown.
const SIDEBAR_EVERY: Duration = Duration::from_secs(1);
/// How long the table keeps its row order after you last moved the cursor,
/// picked a row or moved the pointer over it: re-sorting every second moved
/// rows out from under the pointer and made ↑/↓ jump about.
const ORDER_HOLD: Duration = Duration::from_secs(3);
/// How long a sender whose data was turned away stays on show.
const REJECTED_RECENT_NS: u64 = 30_000_000_000;
/// A live host not heard from for this long is dropped, history and all.
const FORGET_AFTER_NS: u64 = 3600 * 1_000_000_000;
/// At most this many live hosts are kept; past it, the one silent longest
/// goes. Each can hold tens of MB of history, and without a key anyone can
/// send datagrams under made-up host IDs.
const MAX_LIVE_HOSTS: usize = 256;

/// The settings file's problems as one line for the error strip: the
/// first, and how many more (all of them are in the log).
fn settings_problems(problems: &[String]) -> Option<String> {
    let first = problems.first()?;
    Some(match problems.len() {
        1 => format!("Settings: {first}"),
        n => format!("Settings: {first} (and {} more; see the log)", n - 1),
    })
}

/// One sender turned away, and why: "10.0.0.5: its data is …".
fn rejected_line(r: &Rejected) -> String {
    format!("{}: {}", r.from, r.reason)
}

/// What the app starts with; built in `main` before the window opens.
pub struct Start {
    pub live: Option<crate::pipeline::Live>,
    /// A recording to play, and where it is.
    pub replay: Option<(ReplayHandle, PathBuf)>,
    /// Where live data is recorded, if it is.
    pub recording_to: Option<PathBuf>,
    /// Where recordings are kept, recording or not: the Open Recording
    /// dialog lists what's there.
    pub data_dir: PathBuf,
    /// The settings read at startup.
    pub config: crate::config::Config,
    /// Where setting changes are saved; none to keep them for the session.
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum View {
    Live,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Pid,
    User,
    Cpu,
    Virt,
    /// Resident memory (RES).
    Res,
    Shr,
    Threads,
    Command,
}

/// The table's row order, kept while you work in it ([`ORDER_HOLD`]).
struct HeldOrder {
    /// The view and host it was taken from; another one isn't held.
    host: (View, u64),
    /// Each row's place when the order was taken; rows new since go last.
    rank: HashMap<ProcKey, usize>,
    until: std::time::Instant,
}

struct ReplaySession {
    id: u64,
    handle: ReplayHandle,
    label: String,
    hosts: BTreeMap<u64, HostModel>,
    /// Batches with errors, for the timeline; found in the background.
    log_marks: Vec<sysmon_model::LogMark>,
    _feed: Task<()>,
}

/// The bottom panel's tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Panel {
    Graph,
    Logs,
    /// The process under the cursor.
    Details,
}

pub struct AppState {
    view: View,
    live_enabled: bool,
    /// Where agents should send, and whether they need the key.
    listen: Option<(SocketAddr, bool)>,
    /// What the receiver turned away, and the part of it shown: senders
    /// heard from in the last [`REJECTED_RECENT_NS`], newest first.
    rejections: Option<Arc<Rejections>>,
    rejected: Vec<Rejected>,
    live_hosts: BTreeMap<u64, HostModel>,
    /// When the monitor last got anything from each live host (its clock).
    live_heard: HashMap<u64, u64>,
    replay: Option<ReplaySession>,
    next_session: u64,
    /// Where live data is recorded, if it is.
    recording_to: Option<PathBuf>,
    data_dir: PathBuf,
    selected: Option<u64>,
    sort: (SortKey, bool),
    /// Show processes as a tree grouped by parent.
    tree: bool,
    /// Leave kernel threads out of the table (on by default).
    hide_kernel: bool,
    /// List each process's threads (off by default; needs `agent --threads`).
    show_threads: bool,
    /// Collapsed tree nodes, per view and host: process keys are only
    /// unique within a host (pid 1 started at the same tick on many).
    collapsed: HashMap<(View, u64), HashSet<ProcKey>>,
    /// Processes picked for the graph, per view and host.
    selections: HashMap<(View, u64), Selection>,
    /// The highlighted row, moved with ↑/↓ and toggled into the graph with G.
    cursor: Option<ProcKey>,
    /// The row order kept while you work in the table, if it is.
    held: Option<HeldOrder>,
    graph_metric: Metric,
    graph_window_s: u64,
    graph_visible: bool,
    /// The chart, its labels and legend: a view of its own, so moving the
    /// pointer over it builds only that again.
    graph_plot: Entity<plot::GraphPlot>,
    /// The table and sidebar, drawn as cached views: see [`parts`].
    procs_table: Entity<parts::PartView>,
    sidebar_part: Entity<parts::PartView>,
    /// Last known command of each graphed process, so the legend can still
    /// name processes that have exited; per view and host, like `selections`.
    graph_names: HashMap<(View, u64), HashMap<ProcKey, String>>,
    /// Graph lines kept between redraws (the chart redraws on every mouse
    /// move), by view, host, target and metric.
    graph_lines: std::cell::RefCell<graph::LineCache<(View, u64, SeriesTarget, Metric)>>,
    /// Height of the graph panel; drag the divider above it to change it.
    graph_height: Pixels,
    /// The divider was dragged: keep its height rather than the window's share.
    graph_resized: bool,
    /// While dragging the divider: pointer y and panel height at the start.
    graph_drag: Option<(Pixels, Pixels)>,
    /// What the bottom panel shows. The graph only shows while something
    /// is picked and it isn't hidden; the other tabs always do.
    panel: Panel,
    /// The process the Details tab last showed, for after it exits.
    details_memo: Option<details::DetailsMemo>,
    /// Keep the newest log line in view; scrolling up stops it.
    log_follow: bool,
    log_scroll: UniformListScrollHandle,
    /// The highlighted log line, by its receive and log times (which survive
    /// the model being rebuilt by a seek, unlike row ids).
    log_cursor: Option<(u64, u64)>,
    /// Bring the highlighted log line into view on the next render that
    /// has it (set when the seek's reset arrives and the list is rebuilt).
    log_reveal: std::cell::Cell<bool>,
    /// A seek to a log line is under way; reveal it after the reset.
    log_reveal_after_reset: bool,
    /// Log filters: text (message, unit or identifier), lowest priority
    /// shown (7 = all), and one unit or identifier.
    log_filter: Entity<InputState>,
    log_min_priority: u8,
    log_source: Option<String>,
    filter: Entity<InputState>,
    timeline: Entity<SliderState>,
    scrubbing: bool,
    /// The recording being opened, if any.
    opening: Option<String>,
    /// How recordings are opened: [`crate::pipeline::open_replay`], or in
    /// tests one without an engine thread (which would wake the UI from
    /// outside gpui's deterministic test scheduler).
    open_replay: fn(&std::path::Path, f64) -> anyhow::Result<ReplayHandle>,
    /// Longest stretch of replay catch-up applied between two frames.
    replay_slice: Duration,
    /// Other hosts' samples arrived since the sidebar was last drawn.
    sidebar_stale: bool,
    sidebar_drawn: std::time::Instant,
    /// Slices applied so far, for tests.
    #[cfg(test)]
    replay_slices: usize,
    /// The replay status last shown; the ticker redraws only when it changes.
    shown_status: Option<ReplayStatus>,
    scroll: UniformListScrollHandle,
    error: Option<String>,
    _tasks: Vec<Task<()>>,
    _subscriptions: Vec<Subscription>,
    focus: FocusHandle,
    /// In-window menu bar (not used on macOS, which has a native one).
    menu_bar: Option<Entity<AppMenuBar>>,
    show_shortcuts: bool,
    /// Light, dark, or following the system; from the config, then the menu.
    theme: crate::config::ThemePref,
    config_path: Option<PathBuf>,
    /// What the actions can do now; worked out on every render.
    available: actions::Available,
}

impl AppState {
    pub fn new(start: Start, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let filter = cx.new(|cx| InputState::new(window, cx).placeholder("Filter processes"));
        let log_filter = cx.new(|cx| InputState::new(window, cx).placeholder("Filter logs"));
        let timeline = cx.new(|_| {
            SliderState::new()
                .min(0.)
                .max(TIMELINE_STEPS)
                .step(1.)
                .default_value(0.)
        });

        let mut tasks = Vec::new();
        if let Some(events) = start.live.as_ref().map(|l| l.events.clone()) {
            tasks.push(cx.spawn(async move |this, cx| {
                // Wait for one event, then drain whatever else is queued so a
                // burst becomes a single repaint.
                while let Ok(first) = events.recv_async().await {
                    let batch: Vec<Event> =
                        std::iter::once(first).chain(events.try_iter()).collect();
                    let alive = this.update(cx, |this, cx| {
                        if this.apply_live_batch(batch, sysmon_ingest::unix_now_ns()) {
                            cx.notify();
                        }
                    });
                    if alive.is_err() {
                        break;
                    }
                }
            }));
        }
        // Keep the replay position and timeline moving between frames, but
        // only redraw when something changed: a paused or finished replay
        // otherwise cost several times the CPU of a live view with data.
        tasks.push(cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(200))
                    .await;
                let alive = this.update_in(cx, |this, window, cx| {
                    if this.view == View::Replay && this.replay_status_changed() {
                        this.sync_timeline(window, cx);
                        cx.notify();
                    }
                    if this.live_tick(std::time::Instant::now(), sysmon_ingest::unix_now_ns()) {
                        cx.notify();
                    }
                    if this.release_order(std::time::Instant::now()) {
                        cx.notify();
                    }
                });
                if alive.is_err() {
                    break;
                }
            }
        }));

        // Both filters: typing redraws, Enter or clicking away gives the
        // keyboard back to the shortcuts.
        let on_filter = |this: &mut Self,
                         _: &Entity<InputState>,
                         event: &InputEvent,
                         window: &mut Window,
                         cx: &mut Context<Self>| {
            match event {
                InputEvent::Change => cx.notify(),
                // Enter hands the keyboard back to the shortcuts.
                InputEvent::PressEnter { .. } => this.focus.focus(window, cx),
                // Clicking away from the filter leaves nothing focused;
                // take focus back so shortcuts keep working, unless
                // something else (a menu) has it.
                InputEvent::Blur => cx.defer_in(window, |this, window, cx| {
                    if window.focused(cx).is_none() {
                        this.focus.focus(window, cx);
                    }
                }),
                InputEvent::Focus => {}
            }
        };
        apply_theme(start.config.theme, window, cx);
        let subscriptions = vec![
            cx.observe_window_appearance(window, |this, window, cx| {
                if this.theme == crate::config::ThemePref::System {
                    apply_theme(this.theme, window, cx);
                }
            }),
            cx.subscribe_in(&filter, window, on_filter),
            cx.subscribe_in(&log_filter, window, on_filter),
            cx.subscribe_in(
                &timeline,
                window,
                |this, _, event: &SliderEvent, _, cx| match event {
                    SliderEvent::Change(_) => this.scrubbing = true,
                    SliderEvent::Release(v) => {
                        this.scrubbing = false;
                        this.seek_fraction(v.start() / TIMELINE_STEPS);
                        cx.notify();
                    }
                },
            ),
        ];

        let focus = cx.focus_handle();
        focus.focus(window, cx);
        let menu_bar = (!cfg!(target_os = "macos")).then(|| AppMenuBar::new(cx));

        let mut this = Self {
            focus,
            menu_bar,
            show_shortcuts: false,
            theme: start.config.theme,
            config_path: start.config_path,
            available: actions::Available::default(),
            view: View::Live,
            live_enabled: start.live.is_some(),
            listen: start.live.as_ref().map(|l| (l.listen, l.keyed)),
            rejections: start.live.as_ref().map(|l| l.rejections.clone()),
            rejected: Vec::new(),
            live_hosts: BTreeMap::new(),
            live_heard: HashMap::new(),
            replay: None,
            next_session: 0,
            recording_to: start.recording_to,
            data_dir: start.data_dir,
            selected: None,
            sort: (SortKey::Cpu, true),
            tree: false,
            held: None,
            hide_kernel: true,
            show_threads: false,
            collapsed: HashMap::new(),
            selections: HashMap::new(),
            cursor: None,
            graph_metric: Metric::Cpu,
            graph_window_s: graph::WINDOWS_S[2],
            graph_visible: true,
            graph_plot: {
                let app = cx.entity().downgrade();
                cx.new(|_| plot::GraphPlot::new(app))
            },
            procs_table: {
                let app = cx.entity();
                cx.new(|cx| parts::PartView::new(&app, parts::Part::Table, cx))
            },
            sidebar_part: {
                let app = cx.entity();
                cx.new(|cx| parts::PartView::new(&app, parts::Part::Sidebar, cx))
            },

            graph_names: HashMap::new(),
            graph_lines: Default::default(),
            graph_height: px(GRAPH_HEIGHT),
            graph_resized: false,
            graph_drag: None,
            panel: Panel::Graph,
            details_memo: None,
            log_follow: true,
            log_scroll: UniformListScrollHandle::new(),
            log_cursor: None,
            log_reveal: Default::default(),
            log_reveal_after_reset: false,
            log_filter,
            log_min_priority: 7,
            log_source: None,
            filter,
            timeline,
            scrubbing: false,
            opening: None,
            open_replay: crate::pipeline::open_replay,
            replay_slice: REPLAY_SLICE,
            sidebar_stale: false,
            sidebar_drawn: std::time::Instant::now(),
            #[cfg(test)]
            replay_slices: 0,
            shown_status: None,
            scroll: UniformListScrollHandle::new(),
            // What was wrong in the settings file, said once at startup:
            // a typo in [keys] otherwise looks like a key that doesn't work.
            error: settings_problems(&start.config.problems),
            _tasks: tasks,
            _subscriptions: subscriptions,
        };
        if let Some((handle, path)) = start.replay {
            this.start_session(handle, path, cx);
        }
        this
    }

    fn hosts(&self) -> &BTreeMap<u64, HostModel> {
        match (self.view, &self.replay) {
            (View::Replay, Some(s)) => &s.hosts,
            _ => &self.live_hosts,
        }
    }

    /// Apply a batch of live events; whether to redraw now. Only the
    /// selected host's data, or the host list changing, redraws at once:
    /// redrawing for every host's sample cost a full redraw (about 2.4 ms)
    /// per host per second. Other hosts' samples only change the sidebar,
    /// which [`Self::live_tick`] redraws once a second.
    fn apply_live_batch(&mut self, batch: Vec<Event>, now: u64) -> bool {
        let hosts_before: Vec<u64> = self.live_hosts.keys().copied().collect();
        let selected_before = self.selected;
        let mut touches_selected = false;
        for event in batch {
            touches_selected |= Some(event.host_id()) == self.selected;
            self.apply_live(event, now);
        }
        self.forget_hosts(now);
        if self.view != View::Live {
            return false;
        }
        self.ensure_selection();
        let hosts_changed = !self.live_hosts.keys().copied().eq(hosts_before);
        if touches_selected || hosts_changed || self.selected != selected_before {
            true
        } else {
            self.sidebar_stale = true;
            false
        }
    }

    /// Once a second in the Live view: whether the sidebar needs redrawing,
    /// for other hosts' samples or because a host is silent (so its dot
    /// turns red and "silent N s" counts on even when nothing arrives at all).
    fn live_tick(&mut self, now: std::time::Instant, now_ns: u64) -> bool {
        if self.view != View::Live
            || now.saturating_duration_since(self.sidebar_drawn) < SIDEBAR_EVERY
        {
            return false;
        }
        let silent = self
            .live_hosts
            .values()
            .any(|h| Self::silence_at(h, now_ns).is_some());
        // Redrawn when who is turned away, or why, changes; not for counts.
        let rejected = self.rejections.as_ref().map_or_else(Vec::new, |r| {
            r.since(now_ns.saturating_sub(REJECTED_RECENT_NS))
        });
        let same = |a: &[Rejected], b: &[Rejected]| {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|(x, y)| (x.from, x.reason) == (y.from, y.reason))
        };
        let turned_away = !same(&rejected, &self.rejected);
        self.rejected = rejected;
        if std::mem::take(&mut self.sidebar_stale) || silent || turned_away {
            self.sidebar_drawn = now;
            return true;
        }
        false
    }

    fn apply_live(&mut self, event: Event, now: u64) {
        self.live_heard.insert(event.host_id(), now);
        apply(&mut self.live_hosts, event);
    }

    /// Drop live hosts silent for [`FORGET_AFTER_NS`], then the longest
    /// silent while there are more than [`MAX_LIVE_HOSTS`].
    fn forget_hosts(&mut self, now: u64) {
        let heard = |id: &u64| self.live_heard.get(id).copied().unwrap_or(0);
        let mut gone: Vec<u64> = self
            .live_hosts
            .keys()
            .filter(|id| now.saturating_sub(heard(id)) > FORGET_AFTER_NS)
            .copied()
            .collect();
        let left = self.live_hosts.len() - gone.len();
        if left > MAX_LIVE_HOSTS {
            let mut rest: Vec<u64> = self
                .live_hosts
                .keys()
                .filter(|id| !gone.contains(id))
                .copied()
                .collect();
            rest.sort_by_key(|id| heard(id));
            gone.extend(&rest[..left - MAX_LIVE_HOSTS]);
        }
        for id in gone {
            self.live_hosts.remove(&id);
            self.live_heard.remove(&id);
            self.selections.remove(&(View::Live, id));
            self.collapsed.remove(&(View::Live, id));
            self.graph_names.remove(&(View::Live, id));
        }
    }

    /// Host IDs in sidebar order: by name (case-insensitive), then ID.
    fn host_order(&self) -> Vec<u64> {
        let mut ids: Vec<(String, u64)> = self
            .hosts()
            .iter()
            .map(|(&id, h)| (h.name().to_lowercase(), id))
            .collect();
        ids.sort();
        ids.into_iter().map(|(_, id)| id).collect()
    }

    /// The host selected in the sidebar, if it's (still) there.
    fn current_host(&self) -> Option<&HostModel> {
        self.selected.and_then(|id| self.hosts().get(&id))
    }

    fn ensure_selection(&mut self) {
        let hosts = self.hosts();
        if self.selected.is_none_or(|id| !hosts.contains_key(&id)) {
            self.selected = self.host_order().first().copied();
        }
    }

    // ---- replay ---------------------------------------------------------

    fn start_session(&mut self, handle: ReplayHandle, path: PathBuf, cx: &mut Context<Self>) {
        let id = self.next_session;
        self.next_session += 1;
        let label = path.display().to_string();
        // Errors in the whole recording, to mark on the timeline.
        let scan = cx.background_spawn(async move { sysmon_model::logs::error_marks(&path) });
        cx.spawn(async move |this, cx| {
            let Ok(marks) = scan.await else {
                return;
            };
            let _ = this.update(cx, |this, cx| {
                if let Some(s) = this.replay.as_mut().filter(|s| s.id == id) {
                    s.log_marks = marks;
                    cx.notify();
                }
            });
        })
        .detach();
        let feed = handle.feed.clone();
        // A seek delivers the 10 minutes before the target at once: about
        // 120 ms of work per host. It's applied in slices of at most
        // `replay_slice`, so the window keeps drawing (and a recording with
        // many hosts doesn't freeze for seconds) while it catches up.
        let task = cx.spawn(async move |this, cx| {
            let mut queue: std::collections::VecDeque<Feed> = Default::default();
            while let Ok(first) = feed.recv_async().await {
                queue.push_back(first);
                while !queue.is_empty() {
                    queue.extend(feed.try_iter());
                    // Whatever comes before the last reset would be thrown
                    // away by it (seeking again while catching up).
                    if let Some(last) = queue.iter().rposition(|f| matches!(f, Feed::Reset)) {
                        queue.drain(..last);
                    }
                    let alive =
                        this.update(cx, |this, cx| this.apply_replay_slice(id, &mut queue, cx));
                    if alive.is_err() {
                        return;
                    }
                    if !queue.is_empty() {
                        // Let the window draw before the next slice.
                        cx.background_executor().timer(Duration::ZERO).await;
                    }
                }
            }
        });
        // Dropping the previous session's handle stops its engine thread.
        self.replay = Some(ReplaySession {
            id,
            handle,
            label,
            hosts: BTreeMap::new(),
            log_marks: Vec::new(),
            _feed: task,
        });
        self.view = View::Replay;
        self.selected = None;
        self.error = None;
        cx.notify();
    }

    /// Apply queued replay items for up to `replay_slice` (at least one).
    fn apply_replay_slice(
        &mut self,
        id: u64,
        queue: &mut std::collections::VecDeque<Feed>,
        cx: &mut Context<Self>,
    ) {
        let Some(s) = self.replay.as_mut().filter(|s| s.id == id) else {
            queue.clear();
            return;
        };
        let deadline = std::time::Instant::now() + self.replay_slice;
        let mut reset = false;
        while let Some(item) = queue.pop_front() {
            match item {
                Feed::Reset => {
                    s.hosts.clear();
                    reset = true;
                }
                Feed::Event(e) => apply(&mut s.hosts, e),
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
        }
        #[cfg(test)]
        {
            self.replay_slices += 1;
        }
        if reset {
            // The recording's models were rebuilt; so are the lines.
            self.graph_lines.borrow_mut().clear();
            if std::mem::take(&mut self.log_reveal_after_reset) {
                self.log_reveal.set(true);
            }
        }
        if self.view == View::Replay {
            self.ensure_selection();
            cx.notify();
        }
    }

    /// The Open Recording dialog, listing what the data directory holds.
    fn open_recording(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let app = cx.entity().downgrade();
        let on_open: crate::recordings::OnOpen = Rc::new(move |path, window, cx| {
            window.close_dialog(cx);

            let _ = app.update(cx, |app, cx| app.open_path(path, cx));
        });
        let live = self.recording_to.as_ref() == Some(&self.data_dir);
        let dir = self.data_dir.clone();
        // The dialog's builder can run again; the view is created once here.
        let view =
            cx.new(|cx| crate::recordings::RecordingsView::new(dir, live, on_open, window, cx));
        let focus = self.focus.clone();
        let app = cx.entity().downgrade();
        let shown = view.clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let view = shown.clone();
            let (can_open, any) = {
                let v = view.read(cx);
                (v.can_open(), v.has_recordings())
            };
            let focus = focus.clone();
            let (open, confirm, all) = (view.clone(), view.clone(), view.clone());
            let (browse, app) = (app.clone(), app.clone());
            dialog
                .title("Open recording")
                .w(px(860.))
                .child(view.clone())
                // Enter: open the picked row, which closes the dialog itself.
                .on_ok(move |_, window, cx| {
                    // Nothing picked: stay open.
                    crate::recordings::RecordingsView::open(&confirm, window, cx);
                    false
                })
                .footer(
                    DialogFooter::new()
                        .child(
                            Button::new("recordings-browse")
                                .icon(icon(IconName::FolderOpen))
                                .label("Browse…")
                                .on_click(move |_, window, cx| {
                                    window.close_dialog(cx);
                                    let _ = browse.update(cx, |app, cx| app.browse_recording(cx));
                                }),
                        )
                        .child(
                            Button::new("recordings-all")
                                .label("Open all")
                                .disabled(!any)
                                .tooltip("Every machine and boot in the data directory")
                                .on_click(move |_, window, cx| {
                                    let dir = all.read(cx).dir().to_path_buf();
                                    window.close_dialog(cx);
                                    let _ = app.update(cx, |app, cx| app.open_path(dir, cx));
                                }),
                        )
                        .child(div().flex_1())
                        .child(
                            Button::new("recordings-cancel")
                                .label("Cancel")
                                .on_click(|_, window, cx| window.close_dialog(cx)),
                        )
                        .child(
                            Button::new("recordings-open")
                                .label("Open")
                                .primary()
                                .disabled(!can_open)
                                .on_click(move |_, window, cx| {
                                    crate::recordings::RecordingsView::open(&open, window, cx)
                                }),
                        ),
                )
                // Give the keyboard back to the app's shortcuts.
                .on_close(move |_, window, cx| focus.focus(window, cx))
        });
        let filter = view.read(cx).filter().clone();
        filter.update(cx, |f, cx| f.focus(window, cx));
    }

    fn on_open_recording(
        &mut self,
        _: &OpenRecording,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recording(window, cx);
    }

    /// The system's file picker, for a recording outside the data directory.
    fn browse_recording(&mut self, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: true,
            multiple: false,
            prompt: Some("Open recording".into()),
        });
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(paths))) = paths.await else {
                return;
            };
            let Some(path) = paths.into_iter().next() else {
                return;
            };
            let _ = this.update(cx, |this, cx| this.open_path(path, cx));
        })
        .detach();
    }

    /// Open the recording at `path` in the background: opening reads every
    /// segment's index (rebuilding stale ones by scanning), which can take a
    /// while for a big data directory.
    fn open_path(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        let speed = self.status().map_or(1.0, |s| s.speed);
        let open_replay = self.open_replay;
        let label = path.display().to_string();
        self.opening = Some(label.clone());
        self.error = None;
        cx.notify();
        let opened =
            cx.background_spawn(async move { open_replay(&path, speed).map(|h| (h, path)) });
        cx.spawn(async move |this, cx| {
            let result = opened.await;
            let _ = this.update(cx, |this, cx| {
                // Only the latest request counts.
                if this.opening.as_ref() != Some(&label) {
                    return;
                }
                this.opening = None;
                match result {
                    Ok((handle, path)) => this.start_session(handle, path, cx),
                    Err(e) => this.error = Some(format!("{e:#}")),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn status(&self) -> Option<ReplayStatus> {
        self.replay.as_ref().map(|s| s.handle.status())
    }

    /// Whether the replay's status differs from what was last shown. The
    /// position is shown to the second, so finer changes don't count.
    fn replay_status_changed(&mut self) -> bool {
        let shown = |st: Option<ReplayStatus>| {
            st.map(|st| ReplayStatus {
                position_ns: st.position_ns / 1_000_000_000,
                ..st
            })
        };
        let now = shown(self.status());
        let changed = now != self.shown_status;
        self.shown_status = now;
        changed
    }

    fn control(&self, c: Control) {
        if let Some(s) = &self.replay {
            s.handle.send(c);
        }
    }

    fn seek_fraction(&self, frac: f32) {
        if let Some(st) = self.status() {
            let span = st.end_ns.saturating_sub(st.start_ns) as f64;
            let ts = st.start_ns + (span * frac.clamp(0.0, 1.0) as f64) as u64;
            self.control(Control::Seek(ts));
        }
    }

    fn sync_timeline(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.scrubbing {
            return;
        }
        let Some(st) = self.status() else {
            return;
        };
        let span = st.end_ns.saturating_sub(st.start_ns).max(1) as f32;
        let frac = st.position_ns.saturating_sub(st.start_ns) as f32 / span;
        self.timeline.update(cx, |s, cx| {
            s.set_value(frac * TIMELINE_STEPS, window, cx);
        });
    }

    // ---- rendering ------------------------------------------------------

    fn render_toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut bar = div()
            .id("toolbar")
            .test_support()
            .flex_none()
            .flex()
            .items_center()
            .gap_2()
            .px_2()
            .py_1()
            .border_b_1()
            .border_color(theme.border);

        if self.live_enabled {
            bar = bar.child(
                Button::new("view-live")
                    .icon(icon(IconName::RadioTower))
                    .label("Live")
                    .small()
                    .when(self.view == View::Live, |b| b.primary())
                    .on_click(cx.listener(|this, _, _, cx| this.show(View::Live, cx))),
            );
        }
        if let Some(s) = &self.replay {
            bar = bar
                .child(
                    Button::new("view-replay")
                        .icon(icon(IconName::FileClock))
                        .label("Recording")
                        .small()
                        .when(self.view == View::Replay, |b| b.primary())
                        .on_click(cx.listener(|this, _, _, cx| this.show(View::Replay, cx))),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(s.label.clone()),
                );
        }
        bar.child(div().flex_1())
            .when_some(self.opening.clone(), |b, path| {
                b.child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format!("Opening {path}…")),
                )
            })
            .when_some(self.error.clone(), |b, e| {
                b.child(div().text_xs().text_color(theme.danger).child(e))
                    .child(
                        div()
                            .id("error-dismiss")
                            .test_support()
                            .px_1()
                            .cursor_pointer()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .aria_description("Dismiss")
                            .tooltip({
                                let tip = crate::keymap::hinted::<Dismiss>(cx, "Dismiss");
                                move |window, cx| Tooltip::new(tip.clone()).build(window, cx)
                            })
                            .child(icon(IconName::X))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.error = None;
                                cx.notify();
                            })),
                    )
            })
            .child(
                Button::new("open")
                    .icon(icon(IconName::FolderOpen))
                    .label("Open recording…")
                    .small()
                    .ghost()
                    .on_click(cx.listener(|this, _, window, cx| this.open_recording(window, cx))),
            )
            // Where live data goes; nothing in a recording, whose own path
            // is beside the Recording button (the data directory beside it
            // read as a second, different recording).
            .when(self.view == View::Live && self.live_enabled, |b| {
                // A dot and a word; where to is on hover (the whole path
                // took a third of the bar and said the same all session).
                let (text, label) = match &self.recording_to {
                    Some(dir) => (format!("Recording to {}", dir.display()), "Recording"),
                    None => ("Not recording".to_string(), "Not recording"),
                };
                let recording = self.recording_to.is_some();
                b.child(
                    div()
                        .id("recording-to")
                        .test_support()
                        .flex()
                        .items_center()
                        .gap_1()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .aria_description(text.clone())
                        .tooltip(move |window, cx| Tooltip::new(text.clone()).build(window, cx))
                        .when(recording, |d| {
                            d.child(div().size(px(7.)).rounded_full().bg(theme.danger))
                        })
                        .child(label),
                )
            })
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut list = div()
            .flex()
            .flex_col()
            .w(px(SIDEBAR_W))
            .h_full()
            .p_2()
            .gap_1()
            .border_r_1()
            .border_color(theme.border);
        for id in self.host_order() {
            let host = &self.hosts()[&id];
            let selected = self.selected == Some(id);
            let loss = if host.frames_received == 0 {
                0.0
            } else {
                host.frames_incomplete as f32 / host.frames_received as f32 * 100.0
            };
            let silence = self.silence(host);
            let stale = silence.is_some();
            // Not while silent: old figures would pass for current ones.
            let load = (!stale && host.snapshot.mem.total > 0).then(|| {
                let s = &host.snapshot;
                (s.cpu_pct.first().copied().unwrap_or(0.0), mem_pct(&s.mem))
            });
            // Only what's worth knowing: "0.0% incomplete" on every healthy
            // host was noise, and "incomplete" alone didn't say of what.
            let detail = match silence {
                Some(ns) if self.view == View::Live => {
                    Some(format!("silent {}", format::duration(ns)))
                }
                _ if loss >= 0.05 => Some(format!("{loss:.1}% of samples incomplete")),
                _ => None,
            };
            list = list.child(
                div()
                    .id(("host", id as usize))
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .highlighted(selected, theme)
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.selected = Some(id);
                        cx.notify();
                    }))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            // Live: a green dot. Silent: a red "no signal"
                            // icon, which reads without telling the colours apart.
                            .child(if stale {
                                div()
                                    .id(("host-silent", id as usize))
                                    .test_support()
                                    .flex_none()
                                    .flex()
                                    .items_center()
                                    .aria_description("silent")
                                    .child(icon(IconName::WifiOff).text_color(theme.danger))
                                    .into_any_element()
                            } else {
                                div()
                                    .flex_none()
                                    .size(px(7.))
                                    .mx(px(2.5))
                                    .rounded_full()
                                    .bg(theme.success)
                                    .into_any_element()
                            })
                            .child(clipped(
                                ("host-name", id as usize),
                                host.name(),
                                format!("{} · host id {:016x}", host.name(), id),
                            )),
                    )
                    .children(load.map(|(cpu, mem)| {
                        // How busy it is, so a host that needs a look stands
                        // out without clicking through each one.
                        let row = |what: &'static str, pct: f32| {
                            div()
                                .flex()
                                .items_center()
                                .gap_1()
                                .child(div().flex_none().w(px(28.)).whitespace_nowrap().child(what))
                                .child(bar(pct, px(SIDEBAR_BAR_W), theme.muted, theme.primary))
                                .child(div().flex_1().text_right().child(format!("{pct:.0}%")))
                        };
                        div()
                            .id(("host-load", id as usize))
                            .test_support()
                            .mt_1()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .aria_description(format!("CPU {cpu:.0}%, memory {mem:.0}%"))
                            .child(row("CPU", cpu))
                            .child(row("Mem", mem))
                    }))
                    .children(detail.map(|detail| {
                        div()
                            .id(("host-detail", id as usize))
                            .test_support()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .aria_description(detail.clone())
                            .child(detail)
                    })),
            );
        }
        list
    }

    /// How long `host` has been silent, if it has missed a few intervals.
    /// Judged by when the monitor received its last sample, on the
    /// monitor's clock (the playback position when replaying), so a skewed
    /// clock on the agent doesn't matter.
    fn silence(&self, host: &HostModel) -> Option<u64> {
        let now = match self.view {
            View::Live => sysmon_ingest::unix_now_ns(),
            View::Replay => self.status().map_or(0, |s| s.position_ns),
        };
        Self::silence_at(host, now)
    }

    /// A notice above the header while the host is silent: the figures
    /// below are its last sample, not current ones (only the sidebar said
    /// so before, and a stopped agent still showed as running).
    fn render_stale_banner(&self, host: &HostModel, cx: &App) -> Option<impl IntoElement + use<>> {
        if host.last_received_ns == 0 {
            return None;
        }
        let silent = self.silence(host)?;
        let theme = cx.theme();
        let text = format!(
            "No data from {} for {}: showing its last sample, received {}",
            host.name(),
            format::duration(silent),
            format::time(host.last_received_ns)
        );
        Some(
            div()
                .id("stale-banner")
                .test_support()
                .flex_none()
                .px_2()
                .py_1()
                .text_sm()
                .bg(theme.warning.opacity(0.15))
                .border_b_1()
                .border_color(theme.warning)
                .flex()
                .items_center()
                .gap_2()
                .aria_description(text.clone())
                .child(icon(IconName::Link2Off).text_color(theme.warning))
                .child(text),
        )
    }

    /// A notice above the header while data from some sender is turned
    /// away (wrong key, newer agent, …): that machine won't show up, and
    /// otherwise only stderr would say why.
    fn render_rejected_banner(&self, cx: &App) -> Option<impl IntoElement + use<>> {
        let first = self.rejected.first().filter(|_| self.view == View::Live)?;
        let theme = cx.theme();
        let mut text = format!("Turning away data from {}: {}", first.from, first.reason);
        let more = self.rejected.len() - 1;
        if more > 0 {
            text.push_str(&format!(" (and {more} more)"));
        }
        let all: Vec<String> = self.rejected.iter().map(rejected_line).collect();
        let all = all.join("\n");
        Some(
            div()
                .id("rejected-banner")
                .test_support()
                .flex_none()
                .px_2()
                .py_1()
                .text_sm()
                .bg(theme.warning.opacity(0.15))
                .border_b_1()
                .border_color(theme.warning)
                .flex()
                .items_center()
                .gap_2()
                .aria_description(text.clone())
                .when(more > 0, |d| {
                    d.tooltip(move |window, cx| Tooltip::new(all.clone()).build(window, cx))
                })
                .child(icon(IconName::TriangleAlert).text_color(theme.warning))
                .child(text),
        )
    }

    /// The Live view before any agent is heard from: where to send, how to
    /// start one, and why data that did arrive was turned away.
    fn render_waiting(&self, cx: &App) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut col = div()
            .id("waiting")
            .test_support()
            .flex()
            .flex_col()
            .items_center()
            .gap_2()
            .text_sm()
            .text_color(theme.muted_foreground)
            .child(div().text_base().child("Waiting for agents…"));
        if let Some((addr, keyed)) = self.listen {
            let target = if addr.ip().is_unspecified() {
                format!("<this machine>:{}", addr.port())
            } else {
                addr.to_string()
            };
            let key = if keyed { " --key-file <key>" } else { "" };
            let command = format!("sysmon-agent --target {target}{key}");
            col = col
                .child(
                    div()
                        .id("waiting-listen")
                        .test_support()
                        .child(format!("Listening on UDP {addr}. Start an agent with:")),
                )
                .child(
                    div()
                        .id("waiting-command")
                        .test_support()
                        .px_2()
                        .py_1()
                        .rounded_md()
                        .bg(theme.muted)
                        .text_color(theme.foreground)
                        .font_family(theme.mono_font_family.clone())
                        .aria_description(command.clone())
                        .child(command),
                );
        }
        if !self.rejected.is_empty() {
            col = col.child(
                div()
                    .id("waiting-rejected")
                    .test_support()
                    .mt_2()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .text_color(theme.warning)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(icon(IconName::TriangleAlert))
                            .child("Data arrived, but was turned away:"),
                    )
                    .children(self.rejected.iter().map(|r| div().child(rejected_line(r)))),
            );
        }
        col
    }

    /// [`Self::silence`] at monitor time `now`.
    fn silence_at(host: &HostModel, now: u64) -> Option<u64> {
        let interval_ns = host.info.as_ref().map_or(1000, |i| i.interval_ms) as u64 * 1_000_000;
        let since = now.saturating_sub(host.last_received_ns);
        (host.last_received_ns == 0 || since > 3 * interval_ns).then_some(since)
    }

    /// The header for `host`, `width` wide.
    fn render_header(
        host: &HostModel,
        width: Pixels,
        cx: &Context<Self>,
    ) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let s = &host.snapshot;
        // The newest SPARK_POINTS samples of one figure.
        let recent = |f: fn(&sysmon_model::HistoryPoint) -> f32| -> Vec<f32> {
            let skip = host.history.len().saturating_sub(SPARK_POINTS);
            host.history.iter().skip(skip).map(f).collect()
        };
        let mem = s.mem;
        // From the network: available can be bogus (above total).
        let mem_used = mem.total.saturating_sub(mem.available);
        let mem_pct = mem_pct(&mem);
        let swap_used = mem.swap_total.saturating_sub(mem.swap_free);
        let rx: f64 = s.net.iter().map(|n| n.rx_bytes_per_s).sum();
        let tx: f64 = s.net.iter().map(|n| n.tx_bytes_per_s).sum();
        let rd: f64 = s.disks.iter().map(|d| d.read_bytes_per_s).sum();
        let wr: f64 = s.disks.iter().map(|d| d.write_bytes_per_s).sum();

        // Incoming (receive, read) and outgoing (transmit, write), the same
        // in both tiles; from the graph palette, as the theme's chart colours
        // are all shades of one hue.
        let (in_color, out_color) = (selection::color(0), selection::color(1));
        // The colour ties a figure to its line; the description says it in words.
        // Network and disk alike: ↓ in (receive, read), ↑ out (transmit,
        // write); hovering names it.
        let colored = |id: &'static str, text: String, what: &str, color: Hsla| {
            let figure = text.split_once(' ').map_or(text.as_str(), |(_, f)| f);
            let named = format!("{what} {figure}");
            div()
                .id(id)
                .test_support()
                .text_color(color)
                .tooltip({
                    let named = named.clone();
                    move |window, cx| Tooltip::new(named.clone()).build(window, cx)
                })
                .aria_description(named)
                .child(text.clone())
                .into_any_element()
        };
        // A tile: title and figures, the sparkline, and optionally a detail line.
        let metric = |title: &'static str,
                      line1: AnyElement,
                      line2: Option<AnyElement>,
                      chart: AnyElement| {
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .text_xs()
                        .child(div().text_color(theme.muted_foreground).child(title))
                        .child(line1),
                )
                .child(chart)
                .children(
                    line2.map(|l| div().text_xs().text_color(theme.muted_foreground).child(l)),
                )
        };
        // Two figures side by side, as one tile's figure line.
        let pair = |a: AnyElement, b: AnyElement| {
            div().flex().gap_2().child(a).child(b).into_any_element()
        };
        // A tile's headline figure, e.g. both directions added up.
        let total = |id: &'static str, value: String, what: &str| {
            div()
                .id(id)
                .test_support()
                .aria_description(format!("{what} {value}"))
                .child(value)
                .into_any_element()
        };
        let spark = |series: Vec<(Vec<f32>, Hsla)>, max: Option<f32>| {
            sparkline(series, max, HISTORY_LEN.min(SPARK_POINTS), theme.secondary)
                .into_any_element()
        };
        let text = |t: String| div().child(t).into_any_element();
        // A rate graph scales to its highest point, so without a figure a
        // full-height spike could be 2 KiB/s or 2 GiB/s: say what the top is.
        let spark_rates = |id: &'static str, series: Vec<(Vec<f32>, Hsla)>| {
            let top = series
                .iter()
                .flat_map(|(v, _)| v.iter().copied())
                .fold(0.0f32, f32::max);
            let label = format!("max {}", format::bytes_per_s(top as f64));
            div()
                .relative()
                .child(spark(series, None))
                .when(top > 0.0, |d| {
                    d.child(
                        div()
                            .id(id)
                            .test_support()
                            .absolute()
                            .top(px(1.))
                            .left(px(3.))
                            .text_size(px(9.))
                            .line_height(px(10.))
                            .text_color(theme.muted_foreground)
                            .aria_description(label.clone())
                            .child(label),
                    )
                })
                .into_any_element()
        };

        let cpu = s.cpu_pct.first().copied().unwrap_or(0.0);
        // Per-core bars in even rows: as many to a row as fit `width`, then
        // spread evenly (24 cores at 11 a row wrapped as 11, 11 and 2).
        let core_count = s.cpu_pct.len().saturating_sub(1);
        let fit = ((f32::from(width) + CORE_GAP) / (CORE_W + CORE_GAP)).max(1.0) as usize;
        let per_row = cores_per_row(core_count, fit);
        let mut cores = div().flex().flex_col().gap_y_1();
        let mut row = div().flex().gap_x(px(CORE_GAP));
        for (i, pct) in s.cpu_pct.iter().enumerate().skip(1) {
            if i > 1 && (i - 1).is_multiple_of(per_row) {
                cores = cores.child(std::mem::replace(
                    &mut row,
                    div().flex().gap_x(px(CORE_GAP)),
                ));
            }
            row = row.child(
                div()
                    .id(("core", i - 1))
                    .test_support()
                    .flex_none()
                    .w(px(CORE_W))
                    .flex()
                    .items_center()
                    .gap_1()
                    .text_xs()
                    .child(
                        div()
                            .w(px(28.))
                            .text_color(theme.muted_foreground)
                            .child(format!("{}", i - 1)),
                    )
                    .child(bar(*pct, px(70.), theme.secondary, theme.primary))
                    .child(div().w(px(36.)).child(format!("{pct:.0}%"))),
            );
        }
        let cores = cores.child(row);

        div()
            .flex()
            .flex_col()
            .gap_2()
            .p_2()
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_6()
                    .child(metric(
                        "CPU",
                        text(format!("{cpu:.1}%")),
                        Some(text(format!(
                            "load {:.2} {:.2} {:.2}",
                            s.load[0], s.load[1], s.load[2]
                        ))),
                        spark(vec![(recent(|p| p.cpu_pct), theme.primary)], Some(100.0)),
                    ))
                    .child(metric(
                        "Memory",
                        text(format!("{mem_pct:.1}%")),
                        Some(text(format!(
                            "{} / {}  swap {}",
                            format::bytes(mem_used as f64 * 1024.0),
                            format::bytes(mem.total as f64 * 1024.0),
                            format::bytes(swap_used as f64 * 1024.0)
                        ))),
                        spark(
                            vec![(recent(|p| p.mem_used_kib as f32), theme.success)],
                            Some(mem.total.max(1) as f32),
                        ),
                    ))
                    .child(metric(
                        "Network",
                        total("net-total", format::bytes_per_s(rx + tx), "Network total"),
                        Some(pair(
                            colored(
                                "net-rx",
                                format!("↓ {}", format::bytes_per_s(rx)),
                                "Network receive",
                                in_color,
                            ),
                            colored(
                                "net-tx",
                                format!("↑ {}", format::bytes_per_s(tx)),
                                "Network transmit",
                                out_color,
                            ),
                        )),
                        spark_rates(
                            "net-scale",
                            vec![
                                (recent(|p| p.net_rx_bytes_per_s as f32), in_color),
                                (recent(|p| p.net_tx_bytes_per_s as f32), out_color),
                            ],
                        ),
                    ))
                    .child(metric(
                        "Disk",
                        total("disk-total", format::bytes_per_s(rd + wr), "Disk total"),
                        Some(pair(
                            colored(
                                "disk-read",
                                format!("↓ {}", format::bytes_per_s(rd)),
                                "Disk read",
                                in_color,
                            ),
                            colored(
                                "disk-write",
                                format!("↑ {}", format::bytes_per_s(wr)),
                                "Disk write",
                                out_color,
                            ),
                        )),
                        spark_rates(
                            "disk-scale",
                            vec![
                                (recent(|p| p.disk_read_bytes_per_s as f32), in_color),
                                (recent(|p| p.disk_write_bytes_per_s as f32), out_color),
                            ],
                        ),
                    ))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .children(host.info.as_ref().map(|i| {
                                format!(
                                    "{} · {} CPUs · kernel {}",
                                    i.hostname, i.cpu_count, i.kernel
                                )
                            }))
                            .child({
                                // Times are local; the zone is on hover
                                // rather than after every sample time.
                                let zone =
                                    format!("Local time ({})", format::utc_offset(s.ts_unix_ns));
                                div()
                                    .id("sample-line")
                                    .test_support()
                                    .tooltip(move |window, cx| {
                                        Tooltip::new(zone.clone()).build(window, cx)
                                    })
                                    .child(format!(
                                        "{} processes ({} kernel threads) · sample {}",
                                        s.procs.len(),
                                        s.procs.iter().filter(|p| p.kernel_thread).count(),
                                        format::datetime(s.ts_unix_ns),
                                    ))
                            }),
                    ),
            )
            .child(cores)
    }

    /// The rows to show, in order.
    ///
    /// Kernel threads are left out when hidden. With threads shown, each
    /// process is followed by its threads (in the flat view) or has them as
    /// its first children (in the tree). In tree mode every process is kept
    /// so ancestors of filter matches can be shown; otherwise only matches
    /// are kept. A thread matching the filter keeps its process.
    fn table_lines(&self, host: &HostModel, cx: &App) -> Vec<Line> {
        let needle = self.filter.read(cx).value().to_lowercase();
        let filtering = !needle.is_empty();
        // Exactly a pid, as typed ("010" or "+10" isn't pid 10).
        let needle_pid = needle
            .parse::<u32>()
            .ok()
            .filter(|p| p.to_string() == needle);
        let proc_matches = |p: &ProcRow| {
            !filtering
                || p.comm.to_lowercase().contains(&needle)
                || p.cmdline
                    .as_ref()
                    .is_some_and(|c| c.to_lowercase().contains(&needle))
                || p.user
                    .as_ref()
                    .is_some_and(|u| u.to_lowercase().contains(&needle))
                || needle_pid == Some(p.key.pid)
        };
        let thread_matches = |t: &ThreadRow| {
            !filtering || t.comm.to_lowercase().contains(&needle) || needle_pid == Some(t.key.pid)
        };
        let (key, desc) = self.sort;
        // Where each row was while the order is held ([`ORDER_HOLD`]).
        let held_place = self
            .held_rank()
            .map(|rank| move |k: &ProcKey| rank.get(k).copied().unwrap_or(usize::MAX));

        // Threads by owner, in the current sort order where it applies (PID
        // sorts by TID). Threads have no user or memory of their own (those
        // cells show "–"), so for those columns they stay in TID order.
        let mut threads_of: HashMap<u32, Vec<ThreadRow>> = HashMap::new();
        if self.show_threads {
            for t in &host.snapshot.threads {
                threads_of.entry(t.tgid).or_default().push(t.clone());
            }
            let applies = matches!(key, SortKey::Pid | SortKey::Cpu | SortKey::Command);
            for list in threads_of.values_mut() {
                list.sort_by(|a, b| {
                    let ord = match key {
                        SortKey::Cpu => a.cpu_pct.total_cmp(&b.cpu_pct),
                        SortKey::Command => a.comm.cmp(&b.comm),
                        _ => a.key.pid.cmp(&b.key.pid),
                    };
                    let ord = if desc && applies { ord.reverse() } else { ord };
                    ord.then(a.key.pid.cmp(&b.key.pid))
                });
                if let Some(place) = &held_place {
                    list.sort_by_key(|t| place(&t.key));
                }
            }
        }
        let has_matching_thread: HashSet<u32> = if filtering {
            threads_of
                .iter()
                .filter(|(_, ts)| ts.iter().any(&thread_matches))
                .map(|(&tgid, _)| tgid)
                .collect()
        } else {
            HashSet::new()
        };
        let matches = |p: &ProcRow| proc_matches(p) || has_matching_thread.contains(&p.key.pid);
        // The threads to show under a process: all of them unless filtering,
        // in which case those that match, or all if the process itself does.
        // Threads always listed, busy or not: graphed or under the cursor.
        let keep: HashSet<ProcKey> = self
            .selection()
            .into_iter()
            .flat_map(|s| s.iter().map(|p| p.target.key()))
            .chain(self.cursor)
            .collect();
        // The threads to show under a process. Unfiltered, only busy ones:
        // listing every idle thread buried the processes (a desktop has
        // over a thousand). Filtering by a process lists all of its threads,
        // and by a thread's name, those that match.
        let shown_threads = |p: &ProcRow| -> Vec<ThreadRow> {
            let all = filtering && proc_matches(p);
            threads_of
                .get(&p.key.pid)
                .map(|ts| {
                    ts.iter()
                        .filter(|t| {
                            all || keep.contains(&t.key)
                                || if filtering {
                                    thread_matches(t)
                                } else {
                                    t.cpu_pct > 0.0
                                }
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };

        let mut rows: Vec<ProcRow> = host
            .snapshot
            .procs
            .iter()
            .filter(|p| !(self.hide_kernel && p.kernel_thread))
            .filter(|p| self.tree || matches(p))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            let ord = match key {
                SortKey::Pid => a.key.pid.cmp(&b.key.pid),
                SortKey::User => a.user.cmp(&b.user).then(a.uid.cmp(&b.uid)),
                SortKey::Cpu => a.cpu_pct.total_cmp(&b.cpu_pct),
                SortKey::Virt => a.virt_kib.cmp(&b.virt_kib),
                SortKey::Res => a.rss_kib.cmp(&b.rss_kib),
                SortKey::Shr => a.shr_kib.cmp(&b.shr_kib),
                SortKey::Threads => a.threads.cmp(&b.threads),
                SortKey::Command => command(a).cmp(&command(b)),
            };
            let ord = if desc { ord.reverse() } else { ord };
            ord.then(a.key.pid.cmp(&b.key.pid))
        });
        // While held, rows keep their places (the sort is stable, so new
        // ones follow in sorted order).
        if let Some(place) = &held_place {
            rows.sort_by_key(|r| place(&r.key));
        }

        let mut out = Vec::new();
        if !self.tree {
            for row in rows {
                let threads = shown_threads(&row);
                // One copy, shared by the process's line and its threads'.
                let row = Rc::new(row);
                out.push(Line::process(
                    row.clone(),
                    None,
                    filtering && !proc_matches(&row),
                ));
                out.extend(
                    threads
                        .into_iter()
                        .map(|t| Line::thread(row.clone(), t, None)),
                );
            }
            return out;
        }
        let filter: Option<&dyn Fn(&ProcRow) -> bool> =
            filtering.then_some(&matches as &dyn Fn(&ProcRow) -> bool);
        let no_collapsed = HashSet::new();
        let collapsed = self
            .selected
            .and_then(|h| self.collapsed.get(&(self.view, h)))
            .unwrap_or(&no_collapsed);
        for t in sysmon_model::tree::build(&rows, filter, collapsed) {
            let row = Rc::new(rows[t.row].clone());
            let threads = if t.collapsed {
                Vec::new()
            } else {
                shown_threads(&row)
            };
            // Threads go first among the children, so the guides drawn for
            // the real children below stay right.
            let n = threads.len();
            let thread_lines: Vec<Line> = threads
                .into_iter()
                .enumerate()
                .map(|(k, th)| {
                    let last = k + 1 == n && !t.has_children;
                    let tree = TreeLine {
                        row: t.row,
                        depth: t.depth + 1,
                        guides: sysmon_model::tree::child_guides(&t.guides, last),
                        has_children: false,
                        collapsed: false,
                        matched: true,
                        hidden: 0,
                        hidden_cpu_pct: 0.0,
                        hidden_rss_kib: 0,
                        hidden_virt_kib: 0,
                    };
                    Line::thread(row.clone(), th, Some(tree))
                })
                .collect();
            let context = filtering && !proc_matches(&row);
            out.push(Line::process(row, Some(t), context));
            out.extend(thread_lines);
        }
        out
    }

    /// e.g. "113 shown · 359 kernel threads hidden · 12 of 1218 threads
    /// (idle ones hidden) · 2 graphed", for the table's `lines`.
    fn status_line(&self, host: &HostModel, lines: &[Line], cx: &App) -> String {
        let mut parts = vec![format!("{} shown", lines.len())];
        let kernel = host
            .snapshot
            .procs
            .iter()
            .filter(|p| p.kernel_thread)
            .count();
        if self.hide_kernel && kernel > 0 {
            parts.push(format!("{kernel} kernel threads hidden"));
        }
        if self.show_threads {
            if host.sends_threads() {
                let listed = lines.iter().filter(|l| l.thread.is_some()).count();
                let total = host.snapshot.threads.len();
                let filtering = !self.filter.read(cx).value().is_empty();
                parts.push(if filtering || listed == total {
                    format!("{listed} of {total} threads")
                } else {
                    format!("{listed} of {total} threads (idle ones hidden; filter to list them)")
                });
            } else {
                parts.push("threads not reported: start this host's agent with --threads".into());
            }
        }
        if self.held_rank().is_some() {
            parts.push("order held".into());
        }
        match self.selection().filter(|s| !s.is_empty()) {
            Some(sel) => parts.push(format!("{} graphed", sel.len())),
            // The checkboxes have no header: say what they're for.
            None => parts.push(
                match cx.global::<crate::keymap::Keymap>().label::<ToggleGraph>() {
                    Some(key) => format!("tick a row's box (or press {key}) to graph it"),
                    None => "tick a row's box to graph it".into(),
                },
            ),
        }
        parts.join(" · ")
    }

    fn render_procs(
        &self,
        host: &HostModel,
        mono_char: Pixels,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let mono = theme.mono_font_family.clone();
        let rows = Rc::new(self.table_lines(host, cx));
        let status = self.status_line(host, &rows, cx);
        let this = cx.entity().downgrade();
        // As wide as the host's longest name, within USER_MIN_CHARS..=
        // USER_MAX_CHARS: from all its processes, not just those shown, so
        // the columns don't move while scrolling or typing a filter.
        let user_chars = host
            .snapshot
            .procs
            .iter()
            .map(|p| user_name(p).chars().count())
            .max()
            .unwrap_or(0)
            .clamp(USER_MIN_CHARS, USER_MAX_CHARS);
        let user_w = mono_char * user_chars as f32 + px(4.);
        let picked: Rc<HashMap<ProcKey, usize>> = Rc::new(
            self.selection()
                .map(|s| s.iter().map(|p| (p.target.key(), p.slot)).collect())
                .unwrap_or_default(),
        );
        let cursor = self.cursor;
        let mem_total = host.snapshot.mem.total.max(1) as f32;

        let (sort_key, desc) = self.sort;
        let header_cell =
            |key: SortKey, label: &'static str, width: Option<f32>, cx: &mut Context<Self>| {
                let arrow = (key == sort_key).then_some(if desc { "▼" } else { "▲" });
                // A non-wrapping row keeps the indicator beside the label.
                let cell = div()
                    .id(label)
                    .test_support()
                    .flex()
                    .items_center()
                    .gap_1()
                    .whitespace_nowrap()
                    .cursor_pointer()
                    .child(label)
                    .children(arrow.map(|a| div().flex_none().child(a)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.sort_by(key, cx);
                    }));
                match width {
                    Some(w) => cell.w(px(w)),
                    None => cell.flex_1(),
                }
            };
        let header = div()
            .flex()
            .gap_2()
            .px_2()
            .py_1()
            .text_xs()
            .text_color(theme.muted_foreground)
            .border_b_1()
            .border_color(theme.border)
            .child(div().w(px(PICK_COL)))
            .child(header_cell(SortKey::Pid, "PID", Some(PID_COL), cx))
            .child(header_cell(
                SortKey::User,
                "USER",
                Some(f32::from(user_w)),
                cx,
            ))
            .child(div().w(px(STATE_COL)).child("S"))
            .child(header_cell(SortKey::Cpu, "%CPU", Some(CPU_COL), cx))
            .child(header_cell(SortKey::Virt, "VIRT", Some(SIZE_COL), cx))
            .child(header_cell(SortKey::Res, "RES", Some(SIZE_COL), cx))
            .child(header_cell(SortKey::Shr, "SHR", Some(SIZE_COL), cx))
            .child(div().w(px(MEM_PCT_COL)).child("%MEM"))
            .child(header_cell(SortKey::Threads, "THR", Some(THREADS_COL), cx))
            .child(header_cell(SortKey::Command, "COMMAND", None, cx));

        let count = rows.len();
        // An empty table says why, rather than showing nothing.
        let needle = self.filter.read(cx).value().to_string();
        let empty_note = (count == 0 && !needle.is_empty()).then(|| {
            format!("No processes match \u{201c}{needle}\u{201d}. Esc clears the filter.")
        });
        // With the keys in effect, which the settings may have changed.
        let pick_tips: Rc<[SharedString; 3]> = Rc::new([
            crate::keymap::hinted::<ToggleGraph>(cx, "Remove from the graph"),
            crate::keymap::hinted::<ToggleGraph>(cx, "Graph this thread"),
            crate::keymap::hinted::<ToggleGraph>(cx, "Graph this process"),
        ]);
        let list = uniform_list("procs", count, move |range, _, _| {
            range
                .map(|i| {
                    let line = &rows[i];
                    let depth = |l: &Line| l.tree.as_ref().map(|t| t.depth);
                    let opens = |i: usize| rows.get(i + 1).and_then(depth) > depth(&rows[i]);
                    let p = &line.row;
                    let th = line.thread.as_ref();
                    // Thread rows are always dim, so only a process's own
                    // staleness matters here.
                    let dim = th.is_some()
                        || line.context
                        || p.stale
                        || line.tree.as_ref().is_some_and(|t| !t.matched);
                    let slot = picked.get(&line.key()).copied();
                    let pick_tip = match slot {
                        Some(_) => pick_tips[0].clone(),
                        None if line.thread.is_some() => pick_tips[1].clone(),
                        None => pick_tips[2].clone(),
                    };
                    // Process-only figures: a thread's memory and thread
                    // count are its process's, shown on that row.
                    let proc_cell = |w: f32, text: &dyn Fn() -> String| {
                        div().w(px(w)).child(if th.is_some() {
                            "–".to_string()
                        } else {
                            text()
                        })
                    };
                    let on_row = {
                        let (this, rows) = (this.clone(), rows.clone());
                        move |ev: &ClickEvent, _: &mut Window, cx: &mut App| {
                            let m = ev.modifiers();
                            let _ = this.update(cx, |app, cx| {
                                app.row_clicked(&rows, i, m.control || m.platform, m.shift, cx)
                            });
                        }
                    };
                    let on_pick = {
                        let (this, target) = (this.clone(), line.target());
                        move |_: &ClickEvent, _: &mut Window, cx: &mut App| {
                            cx.stop_propagation();
                            let _ = this.update(cx, |app, cx| app.toggle_pick(target, cx));
                        }
                    };
                    div()
                        .id(("row", i))
                        .test_support()
                        .on_click(on_row)
                        .w_full()
                        .flex()
                        .gap_2()
                        .px_2()
                        .h(px(ROW_HEIGHT))
                        .items_center()
                        .text_xs()
                        .font_family(mono.clone())
                        .when(i % 2 == 1, |d| d.bg(theme.muted.opacity(0.3)))
                        .highlighted(cursor == Some(line.key()), &theme)
                        .when(dim, |d| d.text_color(theme.muted_foreground))
                        .child(
                            // Graph checkbox; filled with the line's colour when picked.
                            div()
                                .id(("pick", i))
                                .test_support()
                                .flex_none()
                                .size(px(10.))
                                .mx(px(2.))
                                .rounded_sm()
                                .border_1()
                                .cursor_pointer()
                                .map(|d| match slot {
                                    Some(s) => {
                                        d.bg(selection::color(s)).border_color(selection::color(s))
                                    }
                                    None => d.border_color(theme.muted_foreground),
                                })
                                .aria_description(pick_tip.clone())
                                .tooltip(move |window, cx| {
                                    Tooltip::new(pick_tip.clone()).build(window, cx)
                                })
                                .on_click(on_pick),
                        )
                        .child(div().w(px(PID_COL)).child(line.key().pid.to_string()))
                        .child({
                            let full = user_name(p);
                            let tip = match (&p.user, p.uid) {
                                (Some(name), Some(uid)) => format!("{name} (uid {uid})"),
                                (None, Some(uid)) => format!("uid {uid} (no user name known)"),
                                _ => "user not known yet".into(),
                            };
                            div()
                                .id(("user", i))
                                .test_support()
                                .flex_none()
                                .w(user_w)
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .child(format::fit(&full, user_chars))
                                // Also the accessible description, for screen readers.
                                .aria_description(tip.clone())
                                .tooltip(move |window, cx| {
                                    Tooltip::new(tip.clone()).build(window, cx)
                                })
                        })
                        .child(
                            div()
                                .w(px(STATE_COL))
                                .child(th.map_or(p.state, |t| t.state).to_string()),
                        )
                        .child(
                            div()
                                .w(px(CPU_COL))
                                .child(format!("{:.1}", th.map_or(p.cpu_pct, |t| t.cpu_pct))),
                        )
                        .child(proc_cell(SIZE_COL, &|| size_cell(p.virt_kib)))
                        .child(proc_cell(SIZE_COL, &|| size_cell(Some(p.rss_kib))))
                        .child(proc_cell(SIZE_COL, &|| size_cell(p.shr_kib)))
                        .child(proc_cell(MEM_PCT_COL, &|| {
                            format!("{:.1}", p.rss_kib as f32 / mem_total * 100.0)
                        }))
                        .child(proc_cell(THREADS_COL, &|| p.threads.to_string()))
                        .child(command_cell(line, i, opens(i), &this, mono_char, &theme))
                })
                .collect()
        })
        .track_scroll(&self.scroll)
        // Pointing at a row holds the order, so it's still there to click.
        .on_mouse_move(cx.listener(|this, _: &MouseMoveEvent, _, cx| {
            let was = this.held_rank().is_some();
            this.hold_order(cx);
            if !was {
                cx.notify();
            }
        }))
        .flex_1();

        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .p_2()
                    .child(
                        div().w(px(260.)).child(
                            Input::new(&self.filter)
                                .small()
                                .prefix(icon(IconName::Search))
                                .cleanable(true),
                        ),
                    )
                    .child(
                        Button::new("tree")
                            .icon(icon(IconName::ListTree))
                            .label("Tree")
                            .small()
                            .chosen(self.tree)
                            .disabled(!self.available.has::<ToggleTree>())
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_tree(cx))),
                    )
                    .child(
                        Button::new("kernel-toggle")
                            .icon(icon(IconName::Cpu))
                            .label("Kernel threads")
                            .small()
                            // Like its neighbours: highlighted means shown.
                            .chosen(!self.hide_kernel)
                            .disabled(!self.available.has::<ToggleKernelThreads>())
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_kernel_threads(cx))),
                    )
                    .child(
                        Button::new("threads-toggle")
                            .icon(icon(IconName::CornerDownRight))
                            .label("Threads")
                            .small()
                            .chosen(self.show_threads)
                            .disabled(!self.available.has::<ToggleThreads>())
                            .when(!self.available.has::<ToggleThreads>(), |b| {
                                b.tooltip("This host's agent doesn't send threads: start it with --threads")
                            })
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_threads(cx))),
                    )
                    .when(self.tree, |d| {
                        d.child(
                            Button::new("expand-all")
                                .icon(icon(IconName::ChevronsUpDown))
                                .label("Expand all")
                                .tooltip(crate::keymap::hinted::<ExpandAll>(cx, "Expand all"))
                                .accessibility_label("Expand all")
                                .small()
                                .disabled(!self.available.has::<ExpandAll>())
                                .ghost()
                                .on_click(cx.listener(|this, _, _, cx| this.expand_all(cx))),
                        )
                        .child(
                            Button::new("collapse-all")
                                .icon(icon(IconName::ChevronsDownUp))
                                .label("Collapse all")
                                .tooltip(crate::keymap::hinted::<CollapseAll>(cx, "Collapse all"))
                                .accessibility_label("Collapse all")
                                .small()
                                .disabled(!self.available.has::<CollapseAll>())
                                .ghost()
                                .on_click(cx.listener(|this, _, _, cx| this.collapse_all(cx))),
                        )
                    })
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(status),
                    ),
            )
            .child(header)
            .children(empty_note.map(|note| {
                div()
                    .id("procs-empty")
                    .test_support()
                    .p_4()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .aria_description(note.clone())
                    .child(note)
            }))
            .child(list)
    }

    fn selection(&self) -> Option<&Selection> {
        self.selected
            .and_then(|host| self.selections.get(&(self.view, host)))
    }

    fn selection_mut(&mut self) -> Option<&mut Selection> {
        let host = self.selected?;
        Some(self.selections.entry((self.view, host)).or_default())
    }

    /// Show (or, once a pick fits again, take down) the "graph is full" message.
    fn report_full(&mut self, result: Result<(), selection::Full>) {
        let full = format!(
            "At most {} processes can be graphed at once",
            selection::MAX_SERIES
        );
        if result.is_err() {
            self.error = Some(full);
        } else if self.error.as_ref() == Some(&full) {
            self.error = None;
        }
    }

    fn clear_graph(&mut self, cx: &mut Context<Self>) {
        if let Some(s) = self.selection_mut() {
            s.clear();
        }
        self.report_full(Ok(()));
        cx.notify();
    }

    /// A click on row `i` of `lines`: moves the cursor; Ctrl toggles the row
    /// in the graph, Shift adds the range from the last toggled row.
    fn row_clicked(
        &mut self,
        lines: &[Line],
        i: usize,
        ctrl: bool,
        shift: bool,
        cx: &mut Context<Self>,
    ) {
        let Some(line) = lines.get(i) else {
            return;
        };
        self.hold_order(cx);
        self.cursor = Some(line.key());
        let result = if shift {
            let anchor = self
                .selection()
                .and_then(|s| s.anchor)
                .and_then(|a| lines.iter().position(|l| l.key() == a))
                .unwrap_or(i);
            let (lo, hi) = (anchor.min(i), anchor.max(i));
            let targets: Vec<_> = lines[lo..=hi].iter().map(Line::target).collect();
            self.selection_mut().map(|s| s.add_all(targets))
        } else if ctrl {
            self.selection_mut().map(|s| s.toggle(line.target()))
        } else {
            None
        };
        if let Some(r) = result {
            self.report_full(r);
        }
        cx.notify();
    }

    fn toggle_pick(&mut self, target: SeriesTarget, cx: &mut Context<Self>) {
        self.hold_order(cx);
        if let Some(r) = self.selection_mut().map(|s| s.toggle(target)) {
            self.report_full(r);
        }
        cx.notify();
    }

    /// Take a process (or thread) out of the graph.
    fn remove_pick(&mut self, key: ProcKey, cx: &mut Context<Self>) {
        if let Some(s) = self.selection_mut() {
            s.remove(key);
        }
        self.report_full(Ok(()));
        cx.notify();
    }

    /// The held row order for the table shown now, if it's still held.
    fn held_rank(&self) -> Option<&HashMap<ProcKey, usize>> {
        let host = (self.view, self.selected?);
        self.held
            .as_ref()
            .filter(|h| h.host == host && std::time::Instant::now() < h.until)
            .map(|h| &h.rank)
    }

    /// Keep the table's rows where they are now for [`ORDER_HOLD`] more:
    /// called whenever you work in the table.
    fn hold_order(&mut self, cx: &App) {
        let until = std::time::Instant::now() + ORDER_HOLD;
        if self.held_rank().is_some() {
            if let Some(h) = &mut self.held {
                h.until = until;
            }
            return;
        }
        let (Some(id), Some(host)) = (self.selected, self.current_host()) else {
            return;
        };
        let rank = self
            .table_lines(host, cx)
            .iter()
            .enumerate()
            .map(|(i, l)| (l.key(), i))
            .collect();
        self.held = Some(HeldOrder {
            host: (self.view, id),
            rank,
            until,
        });
    }

    /// Let go of a hold that has run out, at `now`; whether there was one
    /// (so the table re-sorts and the status line stops saying so).
    fn release_order(&mut self, now: std::time::Instant) -> bool {
        if self.held.as_ref().is_some_and(|h| now >= h.until) {
            self.held = None;
            return true;
        }
        false
    }

    /// Move the cursor by `delta` rows in the table's current order.
    fn move_cursor(&mut self, delta: isize, cx: &mut Context<Self>) {
        self.hold_order(cx);
        let Some(host) = self.current_host() else {
            return;
        };
        let lines = self.table_lines(host, cx);
        if lines.is_empty() {
            return;
        }
        let pos = self
            .cursor
            .and_then(|c| lines.iter().position(|l| l.key() == c));
        let next = match pos {
            None => 0,
            Some(p) => (p as isize + delta).clamp(0, lines.len() as isize - 1) as usize,
        };
        self.cursor = Some(lines[next].key());
        self.scroll.scroll_to_item(next, ScrollStrategy::Nearest);
        cx.notify();
    }

    /// Toggle the cursor row in the graph.
    fn toggle_cursor(&mut self, cx: &mut Context<Self>) {
        let Some(host) = self.current_host() else {
            return;
        };
        let lines = self.table_lines(host, cx);
        if let Some(line) = self
            .cursor
            .and_then(|c| lines.iter().find(|l| l.key() == c))
        {
            let target = line.target();
            self.toggle_pick(target, cx);
        }
    }

    fn open_about(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        // The dialog's builder can run again; the view is created once here.
        let view = cx.new(|cx| crate::about::AboutView::new(window, cx));
        let focus = self.focus.clone();
        window.open_dialog(cx, move |dialog, _, _| {
            let focus = focus.clone();
            dialog
                .title("About sysmon")
                .w(px(1000.))
                .child(view.clone())
                .footer(
                    DialogFooter::new().child(
                        Button::new("about-close")
                            .label("Close")
                            .primary()
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    ),
                )
                // Give the keyboard back to the app's shortcuts.
                .on_close(move |_, window, cx| focus.focus(window, cx))
        });
    }

    fn set_metric(&mut self, metric: Metric, cx: &mut Context<Self>) {
        self.graph_metric = metric;
        self.graph_visible = true;
        cx.notify();
    }

    /// Whether the bottom panel is open, with the graph, logs or details.
    fn panel_shown(&self) -> bool {
        self.panel != Panel::Graph || self.graph_shown()
    }

    fn graph_shown(&self) -> bool {
        self.graph_visible && self.selection().is_some_and(|s| !s.is_empty())
    }

    /// Remember the command of each graphed process while it's still
    /// running, and forget those no longer graphed.
    fn refresh_graph_names(&mut self) {
        let Some(host) = self.current_host() else {
            return;
        };
        let here = (self.view, host.host_id);
        let Some(sel) = self.selection() else {
            self.graph_names.remove(&here);
            return;
        };
        let picked: HashSet<ProcKey> = sel.iter().map(|p| p.target.key()).collect();
        let names: Vec<(ProcKey, String)> = sel
            .iter()
            .filter_map(|p| {
                let key = p.target.key();
                if let SeriesTarget::Thread(_) = p.target {
                    let t = host.snapshot.threads.iter().find(|t| t.key == key)?;
                    return Some((key, format!("{} (thread of {})", t.comm, t.tgid)));
                }
                let row = host.snapshot.procs.iter().find(|r| r.key == key)?;
                Some((key, proc_name(row)))
            })
            .collect();
        let known = self.graph_names.entry(here).or_default();
        known.retain(|k, _| picked.contains(k));
        known.extend(names);
    }

    /// The times the graph spans: the chosen window up to the newest
    /// sample, but no further back than the oldest one, so a short history
    /// fills the chart instead of huddling at its right edge.
    fn graph_span(&self, host: &HostModel) -> (u64, u64) {
        let end = host.proc_history.back().map_or(0, |f| f.ts_unix_ns);
        let oldest = host.proc_history.front().map_or(0, |f| f.ts_unix_ns);
        let start = end
            .saturating_sub(self.graph_window_s * 1_000_000_000)
            .max(oldest);
        (start, end)
    }

    fn render_graph(&self, host: &HostModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let metric = self.graph_metric;
        let picks: Vec<selection::Picked> = self
            .selection()
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let (start, end) = self.graph_span(host);
        let view = self.view;
        let mut cache = self.graph_lines.borrow_mut();
        let lines: Rc<Vec<graph::Line>> = Rc::new(
            picks
                .iter()
                .map(|p| graph::Line {
                    color: selection::color(p.slot),
                    points: cache.line(
                        (view, host.host_id, p.target, metric),
                        &host.proc_history,
                        p.target,
                        metric,
                        start,
                    ),
                })
                .collect(),
        );
        // Only what's on screen now is kept.
        cache.retain(|&(v, h, t, m)| {
            v == view && h == host.host_id && m == metric && picks.iter().any(|p| p.target == t)
        });
        drop(cache);
        let y_max = graph::y_max(metric, &lines);

        // Toolbar: tabs, metric, window, clear, hide.
        let mut toolbar = div()
            .flex()
            .items_center()
            .gap_1()
            .px_2()
            .py_1()
            .child(self.render_panel_tabs(cx));
        for (i, m) in Metric::ALL.into_iter().enumerate() {
            toolbar = toolbar.child(
                Button::new(("metric", i))
                    .label(m.label())
                    .small()
                    .chosen(m == metric)
                    .on_click(cx.listener(move |this, _, _, cx| this.set_metric(m, cx))),
            );
        }
        toolbar = toolbar.child(div().w(px(12.)));
        for (i, w) in graph::WINDOWS_S.into_iter().enumerate() {
            toolbar = toolbar.child(
                Button::new(("window", i))
                    .label(format!("{} min", w / 60))
                    .small()
                    .chosen(w == self.graph_window_s)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.graph_window_s = w;
                        cx.notify();
                    })),
            );
        }
        toolbar = toolbar
            .child(div().flex_1())
            .child(
                Button::new("graph-clear")
                    .icon(icon(IconName::Eraser))
                    .label("Clear")
                    .small()
                    .disabled(!self.available.has::<ClearGraph>())
                    .ghost()
                    .on_click(cx.listener(|this, _, _, cx| this.clear_graph(cx))),
            )
            .child(
                Button::new("graph-hide")
                    .icon(icon(IconName::PanelBottomClose))
                    .label("Hide")
                    .tooltip("Hide the panel")
                    .accessibility_label("Hide the panel")
                    .small()
                    .ghost()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.graph_visible = false;
                        cx.notify();
                    })),
            );

        // The chart and legend are drawn by their own view: given the
        // figures here, it redraws alone as the pointer moves.
        let legend = picks
            .iter()
            .map(|p| {
                let key = p.target.key();
                let name = self
                    .graph_names
                    .get(&(view, host.host_id))
                    .and_then(|n| n.get(&key))
                    .cloned()
                    .unwrap_or_else(|| "?".into());
                let latest = host.latest(p.target, metric);
                let label = match p.target {
                    SeriesTarget::Subtree(_) => {
                        let n = latest.map_or(0, |(_, n)| n);
                        format!("{} {name} + subtree ({n})", key.pid)
                    }
                    SeriesTarget::Process(_) | SeriesTarget::Thread(_) => {
                        format!("{} {name}", key.pid)
                    }
                };
                plot::LegendEntry {
                    slot: p.slot,
                    key,
                    label,
                    latest: latest.map(|(v, _)| v),
                }
            })
            .collect();
        let data = plot::PlotData {
            lines,
            start_ns: start,
            end_ns: end,
            y_max,
            metric,
            log_mark: self.log_cursor.map(|(_, ts)| ts),
            legend,
        };
        self.graph_plot.update(cx, |p, _| p.set(data));

        div()
            .id("graph-panel")
            .test_support()
            .flex()
            .flex_col()
            .size_full()
            .border_t_1()
            .border_color(theme.border)
            .child(toolbar)
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .px_2()
                    .pb_2()
                    .child(self.graph_plot.clone()),
            )
    }

    /// Where in `host`'s log rows those that pass the filters are. Lost and
    /// dropped rows only show unfiltered, where they say something about
    /// what's around. Positions rather than rows: a host keeps up to
    /// 20 000 lines, too many to copy on every redraw.
    fn log_rows(&self, host: &HostModel, cx: &App) -> Vec<usize> {
        let needle = self.log_filter.read(cx).value().to_lowercase();
        let narrowed = !needle.is_empty() || self.log_source.is_some();
        host.logs
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, r)| match &r.kind {
                LogKind::Line(e) => {
                    let source = e.unit.as_deref().unwrap_or(&e.ident);
                    e.priority <= self.log_min_priority
                        && self.log_source.as_deref().is_none_or(|s| s == source)
                        && (needle.is_empty()
                            || e.message.to_lowercase().contains(&needle)
                            || source.to_lowercase().contains(&needle)
                            || e.ident.to_lowercase().contains(&needle))
                }
                LogKind::Lost(_) | LogKind::Dropped(_) => !narrowed && self.log_min_priority == 7,
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Move the process table's cursor to `pid`, if it's in the table.
    fn show_process(&mut self, pid: u32, cx: &mut Context<Self>) {
        let Some(host) = self.current_host() else {
            return;
        };
        let Some(key) = host
            .snapshot
            .procs
            .iter()
            .find(|p| p.key.pid == pid)
            .map(|p| p.key)
        else {
            self.error = Some(format!("PID {pid} isn't running at this point"));
            cx.notify();
            return;
        };
        let lines = self.table_lines(host, cx);
        match lines.iter().position(|l| l.key() == key) {
            Some(i) => {
                self.cursor = Some(key);
                self.scroll.scroll_to_item(i, ScrollStrategy::Center);
            }
            None => {
                self.error = Some(format!(
                    "PID {pid} is hidden by the process filter or settings"
                ))
            }
        }
        cx.notify();
    }

    /// A click on the log line `key` (receive time, log time): highlight it,
    /// stop following, and in a recording seek to when it was received, so
    /// the graphs and process table show that moment.
    fn log_clicked(&mut self, key: (u64, u64), cx: &mut Context<Self>) {
        self.log_cursor = Some(key);
        self.log_follow = false;
        if self.view == View::Replay {
            self.control(Control::Seek(key.0));
            self.log_reveal_after_reset = true;
        }
        cx.notify();
    }

    /// Graph / Logs / Details, at the left of the bottom panel's toolbar.
    fn render_panel_tabs(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let picked = self.selection().is_some_and(|s| !s.is_empty());
        div()
            .flex()
            .gap_1()
            .mr_2()
            .child(
                Button::new("tab-graph")
                    .icon(icon(IconName::ChartLine))
                    .label("Graph")
                    .small()
                    .chosen(self.panel == Panel::Graph)
                    // There's nothing to graph until processes are picked.
                    .disabled(!picked)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.panel = Panel::Graph;
                        this.graph_visible = true;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("tab-logs")
                    .icon(icon(IconName::ScrollText))
                    .label("Logs")
                    .small()
                    .disabled(!self.available.has::<ToggleLogs>())
                    .when(!self.available.has::<ToggleLogs>(), |b| {
                        b.tooltip("No logs from this host: start its agent with --logs")
                    })
                    .chosen(self.panel == Panel::Logs)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.panel = Panel::Logs;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("tab-details")
                    .icon(icon(IconName::Info))
                    .label("Details")
                    .small()
                    .disabled(!self.available.has::<ToggleDetails>())
                    .chosen(self.panel == Panel::Details)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.panel = Panel::Details;
                        cx.notify();
                    })),
            )
    }

    fn render_logs(&self, host: &HostModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let mono = theme.mono_font_family.clone();
        let border = theme.border;
        let total = host.logs.rows().len();
        let shown: Rc<Vec<usize>> = Rc::new(self.log_rows(host, cx));
        // Lines from more than one day show the date: a time alone was
        // ambiguous in a recording spanning days.
        let times = host.logs.rows().iter().map(|r| r.ts_unix_ns);
        let spans_days = match (times.clone().min(), times.max()) {
            (Some(first), Some(last)) => format::day(first) != format::day(last),
            _ => false,
        };
        let time_w = if spans_days {
            LOG_DAY_TIME_COL
        } else {
            LOG_TIME_COL
        };
        let count = shown.len();
        if self.log_follow && count > 0 {
            self.log_scroll
                .scroll_to_item(count - 1, ScrollStrategy::Bottom);
        } else if self.log_reveal.get()
            && let Some(i) = self.log_cursor.and_then(|c| {
                let all = host.logs.rows();
                shown
                    .iter()
                    .position(|&j| (all[j].received_ns, all[j].ts_unix_ns) == c)
            })
        {
            self.log_reveal.set(false);
            self.log_scroll.scroll_to_item(i, ScrollStrategy::Center);
        }
        // An empty list says why, rather than looking broken.
        let empty_note = (count == 0 && host.logs.enabled()).then_some(if total == 0 {
            "No log lines yet. The agent sends new ones as they're logged \
             (warnings and worse, unless it was started with --log-priority)."
        } else {
            "No lines match. Clear the filter, or pick All."
        });
        let status = if !host.logs.enabled() {
            "No logs from this host: start its agent with --logs".into()
        } else if count < total {
            format!("{count} of {total} lines")
        } else {
            format!("{count} lines")
        };
        let toolbar = div()
            .flex()
            .items_center()
            .gap_1()
            .px_2()
            .py_1()
            .child(self.render_panel_tabs(cx))
            .child(
                div().w(px(200.)).child(
                    Input::new(&self.log_filter)
                        .small()
                        .prefix(icon(IconName::Search))
                        .cleanable(true),
                ),
            )
            .children(
                [(7u8, "All"), (4, "Warnings"), (3, "Errors")].map(|(p, label)| {
                    Button::new(("logs-priority", p as usize))
                        .label(label)
                        .small()
                        .chosen(self.log_min_priority == p)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.log_min_priority = p;
                            cx.notify();
                        }))
                }),
            )
            .when_some(self.log_source.clone(), |d, source| {
                d.child(
                    Button::new("logs-source")
                        .label(source)
                        .icon(icon(IconName::X))
                        .small()
                        .ghost()
                        .tooltip("Show every unit again")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.log_source = None;
                            cx.notify();
                        })),
                )
            })
            .child(
                div()
                    .id("logs-status")
                    .test_support()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .aria_description(status.clone())
                    .child(status),
            )
            .child(div().flex_1())
            .when(!self.log_follow, |d| {
                d.child(
                    Button::new("logs-latest")
                        .icon(icon(IconName::ArrowDownToLine))
                        .label("Jump to latest")
                        .small()
                        .ghost()
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.log_follow = true;
                            cx.notify();
                        })),
                )
            })
            .child(
                Button::new("logs-hide")
                    .icon(icon(IconName::PanelBottomClose))
                    .label("Hide")
                    .tooltip("Hide the panel")
                    .accessibility_label("Hide the panel")
                    .small()
                    .ghost()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.panel = Panel::Graph;
                        cx.notify();
                    })),
            );
        let header = div()
            .flex()
            .gap_2()
            .px_2()
            .py_1()
            .text_xs()
            .text_color(theme.muted_foreground)
            .border_b_1()
            .border_color(theme.border)
            .child(div().w(px(time_w)).child("TIME"))
            .child(div().w(px(LOG_PRI_COL)).child("PRI"))
            .child(div().w(px(LOG_SOURCE_COL)).child("UNIT"))
            .child(div().w(px(LOG_PID_COL)).child("PID"))
            .child(div().flex_1().child("MESSAGE"));

        let this = cx.entity().downgrade();
        let cursor = self.log_cursor;
        let host_id = host.host_id;
        let list = uniform_list("logs", count, move |range, _, cx| {
            // The rows are read from the model as they're drawn.
            let Some(entity) = this.upgrade() else {
                return Vec::new();
            };
            let Some(all) = entity.read(cx).hosts().get(&host_id).map(|h| h.logs.rows()) else {
                return Vec::new();
            };
            range
                .filter_map(|i| Some((i, all.get(*shown.get(i)?)?)))
                .map(|(i, row)| {
                    let key = (row.received_ns, row.ts_unix_ns);
                    let on_click = {
                        let this = this.clone();
                        move |_: &ClickEvent, _: &mut Window, cx: &mut App| {
                            let _ = this.update(cx, |app, cx| app.log_clicked(key, cx));
                        }
                    };
                    let base = div()
                        .id(("log-row", i))
                        .test_support()
                        .on_click(on_click)
                        .w_full()
                        .flex()
                        .gap_2()
                        .px_2()
                        .h(px(ROW_HEIGHT))
                        .items_center()
                        .text_xs()
                        .font_family(mono.clone())
                        .when(i % 2 == 1, |d| d.bg(theme.muted.opacity(0.3)))
                        .highlighted(cursor == Some(key), &theme)
                        .child({
                            let at = if spans_days {
                                format::day_time(row.ts_unix_ns)
                            } else {
                                format::time(row.ts_unix_ns)
                            };
                            div()
                                .id(("log-time", i))
                                .test_support()
                                .flex_none()
                                .w(px(time_w))
                                .aria_description(at.clone())
                                .child(at)
                        });
                    match &row.kind {
                        LogKind::Line(e) => {
                            let source = e.unit.clone().unwrap_or_else(|| e.ident.clone());
                            let source_tip = match &e.unit {
                                Some(u) => format!("{u} · {}", e.ident),
                                None => e.ident.clone(),
                            };
                            let first = e.message.lines().next().unwrap_or("");
                            let more = e.message.contains('\n');
                            let text = if more {
                                format!("{first} ⏎…")
                            } else {
                                first.to_string()
                            };
                            let tip = if e.truncated {
                                format!("{} … (cut by the agent)", e.message)
                            } else {
                                e.message.clone()
                            };
                            base.child(priority_cell(e.priority, &theme))
                                .child({
                                    // Click: show only this unit's lines.
                                    let (this, picked) = (this.clone(), source.clone());
                                    div()
                                        .id(("log-source-cell", i))
                                        .test_support()
                                        .flex_none()
                                        .w(px(LOG_SOURCE_COL))
                                        .flex()
                                        .cursor_pointer()
                                        .on_click(move |_, _, cx| {
                                            cx.stop_propagation();
                                            let _ = this.update(cx, |app, cx| {
                                                app.log_source = Some(picked.clone());
                                                cx.notify();
                                            });
                                        })
                                        .child(clipped(("log-source", i), source, source_tip))
                                })
                                .child({
                                    // Click: find the process in the table.
                                    let (this, pid) = (this.clone(), e.pid);
                                    div()
                                        .id(("log-pid", i))
                                        .test_support()
                                        .flex_none()
                                        .w(px(LOG_PID_COL))
                                        .when(pid.is_some(), |d| d.cursor_pointer())
                                        .on_click(move |_, _, cx| {
                                            let Some(pid) = pid else {
                                                return;
                                            };
                                            cx.stop_propagation();
                                            let _ = this
                                                .update(cx, |app, cx| app.show_process(pid, cx));
                                        })
                                        .child(pid.map_or_else(|| "–".into(), |p| p.to_string()))
                                })
                                .child(clipped(("log-message", i), text, tip))
                        }
                        LogKind::Lost(n) | LogKind::Dropped(n) => {
                            let what = match row.kind {
                                LogKind::Lost(_) => "lost on the way (datagrams didn't arrive)",
                                _ => "dropped by the agent (over its rate limit)",
                            };
                            let text = format!("{n} line{} {what}", if *n == 1 { "" } else { "s" });
                            base.text_color(theme.muted_foreground)
                                .child(div().flex_none().w(px(LOG_PRI_COL)))
                                .child(div().flex_none().w(px(LOG_SOURCE_COL)))
                                .child(div().flex_none().w(px(LOG_PID_COL)))
                                .child(clipped(("log-message", i), text.clone(), text))
                        }
                    }
                })
                .collect()
        })
        .track_scroll(&self.log_scroll)
        .flex_1();

        div()
            .id("logs-panel")
            .test_support()
            .flex()
            .flex_col()
            .size_full()
            .border_t_1()
            .border_color(border)
            .child(toolbar)
            .child(header)
            .child(
                div()
                    .id("logs-list")
                    .test_support()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    // Scrolling up to read stops following new lines.
                    .on_scroll(cx.listener(|this, ev: &ScrollEvent, _, cx| {
                        if ev.delta.pixel_delta(px(ROW_HEIGHT)).y > px(0.) && this.log_follow {
                            this.log_follow = false;
                            cx.notify();
                        }
                    }))
                    .children(empty_note.map(|note| {
                        div()
                            .id("logs-empty")
                            .test_support()
                            .p_4()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .aria_description(note)
                            .child(note)
                    }))
                    .child(list),
            )
    }

    /// Sort by `key`, or flip the direction if already sorted by it.
    fn sort_by(&mut self, key: SortKey, cx: &mut Context<Self>) {
        // Asked for a new order: show it now.
        self.held = None;
        self.sort = if self.sort.0 == key {
            (key, !self.sort.1)
        } else {
            // Numbers sort high-to-low first, text A-to-Z.
            (
                key,
                matches!(
                    key,
                    SortKey::Cpu | SortKey::Virt | SortKey::Res | SortKey::Shr | SortKey::Threads
                ),
            )
        };
        cx.notify();
    }

    fn show(&mut self, view: View, cx: &mut Context<Self>) {
        let available = match view {
            View::Live => self.live_enabled,
            View::Replay => self.replay.is_some(),
        };
        if available {
            self.view = view;
            self.ensure_selection();
            cx.notify();
        }
    }

    fn step_host(&mut self, forward: bool, cx: &mut Context<Self>) {
        let ids = self.host_order();
        if ids.is_empty() {
            return;
        }
        let pos = self.selected.and_then(|s| ids.iter().position(|&i| i == s));
        let next = match (pos, forward) {
            (None, _) => 0,
            (Some(p), true) => (p + 1) % ids.len(),
            (Some(p), false) => (p + ids.len() - 1) % ids.len(),
        };
        self.selected = Some(ids[next]);
        cx.notify();
    }

    /// Seek the recording on screen to `at(status)`, kept within it.
    fn seek_to(&self, at: impl FnOnce(&ReplayStatus) -> u64) {
        if self.view != View::Replay {
            return;
        }
        if let Some(st) = self.status() {
            self.control(Control::Seek(at(&st).clamp(st.start_ns, st.end_ns)));
        }
    }

    fn seek_by(&self, delta_s: i64) {
        let delta = delta_s.unsigned_abs() * 1_000_000_000;
        self.seek_to(|st| {
            if delta_s < 0 {
                st.position_ns.saturating_sub(delta)
            } else {
                st.position_ns.saturating_add(delta)
            }
        });
    }

    fn change_speed(&self, faster: bool) {
        // Like pausing and seeking: only for the recording on screen.
        if self.view != View::Replay {
            return;
        }
        let Some(st) = self.status() else {
            return;
        };
        let i = SPEEDS
            .iter()
            .position(|&s| s >= st.speed - f64::EPSILON)
            .unwrap_or(SPEEDS.len() - 1);
        let i = if faster {
            (i + 1).min(SPEEDS.len() - 1)
        } else {
            i.saturating_sub(1)
        };
        self.control(Control::SetSpeed(SPEEDS[i]));
    }

    /// What each action can do in the view on screen, with the data there.
    fn compute_available(&self) -> actions::Available {
        let mut can = actions::Available::default();
        for always in [
            TypeId::of::<Quit>(),
            TypeId::of::<OpenRecording>(),
            TypeId::of::<ToggleShortcuts>(),
            TypeId::of::<Dismiss>(),
            TypeId::of::<About>(),
            TypeId::of::<ThemeSystem>(),
            TypeId::of::<ThemeLight>(),
            TypeId::of::<ThemeDark>(),
        ] {
            can.set_type(always, true);
        }
        {
            use crate::config::ThemePref;
            can.check::<ThemeSystem>(self.theme == ThemePref::System);
            can.check::<ThemeLight>(self.theme == ThemePref::Light);
            can.check::<ThemeDark>(self.theme == ThemePref::Dark);
        }
        // The view toggles say whether they're on, as their buttons do:
        // checked means shown.
        can.check::<ToggleTree>(self.tree);
        can.check::<ToggleKernelThreads>(!self.hide_kernel);
        can.check::<ToggleThreads>(self.show_threads);
        can.set::<ShowLive>(self.live_enabled);
        can.set::<ShowRecording>(self.replay.is_some());
        let several_hosts = self.hosts().len() > 1;
        can.set::<NextHost>(several_hosts);
        can.set::<PreviousHost>(several_hosts);

        let host = self.current_host();
        let procs = host.is_some_and(|h| !h.snapshot.procs.is_empty());
        can.set::<FocusFilter>(procs);
        can.set::<ToggleTree>(procs);
        can.set::<ToggleKernelThreads>(procs);
        // Only agents run with --threads send them; turning them off again
        // is always possible.
        can.set::<ToggleThreads>(
            self.show_threads || (procs && host.is_some_and(HostModel::sends_threads)),
        );
        can.set::<CollapseAll>(procs && self.tree);
        let collapsed = self
            .selected
            .and_then(|h| self.collapsed.get(&(self.view, h)))
            .is_some_and(|c| !c.is_empty());
        can.set::<ExpandAll>(procs && self.tree && collapsed);
        for sort in [
            TypeId::of::<SortByCpu>(),
            TypeId::of::<SortByMemory>(),
            TypeId::of::<SortByVirt>(),
            TypeId::of::<SortByShr>(),
            TypeId::of::<SortByPid>(),
            TypeId::of::<SortByUser>(),
            TypeId::of::<SortByCommand>(),
            TypeId::of::<CursorUp>(),
            TypeId::of::<CursorDown>(),
            TypeId::of::<CursorPageUp>(),
            TypeId::of::<CursorPageDown>(),
        ] {
            can.set_type(sort, procs);
        }
        can.set::<ToggleGraph>(procs && self.cursor.is_some());
        // Back from a tab is always possible; to it, once there's something.
        can.set::<ToggleDetails>(procs || self.panel == Panel::Details);
        can.set::<ToggleLogs>(host.is_some_and(|h| h.logs.enabled()) || self.panel == Panel::Logs);

        let picked = self.selection().is_some_and(|s| !s.is_empty());
        for graph in [
            TypeId::of::<ClearGraph>(),
            TypeId::of::<ToggleGraphPanel>(),
            TypeId::of::<GraphCpu>(),
            TypeId::of::<GraphVirt>(),
            TypeId::of::<GraphRss>(),
            TypeId::of::<GraphShr>(),
            TypeId::of::<GraphMem>(),
            TypeId::of::<GraphThreads>(),
            TypeId::of::<CycleGraphWindow>(),
        ] {
            can.set_type(graph, picked);
        }

        // Playback: only for the recording on screen.
        let status = (self.view == View::Replay).then(|| self.status()).flatten();
        for play in [
            TypeId::of::<TogglePause>(),
            TypeId::of::<SeekBackward>(),
            TypeId::of::<SeekForward>(),
            TypeId::of::<SeekBackwardLong>(),
            TypeId::of::<SeekForwardLong>(),
            TypeId::of::<SeekStart>(),
            TypeId::of::<SeekEnd>(),
        ] {
            can.set_type(play, status.is_some());
        }
        let speed = status.map(|st| st.speed);
        can.set::<Faster>(speed.is_some_and(|v| v < SPEEDS[SPEEDS.len() - 1] - f64::EPSILON));
        can.set::<Slower>(speed.is_some_and(|v| v > SPEEDS[0] + f64::EPSILON));
        can
    }

    /// Use `theme` from now on, and save it if there's a config file.
    fn set_theme(
        &mut self,
        theme: crate::config::ThemePref,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.theme = theme;
        apply_theme(theme, window, cx);
        cx.notify();
        let Some(path) = self.config_path.clone() else {
            return;
        };
        let saved = cx.background_spawn(async move {
            crate::config::save_theme(&path, theme).map_err(|e| (path, e))
        });
        cx.spawn(async move |this, cx| {
            if let Err((path, e)) = saved.await {
                tracing::error!(path = %path.display(), error = %e, "saving the theme failed");
                let _ = this.update(cx, |this, cx| {
                    this.error = Some(format!(
                        "Couldn't save the theme to {}: {e}",
                        path.display()
                    ));
                    cx.notify();
                });
            }
        })
        .detach();
    }

    /// Bring [`Self::available`] up to date, and the menus with it.
    fn refresh_available(&mut self, cx: &mut Context<Self>) {
        let now = self.compute_available();
        if now == self.available {
            return;
        }
        actions::set_menus(&now, cx);
        if let Some(bar) = &self.menu_bar {
            bar.update(cx, |bar, cx| bar.reload(cx));
        }
        self.available = now;
    }

    /// Hook the actions that are [`Self::available`] up to the root element.
    fn actions(&self, root: Div, cx: &mut Context<Self>) -> Div {
        let can = &self.available;
        root.on_available(can, cx.listener(Self::on_open_recording))
            .on_available(
                can,
                cx.listener(|this, _: &ShowLive, _, cx| this.show(View::Live, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ShowRecording, _, cx| this.show(View::Replay, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &NextHost, _, cx| this.step_host(true, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &PreviousHost, _, cx| this.step_host(false, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &FocusFilter, window, cx| {
                    this.filter.update(cx, |f, cx| f.focus(window, cx));
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &Dismiss, window, cx| {
                    // A dialog that doesn't take the keyboard (About) leaves
                    // Esc with the app: close it first.
                    if window.has_active_dialog(cx) {
                        window.close_dialog(cx);
                        return;
                    }
                    // In a filter box: clear it, or once empty, leave it.
                    let typing_in = [this.filter.clone(), this.log_filter.clone()]
                        .into_iter()
                        .find(|f| f.focus_handle(cx).is_focused(window));
                    if this.show_shortcuts {
                        this.show_shortcuts = false;
                    } else if let Some(input) = typing_in {
                        if input.read(cx).value().is_empty() {
                            this.focus.focus(window, cx);
                        } else {
                            input.update(cx, |f, cx| f.set_value("", window, cx));
                        }
                    } else if this.error.is_some() {
                        this.error = None;
                    } else {
                        this.filter.update(cx, |f, cx| f.set_value("", window, cx));
                    }
                    cx.notify();
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleShortcuts, _, cx| {
                    this.show_shortcuts = !this.show_shortcuts;
                    cx.notify();
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleKernelThreads, _, cx| this.toggle_kernel_threads(cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleThreads, _, cx| this.toggle_threads(cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleTree, _, cx| this.toggle_tree(cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ExpandAll, _, cx| this.expand_all(cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &CollapseAll, _, cx| this.collapse_all(cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SortByCpu, _, cx| this.sort_by(SortKey::Cpu, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SortByMemory, _, cx| this.sort_by(SortKey::Res, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SortByVirt, _, cx| this.sort_by(SortKey::Virt, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SortByShr, _, cx| this.sort_by(SortKey::Shr, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SortByPid, _, cx| this.sort_by(SortKey::Pid, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SortByUser, _, cx| this.sort_by(SortKey::User, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SortByCommand, _, cx| this.sort_by(SortKey::Command, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &CursorUp, _, cx| this.move_cursor(-1, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &CursorDown, _, cx| this.move_cursor(1, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &CursorPageUp, _, cx| {
                    this.move_cursor(-actions::PAGE_ROWS, cx)
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &CursorPageDown, _, cx| {
                    this.move_cursor(actions::PAGE_ROWS, cx)
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleGraph, _, cx| this.toggle_cursor(cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ClearGraph, _, cx| this.clear_graph(cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &About, window, cx| this.open_about(window, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ThemeSystem, window, cx| {
                    this.set_theme(crate::config::ThemePref::System, window, cx)
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ThemeLight, window, cx| {
                    this.set_theme(crate::config::ThemePref::Light, window, cx)
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ThemeDark, window, cx| {
                    this.set_theme(crate::config::ThemePref::Dark, window, cx)
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleLogs, _, cx| {
                    this.panel = if this.panel == Panel::Logs {
                        Panel::Graph
                    } else {
                        Panel::Logs
                    };
                    cx.notify();
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleDetails, _, cx| {
                    this.panel = if this.panel == Panel::Details {
                        Panel::Graph
                    } else {
                        Panel::Details
                    };
                    cx.notify();
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &ToggleGraphPanel, _, cx| {
                    this.graph_visible = !this.graph_visible;
                    cx.notify();
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &GraphCpu, _, cx| this.set_metric(Metric::Cpu, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &GraphRss, _, cx| this.set_metric(Metric::Rss, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &GraphVirt, _, cx| this.set_metric(Metric::Virt, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &GraphShr, _, cx| this.set_metric(Metric::Shr, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &GraphMem, _, cx| this.set_metric(Metric::MemPct, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &GraphThreads, _, cx| this.set_metric(Metric::Threads, cx)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &CycleGraphWindow, _, cx| {
                    let i = graph::WINDOWS_S
                        .iter()
                        .position(|&w| w == this.graph_window_s)
                        .map_or(0, |i| (i + 1) % graph::WINDOWS_S.len());
                    this.graph_window_s = graph::WINDOWS_S[i];
                    cx.notify();
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &TogglePause, _, _| {
                    if this.view == View::Replay {
                        this.control(Control::TogglePause);
                    }
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &Faster, _, _| this.change_speed(true)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &Slower, _, _| this.change_speed(false)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SeekBackward, _, _| {
                    this.seek_by(-(actions::SEEK_SHORT_S as i64))
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SeekForward, _, _| {
                    this.seek_by(actions::SEEK_SHORT_S as i64)
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SeekBackwardLong, _, _| {
                    this.seek_by(-(actions::SEEK_LONG_S as i64))
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SeekForwardLong, _, _| {
                    this.seek_by(actions::SEEK_LONG_S as i64)
                }),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SeekStart, _, _| this.seek_to(|st| st.start_ns)),
            )
            .on_available(
                can,
                cx.listener(|this, _: &SeekEnd, _, _| this.seek_to(|st| st.end_ns)),
            )
    }

    /// Overlay listing every shortcut, grouped as in [`actions::SHORTCUTS`],
    /// then what the mouse does ([`actions::MOUSE`]).
    fn render_shortcuts(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut groups: Vec<(&str, Vec<(String, &str)>)> = Vec::new();
        // The keys in effect, settings included; an action left without
        // any isn't listed.
        for b in cx.global::<crate::keymap::Keymap>().bindings() {
            if b.keys.is_empty() {
                continue;
            }
            let s = b.shortcut;
            let keys = b
                .keys
                .iter()
                .map(|k| actions::display_key(k))
                .collect::<Vec<_>>()
                .join("  ");
            match groups.last_mut() {
                Some((g, list)) if *g == s.group => list.push((keys, s.description)),
                _ => groups.push((s.group, vec![(keys, s.description)])),
            }
        }
        groups.push((
            "Mouse",
            actions::MOUSE
                .iter()
                .map(|&(what, does)| (what.to_string(), does))
                .collect(),
        ));
        let mut columns = div()
            .id("shortcuts-columns")
            .test_support()
            .flex()
            .flex_wrap()
            .gap_x_8()
            .gap_y_6();
        for (k, (group, list)) in groups.into_iter().enumerate() {
            let mut col = div()
                .id(("shortcuts-group", k))
                .test_support()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::SEMIBOLD)
                        .pb_1()
                        .child(group),
                );
            for (keys, description) in list {
                col = col.child(
                    div()
                        .flex()
                        .gap_3()
                        .text_xs()
                        .child(
                            // The UI font: the monospace one drew ← → ↑ ↓ tiny.
                            div()
                                .w(px(110.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(theme.primary)
                                .child(keys),
                        )
                        .child(description),
                );
            }
            columns = columns.child(col);
        }
        div()
            .id("shortcuts-overlay")
            .test_support()
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            .bg(theme.background.opacity(0.6))
            .on_click(cx.listener(|this, _, _, cx| {
                this.show_shortcuts = false;
                cx.notify();
            }))
            .child(
                div()
                    // Within the window: the columns wrap to its width, and
                    // a short window scrolls them.
                    .id("shortcuts-panel")
                    .max_w(relative(0.95))
                    .max_h(relative(0.95))
                    .overflow_y_scroll()
                    .p_6()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.popover)
                    .shadow_lg()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(div().text_lg().child("Keyboard shortcuts"))
                    .child(columns)
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child("Single-key shortcuts are off while the filter has focus. Esc or click to close."),
                    ),
            )
    }

    fn toggle_tree(&mut self, cx: &mut Context<Self>) {
        self.held = None;
        self.tree = !self.tree;
        cx.notify();
    }

    fn toggle_kernel_threads(&mut self, cx: &mut Context<Self>) {
        self.hide_kernel = !self.hide_kernel;
        cx.notify();
    }

    fn toggle_threads(&mut self, cx: &mut Context<Self>) {
        self.show_threads = !self.show_threads;
        cx.notify();
    }

    /// Collapse every process that has children in the selected host.
    fn collapse_all(&mut self, cx: &mut Context<Self>) {
        cx.notify();
        let Some(host) = self.current_host() else {
            return;
        };
        let parents: HashSet<u32> = host.snapshot.procs.iter().map(|p| p.ppid).collect();
        let all = host
            .snapshot
            .procs
            .iter()
            .filter(|p| parents.contains(&p.key.pid))
            .map(|p| p.key)
            .collect();
        self.collapsed.insert((self.view, host.host_id), all);
    }

    /// Expand every process in the selected host.
    fn expand_all(&mut self, cx: &mut Context<Self>) {
        cx.notify();
        if let Some(host) = self.selected {
            self.collapsed.remove(&(self.view, host));
        }
    }

    /// Collapse or expand `key` in the selected host's tree.
    fn toggle_collapsed(&mut self, key: ProcKey) {
        let Some(host) = self.selected else {
            return;
        };
        let set = self.collapsed.entry((self.view, host)).or_default();
        if !set.remove(&key) {
            set.insert(key);
        }
    }

    /// Red ticks under the timeline where the selected host logged errors.
    /// Each says when, and a click goes there with the logs open.
    fn render_log_marks(
        &self,
        st: &ReplayStatus,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        // One tick per this fraction of the timeline at most.
        const BUCKETS: f64 = 500.;
        let theme = cx.theme().clone();
        let span = st.end_ns.saturating_sub(st.start_ns).max(1) as f64;
        // Each tick's position and its first error's time (marks are sorted).
        let mut ticks: Vec<(u64, u64)> = self
            .replay
            .iter()
            .flat_map(|s| &s.log_marks)
            .filter(|m| Some(m.host_id) == self.selected)
            .map(|m| {
                let bucket = (m.received_ns.saturating_sub(st.start_ns)) as f64 / span * BUCKETS;
                (bucket as u64, m.received_ns)
            })
            .collect();
        ticks.dedup_by_key(|(bucket, _)| *bucket);
        let mut strip = div()
            .id("log-marks")
            .test_support()
            .relative()
            .h(px(8.))
            .mx(px(8.));
        for (k, (bucket, at)) in ticks.into_iter().enumerate() {
            let tip = format!("Error logged at {}: click to go there", format::time(at));
            strip = strip.child(
                div()
                    .id(("log-mark", k))
                    .test_support()
                    .absolute()
                    .top_0()
                    .left(relative((bucket as f64 / BUCKETS).min(1.0) as f32))
                    .w(px(4.))
                    .h_full()
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(theme.danger)
                    .aria_description(tip.clone())
                    .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.control(Control::Seek(at));
                        this.panel = Panel::Logs;
                        cx.notify();
                    })),
            );
        }
        strip
    }

    fn render_timeline(&self, cx: &mut Context<Self>) -> Option<impl IntoElement + use<>> {
        if self.view != View::Replay {
            return None;
        }
        let st = self.status()?;
        let theme = cx.theme().clone();
        let mono = theme.mono_font_family.clone();
        let mut speeds = div().flex().gap_1();
        for (i, &speed) in SPEEDS.iter().enumerate() {
            speeds = speeds.child(
                Button::new(("speed", i))
                    .label(format!("{speed}×"))
                    .small()
                    .chosen((st.speed - speed).abs() < f64::EPSILON)
                    .on_click(
                        cx.listener(move |this, _, _, _| this.control(Control::SetSpeed(speed))),
                    ),
            );
        }
        let (play_label, play_icon) = if st.finished && st.paused {
            ("Replay", IconName::RotateCcw)
        } else if st.paused {
            ("Play", IconName::Play)
        } else {
            ("Pause", IconName::Pause)
        };
        Some(
            div()
                .flex()
                .items_center()
                .gap_3()
                .px_3()
                .py_2()
                .border_t_1()
                .border_color(theme.border)
                .child(
                    // Icon only, so the bar doesn't shift as it changes.
                    Button::new("play")
                        .icon(icon(play_icon))
                        .tooltip(format!("{play_label} (Space)"))
                        .accessibility_label(play_label)
                        .small()
                        .primary()
                        .on_click(cx.listener(|this, _, _, _| this.control(Control::TogglePause))),
                )
                .child(speeds)
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format::datetime(st.start_ns)),
                )
                .child(
                    div()
                        .flex_1()
                        .flex()
                        .flex_col()
                        .child(Slider::new(&self.timeline))
                        .child(self.render_log_marks(&st, cx)),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format::datetime(st.end_ns)),
                )
                .child(div().text_sm().font_family(mono.clone()).child(format!(
                    "{} {}",
                    format::datetime(st.position_ns),
                    format::utc_offset(st.position_ns)
                ))),
        )
    }
}

fn apply(hosts: &mut BTreeMap<u64, HostModel>, event: Event) {
    let id = event.host_id();
    hosts
        .entry(id)
        .or_insert_with(|| HostModel::new(id))
        .apply(event);
}

/// One row of the process table: a process, or one of its threads.
struct Line {
    /// The process (for a thread line, the thread's process), shared
    /// between a process's line and its threads'.
    row: Rc<ProcRow>,
    tree: Option<TreeLine>,
    thread: Option<ThreadRow>,
    /// Shown only because something under it matched the filter.
    context: bool,
}

impl Line {
    fn process(row: Rc<ProcRow>, tree: Option<TreeLine>, context: bool) -> Self {
        Self {
            row,
            tree,
            thread: None,
            context,
        }
    }

    fn thread(row: Rc<ProcRow>, thread: ThreadRow, tree: Option<TreeLine>) -> Self {
        Self {
            row,
            tree,
            thread: Some(thread),
            context: false,
        }
    }

    /// The process's key, or for a thread line the thread's.
    fn key(&self) -> ProcKey {
        self.thread.as_ref().map_or(self.row.key, |t| t.key)
    }

    /// What picking this row graphs: the thread, a collapsed tree node's
    /// whole subtree, or the process.
    fn target(&self) -> SeriesTarget {
        if let Some(t) = &self.thread {
            return SeriesTarget::Thread(t.key);
        }
        match &self.tree {
            Some(t) if t.collapsed && t.has_children => SeriesTarget::Subtree(self.row.key),
            _ => SeriesTarget::Process(self.row.key),
        }
    }
}

/// Tree guides drawn as 1 px lines, one column three characters wide per
/// [`Guide`]. A column's vertical runs down the middle of the ▾/▸ of the
/// ancestor it belongs to, so a parent's line drops from under its arrow.
/// Each piece reaches the row's top and bottom edges, so they join into
/// continuous lines from row to row (glyphs are shorter than the row and
/// left gaps).
fn tree_guides(guides: &[Guide], char_w: Pixels, color: Hsla) -> Div {
    // Whole pixels, so the lines stay sharp.
    let col_w = (char_w * 3.).round();
    let x = px((TWISTY_W / 2.).floor());
    let line = |id: (&'static str, usize)| div().id(id).test_support().absolute().bg(color);
    let mut d = div().flex_none().h_full().flex();
    for (c, &g) in guides.iter().enumerate() {
        let col = div().relative().flex_none().w(col_w).h_full();
        let vertical = |to_middle: bool| {
            line(("guide-v", c))
                .left(x)
                .w(px(1.))
                .top_0()
                .when(to_middle, |l| l.h(relative(0.5)))
                .when(!to_middle, |l| l.bottom_0())
        };
        let horizontal = || {
            // On to the ▾/▸ (or, for a leaf, see `command_cell`).
            line(("guide-h", c))
                .left(x)
                .right_0()
                .top(relative(0.5))
                .h(px(1.))
        };
        d = d.child(match g {
            Guide::Blank => col,
            Guide::Pass => col.child(vertical(false)),
            Guide::Tee => col.child(vertical(false)).child(horizontal()),
            Guide::Last => col.child(vertical(true)).child(horizontal()),
        });
    }
    d
}

/// The COMMAND cell: in tree mode, guide lines, a clickable expand/collapse
/// marker, and a summary of what a collapsed subtree hides.
fn command_cell(
    line: &Line,
    i: usize,
    // The next line is this one's child: its guide line starts here.
    opens: bool,
    this: &WeakEntity<AppState>,
    char_w: Pixels,
    theme: &gpui_kit::component::Theme,
) -> impl IntoElement + use<> {
    let cell = div()
        // The row's full height, for the tree guides to reach its edges.
        .h_full()
        .flex_1()
        .min_w_0()
        .flex()
        .items_center()
        .overflow_hidden()
        .whitespace_nowrap();
    let (label, tip) = match &line.thread {
        Some(t) => (
            format!("↳ {}", t.comm),
            format!(
                "thread {} \"{}\" of {} {}",
                t.key.pid,
                t.comm,
                line.row.key.pid,
                command(&line.row)
            ),
        ),
        None => (command(&line.row), command(&line.row)),
    };
    // The program's name in full colour, its directory and arguments
    // muted: rows of long paths and flags read alike otherwise.
    let text = if line.thread.is_none() {
        let (dir, _, args) = command_parts(&label);
        let muted = HighlightStyle {
            color: Some(theme.muted_foreground),
            ..Default::default()
        };
        clipped_styled(("cmd", i), label, [(dir, muted), (args, muted)], tip).into_any_element()
    } else {
        clipped(("cmd", i), label, tip).into_any_element()
    };
    let Some(t) = &line.tree else {
        return cell.child(text);
    };
    let twisty = if t.has_children {
        let key = line.row.key;
        let this = this.clone();
        div()
            .id(("twisty", i))
            .test_support()
            .flex_none()
            .w(px(TWISTY_W))
            .h_full()
            .flex()
            .items_center()
            .cursor_pointer()
            .text_color(theme.foreground)
            .aria_description(if t.collapsed { "expand" } else { "collapse" })
            .child(icon(if t.collapsed {
                IconName::ChevronRight
            } else {
                IconName::ChevronDown
            }))
            .on_click(move |_, _, cx| {
                let _ = this.update(cx, |this, cx| {
                    this.toggle_collapsed(key);
                    cx.notify();
                });
            })
    } else {
        div()
            .id(("twisty", i))
            .test_support()
            .flex_none()
            .w(px(TWISTY_W))
            .h_full()
            // A leaf has no arrow: its connector runs on to the name.
            .when(!t.guides.is_empty(), |d| {
                d.child(
                    div()
                        .id("guide-leaf")
                        .test_support()
                        .absolute()
                        .left_0()
                        .right(px(3.))
                        .top(relative(0.5))
                        .h(px(1.))
                        .bg(theme.muted_foreground),
                )
            })
    };
    // The line to this line's children starts under its arrow.
    let twisty = twisty.relative().when(opens, |d| {
        d.child(
            div()
                .id("guide-stub")
                .test_support()
                .absolute()
                .left(px((TWISTY_W / 2.).floor()))
                .w(px(1.))
                .top(px(TWISTY_STUB_TOP))
                .bottom_0()
                .bg(theme.muted_foreground),
        )
    });
    cell.child(tree_guides(&t.guides, char_w, theme.muted_foreground))
        .child(twisty)
        .child(text)
        .when(t.collapsed, |d| {
            d.child(
                div()
                    .flex_none()
                    .ml_2()
                    .text_color(theme.muted_foreground)
                    .child(format!(
                        "+{} · {:.1}% CPU · RES {} · VIRT {}",
                        t.hidden,
                        t.hidden_cpu_pct,
                        format::bytes(t.hidden_rss_kib as f64 * 1024.0),
                        format::bytes(t.hidden_virt_kib as f64 * 1024.0)
                    )),
            )
        })
}

/// How many of `cores` per-core bars to put in a row when `fit` fit: as
/// few rows as fit allows, filled evenly.
fn cores_per_row(cores: usize, fit: usize) -> usize {
    let fit = fit.max(1);
    let rows = cores.div_ceil(fit).max(1);
    cores.div_ceil(rows).max(1)
}

/// A command line's directory, program name and arguments, as byte ranges:
/// `/usr/bin/sshd -D` → `/usr/bin/`, `sshd`, ` -D`. A `[name]` without a
/// command line (a kernel thread's) is all name, slashes and all.
fn command_parts(cmd: &str) -> (Range<usize>, Range<usize>, Range<usize>) {
    if cmd.starts_with('[') {
        return (0..0, 0..cmd.len(), cmd.len()..cmd.len());
    }
    let program_end = cmd.find(' ').unwrap_or(cmd.len());
    let name_start = cmd[..program_end].rfind('/').map_or(0, |i| i + 1);
    (
        0..name_start,
        name_start..program_end,
        program_end..cmd.len(),
    )
}

/// [`clipped`] with parts of the text styled.
fn clipped_styled(
    id: impl Into<ElementId>,
    text: String,
    styles: impl IntoIterator<Item = (Range<usize>, HighlightStyle)>,
    tip: String,
) -> impl IntoElement {
    let styles: Vec<_> = styles.into_iter().filter(|(r, _)| !r.is_empty()).collect();
    div()
        .id(id)
        .test_support()
        .flex_1()
        .min_w_0()
        .truncate()
        .child(StyledText::new(text).with_highlights(styles))
        .aria_description(tip.clone())
        .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
}

/// Text that ends with "…" when it doesn't fit, with the full text (or
/// `tip`) on hover and as its accessible description.
fn clipped(id: impl Into<ElementId>, text: String, tip: String) -> impl IntoElement {
    div()
        .id(id)
        .test_support()
        .flex_1()
        .min_w_0()
        .truncate()
        .child(text)
        .aria_description(tip.clone())
        .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
}

/// The USER column's text: the name, or the uid while it isn't known.
fn user_name(p: &ProcRow) -> String {
    p.user
        .clone()
        .or_else(|| p.uid.map(|u| u.to_string()))
        .unwrap_or_else(|| "-".into())
}

/// Width of one character of the table's monospace font at its text size.
fn mono_char_width(window: &Window, cx: &App) -> Pixels {
    let theme = cx.theme();
    let size = window.rem_size() * 0.75; // text_xs
    let ts = window.text_system();
    let id = ts.resolve_font(&font(theme.mono_font_family.clone()));
    ts.advance(id, size, 'm')
        .map(|s| s.width)
        .unwrap_or(size * 0.6)
}

/// Widths of the log table's fixed columns.
const LOG_TIME_COL: f32 = 64.;
/// The time column when it shows the date too.
const LOG_DAY_TIME_COL: f32 = 104.;
const LOG_PRI_COL: f32 = 68.;
const LOG_SOURCE_COL: f32 = 160.;
const LOG_PID_COL: f32 = 56.;

/// A syslog priority's label and colour: errors and worse red, warnings
/// orange, notices plain, info and debug muted.
/// A log line's priority as its PRI cell: the label in its colour, after
/// an icon for warnings and worse, so they stand out in a long list.
fn priority_cell(p: u8, theme: &gpui_kit::component::Theme) -> Div {
    let (label, color) = priority_style(p, theme);
    let mark = match p {
        0..=3 => Some(IconName::CircleAlert),
        4 => Some(IconName::TriangleAlert),
        _ => None,
    };
    div()
        .flex_none()
        .w(px(LOG_PRI_COL))
        .flex()
        .items_center()
        .gap_1()
        .text_color(color)
        .children(mark.map(|m| icon(m).text_color(color)))
        .child(label)
}

fn priority_style(p: u8, theme: &gpui_kit::component::Theme) -> (&'static str, Hsla) {
    const LABELS: [&str; 8] = [
        "EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG",
    ];
    let color = match p {
        0..=3 => theme.danger,
        4 => theme.warning,
        5 => theme.foreground,
        _ => theme.muted_foreground,
    };
    (LABELS[p.min(7) as usize], color)
}

/// Memory in use (all but what's available) as a share of the total.
fn mem_pct(mem: &sysmon_proto::MemInfo) -> f32 {
    // From the network: available can be bogus (above total).
    let used = mem.total.saturating_sub(mem.available);
    if mem.total > 0 {
        used as f32 / mem.total as f32 * 100.0
    } else {
        0.0
    }
}

/// A size in KiB as table text; "–" when the agent didn't report it.
fn size_cell(kib: Option<u64>) -> String {
    kib.map_or_else(|| "–".into(), |k| format::bytes(k as f64 * 1024.0))
}

/// A process's name for people: the kernel's name (`comm`), unless that's
/// a cut-off start of the program's own name, as it is past 15 characters
/// (`xdg-document-po` for `xdg-document-portal`). A process that renamed
/// itself (`Isolated Web Co` for `zen-bin`) keeps the name it chose.
fn proc_name(p: &ProcRow) -> String {
    name_of(&p.comm, p.cmdline.as_deref())
}

/// [`proc_name`] from the kernel's name and the command line.
fn name_of(comm: &str, cmdline: Option<&str>) -> String {
    let program = cmdline.and_then(|c| {
        let (_, name, _) = command_parts(c);
        c.get(name).filter(|n| !n.is_empty())
    });
    match program {
        Some(program) if program.len() > comm.len() && program.starts_with(comm) => {
            program.to_string()
        }
        _ => comm.to_string(),
    }
}

fn command(p: &ProcRow) -> String {
    p.cmdline
        .as_deref()
        .filter(|c| !c.is_empty())
        .map_or_else(|| format!("[{}]", p.comm), printable)
}

/// `text` without terminal escape sequences (colours in an fzf or ls
/// argument), which would show as boxes and noise, and with other control
/// characters as spaces.
fn printable(text: &str) -> String {
    if !text.chars().any(char::is_control) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(if c.is_control() { ' ' } else { c });
            continue;
        }
        match chars.next() {
            // CSI: parameters up to a final byte in @..=~.
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: up to BEL or ESC \.
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' {
                        chars.next_if_eq(&'\\');
                        break;
                    }
                }
            }
            // Any other escape is two characters long.
            _ => {}
        }
    }
    out
}

/// Light or dark: as `theme` says, or as the system is.
fn apply_theme(theme: crate::config::ThemePref, window: &mut Window, cx: &mut App) {
    use crate::config::ThemePref;
    use gpui_kit::component::{Theme, ThemeMode};
    match theme {
        ThemePref::System => Theme::sync_system_appearance(Some(window), cx),
        ThemePref::Light => Theme::change(ThemeMode::Light, Some(window), cx),
        ThemePref::Dark => Theme::change(ThemeMode::Dark, Some(window), cx),
    }
}

impl Render for AppState {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.refresh_available(cx);
        self.refresh_graph_names();
        self.refresh_details();
        let panel_shown = self.panel_shown();
        // Keep the panel within the window if the window shrank.
        let viewport = window.viewport_size().height;
        let max_graph = (viewport - px(GRAPH_MIN_LIST)).max(px(GRAPH_MIN));
        if !self.graph_resized {
            self.graph_height = (viewport * GRAPH_SHARE).max(px(GRAPH_HEIGHT));
        }
        self.graph_height = self.graph_height.clamp(px(GRAPH_MIN), max_graph);
        let theme = cx.theme().clone();
        let toolbar = self.render_toolbar(cx);
        let sidebar = self
            .sidebar_part
            .clone()
            .cached(parts::PartView::style(parts::Part::Sidebar));
        let timeline = self.render_timeline(cx);

        let main = match self.current_host() {
            Some(host) => {
                let graph = panel_shown.then(|| match self.panel {
                    Panel::Logs => self.render_logs(host, cx).into_any_element(),
                    Panel::Details => self.render_details(host, cx).into_any_element(),
                    Panel::Graph => self.render_graph(host, cx).into_any_element(),
                });
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .children(self.render_rejected_banner(cx))
                    .children(self.render_stale_banner(host, cx))
                    .child(Self::render_header(
                        host,
                        window.viewport_size().width - px(SIDEBAR_W) - px(16.),
                        cx,
                    ))
                    .child(
                        div()
                            .id("procs-panel")
                            .test_support()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_h_0()
                            .child(
                                self.procs_table
                                    .clone()
                                    .cached(parts::PartView::style(parts::Part::Table)),
                            ),
                    )
                    .when_some(graph, |d, graph| {
                        d.child(
                            // Divider: drag to resize the graph panel.
                            div()
                                .id("graph-resize")
                                .test_support()
                                .flex_none()
                                .h(px(5.))
                                .cursor_row_resize()
                                .border_t_1()
                                .border_color(theme.border)
                                .hover(|d| d.bg(theme.accent))
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, ev: &MouseDownEvent, _, cx| {
                                        this.graph_drag = Some((ev.position.y, this.graph_height));
                                        this.graph_resized = true;
                                        cx.notify();
                                    }),
                                ),
                        )
                        .child(div().flex_none().h(self.graph_height).child(graph))
                    })
            }
            None => div()
                .flex()
                .flex_1()
                .items_center()
                .justify_center()
                .text_color(theme.muted_foreground)
                .child(match self.view {
                    View::Live => self.render_waiting(cx).into_any_element(),
                    View::Replay => "Loading recording…".into_any_element(),
                }),
        };

        let shortcuts = self.show_shortcuts.then(|| self.render_shortcuts(cx));
        let root = div()
            // Divider drags are tracked on the root so they continue when
            // the pointer leaves the divider.
            .on_mouse_move(cx.listener(move |this, ev: &MouseMoveEvent, _, cx| {
                if let Some((y0, h0)) = this.graph_drag {
                    this.graph_height = (h0 + (y0 - ev.position.y)).clamp(px(GRAPH_MIN), max_graph);
                    cx.notify();
                }
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _: &MouseUpEvent, _, cx| {
                    if this.graph_drag.take().is_some() {
                        cx.notify();
                    }
                }),
            )
            .key_context(actions::CONTEXT)
            .track_focus(&self.focus)
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground);
        self.actions(root, cx)
            .children(self.menu_bar.clone().map(|bar| {
                // AppMenuBar fills its parent (it's designed for a title
                // bar), so give it a fixed-height strip of its own; otherwise
                // the column stretches it and the menus drift down the window.
                div()
                    .id("menu-bar")
                    .test_support()
                    .flex_none()
                    .w_full()
                    .h(px(MENU_BAR_HEIGHT))
                    .px_1()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(bar)
            }))
            .child(toolbar)
            .child(div().flex().flex_1().min_h_0().child(sidebar).child(main))
            .children(timeline)
            .children(shortcuts)
    }
}

#[cfg(test)]
mod tests {
    // Explicit imports: the gpui glob would shadow `#[test]`.
    use super::{
        AppState, FORGET_AFTER_NS, MAX_LIVE_HOSTS, Panel, Selection, SortKey, Start, View, apply,
    };
    use gpui_kit::Modifiers;
    use sysmon_model::SeriesTarget;
    use sysmon_model::{Control, Feed, ReplayHandle, ReplayStatus};
    use sysmon_proto::ProcKey;

    fn picked(app: &AppState) -> Vec<SeriesTarget> {
        app.selection()
            .map(|s| s.iter().map(|p| p.target).collect())
            .unwrap_or_default()
    }

    fn key(pid: u32) -> ProcKey {
        ProcKey { pid, starttime: 0 }
    }

    /// A complete sample from `host_id`, with no processes or threads,
    /// received at 0 (tests override what they need).
    fn test_frame(
        host_id: u64,
        seq: u32,
        system: sysmon_proto::SystemSample,
    ) -> sysmon_proto::Frame {
        sysmon_proto::Frame {
            host_id,
            boot_id: 1,
            seq,
            system: Some(system),
            procs: vec![],
            threads: vec![],
            complete: true,
            received_ns: 0,
        }
    }

    /// A system sample taken at `ts_unix_ns`, otherwise empty.
    fn sampled_at(ts_unix_ns: u64) -> sysmon_proto::SystemSample {
        sysmon_proto::SystemSample {
            ts_unix_ns,
            ..Default::default()
        }
    }
    use crate::format;
    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{
        AnyWindowHandle, AppContext as _, Bounds, Entity, TestAppContext, WindowBounds,
        WindowOptions, point, px, size,
    };

    fn open(cx: &mut TestAppContext) -> (AnyWindowHandle, Entity<AppState>) {
        open_with(cx, |_| {})
    }

    /// [`open`], with `Start` changed by `tweak` first. Its settings'
    /// `[keys]` are bound as `main` binds them.
    fn open_with(
        cx: &mut TestAppContext,
        tweak: impl FnOnce(&mut Start),
    ) -> (AnyWindowHandle, Entity<AppState>) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: point(px(0.), px(0.)),
                    size: size(px(1200.), px(800.)),
                })),
                ..Default::default()
            };
            let mut start = Start {
                live: None,
                replay: None,
                recording_to: Some(std::env::temp_dir()),
                data_dir: std::env::temp_dir(),
                config: Default::default(),
                config_path: None,
            };
            tweak(&mut start);
            let (keymap, problems) = crate::keymap::Keymap::resolve(&start.config.keys);
            start.config.problems.extend(problems);
            crate::actions::init(cx, keymap);
            gpui_kit::open_window(options, cx, |window, cx| {
                cx.new(|cx| AppState::new(start, window, cx))
            })
            .expect("open test window")
        })
    }

    #[gpui_kit::test]
    fn keys_set_in_the_settings_replace_the_defaults(cx: &mut TestAppContext) {
        let (window, app) = open_with(cx, |s| {
            s.config.keys = vec![
                ("toggle_graph".into(), vec!["x".into()]),
                ("toggel_tree".into(), vec!["t".into()]),
            ];
        });
        add_host(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        // The typo is reported, once, where it shows.
        app.read_with(cx, |app, _| {
            let e = app.error.clone().unwrap_or_default();
            assert!(
                e.starts_with("Settings: [keys] toggel_tree: no such action"),
                "{e}"
            );
        });
        // Hints name the key in effect.
        step(cx, &|w, cx| {
            w.render_frame(cx);
            let pick = w.find(("pick", 0usize));
            assert_eq!(pick.description(), Some("Graph this process (x)"));
        });
        app.read_with(cx, |app, cx| {
            let host = app.current_host().unwrap();
            let status = app.status_line(host, &app.table_lines(host, cx), cx);
            assert!(status.contains("(or press x)"), "{status}");
        });
        step(cx, &|w, cx| {
            w.press("down", cx);
            w.press("g", cx);
        });
        app.read_with(cx, |app, _| {
            assert!(picked(app).is_empty(), "g does nothing now")
        });
        step(cx, &|w, cx| w.press("x", cx));
        app.read_with(cx, |app, _| {
            assert_eq!(picked(app).len(), 1, "x graphs the row")
        });
        // The shortcuts list says x.
        step(cx, &|w, cx| w.press("f1", cx));
        step(cx, &|w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("shortcuts-columns").is_some());
        });
        cx.update(|cx| {
            let keymap = cx.global::<crate::keymap::Keymap>();
            assert_eq!(
                keymap.label::<crate::actions::ToggleGraph>().as_deref(),
                Some("x")
            );
        });
    }

    #[gpui_kit::test]
    fn menu_bar_is_a_strip_at_the_top(cx: &mut TestAppContext) {
        for with_host in [false, true] {
            let (window, app) = open(cx);
            if with_host {
                add_host(&app, cx);
            }
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                let bar = window.find("menu-bar").bounds();
                assert_eq!(bar.origin.y, px(0.), "menu bar starts at the top");
                assert_eq!(bar.size.height, px(super::MENU_BAR_HEIGHT));
                assert_eq!(bar.size.width, px(1200.));
                let toolbar = window.find("toolbar").bounds();
                assert_eq!(toolbar.origin.y, bar.size.height, "toolbar follows it");
            })
            .unwrap();
        }
    }

    /// Whether the in-window menu's item `name` (in `menu`) is enabled.
    fn menu_enabled(cx: &mut TestAppContext, menu: &str, name: &str) -> bool {
        fn find(items: &[gpui_kit::OwnedMenuItem], name: &str) -> Option<bool> {
            items.iter().find_map(|i| match i {
                gpui_kit::OwnedMenuItem::Action {
                    name: n, disabled, ..
                } if n == name => Some(!disabled),
                gpui_kit::OwnedMenuItem::Submenu(m) => find(&m.items, name),
                _ => None,
            })
        }
        cx.update(|cx| {
            let menus = gpui_kit::component::GlobalState::global(cx).app_menus();
            let menu = menus.iter().find(|m| m.name == menu).expect("menu");
            find(&menu.items, name).expect("menu item")
        })
    }

    #[gpui_kit::test]
    fn view_toggles_are_checked_in_the_menu_when_on(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        let checked = |cx: &mut TestAppContext, name: &str| {
            cx.update(|cx| {
                let menus = gpui_kit::component::GlobalState::global(cx).app_menus();
                let menu = menus.iter().find(|m| m.name == "Processes").unwrap();
                menu.items.iter().find_map(|i| match i {
                    gpui_kit::OwnedMenuItem::Action {
                        name: n, checked, ..
                    } if n == name => Some(*checked),
                    _ => None,
                })
            })
            .expect("menu item")
        };
        let draw = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| w.render_frame(cx))
                .unwrap();
            cx.run_until_parked();
        };
        draw(cx);
        assert!(!checked(cx, "Kernel Threads"), "hidden at first");
        assert!(!checked(cx, "Tree View"));
        app.update(cx, |app, _| {
            app.hide_kernel = false;
            app.tree = true;
        });
        draw(cx);
        assert!(checked(cx, "Kernel Threads"), "checked means shown");
        assert!(checked(cx, "Tree View"));
    }

    #[gpui_kit::test]
    fn menus_grey_out_what_has_no_data(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        let draw = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| w.render_frame(cx))
                .unwrap();
            cx.run_until_parked();
        };
        draw(cx);
        // Nothing has arrived: only what needs no data.
        assert!(menu_enabled(cx, "File", "Open Recording…"));
        assert!(menu_enabled(cx, "File", "Quit"));
        assert!(!menu_enabled(cx, "View", "Live"), "not listening");
        assert!(!menu_enabled(cx, "View", "Recording"), "none open");
        assert!(!menu_enabled(cx, "View", "Next Host"));
        assert!(!menu_enabled(cx, "Processes", "Tree View"));
        assert!(!menu_enabled(cx, "Processes", "CPU"), "submenus too");
        assert!(!menu_enabled(cx, "Graph", "Clear Graph"));
        assert!(!menu_enabled(cx, "Playback", "Play / Pause"));

        add_host(&app, cx);
        draw(cx);
        assert!(menu_enabled(cx, "Processes", "Tree View"));
        assert!(menu_enabled(cx, "Processes", "CPU"));
        assert!(
            !menu_enabled(cx, "Processes", "Threads"),
            "agent sends none"
        );
        assert!(!menu_enabled(cx, "Processes", "Expand All"), "not a tree");
        assert!(!menu_enabled(cx, "View", "Next Host"), "only one");
        assert!(!menu_enabled(cx, "Graph", "%CPU"), "nothing graphed");
        assert!(!menu_enabled(cx, "Playback", "Play / Pause"), "live");

        cx.update_window(window, |_, w, cx| w.press("down", cx))
            .unwrap();
        cx.update_window(window, |_, w, cx| w.press("g", cx))
            .unwrap();
        draw(cx);
        assert!(menu_enabled(cx, "Graph", "%CPU"));
        assert!(menu_enabled(cx, "Graph", "Clear Graph"));
    }

    #[gpui_kit::test]
    fn shortcuts_change_view_state(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        // With no processes yet, the process keys do nothing.
        cx.update_window(window, |_, window, cx| {
            window.render_frame(cx);
            window.press("t", cx);
            assert!(!app.read(cx).tree, "nothing to show as a tree");
        })
        .unwrap();
        add_host(&app, cx);
        cx.update_window(window, |_, window, cx| {
            window.render_frame(cx);
            window.press("t", cx);
            assert!(app.read(cx).tree, "t toggles the tree");

            window.press("shift-m", cx);
            assert_eq!(app.read(cx).sort, (SortKey::Res, true));
            window.press("shift-m", cx);
            assert_eq!(
                app.read(cx).sort,
                (SortKey::Res, false),
                "again flips direction"
            );
            window.press("shift-n", cx);
            assert_eq!(app.read(cx).sort, (SortKey::Pid, false));

            window.press("f1", cx);
            assert!(app.read(cx).show_shortcuts);
            window.press("escape", cx);
            assert!(!app.read(cx).show_shortcuts, "escape closes the overlay");

            // No recording is open, so the Recording view isn't available.
            window.press("ctrl-2", cx);
            assert_eq!(app.read(cx).view, View::Live);
        })
        .unwrap();
    }

    /// Give the app one live host so the process table (and its filter) renders.
    fn add_host(app: &Entity<AppState>, cx: &mut TestAppContext) {
        add_frame(app, cx, 0);
    }

    /// Sample `seq` of the test host, `seq` seconds in, with CPU ticks growing.
    fn add_frame(app: &Entity<AppState>, cx: &mut TestAppContext, seq: u32) {
        add_frame_for(app, cx, 1, seq);
    }

    /// [`add_frame`] for host `host_id`: the same processes, so the same keys.
    fn add_frame_for(app: &Entity<AppState>, cx: &mut TestAppContext, host_id: u64, seq: u32) {
        app.update(cx, |app, cx| {
            // 1 ─┬─ 10 ── 11      10 also has threads 101 "worker-a" and 102 "io".
            //    └─ 20
            // 2 ─── 3            kthreadd and a kworker: kernel threads.
            let proc = |pid: u32, ppid: u32, comm: &str| sysmon_proto::ProcSample {
                pid,
                ppid,
                starttime: 0,
                state: b'S',
                utime: seq as u64 * pid as u64,
                stime: 0,
                rss_pages: pid as u64,
                threads: 1,
                comm: comm.into(),
                vsize_bytes: Some(1 << 30),
                shared_pages: Some(100),
                kernel_thread: None,
            };
            let frame = sysmon_proto::Frame {
                procs: vec![
                    proc(1, 0, "init"),
                    proc(10, 1, "bash"),
                    proc(11, 10, "vim"),
                    proc(20, 1, "sshd"),
                    sysmon_proto::ProcSample {
                        kernel_thread: Some(true),
                        ..proc(2, 0, "kthreadd")
                    },
                    sysmon_proto::ProcSample {
                        kernel_thread: Some(true),
                        ..proc(3, 2, "kworker/0:0")
                    },
                ],
                threads: [(101, "worker-a"), (102, "io")]
                    .into_iter()
                    .map(|(tid, comm)| sysmon_proto::ThreadSample {
                        tgid: 10,
                        tid,
                        starttime: 0,
                        state: b'S',
                        utime: seq as u64 * tid as u64,
                        stime: 0,
                        comm: comm.into(),
                    })
                    .collect(),
                ..test_frame(host_id, seq, sampled_at(1_000_000_000 * (1 + seq as u64)))
            };
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            app.ensure_selection();
            cx.notify();
        });
    }

    #[gpui_kit::test]
    fn a_slash_can_be_typed_into_the_filter(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        cx.update_window(window, |_, w, cx| {
            w.press("ctrl-f", cx);
            w.press("/", cx);
            w.press("u", cx);
        })
        .unwrap();
        cx.run_until_parked();
        // `/` also opens the filter, but typed in it, it's text.
        let v = app.read_with(cx, |a, cx| a.filter.read(cx).value().to_string());
        assert_eq!(v, "/u");
    }

    #[gpui_kit::test]
    fn single_key_shortcuts_are_off_while_typing_in_the_filter(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        // Each step is its own update so subscriptions (the filter's Enter
        // event) are delivered between steps, as they are for real input.
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };

        step(cx, &|window, cx| {
            window.press("ctrl-f", cx);
            window.press("t", cx);
            window.press("d", cx);
            window.input("bash", cx);
        });
        app.read_with(cx, |app, cx| {
            assert!(!app.tree, "t is typed into the filter, not a shortcut");
            assert_eq!(app.panel, Panel::Graph, "and so is d");
            assert_eq!(app.filter.read(cx).value().as_ref(), "tdbash");
        });

        // Enter returns focus to the app; single-key shortcuts work again.
        step(cx, &|window, cx| window.press("enter", cx));
        app.read_with(cx, |app, _| {
            assert_eq!(app.panel, Panel::Graph, "Enter in the filter only returns")
        });
        step(cx, &|window, cx| window.press("t", cx));
        app.read_with(cx, |app, _| assert!(app.tree));

        // Escape outside the filter clears it.
        step(cx, &|window, cx| window.press("escape", cx));
        app.read_with(cx, |app, cx| {
            assert_eq!(app.filter.read(cx).value().as_ref(), "")
        });

        // In the filter, as in most search boxes, Escape clears what was
        // typed, and once it's empty hands the keyboard back.
        step(cx, &|window, cx| {
            window.press("ctrl-f", cx);
            window.input("vim", cx);
        });
        step(cx, &|window, cx| window.press("escape", cx));
        app.read_with(cx, |app, cx| {
            assert_eq!(app.filter.read(cx).value().as_ref(), "", "cleared");
        });
        step(cx, &|window, cx| window.press("t", cx));
        app.read_with(cx, |app, cx| {
            assert_eq!(app.filter.read(cx).value().as_ref(), "t", "still typing");
        });
        step(cx, &|window, cx| window.press("escape", cx));
        step(cx, &|window, cx| window.press("escape", cx));
        step(cx, &|window, cx| window.press("t", cx));
        app.read_with(cx, |app, cx| {
            assert_eq!(app.filter.read(cx).value().as_ref(), "");
            assert!(!app.tree, "t is a shortcut again: tree toggled back off");
        });
    }

    #[gpui_kit::test]
    fn rows_are_picked_by_checkbox_ctrl_and_shift_click(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let ctrl = Modifiers {
            control: true,
            ..Default::default()
        };
        let shift = Modifiers {
            shift: true,
            ..Default::default()
        };
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        // Rows sort by CPU (all equal here), then PID: 1, 10, 11, 20.
        step(cx, &|window, cx| window.click(("pick", 0usize), cx));
        step(cx, &|window, cx| {
            window.click_with_modifiers(("row", 2usize), ctrl, cx)
        });
        app.read_with(cx, |app, _| {
            assert_eq!(
                picked(app),
                [
                    SeriesTarget::Process(key(1)),
                    SeriesTarget::Process(key(11))
                ]
            );
            assert_eq!(app.cursor, Some(key(11)));
        });

        // A plain click only moves the cursor.
        step(cx, &|window, cx| window.click(("row", 3usize), cx));
        app.read_with(cx, |app, _| {
            assert_eq!(picked(app).len(), 2);
            assert_eq!(app.cursor, Some(key(20)));
        });

        // Picks are by process, so they survive re-sorting.
        step(cx, &|window, cx| window.press("shift-m", cx)); // RSS, largest first: 20, 11, 10, 1
        step(cx, &|window, cx| {
            window.click_with_modifiers(("row", 0usize), ctrl, cx)
        });
        app.read_with(cx, |app, _| {
            assert_eq!(picked(app).len(), 3);
            assert!(picked(app).contains(&SeriesTarget::Process(key(20))));
        });

        // Shift+click adds the range from the last toggled row (20 at row 0).
        step(cx, &|window, cx| {
            window.click_with_modifiers(("row", 2usize), shift, cx)
        });
        app.read_with(cx, |app, _| assert_eq!(picked(app).len(), 4));

        step(cx, &|window, cx| window.press("ctrl-g", cx));
        app.read_with(cx, |app, _| assert!(picked(app).is_empty()));
    }

    #[gpui_kit::test]
    fn g_graphs_the_cursor_row_and_a_collapsed_row_as_its_subtree(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        step(cx, &|window, cx| {
            window.press("down", cx); // cursor on row 0 (pid 1)
            window.press("down", cx); // pid 10
            window.press("g", cx);
        });
        app.read_with(cx, |app, _| {
            assert_eq!(picked(app), [SeriesTarget::Process(key(10))])
        });

        // In tree view, collapse pid 10 and pick it again: now its subtree.
        step(cx, &|window, cx| {
            window.press("g", cx); // unpick
            window.press("t", cx);
        });
        // Tree order: 1, 10, 11, 20; row 1 is pid 10.
        step(cx, &|window, cx| window.click(("twisty", 1usize), cx));
        step(cx, &|window, cx| window.press("g", cx));
        app.read_with(cx, |app, _| {
            assert_eq!(picked(app), [SeriesTarget::Subtree(key(10))]);
            assert_eq!(
                app.hosts()[&1].latest(
                    SeriesTarget::Subtree(key(10)),
                    sysmon_model::Metric::Threads
                ),
                Some((2.0, 2)),
                "pid 10 and its child 11"
            );
        });
    }

    #[gpui_kit::test]
    fn graph_panel_sits_below_the_process_list(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        for seq in 0..5 {
            add_frame(&app, cx, seq);
        }
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };

        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(
                window.try_find("graph-panel").is_none(),
                "hidden until something is picked"
            );
        });
        step(cx, &|window, cx| window.click(("pick", 1usize), cx));
        step(cx, &|window, cx| window.click(("pick", 2usize), cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            let procs = window.find("procs-panel").bounds();
            let graph = window.find("graph-panel").bounds();
            assert!(graph.origin.y >= procs.origin.y + procs.size.height - px(1.));
            assert!((graph.size.height - px(super::GRAPH_HEIGHT)).abs() < px(8.));
            assert!(window.try_find(("legend", 0usize)).is_some());
            assert!(window.try_find(("legend", 1usize)).is_some());
        });

        // Dragging the divider up by 100 px makes the panel 100 px taller.
        step(cx, &|window, cx| {
            let handle = window.find("graph-resize").bounds().center();
            window.drag(handle, handle - point(px(0.), px(100.)), cx);
        });
        app.read_with(cx, |app, _| {
            assert_eq!(app.graph_height, px(super::GRAPH_HEIGHT + 100.));
            assert!(app.graph_drag.is_none(), "drag ended on mouse up");
        });

        // Metric keys and hover.
        step(cx, &|window, cx| window.press("3", cx));
        app.read_with(cx, |app, _| {
            assert_eq!(app.graph_metric, sysmon_model::Metric::Rss)
        });
        step(cx, &|window, cx| window.hover("graph-plot", cx));
        app.read_with(cx, |app, cx| {
            let at = app
                .graph_plot
                .read(cx)
                .hover
                .expect("hovering sets the crosshair");
            // On a sample, about halfway along.
            let host = &app.live_hosts[&1];
            let (start, end) = app.graph_span(host);
            let f = (at - start) as f64 / (end - start) as f64;
            assert!((f - 0.5).abs() < 0.1, "{f}");
            assert!(
                host.proc_history.iter().any(|s| s.ts_unix_ns == at),
                "a sample's time"
            );
        });

        // A subtree line: pid 10 and its child 11 use 10 + 11 ticks/s
        // (clk_tck 100), so 21 % CPU.
        step(cx, &|window, cx| {
            window.press("1", cx);
            window.press("shift-n", cx); // PID order: 1, 10, 11, 20
            window.press("t", cx);
        });
        step(cx, &|window, cx| window.click(("twisty", 1usize), cx));
        step(cx, &|window, cx| window.click(("pick", 1usize), cx)); // unpick 10
        step(cx, &|window, cx| window.click(("pick", 1usize), cx)); // repick as subtree
        app.read_with(cx, |app, _| {
            let host = &app.hosts()[&1];
            let t = SeriesTarget::Subtree(key(10));
            assert!(picked(app).contains(&t));
            assert_eq!(host.latest(t, sysmon_model::Metric::Cpu), Some((21.0, 2)));
            assert_eq!(host.series(t, sysmon_model::Metric::Cpu, 0).len(), 5);
        });
        step(cx, &|window, cx| window.render_frame(cx));

        // Removing from the legend unpicks the process.
        step(cx, &|window, cx| {
            window.click(("legend-remove", 0usize), cx)
        });
        app.read_with(cx, |app, _| assert_eq!(picked(app).len(), 1));

        // V hides and shows the panel.
        step(cx, &|window, cx| window.press("v", cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("graph-panel").is_none());
        });
        step(cx, &|window, cx| window.press("v", cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("graph-panel").is_some());
        });
    }

    #[gpui_kit::test]
    fn about_dialog_shows_notices_and_returns_focus(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        step(cx, &|window, cx| {
            window.dispatch_action(Box::new(crate::actions::About), cx)
        });
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("about").is_some(), "dialog open");
            assert!(
                window.try_find(("about-crate", 0usize)).is_some(),
                "crate list"
            );
            assert!(window.try_find("about-text").is_some(), "license text");
        });
        step(cx, &|window, cx| window.click(("about-crate", 0usize), cx));
        step(cx, &|window, cx| window.press("escape", cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("about").is_none(), "Esc closes it");
        });
        // Single-key shortcuts work again once it's closed.
        step(cx, &|window, cx| window.press("?", cx));
        app.read_with(cx, |app, _| assert!(app.show_shortcuts));

        // Opened from the Help menu, the menu hands the keyboard back to
        // the app as it closes, so the dialog doesn't have it: Esc still
        // closes it.
        let focus = app.read_with(cx, |app, _| app.focus.clone());
        step(cx, &|window, cx| {
            window.dispatch_action(Box::new(crate::actions::About), cx)
        });
        step(cx, &|window, cx| focus.focus(window, cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("about").is_some(), "open again");
            window.press("escape", cx)
        });
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("about").is_none(), "Esc closes it at once");
        });

        // So does the Close button.
        step(cx, &|window, cx| {
            window.dispatch_action(Box::new(crate::actions::About), cx)
        });
        step(cx, &|window, cx| window.click("about-close", cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("about").is_none(), "Close closes it");
        });
        step(cx, &|window, cx| window.press("t", cx));
        app.read_with(cx, |app, _| {
            assert!(!app.tree, "shortcuts work after Close too")
        });
    }

    #[gpui_kit::test]
    fn virt_res_shr_columns_sort_and_graph(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        // Our column order, with the new columns around RES.
        step(cx, &|window, cx| {
            window.render_frame(cx);
            let x = |id: &'static str| window.find(id).bounds().origin.x;
            assert!(x("%CPU") < x("VIRT"));
            assert!(x("VIRT") < x("RES"));
            assert!(x("RES") < x("SHR"));
            assert!(x("SHR") < x("THR"));
        });
        step(cx, &|window, cx| window.click("VIRT", cx));
        app.read_with(cx, |app, _| assert_eq!(app.sort, (SortKey::Virt, true)));
        step(cx, &|window, cx| window.press("shift-s", cx));
        app.read_with(cx, |app, _| assert_eq!(app.sort, (SortKey::Shr, true)));
        step(cx, &|window, cx| window.press("shift-m", cx));
        app.read_with(cx, |app, _| assert_eq!(app.sort, (SortKey::Res, true)));

        // Graph keys follow the column order, once there's a graph.
        step(cx, &|window, cx| window.press("2", cx));
        app.read_with(cx, |app, _| {
            assert_eq!(
                app.graph_metric,
                sysmon_model::Metric::Cpu,
                "nothing graphed"
            )
        });
        step(cx, &|window, cx| window.press("down", cx));
        step(cx, &|window, cx| window.press("g", cx));
        step(cx, &|window, cx| window.press("2", cx));
        app.read_with(cx, |app, _| {
            assert_eq!(app.graph_metric, sysmon_model::Metric::Virt)
        });
        step(cx, &|window, cx| window.press("4", cx));
        app.read_with(cx, |app, _| {
            assert_eq!(app.graph_metric, sysmon_model::Metric::Shr)
        });

        // The rows carry the values (fixture: 1 GiB VIRT, 100 shared pages).
        app.read_with(cx, |app, _| {
            let p = &app.hosts()[&1].snapshot.procs[0];
            assert_eq!((p.virt_kib, p.shr_kib), (Some(1 << 20), Some(400)));
        });
        assert_eq!(super::size_cell(None), "–");
        assert_eq!(super::size_cell(Some(1 << 20)), "1.0 GiB");
    }

    #[gpui_kit::test]
    fn tree_guides_join_up_between_rows(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        app.update(cx, |app, cx| app.toggle_tree(cx));
        // 1 ─┬─ 10 ── 11: 10's line carries on past 11 to its sibling 20.
        let t = table(&app, cx);
        let at = |pid| t.iter().position(|(p, _, _)| *p == pid).unwrap();
        let (ten, eleven) = (at(10), at(11));
        assert_eq!(eleven, ten + 1);
        assert_eq!(t[ten].2, "├─ ");
        assert_eq!(t[eleven].2, "│  └─ ");
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let piece = |w: &mut gpui_kit::Window, row: usize, id: &'static str, col: usize| {
                w.within(("row", row)).find((id, col)).bounds()
            };
            let row_h = px(super::ROW_HEIGHT);
            let a = piece(w, ten, "guide-v", 0);
            let b = piece(w, eleven, "guide-v", 0);
            assert_eq!(a.size.height, row_h, "full height");
            assert_eq!(a.bottom(), b.origin.y, "no gap between the rows");
            assert_eq!(a.origin.x, b.origin.x, "one straight line");
            assert_eq!(b.size.height, row_h);
            // The last child's line stops at its connector, halfway down.
            let last = piece(w, eleven, "guide-v", 1);
            assert_eq!(last.size.height, row_h * 0.5);
            let arm = piece(w, eleven, "guide-h", 1);
            assert_eq!(arm.origin.y, last.bottom());
            assert_eq!(arm.origin.x, last.origin.x);

            // Each line drops from under its parent's arrow: a stub there
            // runs down to the row's edge, on into the children's column.
            let stub = |w: &mut gpui_kit::Window, row: usize| {
                w.within(("row", row)).find("guide-stub").bounds()
            };
            let (one, under_one) = (stub(w, at(1)), a);
            assert_eq!(one.origin.x, under_one.origin.x, "1's line is 10's column");
            assert_eq!(one.bottom(), under_one.origin.y);
            let under_ten = stub(w, ten);
            assert_eq!(
                under_ten.origin.x, last.origin.x,
                "10's line is 11's column"
            );
            assert_eq!(under_ten.bottom(), last.origin.y);
            let arrow = w.within(("row", ten)).find(("twisty", ten)).bounds();
            assert_eq!(
                under_ten.origin.x,
                arrow.origin.x + px((super::TWISTY_W / 2.).floor()),
                "under the middle of the arrow"
            );
            assert!(under_ten.origin.y > arrow.center().y, "below the chevron");
            // A leaf has no arrow, so neither a stub nor a gap: its arm runs
            // on to the name.
            assert!(w.within(("row", eleven)).try_find("guide-stub").is_none());
            let leaf = w.within(("row", eleven)).find("guide-leaf").bounds();
            assert_eq!(leaf.origin.x, arm.right());
            assert_eq!(leaf.origin.y, arm.origin.y);
        })
        .unwrap();
    }

    /// The table as (key, is-thread, guides) for assertions.
    fn table(app: &Entity<AppState>, cx: &mut TestAppContext) -> Vec<(u32, bool, String)> {
        app.read_with(cx, |app, cx| {
            let host = &app.hosts()[&1];
            app.table_lines(host, cx)
                .iter()
                .map(|l| {
                    (
                        l.key().pid,
                        l.thread.is_some(),
                        l.tree
                            .as_ref()
                            .map(|t| sysmon_model::tree::guides_text(&t.guides))
                            .unwrap_or_default(),
                    )
                })
                .collect()
        })
    }

    fn pids(t: &[(u32, bool, String)]) -> Vec<u32> {
        t.iter().map(|(p, _, _)| *p).collect()
    }

    /// Mark the test host as sending threads, as `sysmon-agent --threads` does.
    fn send_threads(app: &Entity<AppState>, cx: &mut TestAppContext) {
        app.update(cx, |app, cx| {
            let info = sysmon_proto::HostInfo {
                hostname: "test".into(),
                kernel: "6".into(),
                cpu_count: 1,
                mem_total_kib: 1 << 20,
                clk_tck: 100,
                page_size: 4096,
                interval_ms: 1000,
                sends_threads: true,
            };
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::HostInfo { host_id: 1, info },
            );
            cx.notify();
        });
    }

    #[gpui_kit::test]
    fn kernel_threads_are_hidden_by_default_and_ctrl_k_shows_them(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        assert_eq!(pids(&table(&app, cx)), [1, 10, 11, 20]);
        app.read_with(cx, |app, cx| {
            let host = &app.hosts()[&1];
            let s = app.status_line(host, &app.table_lines(host, cx), cx);
            assert!(s.contains("2 kernel threads hidden"), "{s}");
        });

        step(cx, &|window, cx| window.press("ctrl-k", cx));
        assert_eq!(pids(&table(&app, cx)), [1, 2, 3, 10, 11, 20]);

        // In the tree, they're kthreadd's subtree, and hiding removes it whole.
        step(cx, &|window, cx| window.press("t", cx));
        let t = table(&app, cx);
        assert_eq!(pids(&t), [1, 10, 11, 20, 2, 3]);
        assert_eq!(t[5].2, "└─ ");
        step(cx, &|window, cx| window.press("ctrl-k", cx));
        assert_eq!(pids(&table(&app, cx)), [1, 10, 11, 20]);
    }

    #[gpui_kit::test]
    fn ctrl_h_lists_threads_under_their_process(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        // Off by default, and can't be turned on while the agent doesn't
        // send threads.
        assert!(table(&app, cx).iter().all(|(_, th, _)| !th));
        step(cx, &|window, cx| window.render_frame(cx));
        step(cx, &|window, cx| window.press("ctrl-h", cx));
        app.read_with(cx, |app, _| assert!(!app.show_threads));

        send_threads(&app, cx);
        step(cx, &|window, cx| window.render_frame(cx));
        step(cx, &|window, cx| window.press("ctrl-h", cx));
        // One sample: no thread has used any CPU yet, so none is listed,
        // and the status says why.
        assert!(table(&app, cx).iter().all(|(_, th, _)| !th));
        app.read_with(cx, |app, cx| {
            let host = &app.hosts()[&1];
            let s = app.status_line(host, &app.table_lines(host, cx), cx);
            assert!(s.contains("0 of 2 threads (idle ones hidden"), "{s}");
        });
        // Filtering by the process lists all of its threads, idle or not.
        step(cx, &|window, cx| {
            window.press("ctrl-f", cx);
            window.input("bash", cx);
        });
        assert_eq!(pids(&table(&app, cx)), [10, 101, 102]);
        step(cx, &|window, cx| window.press("escape", cx));
        step(cx, &|window, cx| window.press("escape", cx));

        // Once they've run, they're listed (by PID here: with CPU figures
        // now, the default %CPU order would shuffle them).
        add_frame(&app, cx, 1);
        step(cx, &|window, cx| window.press("shift-n", cx));
        let t = table(&app, cx);
        assert_eq!(pids(&t), [1, 10, 101, 102, 11, 20]);
        assert_eq!(
            t.iter().map(|(_, th, _)| *th).collect::<Vec<_>>(),
            [false, false, true, true, false, false]
        );
        app.read_with(cx, |app, cx| {
            let host = &app.hosts()[&1];
            let s = app.status_line(host, &app.table_lines(host, cx), cx);
            assert!(s.contains("2 of 2 threads"), "{s}");
        });

        // In the tree, threads are the first children of their process.
        step(cx, &|window, cx| window.press("t", cx));
        let guides: Vec<(u32, String)> = table(&app, cx)
            .into_iter()
            .map(|(p, _, g)| (p, g))
            .collect();
        assert_eq!(
            guides,
            [
                (1, "".into()),
                (10, "├─ ".into()),
                (101, "│  ├─ ".into()),
                (102, "│  ├─ ".into()),
                (11, "│  └─ ".into()),
                (20, "└─ ".into()),
            ]
        );

        // Collapsing the process hides its threads too.
        step(cx, &|window, cx| window.click(("twisty", 1usize), cx));
        assert_eq!(pids(&table(&app, cx)), [1, 10, 20]);
    }

    #[gpui_kit::test]
    fn threads_can_be_filtered_and_graphed(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        send_threads(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        step(cx, &|window, cx| window.press("ctrl-h", cx));

        // A thread's name keeps its process (shown as context) in the list.
        step(cx, &|window, cx| {
            window.press("ctrl-f", cx);
            window.input("worker", cx);
        });
        assert_eq!(pids(&table(&app, cx)), [10, 101]);
        app.read_with(cx, |app, cx| {
            let lines = app.table_lines(&app.hosts()[&1], cx);
            assert!(lines[0].context, "process shown because of its thread");
            assert!(!lines[1].context);
        });

        // Pick the thread row for the graph.
        step(cx, &|window, cx| window.click(("pick", 1usize), cx));
        app.read_with(cx, |app, _| {
            assert_eq!(picked(app), [SeriesTarget::Thread(key(101))]);
            assert_eq!(
                app.hosts()[&1].latest(SeriesTarget::Thread(key(101)), sysmon_model::Metric::Cpu),
                Some((0.0, 1))
            );
        });
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(
                window.try_find(("legend", 0usize)).is_some(),
                "thread line in the legend"
            );
        });
        app.read_with(cx, |app, _| {
            assert_eq!(
                app.graph_names[&(View::Live, 1)][&key(101)],
                "worker-a (thread of 10)"
            );
        });
    }

    /// Give the test host's processes these users.
    fn set_users(
        app: &Entity<AppState>,
        cx: &mut TestAppContext,
        seq: u32,
        users: &[(u32, u32, &str)],
    ) {
        app.update(cx, |app, cx| {
            let meta = users
                .iter()
                .map(|&(pid, uid, _)| sysmon_proto::ProcMeta {
                    key: key(pid),
                    uid,
                    cmdline: String::new(),
                })
                .collect();
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::ProcMeta { host_id: 1, meta },
            );
            let users = users
                .iter()
                .map(|&(_, uid, name)| sysmon_proto::UserName {
                    uid,
                    name: name.into(),
                })
                .collect();
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Users { host_id: 1, users },
            );
            cx.notify();
        });
        // Names reach the rows with the next sample (a new one: a repeated
        // sample is ignored as a duplicate).
        add_frame(app, cx, seq);
    }

    #[gpui_kit::test]
    fn user_column_fits_names_up_to_16_characters(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        let width = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                let char_w = super::mono_char_width(window, cx);
                (window.find("USER").bounds().size.width, char_w)
            })
            .unwrap()
        };

        set_users(&app, cx, 1, &[(1, 0, "root"), (10, 1000, "anna")]);
        let (w, ch) = width(cx);
        assert!(
            (w - (ch * 4.0 + px(4.))).abs() < px(1.),
            "narrow for short names: {w:?}"
        );

        set_users(&app, cx, 2, &[(11, 961, "systemd-journal-remote")]);
        let (w, ch) = width(cx);
        assert!(
            (w - (ch * 16.0 + px(4.))).abs() < px(1.),
            "capped at 16: {w:?}"
        );
        // Filtering the long name out doesn't narrow the column: the
        // columns would jump about while typing.
        step(cx, &|window, cx| {
            window.press("ctrl-f", cx);
            window.input("init", cx);
        });
        let (w, ch) = width(cx);
        assert!(
            (w - (ch * 16.0 + px(4.))).abs() < px(1.),
            "still 16 while filtering: {w:?}"
        );
        step(cx, &|window, cx| window.press("escape", cx));
        step(cx, &|window, cx| window.press("escape", cx));

        // In PID order (1, 10, 11, 20), cells line up with the header.
        step(cx, &|window, cx| window.press("shift-n", cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            let header = window.find("USER").bounds();
            let cell = window.find(("user", 2usize)).bounds();
            assert!((cell.origin.x - header.origin.x).abs() < px(1.));
            assert!((cell.size.width - header.size.width).abs() < px(1.));
        });
        app.read_with(cx, |app, cx| {
            let lines = app.table_lines(&app.hosts()[&1], cx);
            assert_eq!(super::user_name(&lines[2].row), "systemd-journal-remote");
        });
        assert_eq!(
            format::fit("systemd-journal-remote", 16),
            "systemd-…-remote"
        );

        // The full name and uid are the cell's tooltip and description.
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find(("user", 2usize)).description(),
                Some("systemd-journal-remote (uid 961)")
            );
        });
    }

    #[gpui_kit::test]
    fn long_hostnames_and_commands_are_clipped_with_the_full_text_kept(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        send_threads(&app, cx);
        let long_host = "build-07.eu-west-1.compute.internal.corp.example.com";
        let long_cmd = format!("/usr/bin/python3 -m worker --queue {}", "x".repeat(400));
        app.update(cx, |app, cx| {
            let host = app.live_hosts.get_mut(&1).unwrap();
            host.info.as_mut().unwrap().hostname = long_host.into();
            let meta = vec![sysmon_proto::ProcMeta {
                key: key(10),
                uid: 1000,
                cmdline: long_cmd.clone(),
            }];
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::ProcMeta { host_id: 1, meta },
            );
            cx.notify();
        });
        add_frame(&app, cx, 1);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        step(cx, &|window, cx| {
            window.press("ctrl-h", cx);
            window.press("shift-n", cx); // PID order: 1, 10, 101, 102, 11, 20
        });
        let (long_cmd2, long_host2) = (long_cmd.clone(), long_host.to_string());
        step(cx, &move |window, cx| {
            window.render_frame(cx);
            // The hostname stays inside the 190 px sidebar.
            let name = window.find(("host-name", 1usize));
            assert!(name.bounds().size.width < px(190.), "{:?}", name.bounds());
            assert!(name.description().unwrap().starts_with(&long_host2));
            // The command stays inside its column; the full text is kept.
            let row = window.find(("row", 1usize)).bounds();
            let cmd = window.find(("cmd", 1usize));
            assert!(
                cmd.bounds().origin.x + cmd.bounds().size.width <= row.origin.x + row.size.width
            );
            assert_eq!(cmd.description(), Some(long_cmd2.as_str()));
            // A thread row's tooltip says whose thread it is.
            let thread = window.find(("cmd", 2usize));
            assert!(
                thread
                    .description()
                    .unwrap()
                    .starts_with("thread 101 \"worker-a\" of 10 /usr/bin/python3"),
                "{:?}",
                thread.description()
            );
        });
    }

    #[gpui_kit::test]
    fn bogus_memory_figures_dont_crash_the_header(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        app.update(cx, |app, cx| {
            let frame = test_frame(
                1,
                0,
                sysmon_proto::SystemSample {
                    ts_unix_ns: 1_000_000_000,
                    // Available above total, as a buggy or hostile agent might send.
                    mem: sysmon_proto::MemInfo {
                        total: 1000,
                        available: 2000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            app.ensure_selection();
            cx.notify();
        });
        cx.update_window(window, |_, window, cx| window.render_frame(cx))
            .unwrap();
    }

    #[gpui_kit::test]
    fn the_sidebar_shows_how_busy_each_host_is_while_it_reports(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        let now = sysmon_ingest::unix_now_ns();
        let sample = |received: u64| sysmon_proto::Frame {
            received_ns: received,
            ..test_frame(
                1,
                0,
                sysmon_proto::SystemSample {
                    ts_unix_ns: received,
                    mem: sysmon_proto::MemInfo {
                        total: 4000,
                        available: 1000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
        };
        let load = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.try_find(("host-load", 1usize))
                    .and_then(|e| e.description().map(str::to_string))
            })
            .unwrap()
        };
        app.update(cx, |app, cx| {
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Frame(sample(now)),
            );
            app.ensure_selection();
            cx.notify();
        });
        assert_eq!(load(cx).as_deref(), Some("CPU 0%, memory 75%"));

        // Silent: no figures, which would be old.
        app.update(cx, |app, cx| {
            app.live_hosts.clear();
            let then = now - 10_000_000_000;
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Frame(sample(then)),
            );
            cx.notify();
        });
        assert_eq!(load(cx), None);
    }

    #[gpui_kit::test]
    fn silence_is_judged_by_the_monitors_clock_not_the_agents(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        let now = sysmon_ingest::unix_now_ns();
        let sample = |agent_ts: u64, received: u64| sysmon_proto::Frame {
            received_ns: received,
            ..test_frame(1, 0, sampled_at(agent_ts))
        };
        // The agent's clock is 10 s behind, but the sample just arrived.
        app.update(cx, |app, _| {
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Frame(sample(now - 10_000_000_000, now)),
            );
        });
        app.read_with(cx, |app, _| {
            assert_eq!(app.silence(&app.live_hosts[&1]), None)
        });
        app.update(cx, |app, cx| {
            app.ensure_selection();
            cx.notify();
        });
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("stale-banner").is_none(), "live data: no notice");
            assert!(w.try_find(("host-silent", 1usize)).is_none(), "a green dot");
        })
        .unwrap();

        // A host whose last sample arrived 10 s ago is silent, whatever its clock says.
        app.update(cx, |app, _| {
            app.live_hosts.clear();
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Frame(sample(now, now - 10_000_000_000)),
            );
        });
        app.read_with(cx, |app, _| {
            let s = app.silence(&app.live_hosts[&1]).expect("silent");
            assert!(s >= 10_000_000_000);
        });
        // And the main view says its figures are old, not just the sidebar.
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let banner = w.find("stale-banner");
            let notice = banner.description().unwrap_or_default();
            assert!(notice.starts_with("No data from"), "{notice}");
            // The sidebar marks it with an icon, not just a red dot.
            assert!(w.try_find(("host-silent", 1usize)).is_some());
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn waiting_says_where_to_send_and_what_was_turned_away(cx: &mut TestAppContext) {
        use sysmon_ingest::{Reason, Rejections};
        let (window, app) = open(cx);
        let rejections = std::sync::Arc::new(Rejections::default());
        app.update(cx, |app, cx| {
            app.live_enabled = true;
            app.listen = Some(("0.0.0.0:9876".parse().unwrap(), true));
            app.rejections = Some(rejections.clone());
            cx.notify();
        });
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let found = w.find("waiting-command");
            let cmd = found.description().unwrap_or_default();
            assert_eq!(
                cmd,
                "sysmon-agent --target <this machine>:9876 --key-file <key>"
            );
            assert!(
                w.try_find("waiting-rejected").is_none(),
                "nothing turned away yet"
            );
        })
        .unwrap();

        // An agent with the wrong key: the next tick shows it, and why.
        let now = sysmon_ingest::unix_now_ns();
        rejections.record("10.0.0.5".parse().unwrap(), Reason::WrongKey, now);
        let t = std::time::Instant::now() + std::time::Duration::from_secs(2);
        app.update(cx, |app, cx| {
            assert!(app.live_tick(t, now), "redrawn for it");
            cx.notify();
        });
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("waiting-rejected").is_some());
        })
        .unwrap();
        app.read_with(cx, |app, _| {
            assert_eq!(app.rejected.len(), 1);
            assert_eq!(app.rejected[0].reason, Reason::WrongKey);
        });

        // Once another host is up, a banner keeps saying so above it.
        app.update(cx, |app, cx| {
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Frame(sysmon_proto::Frame {
                    received_ns: now,
                    ..test_frame(1, 0, sampled_at(now))
                }),
            );
            app.ensure_selection();
            cx.notify();
        });
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let found = w.find("rejected-banner");
            let banner = found.description().unwrap_or_default();
            assert!(
                banner.starts_with("Turning away data from 10.0.0.5: "),
                "{banner}"
            );
        })
        .unwrap();

        // It goes once the sender has been quiet for a while.
        let later = now + super::REJECTED_RECENT_NS + 1;
        app.update(cx, |app, _| {
            assert!(app.live_tick(t + std::time::Duration::from_secs(2), later));
            assert!(app.rejected.is_empty());
        });
    }

    #[gpui_kit::test]
    fn errors_can_be_dismissed_and_the_full_graph_one_clears_itself(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        app.update(cx, |app, cx| {
            let procs = (1..=12u32)
                .map(|pid| sysmon_proto::ProcSample {
                    pid,
                    ppid: 0,
                    starttime: 0,
                    state: b'S',
                    utime: 0,
                    stime: 0,
                    rss_pages: 1,
                    threads: 1,
                    comm: format!("p{pid}"),
                    vsize_bytes: None,
                    shared_pages: None,
                    kernel_thread: Some(false),
                })
                .collect();
            let frame = sysmon_proto::Frame {
                procs,
                ..test_frame(1, 0, sampled_at(1_000_000_000))
            };
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            app.ensure_selection();
            cx.notify();
        });
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                f(window, cx)
            })
            .unwrap();
            cx.run_until_parked();
        };
        for i in 0..9usize {
            step(cx, &move |w, cx| w.click(("pick", i), cx));
        }
        assert!(
            app.read_with(cx, |a, _| a.error.is_some()),
            "9th pick refused"
        );
        // Clearing the graph takes the message down.
        step(cx, &|w, cx| w.press("ctrl-g", cx));
        assert_eq!(app.read_with(cx, |a, _| a.error.clone()), None);

        // Any error: the × and Esc dismiss it.
        app.update(cx, |a, _| a.error = Some("boom".into()));
        step(cx, &|w, cx| w.click("error-dismiss", cx));
        assert_eq!(app.read_with(cx, |a, _| a.error.clone()), None);
        app.update(cx, |a, _| a.error = Some("boom".into()));
        step(cx, &|w, cx| w.press("escape", cx));
        assert_eq!(app.read_with(cx, |a, _| a.error.clone()), None);
    }

    #[gpui_kit::test]
    fn live_hosts_that_go_away_are_forgotten(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        let info = |host_id: u64| sysmon_ingest::Event::HostInfo {
            host_id,
            info: sysmon_proto::HostInfo {
                hostname: format!("h{host_id}"),
                kernel: "6".into(),
                cpu_count: 1,
                mem_total_kib: 1 << 20,
                clk_tck: 100,
                page_size: 4096,
                interval_ms: 1000,
                sends_threads: false,
            },
        };
        let hour = FORGET_AFTER_NS;
        app.update(cx, |app, _| {
            app.apply_live(info(1), 1_000);
            app.apply_live(info(2), 1_000 + hour);
            app.selections.insert((View::Live, 1), Selection::default());
            app.forget_hosts(1_000 + hour + 1);
            assert_eq!(app.live_hosts.keys().copied().collect::<Vec<_>>(), [2]);
            assert!(!app.selections.contains_key(&(View::Live, 1)));

            // A flood of host IDs: the longest silent go first.
            for id in 10..10 + MAX_LIVE_HOSTS as u64 + 5 {
                app.apply_live(info(id), 2 * hour + id);
            }
            app.forget_hosts(2 * hour + 1_000);
            assert_eq!(app.live_hosts.len(), MAX_LIVE_HOSTS);
            assert!(!app.live_hosts.contains_key(&2));
            assert!(
                app.live_hosts
                    .contains_key(&(10 + MAX_LIVE_HOSTS as u64 + 4))
            );
        });
    }

    #[gpui_kit::test]
    fn hosts_are_listed_by_name(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        let info = |host_id: u64, name: &str| sysmon_ingest::Event::HostInfo {
            host_id,
            info: sysmon_proto::HostInfo {
                hostname: name.into(),
                kernel: "6".into(),
                cpu_count: 1,
                mem_total_kib: 1 << 20,
                clk_tck: 100,
                page_size: 4096,
                interval_ms: 1000,
                sends_threads: false,
            },
        };
        app.update(cx, |app, _| {
            // IDs are hashes, unrelated to the names.
            app.apply_live(info(3, "alpha"), 1);
            app.apply_live(info(1, "Charlie"), 1);
            app.apply_live(info(2, "bravo"), 1);
            assert_eq!(app.host_order(), [3, 2, 1]);
            app.ensure_selection();
            assert_eq!(app.selected, Some(3));
        });
    }

    #[gpui_kit::test]
    fn threads_follow_a_descending_pid_sort(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        app.update(cx, |app, cx| {
            let proc = sysmon_proto::ProcSample {
                pid: 10,
                ppid: 0,
                starttime: 0,
                state: b'S',
                utime: 0,
                stime: 0,
                rss_pages: 1,
                threads: 3,
                comm: "p".into(),
                vsize_bytes: None,
                shared_pages: None,
                kernel_thread: Some(false),
            };
            // Two samples, so the threads have run (idle ones aren't listed).
            for seq in 0..2u32 {
                let threads = [10u32, 11, 12]
                    .map(|tid| sysmon_proto::ThreadSample {
                        tgid: 10,
                        tid,
                        starttime: 0,
                        state: b'S',
                        utime: seq as u64 * 10,
                        stime: 0,
                        comm: format!("t{tid}"),
                    })
                    .to_vec();
                let frame = sysmon_proto::Frame {
                    procs: vec![proc.clone()],
                    threads,
                    ..test_frame(1, seq, sampled_at(1_000_000_000 * (1 + seq as u64)))
                };
                apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            }
            app.ensure_selection();
            app.show_threads = true;
            app.sort = (SortKey::Pid, true);
            let host = &app.live_hosts[&1];
            let tids: Vec<u32> = app
                .table_lines(host, cx)
                .iter()
                .filter(|l| l.thread.is_some())
                .map(|l| l.key().pid)
                .collect();
            assert_eq!(tids, [12, 11, 10]);
        });
    }

    /// Feed host 1 a sample in which each `(pid, utime)` process has used
    /// that much CPU time so far; two of them give each a %CPU.
    fn busy_sample(app: &mut AppState, seq: u32, procs: &[(u32, u64)]) {
        let procs = procs
            .iter()
            .map(|&(pid, utime)| sysmon_proto::ProcSample {
                pid,
                ppid: 0,
                starttime: 0,
                state: b'S',
                utime,
                stime: 0,
                rss_pages: 1,
                threads: 1,
                comm: format!("p{pid}"),
                vsize_bytes: None,
                shared_pages: None,
                kernel_thread: Some(false),
            })
            .collect();
        let frame = sysmon_proto::Frame {
            procs,
            ..test_frame(1, seq, sampled_at(1_000_000_000 * (1 + seq as u64)))
        };
        apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
    }

    #[gpui_kit::test]
    fn the_bottom_panel_takes_a_share_of_a_tall_window(cx: &mut TestAppContext) {
        use gpui_kit::{px, size};
        let (window, app) = open(cx);
        for seq in 0..2 {
            add_frame(&app, cx, seq);
        }
        let height = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.find("graph-panel").bounds().size.height
            })
            .unwrap()
        };
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            w.click(("pick", 1usize), cx)
        })
        .unwrap();
        cx.run_until_parked();
        assert!(
            (height(cx) - px(super::GRAPH_HEIGHT)).abs() < px(8.),
            "the least"
        );

        cx.simulate_window_resize(window, size(px(1200.), px(2000.)));
        cx.run_until_parked();
        assert!((height(cx) - px(600.)).abs() < px(8.), "30% of 2000 px");

        // Once dragged, the height is yours, whatever the window does.
        app.update(cx, |app, _| {
            app.graph_resized = true;
            app.graph_height = px(400.);
        });
        cx.simulate_window_resize(window, size(px(1200.), px(2400.)));
        cx.run_until_parked();
        assert!((height(cx) - px(400.)).abs() < px(8.));
    }

    #[gpui_kit::test]
    fn the_row_order_holds_while_you_work_in_the_table(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        let order = |app: &AppState, cx: &gpui_kit::App| -> Vec<u32> {
            app.table_lines(&app.live_hosts[&1], cx)
                .iter()
                .map(|l| l.key().pid)
                .collect()
        };
        app.update(cx, |app, cx| {
            // 20 is the busier, so first by %CPU.
            busy_sample(app, 0, &[(10, 0), (20, 0)]);
            busy_sample(app, 1, &[(10, 10), (20, 50)]);
            app.ensure_selection();
            app.sort = (SortKey::Cpu, true);
            assert_eq!(order(app, cx), [20, 10]);

            // Moving the cursor holds the order: 10 gets busier, and a new
            // process shows up, but the rows stay where they were.
            app.move_cursor(1, cx);
            busy_sample(app, 2, &[(10, 110), (20, 60), (30, 0)]);
            assert_eq!(order(app, cx), [20, 10, 30], "held; the new one last");
            let host = &app.live_hosts[&1];
            let status = app.status_line(host, &app.table_lines(host, cx), cx);
            assert!(status.contains("order held"), "{status}");

            // Once it runs out, the table sorts again.
            let later = std::time::Instant::now() + super::ORDER_HOLD;
            assert!(app.release_order(later));
            assert!(!app.release_order(later), "only once");
            assert_eq!(order(app, cx), [10, 20, 30]);

            // Choosing a sort shows it at once, held or not.
            app.move_cursor(1, cx);
            app.sort_by(SortKey::Pid, cx);
            assert_eq!(app.sort, (SortKey::Pid, false));
            assert_eq!(order(app, cx), [10, 20, 30]);
            app.sort_by(SortKey::Pid, cx);
            assert_eq!(order(app, cx), [30, 20, 10]);
        });
    }

    /// Stripes and the cursor highlight span the table, however short the
    /// row's command (they stopped where the text did, leaving boxes).
    #[test]
    fn cores_fill_rows_evenly() {
        use super::cores_per_row;
        assert_eq!(cores_per_row(24, 11), 8, "3 rows of 8, not 11, 11, 2");
        assert_eq!(cores_per_row(24, 12), 12);
        assert_eq!(cores_per_row(8, 11), 8);
        assert_eq!(cores_per_row(64, 11), 11);
        assert_eq!(cores_per_row(13, 12), 7);
        assert_eq!(cores_per_row(1, 0), 1);
        assert_eq!(cores_per_row(0, 5), 1);
    }

    #[test]
    fn processes_are_named_by_their_program_when_comm_is_cut_off() {
        let name = super::name_of;
        assert_eq!(
            name("xdg-document-po", Some("/usr/lib/xdg-document-portal")),
            "xdg-document-portal"
        );
        assert_eq!(
            name("Isolated Web Co", Some("/opt/zen/zen-bin -contentproc")),
            "Isolated Web Co"
        );
        assert_eq!(name("zsh", Some("-zsh")), "zsh");
        assert_eq!(name("kworker/0:1", None), "kworker/0:1");
        assert_eq!(name("bash", Some("/bin/bash")), "bash");
    }

    #[test]
    fn escape_codes_are_left_out_of_commands() {
        use super::printable;
        assert_eq!(printable("ls --color=auto"), "ls --color=auto");
        assert_eq!(
            printable(
                "fzf --border-label '\x1b[48;2;24;24;37m\x1b[38;2;166;173;200m Files \x1b[0m'"
            ),
            "fzf --border-label ' Files '"
        );
        assert_eq!(printable("a\x1b]0;title\x07b"), "ab", "OSC to BEL");
        assert_eq!(printable("a\x1b]8;;url\x1b\\b"), "ab", "OSC to ST");
        assert_eq!(printable("tab\there"), "tab here");
        assert_eq!(printable("cut off\x1b[38;2"), "cut off");
    }

    #[test]
    fn commands_split_into_directory_name_and_arguments() {
        let parts = |c: &str| {
            let (d, n, a) = super::command_parts(c);
            (c[d].to_string(), c[n].to_string(), c[a].to_string())
        };
        assert_eq!(
            parts("/opt/zen/zen-bin -contentproc 7"),
            (
                "/opt/zen/".into(),
                "zen-bin".into(),
                " -contentproc 7".into()
            )
        );
        assert_eq!(
            parts("Hyprland --watchdog-fd 5"),
            ("".into(), "Hyprland".into(), " --watchdog-fd 5".into())
        );
        assert_eq!(
            parts("/sbin/init"),
            ("/sbin/".into(), "init".into(), "".into())
        );
        assert_eq!(
            parts("[kworker/0:1]"),
            ("".into(), "[kworker/0:1]".into(), "".into())
        );
    }

    #[gpui_kit::test]
    fn the_theme_menu_picks_ticks_and_saves_the_theme(cx: &mut TestAppContext) {
        use crate::config::ThemePref;
        use gpui_kit::component::ActiveTheme as _;
        let dir = std::env::temp_dir().join(format!("sysmon-ui-theme-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");
        let (window, app) = open_with(cx, |s| s.config_path = Some(path.clone()));
        let pick = |cx: &mut TestAppContext, action: Box<dyn gpui_kit::Action>| {
            cx.update_window(window, |_, w, cx| {
                w.dispatch_action(action, cx);
                w.render_frame(cx);
            })
            .unwrap();
            cx.run_until_parked();
        };
        let dark = |cx: &mut TestAppContext| cx.update(|cx| cx.theme().is_dark());
        let checked = |cx: &mut TestAppContext, name: &str| {
            cx.update(|cx| {
                let menus = gpui_kit::component::GlobalState::global(cx).app_menus();
                let view = menus.iter().find(|m| m.name == "View").unwrap();
                view.items.iter().find_map(|i| match i {
                    gpui_kit::OwnedMenuItem::Submenu(m) if m.name == "Theme" => {
                        m.items.iter().find_map(|i| match i {
                            gpui_kit::OwnedMenuItem::Action {
                                name: n, checked, ..
                            } if n == name => Some(*checked),
                            _ => None,
                        })
                    }
                    _ => None,
                })
            })
            .expect("Theme item")
        };
        cx.update_window(window, |_, w, cx| w.render_frame(cx))
            .unwrap();
        assert!(
            checked(cx, "System") && !checked(cx, "Dark"),
            "follows the system at first"
        );
        assert!(!path.exists(), "nothing saved until something is picked");

        pick(cx, Box::new(crate::actions::ThemeDark));
        assert!(dark(cx));
        assert!(checked(cx, "Dark") && !checked(cx, "System"));
        assert_eq!(crate::config::load(&path).0.theme, ThemePref::Dark);

        pick(cx, Box::new(crate::actions::ThemeLight));
        assert!(!dark(cx));
        assert_eq!(crate::config::load(&path).0.theme, ThemePref::Light);

        pick(cx, Box::new(crate::actions::ThemeSystem));
        app.read_with(cx, |app, _| assert_eq!(app.theme, ThemePref::System));
        assert!(checked(cx, "System"));
        assert_eq!(crate::config::load(&path).0.theme, ThemePref::System);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui_kit::test]
    fn the_saved_theme_applies_at_startup(cx: &mut TestAppContext) {
        use crate::config::{Config, ThemePref};
        use gpui_kit::component::ActiveTheme as _;
        for (theme, is_dark) in [(ThemePref::Dark, true), (ThemePref::Light, false)] {
            let (_window, app) = open_with(cx, |s| {
                s.config = Config {
                    theme,
                    ..Default::default()
                }
            });
            assert_eq!(cx.update(|cx| cx.theme().is_dark()), is_dark);
            app.read_with(cx, |app, _| assert_eq!(app.theme, theme));
        }
    }

    #[gpui_kit::test]
    fn log_times_show_the_date_when_the_lines_span_days(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        let day = 24 * 3600 * 1_000_000_000u64;
        let t0 = 1_795_332_065 * 1_000_000_000u64;
        let entry = |ts| sysmon_proto::LogEntry {
            ts_unix_ns: ts,
            priority: 3,
            unit: None,
            ident: "web".into(),
            pid: None,
            message: "m".into(),
            truncated: false,
        };
        let add = |app: &Entity<AppState>, cx: &mut TestAppContext, seq: u64, ts: u64| {
            app.update(cx, |app, cx| {
                if app.live_hosts.is_empty() {
                    let frame = sysmon_proto::Frame {
                        received_ns: t0,
                        ..test_frame(1, 0, sampled_at(t0))
                    };
                    apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
                }
                apply(
                    &mut app.live_hosts,
                    sysmon_ingest::Event::Logs {
                        host_id: 1,
                        boot_id: 1,
                        batch: sysmon_proto::LogBatch {
                            run: 1,
                            first_seq: seq,
                            dropped: 0,
                            entries: vec![entry(ts)],
                        },
                        received_ns: ts,
                    },
                );
                app.ensure_selection();
                app.panel = Panel::Logs;
                cx.notify();
            });
        };
        let first_time = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.find(("log-time", 0usize))
                    .description()
                    .unwrap_or_default()
                    .to_string()
            })
            .unwrap()
        };
        add(&app, cx, 0, t0);
        assert_eq!(
            first_time(cx),
            crate::format::time(t0),
            "one day: time only"
        );
        add(&app, cx, 1, t0 + 2 * day);
        assert_eq!(
            first_time(cx),
            crate::format::day_time(t0),
            "two days: dated"
        );
    }

    #[gpui_kit::test]
    fn per_core_bars_wrap_into_even_rows(cx: &mut TestAppContext) {
        // Machines of many sizes, in the 1200 px test window.
        for cores in [1usize, 2, 4, 6, 8, 12, 13, 16, 24, 32, 64, 128] {
            let (window, app) = open(cx);
            app.update(cx, |app, cx| {
                // Two samples (cores plus the aggregate line), so there are
                // per-core figures.
                for seq in 0..2u32 {
                    let cpu = sysmon_proto::CpuCounters {
                        user: seq as u64 * 10,
                        idle: seq as u64 * 90,
                        ..Default::default()
                    };
                    let system = sysmon_proto::SystemSample {
                        cpus: vec![cpu; cores + 1],
                        ..sampled_at((1 + seq as u64) * 1_000_000_000)
                    };
                    apply(
                        &mut app.live_hosts,
                        sysmon_ingest::Event::Frame(test_frame(1, seq, system)),
                    );
                }
                app.ensure_selection();
                cx.notify();
            });
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                // The bars share the table's width; none may run past it.
                let panel = w.find("procs-panel").bounds();
                let right = panel.origin.x + panel.size.width;
                let mut per_row: std::collections::BTreeMap<i32, usize> = Default::default();
                for i in 0..cores {
                    let bar = w.find(("core", i)).bounds();
                    assert!(
                        bar.origin.x + bar.size.width <= right,
                        "{cores} cores: core {i} ends at {:?}, past {right:?}",
                        bar.origin.x + bar.size.width
                    );
                    *per_row.entry(f32::from(bar.origin.y) as i32).or_default() += 1;
                }
                let counts: Vec<usize> = per_row.into_values().collect();
                // Full rows of the same length; only the last may be short.
                let (last, full) = counts.split_last().unwrap();
                assert!(
                    full.iter().all(|&n| n == counts[0]) && *last <= counts[0],
                    "{cores} cores: rows of {counts:?}"
                );
            })
            .unwrap();
        }
    }

    #[gpui_kit::test]
    fn the_graph_spans_the_history_it_has(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        for seq in 0..5 {
            add_frame(&app, cx, seq);
        }
        let s = 1_000_000_000;
        app.update(cx, |app, _| {
            // Samples at 1..=5 s: 4 s of history, within the 10 min window.
            let host = &app.live_hosts[&1];
            assert_eq!(app.graph_span(host), (s, 5 * s));
            // A window shorter than the history cuts it.
            app.graph_window_s = 2;
            let host = &app.live_hosts[&1];
            assert_eq!(app.graph_span(host), (3 * s, 5 * s));
        });
    }

    #[gpui_kit::test]
    fn the_toolbar_says_where_live_data_is_recorded_only_when_live(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        app.update(cx, |app, cx| {
            app.live_enabled = true;
            cx.notify();
        });
        let label = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.try_find("recording-to")
                    .and_then(|e| e.description().map(str::to_string))
            })
            .unwrap()
        };
        assert!(label(cx).unwrap().starts_with("Recording to "));
        app.update(cx, |app, cx| {
            app.recording_to = None;
            cx.notify();
        });
        assert_eq!(label(cx).as_deref(), Some("Not recording"));
        let (handle, _driver) = ReplayHandle::manual(ReplayStatus::default());
        app.update(cx, |app, cx| app.start_session(handle, "rec".into(), cx));
        assert_eq!(label(cx), None, "not beside a recording");
    }

    #[gpui_kit::test]
    fn the_sidebar_mentions_incomplete_samples_only_when_there_are_some(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        // Heard from just now, so not silent.
        app.update(cx, |app, _| {
            app.live_hosts.get_mut(&1).unwrap().last_received_ns = sysmon_ingest::unix_now_ns();
        });
        let detail = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.try_find(("host-detail", 1usize))
                    .and_then(|e| e.description().map(str::to_string))
            })
            .unwrap()
        };
        assert_eq!(detail(cx), None, "nothing to say about a healthy host");
        app.update(cx, |app, cx| {
            let host = app.live_hosts.get_mut(&1).unwrap();
            host.frames_received = 4;
            host.frames_incomplete = 1;
            cx.notify();
        });
        assert_eq!(detail(cx).as_deref(), Some("25.0% of samples incomplete"));
    }

    #[gpui_kit::test]
    fn the_shortcuts_overlay_lists_the_mouse_and_fits_the_window(cx: &mut TestAppContext) {
        let (window, _app) = open(cx);
        cx.update_window(window, |_, w, cx| w.press("f1", cx))
            .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let screen = w.find("shortcuts-overlay").bounds();
            // Every group, the mouse's last, is within the width: they wrap
            // (and the panel scrolls if the window is short).
            let groups = crate::actions::SHORTCUTS
                .iter()
                .map(|s| s.group)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                + 1;
            for k in 0..groups {
                let col = w.find(("shortcuts-group", k)).bounds();
                assert!(
                    col.origin.x >= screen.origin.x
                        && col.origin.x + col.size.width <= screen.origin.x + screen.size.width,
                    "group {k}: {col:?} within {screen:?}"
                );
            }
        })
        .unwrap();
        assert!(
            crate::actions::MOUSE
                .iter()
                .any(|(what, _)| *what == "Ctrl+click")
        );
    }

    #[gpui_kit::test]
    fn the_graph_checkboxes_explain_themselves(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        app.read_with(cx, |app, cx| {
            let host = &app.hosts()[&1];
            let s = app.status_line(host, &app.table_lines(host, cx), cx);
            assert!(s.contains("to graph it"), "{s}");
        });
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let pick = w.find(("pick", 0usize));
            assert_eq!(pick.description(), Some("Graph this process (g)"));
            w.click(("pick", 0usize), cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let pick = w.find(("pick", 0usize));
            assert_eq!(pick.description(), Some("Remove from the graph (g)"));
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn a_filter_that_matches_nothing_says_so(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("procs-empty").is_none());
            w.press("ctrl-f", cx);
            w.input("nothing-like-it", cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let note = w.find("procs-empty");
            let text = note.description().unwrap_or_default();
            assert!(text.contains("nothing-like-it"), "{text}");
        })
        .unwrap();
    }

    /// Frames drawn as the app draws them, not forced afresh as
    /// `render_frame` does: the table, a cached view, must still show what
    /// changed.
    #[gpui_kit::test]
    fn the_table_and_sidebar_follow_changes_between_frames(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let draw = |cx: &mut TestAppContext| {
            cx.run_until_parked();
            cx.update_window(window, |_, w, cx| w.draw(cx).clear(cx))
                .unwrap();
        };
        cx.update_window(window, |_, w, cx| w.render_frame(cx))
            .unwrap();
        let shown = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, _| {
                (0..10usize)
                    .filter(|&i| w.try_find(("row", i)).is_some())
                    .count()
            })
            .unwrap()
        };
        assert_eq!(shown(cx), 4, "kernel threads hidden");
        app.update(cx, |app, cx| app.toggle_kernel_threads(cx));
        draw(cx);
        assert_eq!(shown(cx), 6, "and now listed");

        // A sample that makes the host silent shows in the sidebar.
        app.update(cx, |app, cx| {
            let host = app.live_hosts.get_mut(&1).unwrap();
            host.last_received_ns = 1;
            cx.notify();
        });
        draw(cx);
        cx.update_window(window, |_, w, _| {
            assert!(w.try_find(("host-silent", 1usize)).is_some())
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn the_table_starts_below_the_header(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            // The figures under the header's graphs (the test host has no cores).
            let header = w.find("net-rx").bounds();
            let table = w.find("procs-panel").bounds();
            assert!(header.bottom() <= table.top(), "{header:?} over {table:?}");
            // And its rows are drawn, in the room under its own header.
            let row = w.find(("row", 0usize)).bounds();
            assert!(row.top() > table.top() && row.bottom() <= table.bottom());
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn rows_span_the_table(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let table = w.find("procs-panel").bounds();
            for i in 0..4usize {
                let row = w.find(("row", i)).bounds();
                assert!(
                    (row.size.width - table.size.width).abs() < px(1.),
                    "row {i}: {:?} of {:?}",
                    row.size.width,
                    table.size.width
                );
            }
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn tree_state_and_legend_names_stay_with_their_host(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_frame_for(&app, cx, 1, 0);
        add_frame_for(&app, cx, 2, 0);
        let collapsed_rows = |app: &Entity<AppState>, cx: &mut TestAppContext| {
            app.update(cx, |app, cx| {
                let host = &app.hosts()[&app.selected.unwrap()];
                app.table_lines(host, cx)
                    .iter()
                    .filter(|l| l.tree.as_ref().is_some_and(|t| t.collapsed))
                    .map(|l| l.row.key.pid)
                    .collect::<Vec<_>>()
            })
        };
        app.update(cx, |app, cx| {
            app.tree = true;
            app.selected = Some(1);
            app.toggle_collapsed(key(1));
            app.selection_mut()
                .unwrap()
                .add(SeriesTarget::Process(key(10)))
                .unwrap();
            cx.notify();
        });
        cx.update_window(window, |_, w, cx| w.render_frame(cx))
            .unwrap();
        assert_eq!(collapsed_rows(&app, cx), [1]);
        app.update(cx, |app, cx| {
            app.selected = Some(2);
            cx.notify();
        });
        cx.update_window(window, |_, w, cx| w.render_frame(cx))
            .unwrap();
        assert!(
            collapsed_rows(&app, cx).is_empty(),
            "host 2's pid 1 isn't collapsed"
        );
        app.read_with(cx, |app, _| {
            assert_eq!(app.graph_names[&(View::Live, 1)][&key(10)], "bash");
            assert!(!app.graph_names.contains_key(&(View::Live, 2)));
        });
        // Unpicked, its name goes too.
        app.update(cx, |app, cx| {
            app.selected = Some(1);
            app.selection_mut().unwrap().clear();
            cx.notify();
        });
        cx.update_window(window, |_, w, cx| w.render_frame(cx))
            .unwrap();
        app.read_with(cx, |app, _| {
            assert!(
                app.graph_names
                    .get(&(View::Live, 1))
                    .is_none_or(|n| n.is_empty())
            );
        });
    }

    #[gpui_kit::test]
    fn speed_keys_only_act_on_a_recording_on_screen(cx: &mut TestAppContext) {
        let (handle, driver) = ReplayHandle::manual(ReplayStatus {
            speed: 1.,
            ..Default::default()
        });
        let (window, app) = open(cx);
        app.update(cx, |app, cx| {
            app.start_session(handle, "rec".into(), cx);
            app.live_enabled = true;
            app.show(View::Live, cx);
        });
        cx.update_window(window, |_, w, cx| w.press("]", cx))
            .unwrap();
        cx.run_until_parked();
        assert_eq!(
            driver.controls.try_recv().ok(),
            None,
            "not in the Live view"
        );
        app.update(cx, |app, cx| app.show(View::Replay, cx));
        cx.update_window(window, |_, w, cx| w.press("]", cx))
            .unwrap();
        cx.run_until_parked();
        assert_eq!(driver.controls.try_recv().ok(), Some(Control::SetSpeed(4.)));
    }

    /// Opens the recording for real (in the background), but plays it with
    /// a handle driven by hand rather than an engine thread.
    fn open_without_engine(path: &std::path::Path, _speed: f64) -> anyhow::Result<ReplayHandle> {
        let source = sysmon_model::ReplaySource::open(path)?;
        let (start, end) = source
            .time_range()
            .ok_or_else(|| anyhow::anyhow!("no recorded data under {}", path.display()))?;
        let (handle, driver) = ReplayHandle::manual(ReplayStatus {
            start_ns: start,
            end_ns: end,
            position_ns: start,
            ..Default::default()
        });
        // Nothing is fed: the session's feed just ends.
        drop(driver);
        Ok(handle)
    }

    #[gpui_kit::test]
    fn the_open_dialog_has_nothing_to_open_in_an_empty_dir(cx: &mut TestAppContext) {
        let dir = std::env::temp_dir().join(format!("sysmon-ui-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (window, app) = open(cx);
        app.update(cx, |app, _| app.data_dir = dir.clone());
        cx.update_window(window, |_, w, cx| {
            w.dispatch_action(Box::new(crate::actions::OpenRecording), cx)
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("recordings-message").is_some());
            w.click("recordings-open", cx);
            w.click("recordings-all", cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("recordings").is_some(), "still open");
        })
        .unwrap();
        app.read_with(cx, |app, _| {
            assert!(app.opening.is_none() && app.replay.is_none())
        });
    }

    #[gpui_kit::test]
    fn the_open_dialog_lists_machines_and_boots(cx: &mut TestAppContext) {
        let dir = std::env::temp_dir().join(format!("sysmon-ui-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut rec = sysmon_store::Recorder::new(&dir);
        let now = sysmon_ingest::unix_now_ns();
        let sec = 1_000_000_000u64;
        // web1 (host 1) recorded a minute ago, db1 (host 2) an hour ago.
        for (host, name, at) in [(1u64, "web1", now - 60 * sec), (2, "db1", now - 3600 * sec)] {
            let header = sysmon_proto::Header {
                host_id: host,
                boot_id: 7,
                seq: 0,
                chunk: 0,
                chunks: 1,
            };
            let info = sysmon_proto::HostInfo {
                hostname: name.into(),
                kernel: "6.0".into(),
                cpu_count: 1,
                mem_total_kib: 1,
                clk_tck: 100,
                page_size: 4096,
                interval_ms: 1000,
                sends_threads: false,
            };
            let d = sysmon_proto::encode(&header, &sysmon_proto::Msg::HostInfo(info)).unwrap();
            for s in 0..3 {
                rec.append(host, 7, at + s * sec, &d).unwrap();
            }
        }
        rec.flush().unwrap();
        drop(rec);

        let (window, app) = open(cx);
        app.update(cx, |app, _| {
            app.open_replay = open_without_engine;
            app.data_dir = dir.clone();
            app.recording_to = Some(dir.clone());
        });
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| f(window, cx))
                .unwrap();
            cx.run_until_parked();
        };
        step(cx, &|window, cx| {
            window.dispatch_action(Box::new(crate::actions::OpenRecording), cx)
        });
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("recordings").is_some(), "dialog open");
            // web1, its boot, db1, its boot: newest machine first.
            for i in 0..4usize {
                assert!(window.try_find(("recording-row", i)).is_some(), "row {i}");
            }
            assert!(window.try_find(("recording-row", 4usize)).is_none());
            assert!(window.try_find(("recording-span", 1usize)).is_some());
            assert!(
                window.try_find(("recording-live", 1usize)).is_some(),
                "web1 is still being recorded"
            );
            assert!(window.try_find(("recording-live", 3usize)).is_none());
        });
        // The newest boot is picked; the keys move through the rows.
        step(cx, &|window, cx| window.press("down", cx));
        step(cx, &|window, cx| window.press("down", cx));
        step(cx, &|window, cx| window.press("up", cx));
        step(cx, &|window, cx| window.press("enter", cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(
                window.try_find("recordings").is_none(),
                "Enter opens and closes"
            );
        });
        app.read_with(cx, |app, _| {
            let s = app.replay.as_ref().expect("a recording is open");
            assert_eq!(
                s.label,
                dir.join(format!("{:016x}", 2)).display().to_string(),
                "db1, all boots"
            );
        });

        // Cancel closes without opening; keyboard shortcuts work again.
        step(cx, &|window, cx| {
            window.dispatch_action(Box::new(crate::actions::OpenRecording), cx)
        });
        step(cx, &|window, cx| window.click("recordings-cancel", cx));
        step(cx, &|window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("recordings").is_none());
        });
        step(cx, &|window, cx| window.press("?", cx));
        app.read_with(cx, |app, _| assert!(app.show_shortcuts));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui_kit::test]
    fn recordings_open_in_the_background(cx: &mut TestAppContext) {
        let dir = std::env::temp_dir().join(format!("sysmon-ui-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut rec = sysmon_store::Recorder::new(&dir);
        let now = sysmon_ingest::unix_now_ns();
        for seq in 0..3u32 {
            let system = sysmon_proto::SystemSample {
                ts_unix_ns: now + seq as u64 * 1_000_000_000,
                ..Default::default()
            };
            for d in sysmon_proto::encode_sample(1, 2, seq, &system, &[], &[]).unwrap() {
                rec.append(1, 2, now + seq as u64 * 1_000_000_000, &d)
                    .unwrap();
            }
        }
        rec.flush().unwrap();
        drop(rec);

        let (_window, app) = open(cx);
        app.update(cx, |app, _| app.open_replay = open_without_engine);
        app.update(cx, |app, cx| app.open_path(dir.clone(), cx));
        // Returned at once, with the work still to do.
        app.read_with(cx, |app, _| {
            assert!(app.opening.is_some());
            assert!(app.replay.is_none());
        });
        cx.run_until_parked();
        app.read_with(cx, |app, _| {
            assert!(app.opening.is_none());
            assert!(app.replay.is_some(), "error: {:?}", app.error);
            assert_eq!(app.view, View::Replay);
        });

        // A failure is reported, not fatal.
        app.update(cx, |app, cx| app.open_path(dir.join("nothing-here"), cx));
        cx.run_until_parked();
        app.read_with(cx, |app, _| assert!(app.error.is_some()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui_kit::test]
    fn network_and_disk_tiles_show_both_directions(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        app.update(cx, |app, cx| {
            for seq in 0..2u32 {
                let k = seq as u64;
                let frame = test_frame(
                    1,
                    seq,
                    sysmon_proto::SystemSample {
                        ts_unix_ns: (1 + k) * 1_000_000_000,
                        net: vec![sysmon_proto::NetIf {
                            name: "eth0".into(),
                            rx_bytes: k * 2048,
                            tx_bytes: k * 1024,
                            rx_packets: 0,
                            tx_packets: 0,
                        }],
                        disks: vec![sysmon_proto::DiskStat {
                            name: "sda".into(),
                            sectors_read: k * 8,
                            sectors_written: k * 16,
                            io_ms: 0,
                        }],
                        ..Default::default()
                    },
                );
                apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            }
            app.ensure_selection();
            cx.notify();
        });
        cx.update_window(window, |_, window, cx| {
            window.render_frame(cx);
            let d = |id: &'static str| window.find(id).description().map(|d| d.to_string());
            assert_eq!(d("net-rx").as_deref(), Some("Network receive 2.0 KiB/s"));
            assert_eq!(d("net-tx").as_deref(), Some("Network transmit 1.0 KiB/s"));
            assert_eq!(d("disk-read").as_deref(), Some("Disk read 4.0 KiB/s"));
            assert_eq!(d("disk-write").as_deref(), Some("Disk write 8.0 KiB/s"));
            assert_eq!(d("net-total").as_deref(), Some("Network total 3.0 KiB/s"));
            assert_eq!(d("disk-total").as_deref(), Some("Disk total 12.0 KiB/s"));
            // The graphs say what their top stands for: the highest point.
            assert_eq!(d("net-scale").as_deref(), Some("max 2.0 KiB/s"));
            assert_eq!(d("disk-scale").as_deref(), Some("max 8.0 KiB/s"));
            // The total heads the tile, the directions go under the sparkline.
            for (t, a) in [("net-total", "net-rx"), ("disk-total", "disk-read")] {
                let (t, a) = (window.find(t).bounds(), window.find(a).bounds());
                assert!(t.origin.y + t.size.height < a.origin.y, "{t:?} {a:?}");
            }
            // Each pair sits on one line, incoming first.
            for (a, b) in [("net-rx", "net-tx"), ("disk-read", "disk-write")] {
                let (a, b) = (window.find(a).bounds(), window.find(b).bounds());
                assert_eq!(a.origin.y, b.origin.y, "{a:?} {b:?}");
                assert!(a.origin.x + a.size.width <= b.origin.x, "{a:?} {b:?}");
            }
            // A wider figure line widens its tile rather than overlapping the next.
            let (tx, rd) = (
                window.find("net-tx").bounds(),
                window.find("disk-read").bounds(),
            );
            assert!(
                tx.origin.x + tx.size.width <= rd.origin.x || tx.origin.y != rd.origin.y,
                "{tx:?} {rd:?}"
            );
        })
        .unwrap();
        // The history holds both directions separately, which the lines draw.
        app.read_with(cx, |app, _| {
            let p = app.live_hosts[&1].history.back().copied().unwrap();
            assert_eq!(
                (p.net_rx_bytes_per_s, p.net_tx_bytes_per_s),
                (2048.0, 1024.0)
            );
            assert_eq!(
                (p.disk_read_bytes_per_s, p.disk_write_bytes_per_s),
                (4096.0, 8192.0)
            );
        });
    }

    /// A host with one sample and, unless `lines` is empty, log lines
    /// numbered from 0 with a gap of two after the first.
    #[gpui_kit::test]
    fn an_empty_log_list_says_why(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        let note = |cx: &mut TestAppContext| {
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.try_find("logs-empty")
                    .and_then(|e| e.description().map(str::to_string))
            })
            .unwrap()
        };
        // Sending logs, but none yet.
        host_with_logs(&app, cx, &[]);
        app.update(cx, |app, cx| {
            app.ensure_selection();
            app.panel = Panel::Logs;
            cx.notify();
        });
        assert!(note(cx).unwrap().starts_with("No log lines yet"));

        // Lines, but none from the unit picked.
        host_with_logs(&app, cx, &["boom"]);
        app.update(cx, |app, cx| {
            app.log_source = Some("other.service".into());
            cx.notify();
        });
        assert!(note(cx).unwrap().starts_with("No lines match"));
        app.update(cx, |app, cx| {
            app.log_source = None;
            cx.notify();
        });
        assert_eq!(note(cx), None);
    }

    fn host_with_logs(app: &Entity<AppState>, cx: &mut TestAppContext, lines: &[&str]) {
        app.update(cx, |app, cx| {
            let frame = sysmon_proto::Frame {
                received_ns: 1,
                ..test_frame(1, 0, sampled_at(1_000_000_000))
            };
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            let entry = |msg: &str| sysmon_proto::LogEntry {
                ts_unix_ns: 1_000_000_000,
                priority: 3,
                unit: Some("web.service".into()),
                ident: "web".into(),
                pid: Some(42),
                message: msg.into(),
                truncated: false,
            };
            for (i, msg) in lines.iter().enumerate() {
                let first_seq = if i == 0 { 0 } else { i as u64 + 2 };
                apply(
                    &mut app.live_hosts,
                    sysmon_ingest::Event::Logs {
                        host_id: 1,
                        boot_id: 1,
                        batch: sysmon_proto::LogBatch {
                            run: 7,
                            first_seq,
                            dropped: 0,
                            entries: vec![entry(msg)],
                        },
                        received_ns: 10 + i as u64,
                    },
                );
            }
            // Past the reorder wait, so the gap is called lost.
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Logs {
                    host_id: 1,
                    boot_id: 1,
                    batch: sysmon_proto::LogBatch {
                        run: 7,
                        first_seq: if lines.is_empty() {
                            0
                        } else {
                            lines.len() as u64 + 2
                        },
                        dropped: 0,
                        entries: vec![],
                    },
                    received_ns: 20 + sysmon_model::logs::REORDER_WAIT_NS,
                },
            );
            app.ensure_selection();
            cx.notify();
        });
    }

    #[gpui_kit::test]
    fn the_logs_tab_lists_lines_and_follows_until_scrolled(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        host_with_logs(&app, cx, &["first\nmore", "second", "third"]);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                f(window, cx)
            })
            .unwrap();
            cx.run_until_parked();
        };
        step(cx, &|w, cx| w.press("l", cx));
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            w.render_frame(cx);
            let msg = |i: usize| {
                w.find(("log-message", i))
                    .description()
                    .map(|d| d.to_string())
            };
            assert_eq!(msg(0).as_deref(), Some("first\nmore"), "full text on hover");
            assert_eq!(
                msg(1).as_deref(),
                Some("2 lines lost on the way (datagrams didn't arrive)")
            );
            assert_eq!(msg(3).as_deref(), Some("third"));
            assert_eq!(
                w.find("logs-status")
                    .description()
                    .map(|d| d.to_string())
                    .as_deref(),
                Some("4 lines")
            );
            assert!(w.try_find("logs-latest").is_none(), "following");
        })
        .unwrap();

        // Nothing is picked, so the Graph tab can't be chosen.
        step(cx, &|w, cx| w.click("tab-graph", cx));
        assert!(app.read_with(cx, |a, _| a.panel == Panel::Logs));

        // Scrolling up stops following; Jump to latest resumes.
        step(cx, &|w, cx| {
            let at = w.find("logs-list").bounds().center();
            w.dispatch_event(
                gpui_kit::PlatformInput::Scroll(gpui_kit::ScrollEvent {
                    position: at,
                    delta: gpui_kit::ScrollDelta::Pixels(gpui_kit::point(
                        gpui_kit::px(0.),
                        gpui_kit::px(40.),
                    )),
                    ..Default::default()
                }),
                cx,
            );
        });
        assert!(!app.read_with(cx, |a, _| a.log_follow));
        step(cx, &|w, cx| w.click("logs-latest", cx));
        assert!(app.read_with(cx, |a, _| a.log_follow));

        // Clicking a line highlights it.
        step(cx, &|w, cx| w.click(("log-row", 2usize), cx));
        app.read_with(cx, |a, _| {
            assert_eq!(a.log_cursor, Some((11, 1_000_000_000)));
            assert!(!a.log_follow);
        });
        step(cx, &|w, cx| w.press("l", cx));
        assert!(!app.read_with(cx, |a, _| a.panel == Panel::Logs));
    }

    #[gpui_kit::test]
    fn the_logs_tab_is_off_when_a_host_sends_none(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        host_with_logs(&app, cx, &[]);
        app.update(cx, |a, _| {
            a.live_hosts.get_mut(&1).unwrap().logs = Default::default()
        });
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            w.press("l", cx);
        })
        .unwrap();
        cx.run_until_parked();
        app.read_with(cx, |app, _| {
            assert_ne!(app.panel, Panel::Logs);
            assert!(!app.available.has::<crate::actions::ToggleLogs>());
        });
    }

    #[gpui_kit::test]
    fn recorded_logs_mark_errors_and_seek_when_clicked(cx: &mut TestAppContext) {
        let dir = std::env::temp_dir().join(format!("sysmon-ui-logs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut rec = sysmon_store::Recorder::new(&dir);
        let s = 1_000_000_000u64;
        let t = 1_700_000_000 * s;
        let line = |first_seq: u64, priority: u8, msg: &str, at: u64| sysmon_proto::LogBatch {
            run: 5,
            first_seq,
            dropped: 0,
            entries: vec![sysmon_proto::LogEntry {
                ts_unix_ns: at,
                priority,
                unit: None,
                ident: "app".into(),
                pid: None,
                message: msg.into(),
                truncated: false,
            }],
        };
        // Ten seconds of samples, a warning at 2 s and an error at 6 s, in
        // the order received (as a recording always is).
        for seq in 0..10u32 {
            let at = t + seq as u64 * s;
            let system = sysmon_proto::SystemSample {
                ts_unix_ns: at,
                ..Default::default()
            };
            for d in sysmon_proto::encode_sample(1, 2, seq, &system, &[], &[]).unwrap() {
                rec.append(1, 2, at, &d).unwrap();
            }
            let log = match seq {
                2 => Some(line(0, 4, "warned", at)),
                6 => Some(line(1, 3, "failed", at)),
                _ => None,
            };
            if let Some(b) = log {
                let d = sysmon_proto::encode_logs(1, 2, seq, &b).unwrap();
                // Marked as the live recorder marks it.
                let errors =
                    sysmon_model::logs::has_errors(&sysmon_proto::decode(&d[0]).unwrap().1);
                rec.append_marked(1, 2, at, &d[0], errors).unwrap();
            }
        }
        rec.flush().unwrap();
        drop(rec);

        // The recording's events, fed by hand (an engine thread would wake
        // the UI from outside the test scheduler).
        let events: Vec<sysmon_ingest::Event> = {
            let mut src = sysmon_model::ReplaySource::open(&dir).unwrap();
            std::iter::from_fn(|| src.next_event()).collect()
        };
        let (handle, driver) = ReplayHandle::manual(ReplayStatus {
            start_ns: t,
            end_ns: t + 9 * s,
            position_ns: t + 9 * s,
            speed: 1.,
            paused: true,
            finished: true,
        });
        let (window, app) = open(cx);
        app.update(cx, |app, cx| app.start_session(handle, dir.clone(), cx));
        for e in events {
            driver.feed.send(Feed::Event(e)).unwrap();
        }
        cx.run_until_parked();
        app.read_with(cx, |a, _| {
            let marks = &a.replay.as_ref().unwrap().log_marks;
            assert_eq!(marks.len(), 1, "only the error is marked");
            assert_eq!(marks[0].received_ns, t + 6 * s);
            assert_eq!(a.hosts()[&1].logs.rows().len(), 2);
        });
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(
                w.try_find(("log-mark", 0usize)).is_some(),
                "error marked on the timeline"
            );
            assert!(w.try_find(("log-mark", 1usize)).is_none());
            // Clicking the mark goes to the error, with the logs open.
            w.click(("log-mark", 0usize), cx);
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(
            driver.controls.try_recv().ok(),
            Some(Control::Seek(t + 6 * s))
        );
        app.read_with(cx, |a, _| assert!(a.panel == Panel::Logs));

        // Clicking the warning seeks to when it was received.
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            w.click(("log-row", 0usize), cx);
        })
        .unwrap();
        cx.run_until_parked();
        app.read_with(cx, |a, _| {
            assert_eq!(a.log_cursor, Some((t + 2 * s, t + 2 * s)));
            assert!(
                a.log_reveal_after_reset,
                "to be brought into view after the seek"
            );
        });
        assert_eq!(
            driver.controls.try_recv().ok(),
            Some(Control::Seek(t + 2 * s))
        );

        // After the seek the list is rebuilt; the warning is found again and
        // brought into view.
        driver.feed.send(Feed::Reset).unwrap();
        let events: Vec<_> = {
            let mut src = sysmon_model::ReplaySource::open(&dir).unwrap();
            std::iter::from_fn(|| src.next_event()).collect()
        };
        for e in events.into_iter().take(4) {
            driver.feed.send(Feed::Event(e)).unwrap();
        }
        cx.run_until_parked();
        app.read_with(cx, |a, _| {
            assert!(!a.log_reveal_after_reset);
            assert_eq!(
                a.hosts()[&1].logs.rows().len(),
                1,
                "rebuilt up to the warning"
            );
        });
        cx.update_window(window, |_, w, cx| w.render_frame(cx))
            .unwrap();
        app.read_with(cx, |a, _| assert!(!a.log_reveal.get(), "revealed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One host running PID 42 ("web") at 1 s and 2 s, which logged a
    /// warning from web.service, an error from db.service, and later lost
    /// a line.
    fn host_with_mixed_logs(app: &Entity<AppState>, cx: &mut TestAppContext) {
        let s = 1_000_000_000u64;
        app.update(cx, |app, cx| {
            for seq in 0..2u32 {
                let at = (1 + seq as u64) * s;
                let frame = sysmon_proto::Frame {
                    procs: vec![sysmon_proto::ProcSample {
                        pid: 42,
                        ppid: 1,
                        starttime: 7,
                        state: b'S',
                        utime: seq as u64,
                        stime: 0,
                        rss_pages: 1,
                        threads: 1,
                        comm: "web".into(),
                        vsize_bytes: None,
                        shared_pages: None,
                        kernel_thread: Some(false),
                    }],
                    received_ns: at,
                    ..test_frame(
                        1,
                        seq,
                        sysmon_proto::SystemSample {
                            ts_unix_ns: at,
                            mem: sysmon_proto::MemInfo {
                                total: 1 << 20,
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                    )
                };
                apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            }
            let entry = |priority, unit: &str, pid, msg: &str| sysmon_proto::LogEntry {
                ts_unix_ns: 1_500_000_000,
                priority,
                unit: Some(unit.into()),
                ident: unit.trim_end_matches(".service").into(),
                pid: Some(pid),
                message: msg.into(),
                truncated: false,
            };
            let logs = |first_seq, entries, received_ns| sysmon_ingest::Event::Logs {
                host_id: 1,
                boot_id: 1,
                batch: sysmon_proto::LogBatch {
                    run: 1,
                    first_seq,
                    dropped: 0,
                    entries,
                },
                received_ns,
            };
            apply(
                &mut app.live_hosts,
                logs(
                    0,
                    vec![
                        entry(4, "web.service", 42, "slow request"),
                        entry(3, "db.service", 99, "connection refused"),
                    ],
                    2 * s,
                ),
            );
            apply(&mut app.live_hosts, logs(3, vec![], 2 * s));
            apply(&mut app.live_hosts, logs(3, vec![], 5 * s));
            app.ensure_selection();
            app.panel = Panel::Logs;
            cx.notify();
        });
    }

    fn shown_messages(app: &Entity<AppState>, cx: &mut TestAppContext) -> Vec<String> {
        app.read_with(cx, |a, cx| {
            let host = &a.live_hosts[&1];
            a.log_rows(host, cx)
                .into_iter()
                .map(|i| match &host.logs.rows()[i].kind {
                    sysmon_model::LogKind::Line(e) => e.message.clone(),
                    sysmon_model::LogKind::Lost(n) => format!("lost {n}"),
                    sysmon_model::LogKind::Dropped(n) => format!("dropped {n}"),
                })
                .collect()
        })
    }

    #[gpui_kit::test]
    fn logs_filter_by_text_priority_and_unit(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        host_with_mixed_logs(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                f(window, cx)
            })
            .unwrap();
            cx.run_until_parked();
        };
        assert_eq!(
            shown_messages(&app, cx),
            ["slow request", "connection refused", "lost 1"]
        );
        // Errors only; lost lines aren't shown once narrowed.
        step(cx, &|w, cx| w.click(("logs-priority", 3usize), cx));
        assert_eq!(shown_messages(&app, cx), ["connection refused"]);
        step(cx, &|w, cx| w.click(("logs-priority", 7usize), cx));

        // Clicking a unit shows only its lines, until its chip is removed.
        step(cx, &|w, cx| w.click(("log-source-cell", 0usize), cx));
        assert_eq!(shown_messages(&app, cx), ["slow request"]);
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert_eq!(
                w.find("logs-status")
                    .description()
                    .map(|d| d.to_string())
                    .as_deref(),
                Some("1 of 3 lines")
            );
        })
        .unwrap();
        assert_eq!(
            app.read_with(cx, |a, _| a.log_cursor),
            None,
            "not a row click"
        );
        step(cx, &|w, cx| w.click("logs-source", cx));
        assert_eq!(shown_messages(&app, cx).len(), 3);

        // Text matches the message or the unit, case-insensitively.
        let filter = app.read_with(cx, |a, _| a.log_filter.clone());
        cx.update_window(window, |_, w, cx| {
            filter.update(cx, |f, cx| f.set_value("REFUSED", w, cx))
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(shown_messages(&app, cx), ["connection refused"]);
        let filter = app.read_with(cx, |a, _| a.log_filter.clone());
        cx.update_window(window, |_, w, cx| {
            filter.update(cx, |f, cx| f.set_value("web", w, cx))
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(shown_messages(&app, cx), ["slow request"]);
    }

    #[gpui_kit::test]
    fn a_log_lines_pid_finds_the_process_and_its_time_marks_the_graph(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        host_with_mixed_logs(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                f(window, cx)
            })
            .unwrap();
            cx.run_until_parked();
        };
        // PID 42 is running: the table's cursor moves to it.
        step(cx, &|w, cx| w.click(("log-pid", 0usize), cx));
        app.read_with(cx, |a, _| {
            assert_eq!(a.cursor.map(|k| k.pid), Some(42));
            assert_eq!(a.error, None);
            assert_eq!(a.log_cursor, None, "not a row click");
        });
        // PID 99 isn't.
        step(cx, &|w, cx| w.click(("log-pid", 1usize), cx));
        assert_eq!(
            app.read_with(cx, |a, _| a.error.clone()).as_deref(),
            Some("PID 99 isn't running at this point")
        );

        // Select the warning, graph PID 42, and the graph marks the line's time.
        step(cx, &|w, cx| w.click(("log-row", 0usize), cx));
        step(cx, &|w, cx| w.press("g", cx));
        step(cx, &|w, cx| w.click("tab-graph", cx));
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let mark = w
                .find("graph-log-mark")
                .description()
                .map(|d| d.to_string());
            let expected = format!("log line {}", crate::format::time(1_500_000_000));
            assert_eq!(mark.as_deref(), Some(expected.as_str()));
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn the_details_tab_follows_the_cursor_and_keeps_an_exited_process(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        for seq in 0..3 {
            add_frame(&app, cx, seq);
        }
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                f(window, cx)
            })
            .unwrap();
            cx.run_until_parked();
        };
        let describe = |cx: &mut TestAppContext, id: gpui_kit::ElementId| {
            cx.update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.find(id).description().map(|d| d.to_string())
            })
            .unwrap()
        };

        // Nothing under the cursor yet.
        step(cx, &|w, cx| w.press("d", cx));
        app.read_with(cx, |a, _| assert_eq!(a.panel, Panel::Details));
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("details-empty").is_some());
        })
        .unwrap();

        // pid 10 (bash): its parent and child. By PID, rows are 1, 10, 11, 20.
        step(cx, &|w, cx| {
            w.press("shift-n", cx);
            w.press("down", cx);
            w.press("down", cx);
        });
        assert_eq!(
            describe(cx, "details-title".into()).as_deref(),
            Some("bash · PID 10")
        );
        assert_eq!(
            describe(cx, "details-parent".into()).as_deref(),
            Some("Parent 1 init")
        );
        let child = describe(cx, ("details-child", 0usize).into()).unwrap();
        assert!(child.contains("11") && child.contains("vim"), "{child}");
        assert_eq!(
            describe(cx, "details-state".into()).as_deref(),
            Some("State S – sleeping")
        );

        // The cursor moves on to vim, which then exits: still shown, marked.
        step(cx, &|w, cx| w.press("down", cx));
        assert_eq!(
            describe(cx, "details-title".into()).as_deref(),
            Some("vim · PID 11")
        );
        app.update(cx, |app, cx| {
            let frame = sysmon_proto::Frame {
                procs: vec![],
                ..test_frame(1, 3, sampled_at(4_000_000_000))
            };
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            cx.notify();
        });
        assert_eq!(
            describe(cx, "details-title".into()).as_deref(),
            Some("vim · PID 11")
        );
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert!(w.try_find("details-exited").is_some());
        })
        .unwrap();

        // Hide goes back to the graph (hidden, as nothing is picked).
        step(cx, &|w, cx| w.click("details-hide", cx));
        app.read_with(cx, |a, _| {
            assert_eq!(a.panel, Panel::Graph);
            assert!(!a.panel_shown());
        });
    }

    #[gpui_kit::test]
    fn the_details_tab_leads_to_relatives_the_graph_and_log_lines(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        add_host(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                f(window, cx)
            })
            .unwrap();
            cx.run_until_parked();
        };
        // pid 10 (bash), by PID rows 1, 10, 11, 20.
        step(cx, &|w, cx| {
            w.press("shift-n", cx);
            w.press("down", cx);
            w.press("down", cx);
            w.press("enter", cx);
        });
        // Its child, then that one's parent.
        step(cx, &|w, cx| w.click(("details-child", 0usize), cx));
        app.read_with(cx, |a, _| assert_eq!(a.cursor, Some(key(11))));
        step(cx, &|w, cx| w.click("details-parent", cx));
        app.read_with(cx, |a, _| assert_eq!(a.cursor, Some(key(10))));
        // Graph it, and take it out again.
        step(cx, &|w, cx| {
            assert!(w.try_find("details-graph-color").is_none());
            w.click("details-graph", cx)
        });
        app.read_with(cx, |a, _| {
            assert_eq!(picked(a), [SeriesTarget::Process(key(10))]);
            assert_eq!(a.panel, Panel::Details, "stays on Details");
        });
        // It says so, in its line's colour.
        step(cx, &|w, cx| {
            assert!(w.try_find("details-graph-color").is_some());
            w.click("details-graph", cx)
        });
        app.read_with(cx, |a, _| assert!(picked(a).is_empty()));
    }

    #[gpui_kit::test]
    fn a_details_log_line_opens_in_the_logs_tab(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        host_with_mixed_logs(&app, cx);
        let step = |cx: &mut TestAppContext,
                    f: &dyn Fn(&mut gpui_kit::Window, &mut gpui_kit::App)| {
            cx.update_window(window, |_, window, cx| {
                window.render_frame(cx);
                f(window, cx)
            })
            .unwrap();
            cx.run_until_parked();
        };
        // The helper opens the Logs tab.
        step(cx, &|w, cx| w.click(("log-pid", 0usize), cx)); // cursor on PID 42
        step(cx, &|w, cx| w.click("tab-details", cx));
        let logged = cx
            .update_window(window, |_, w, cx| {
                w.render_frame(cx);
                w.try_find(("details-log", 0usize)).is_some()
            })
            .unwrap();
        assert!(logged, "PID 42's line is listed");
        step(cx, &|w, cx| w.click(("details-log", 0usize), cx));
        app.read_with(cx, |a, _| {
            assert_eq!(a.panel, Panel::Logs);
            assert!(a.log_cursor.is_some());
            assert!(!a.log_follow);
        });
    }

    /// Buttons drawn as an icon alone still have a name to be found by.
    #[gpui_kit::test]
    fn icon_only_buttons_are_named(cx: &mut TestAppContext) {
        use gpui_kit::test::TestQueryExt as _;
        let (window, app) = open(cx);
        add_host(&app, cx);
        cx.update_window(window, |_, w, cx| {
            w.press("t", cx);
            w.press("d", cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            for name in ["Expand all", "Collapse all", "Hide the panel"] {
                assert!(w.try_find_by_label(name).is_some(), "{name}");
            }
        })
        .unwrap();
    }

    /// In the shortest panel, the details lists scroll: their rows keep
    /// their height rather than being squeezed together to fit.
    #[gpui_kit::test]
    fn details_rows_stay_whole_in_a_short_panel(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        send_threads(&app, cx);
        app.update(cx, |app, cx| {
            let proc = |pid: u32, ppid: u32, comm: String| sysmon_proto::ProcSample {
                pid,
                ppid,
                starttime: 0,
                state: b'S',
                utime: 0,
                stime: 0,
                rss_pages: 1,
                threads: 1,
                comm,
                vsize_bytes: None,
                shared_pages: None,
                kernel_thread: Some(false),
            };
            // pid 10 with 20 children, 40 threads and 20 log lines.
            let frame = sysmon_proto::Frame {
                procs: std::iter::once(proc(10, 1, "server".into()))
                    .chain((0..20).map(|i| proc(1000 + i, 10, format!("child-{i}"))))
                    .collect(),
                threads: (0..40)
                    .map(|i| sysmon_proto::ThreadSample {
                        tgid: 10,
                        tid: 100 + i,
                        starttime: 0,
                        state: b'S',
                        utime: 0,
                        stime: 0,
                        comm: format!("worker-{i}"),
                    })
                    .collect(),
                ..test_frame(1, 0, sampled_at(1_000_000_000))
            };
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            let entries = (0..20)
                .map(|i| sysmon_proto::LogEntry {
                    ts_unix_ns: 1_000_000_000 + i,
                    priority: 6,
                    unit: Some("server.service".into()),
                    ident: "server".into(),
                    pid: Some(10),
                    message: format!("line {i}"),
                    truncated: false,
                })
                .collect();
            apply(
                &mut app.live_hosts,
                sysmon_ingest::Event::Logs {
                    host_id: 1,
                    boot_id: 1,
                    batch: sysmon_proto::LogBatch {
                        run: 1,
                        first_seq: 0,
                        dropped: 0,
                        entries,
                    },
                    received_ns: 1_000_000_000,
                },
            );
            app.ensure_selection();
            app.cursor = Some(key(10));
            app.panel = Panel::Details;
            app.graph_height = px(super::GRAPH_MIN);
            cx.notify();
        });
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let panel = w.find("details-lists").bounds();
            let list = |id: &'static str, n: usize| -> Vec<_> {
                (0..n).map(|i| w.find((id, i)).bounds()).collect()
            };
            let children = list("details-child", 20);
            let threads = list("details-thread", 40);
            let logs = list("details-log", 20);
            // One column: children, then threads, then log lines.
            let column: Vec<_> = [&children, &threads, &logs]
                .into_iter()
                .flatten()
                .copied()
                .collect();
            assert!(
                column.last().unwrap().bottom() > panel.bottom(),
                "80 rows don't fit {panel:?}: the list scrolls"
            );
            // The facts beside them too.
            let facts: Vec<_> = [
                "details-pid",
                "details-parent",
                "details-user",
                "details-state",
                "details-started",
                "details-running",
                "details-threads",
                "details-cmdline",
            ]
            .into_iter()
            .map(|id| w.find(id).bounds())
            .collect();
            for (rows, what) in [
                (&children, "child"),
                (&threads, "thread"),
                (&logs, "log line"),
                (&column, "list row"),
                (&facts, "fact"),
            ] {
                for pair in rows.windows(2) {
                    assert!(pair[0].size.height >= px(12.), "{what} squeezed: {pair:?}");
                    assert!(
                        pair[1].top() >= pair[0].bottom(),
                        "{what}s overlap: {pair:?}"
                    );
                }
            }
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn replay_catch_up_is_applied_in_slices_and_skips_superseded_work(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        let (handle, driver) = ReplayHandle::manual(ReplayStatus::default());
        app.update(cx, |app, cx| {
            app.start_session(handle, std::path::PathBuf::from("/nonexistent"), cx);
            // One item per slice, to count them.
            app.replay_slice = std::time::Duration::ZERO;
        });
        let frame = |seq: u32| {
            Feed::Event(sysmon_ingest::Event::Frame(test_frame(
                1,
                seq,
                sampled_at((1 + seq as u64) * 1_000_000_000),
            )))
        };
        for seq in 0..5 {
            driver.feed.send(frame(seq)).unwrap();
        }
        cx.run_until_parked();
        app.read_with(cx, |a, _| {
            assert_eq!(a.replay_slices, 5, "one slice each, with frames between");
            assert_eq!(a.hosts()[&1].frames_received, 5, "all applied");
        });

        // A seek's reset queued behind unapplied work: that work is skipped.
        for seq in 5..50 {
            driver.feed.send(frame(seq)).unwrap();
        }
        driver.feed.send(Feed::Reset).unwrap();
        driver.feed.send(frame(100)).unwrap();
        cx.run_until_parked();
        app.read_with(cx, |a, _| {
            assert_eq!(
                a.replay_slices,
                5 + 2,
                "just the reset and the frame after it"
            );
            assert_eq!(a.hosts()[&1].frames_received, 1);
        });
    }

    #[gpui_kit::test]
    fn the_live_view_redraws_for_the_selected_host_and_ticks_for_the_rest(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        let s = 1_000_000_000u64;
        let sample = |host_id: u64, seq: u32, received_ns: u64| {
            sysmon_ingest::Event::Frame(sysmon_proto::Frame {
                received_ns,
                ..test_frame(host_id, seq, sampled_at((1 + seq as u64) * s))
            })
        };
        let t0 = std::time::Instant::now();
        let now = 100 * s;
        app.update(cx, |a, _| {
            // New hosts change the list: redraw.
            assert!(a.apply_live_batch(vec![sample(1, 0, now), sample(2, 0, now)], now));
            assert_eq!(a.selected, Some(1));
            // The selected host's sample: redraw at once.
            assert!(a.apply_live_batch(vec![sample(1, 1, now)], now));
            // Another host's: not at once, but the sidebar is out of date...
            assert!(!a.apply_live_batch(vec![sample(2, 1, now)], now));
            // ... and the next tick, a second on, redraws it, once.
            assert!(!a.live_tick(t0, now), "not yet a second since the last");
            let t1 = a.sidebar_drawn + std::time::Duration::from_secs(1);
            assert!(a.live_tick(t1, now));
            assert!(
                !a.live_tick(t1 + std::time::Duration::from_secs(1), now),
                "nothing new"
            );
            // Once a host is silent (nothing at all arrives), each tick
            // redraws so its dot turns red and the silence counts on.
            let later = now + 10 * s;
            let t2 = t1 + std::time::Duration::from_secs(2);
            assert!(a.live_tick(t2, later));
            assert!(a.live_tick(t2 + std::time::Duration::from_secs(1), later + s));
            // Not in the Recording view.
            a.view = View::Replay;
            assert!(!a.apply_live_batch(vec![sample(1, 2, now)], now));
            assert!(!a.live_tick(t2 + std::time::Duration::from_secs(5), later));
        });
    }
}
