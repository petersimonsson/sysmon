//! Top-level gpui entity: owns the live and replay host models and renders
//! the toolbar, host list, header, process table and replay timeline.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;
use std::path::PathBuf;
use std::rc::Rc;
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
use sysmon_ingest::Event;
use sysmon_model::{
    Control, Feed, HISTORY_LEN, HostModel, LogKind, Metric, ProcRow, ReplayHandle, ReplayStatus,
    SeriesTarget, ThreadRow, TreeLine,
};
use sysmon_proto::ProcKey;

use crate::actions::{self, *};
use crate::format;
use crate::graph;
use crate::selection::{self, Selection};
use crate::widgets::{Chosen as _, Highlighted as _, bar, sparkline};

mod details;

const ROW_HEIGHT: f32 = 20.;
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
/// Samples shown in the header's sparklines.
const SPARK_POINTS: usize = 240;
/// Initial height of the graph panel below the process list.
const GRAPH_HEIGHT: f32 = 260.;
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
/// A live host not heard from for this long is dropped, history and all.
const FORGET_AFTER_NS: u64 = 3600 * 1_000_000_000;
/// At most this many live hosts are kept; past it, the one silent longest
/// goes. Each can hold tens of MB of history, and without a key anyone can
/// send datagrams under made-up host IDs.
const MAX_LIVE_HOSTS: usize = 256;

/// What the app starts with; built in `main` before the window opens.
pub struct Start {
    pub live: Option<flume::Receiver<Event>>,
    /// A recording to play, and where it is.
    pub replay: Option<(ReplayHandle, PathBuf)>,
    /// Where live data is recorded, if it is.
    pub recording_to: Option<PathBuf>,
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
    live_hosts: BTreeMap<u64, HostModel>,
    /// When the monitor last got anything from each live host (its clock).
    live_heard: HashMap<u64, u64>,
    replay: Option<ReplaySession>,
    next_session: u64,
    /// Where live data is recorded, if it is.
    recording_to: Option<PathBuf>,
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
    graph_metric: Metric,
    graph_window_s: u64,
    graph_visible: bool,
    /// Mouse position over the chart, as a fraction of its width.
    graph_hover: Option<f32>,
    graph_bounds: graph::ChartBounds,
    /// Last known command of each graphed process, so the legend can still
    /// name processes that have exited; per view and host, like `selections`.
    graph_names: HashMap<(View, u64), HashMap<ProcKey, String>>,
    /// Graph lines kept between redraws (the chart redraws on every mouse
    /// move), by view, host, target and metric.
    graph_lines: std::cell::RefCell<graph::LineCache<(View, u64, SeriesTarget, Metric)>>,
    /// Height of the graph panel; drag the divider above it to change it.
    graph_height: Pixels,
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
    /// Light or dark was picked from the menu: stop following the system.
    theme_chosen: bool,
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
        if let Some(events) = start.live.clone() {
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
        // Light or dark as the system is, until one is picked from the menu.
        gpui_kit::component::Theme::sync_system_appearance(Some(window), cx);
        let subscriptions = vec![
            cx.observe_window_appearance(window, |this, window, cx| {
                if !this.theme_chosen {
                    gpui_kit::component::Theme::sync_system_appearance(Some(window), cx);
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
            theme_chosen: false,
            view: View::Live,
            live_enabled: start.live.is_some(),
            live_hosts: BTreeMap::new(),
            live_heard: HashMap::new(),
            replay: None,
            next_session: 0,
            recording_to: start.recording_to,
            selected: None,
            sort: (SortKey::Cpu, true),
            tree: false,
            hide_kernel: true,
            show_threads: false,
            collapsed: HashMap::new(),
            selections: HashMap::new(),
            cursor: None,
            graph_metric: Metric::Cpu,
            graph_window_s: graph::WINDOWS_S[2],
            graph_visible: true,
            graph_hover: None,
            graph_bounds: Default::default(),

            graph_names: HashMap::new(),
            graph_lines: Default::default(),
            graph_height: px(GRAPH_HEIGHT),
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
            error: None,
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
        if std::mem::take(&mut self.sidebar_stale) || silent {
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

    fn open_recording(&mut self, cx: &mut Context<Self>) {
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
                            .child("×")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.error = None;
                                cx.notify();
                            })),
                    )
            })
            .child(
                Button::new("open")
                    .label("Open recording…")
                    .small()
                    .ghost()
                    .on_click(cx.listener(|this, _, _, cx| this.open_recording(cx))),
            )
            // Where live data goes; nothing in a recording, whose own path
            // is beside the Recording button (the data directory beside it
            // read as a second, different recording).
            .when(self.view == View::Live && self.live_enabled, |b| {
                let text = match &self.recording_to {
                    Some(dir) => format!("Recording to {}", dir.display()),
                    None => "Not recording".into(),
                };
                b.child(
                    div()
                        .id("recording-to")
                        .test_support()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .aria_description(text.clone())
                        .child(text),
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
                            .child(div().size(px(7.)).rounded_full().bg(if stale {
                                theme.danger
                            } else {
                                theme.success
                            }))
                            .child(clipped(
                                ("host-name", id as usize),
                                host.name(),
                                format!("{} · host id {:016x}", host.name(), id),
                            )),
                    )
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
                .aria_description(text.clone())
                .child(text),
        )
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
        let mem_pct = if mem.total > 0 {
            mem_used as f32 / mem.total as f32 * 100.0
        } else {
            0.0
        };
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
        let colored = |id: &'static str, text: String, what: &str, color: Hsla| {
            let figure = text.split_once(' ').map_or(text.as_str(), |(_, f)| f);
            div()
                .id(id)
                .test_support()
                .text_color(color)
                .aria_description(format!("{what} {figure}"))
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
                        spark(
                            vec![
                                (recent(|p| p.net_rx_bytes_per_s as f32), in_color),
                                (recent(|p| p.net_tx_bytes_per_s as f32), out_color),
                            ],
                            None,
                        ),
                    ))
                    .child(metric(
                        "Disk",
                        total("disk-total", format::bytes_per_s(rd + wr), "Disk total"),
                        Some(pair(
                            colored(
                                "disk-read",
                                format!("R {}", format::bytes_per_s(rd)),
                                "Disk read",
                                in_color,
                            ),
                            colored(
                                "disk-write",
                                format!("W {}", format::bytes_per_s(wr)),
                                "Disk write",
                                out_color,
                            ),
                        )),
                        spark(
                            vec![
                                (recent(|p| p.disk_read_bytes_per_s as f32), in_color),
                                (recent(|p| p.disk_write_bytes_per_s as f32), out_color),
                            ],
                            None,
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
                            .child(format!(
                                "{} processes ({} kernel threads) · sample {} ({})",
                                s.procs.len(),
                                s.procs.iter().filter(|p| p.kernel_thread).count(),
                                format::datetime(s.ts_unix_ns),
                                format::utc_offset(s.ts_unix_ns)
                            )),
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
            let prefix = child_prefix(&t.guides);
            let n = threads.len();
            let thread_lines: Vec<Line> = threads
                .into_iter()
                .enumerate()
                .map(|(k, th)| {
                    let last = k + 1 == n && !t.has_children;
                    let tree = TreeLine {
                        row: t.row,
                        depth: t.depth + 1,
                        guides: format!("{prefix}{}", if last { "└─ " } else { "├─ " }),
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
        match self.selection().filter(|s| !s.is_empty()) {
            Some(sel) => parts.push(format!("{} graphed", sel.len())),
            // The checkboxes have no header: say what they're for.
            None => parts.push("tick a row's box (or press G) to graph it".into()),
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
        let list = uniform_list("procs", count, move |range, _, _| {
            range
                .map(|i| {
                    let line = &rows[i];
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
                        Some(_) => "Remove from the graph (G)",
                        None if line.thread.is_some() => "Graph this thread (G)",
                        None => "Graph this process (G)",
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
                                .aria_description(pick_tip)
                                .tooltip(move |window, cx| Tooltip::new(pick_tip).build(window, cx))
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
                        .child(command_cell(line, i, &this, &theme))
                })
                .collect()
        })
        .track_scroll(&self.scroll)
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
                        div()
                            .w(px(260.))
                            .child(Input::new(&self.filter).small().cleanable(true)),
                    )
                    .child(
                        Button::new("tree")
                            .label("Tree")
                            .small()
                            .chosen(self.tree)
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_tree(cx))),
                    )
                    .child(
                        Button::new("kernel-toggle")
                            .label("Kernel threads")
                            .small()
                            // Like its neighbours: highlighted means shown.
                            .chosen(!self.hide_kernel)
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_kernel_threads(cx))),
                    )
                    .child(
                        Button::new("threads-toggle")
                            .label("Threads")
                            .small()
                            .chosen(self.show_threads)
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_threads(cx))),
                    )
                    .when(self.tree, |d| {
                        d.child(
                            Button::new("expand-all")
                                .label("Expand all")
                                .small()
                                .ghost()
                                .on_click(cx.listener(|this, _, _, cx| this.expand_all(cx))),
                        )
                        .child(
                            Button::new("collapse-all")
                                .label("Collapse all")
                                .small()
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

    /// Move the cursor by `delta` rows in the table's current order.
    fn move_cursor(&mut self, delta: isize, cx: &mut Context<Self>) {
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
                Some((key, row.comm.clone()))
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
        let hover_ns = self
            .graph_hover
            .map(|f| start + ((end - start) as f64 * f as f64) as u64);

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
                    .label("Clear")
                    .small()
                    .ghost()
                    .on_click(cx.listener(|this, _, _, cx| this.clear_graph(cx))),
            )
            .child(
                Button::new("graph-hide")
                    .label("Hide")
                    .small()
                    .ghost()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.graph_visible = false;
                        cx.notify();
                    })),
            );

        // Chart with y labels on the left and times underneath.
        let y_labels = div()
            .flex()
            .flex_col()
            .justify_between()
            .w(px(AXIS_LABELS_W))
            .h_full()
            .pr_1()
            .text_xs()
            .text_color(theme.muted_foreground)
            .items_end()
            .child(graph::format_value(metric, y_max))
            .child(graph::format_value(metric, y_max / 2.0))
            .child(graph::format_value(metric, 0.0));
        let plot = div()
            .id("graph-plot")
            .test_support()
            .flex_1()
            .h_full()
            .border_1()
            .border_color(theme.border)
            .on_mouse_move(cx.listener(|this, ev: &MouseMoveEvent, _, cx| {
                if let Some(b) = this.graph_bounds.get() {
                    let f = f32::from(ev.position.x - b.origin.x) / f32::from(b.size.width);
                    this.graph_hover = Some(f.clamp(0.0, 1.0));
                    cx.notify();
                }
            }))
            .on_hover(cx.listener(|this, hovered: &bool, _, cx| {
                if !*hovered {
                    this.graph_hover = None;
                    cx.notify();
                }
            }))
            .child(graph::chart(
                graph::ChartSpec {
                    lines: lines.clone(),
                    start_ns: start,
                    end_ns: end,
                    y_max,
                    hover_ns,
                    mark: self.log_cursor.map(|(_, ts)| (ts, theme.warning)),
                    grid: theme.border,
                    crosshair: theme.muted_foreground,
                },
                self.graph_bounds.clone(),
            ));
        let x_labels = div()
            .flex()
            .justify_between()
            .pl(px(AXIS_LABELS_W))
            .text_xs()
            .text_color(theme.muted_foreground)
            .child(format::time(start))
            .child(match (hover_ns, self.log_cursor) {
                (Some(h), _) => div().child(format::time(h)).into_any_element(),
                // The selected log line's time, drawn as a line on the chart.
                (None, Some((_, ts))) if (start..=end).contains(&ts) => {
                    let text = format!("log line {}", format::time(ts));
                    div()
                        .id("graph-log-mark")
                        .test_support()
                        .text_color(theme.warning)
                        .aria_description(text.clone())
                        .child(text)
                        .into_any_element()
                }
                _ => div().into_any_element(),
            })
            .child(format::time(end));
        let chart = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .h_full()
            .gap_1()
            .child(div().flex().flex_1().min_h_0().child(y_labels).child(plot))
            .child(x_labels);

        // Legend: one entry per line with its value now (or at the crosshair).
        let mut legend = div()
            .flex()
            .flex_col()
            .gap_1()
            .w(px(300.))
            .pl_3()
            .text_xs()
            .child(
                div()
                    .text_color(theme.muted_foreground)
                    .child(match hover_ns {
                        Some(t) => format!("{} at {}", metric.label(), format::time(t)),
                        None => format!("{} now", metric.label()),
                    }),
            );
        for (p, line) in picks.iter().zip(lines.iter()) {
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
            let value = match hover_ns {
                Some(t) => graph::value_at(&line.points, t),
                None => latest.map(|(v, _)| v),
            };
            let value = match (value, latest) {
                (Some(v), _) => graph::format_value(metric, v),
                (None, None) => "exited".into(),
                (None, Some(_)) => "–".into(),
            };
            legend = legend.child(
                div()
                    .id(("legend", p.slot))
                    .test_support()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_none().size(px(10.)).rounded_sm().bg(line.color))
                    .child(clipped(("legend-label", p.slot), label.clone(), label))
                    .child(
                        div()
                            .flex_none()
                            .font_family(theme.mono_font_family.clone())
                            .child(value),
                    )
                    .child(
                        div()
                            .id(("legend-remove", p.slot))
                            .test_support()
                            .flex_none()
                            .px_1()
                            .cursor_pointer()
                            .text_color(theme.muted_foreground)
                            .child("×")
                            .on_click(cx.listener(move |this, _, _, cx| this.remove_pick(key, cx))),
                    ),
            );
        }

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
                    .child(chart)
                    .child(legend),
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
                    .label("Logs")
                    .small()
                    .chosen(self.panel == Panel::Logs)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.panel = Panel::Logs;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("tab-details")
                    .label("Details")
                    .small()
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
                div()
                    .w(px(200.))
                    .child(Input::new(&self.log_filter).small().cleanable(true)),
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
                        .label(format!("{source} ×"))
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
                    .label("Hide")
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
                            let (label, color) = priority_style(e.priority, &theme);
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
                            base.child(
                                div()
                                    .flex_none()
                                    .w(px(LOG_PRI_COL))
                                    .text_color(color)
                                    .child(label),
                            )
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
                                        let _ =
                                            this.update(cx, |app, cx| app.show_process(pid, cx));
                                    })
                                    .child(pid.map_or_else(|| "–".into(), |p| p.to_string()))
                            })
                            .child(clipped(
                                ("log-message", i),
                                text,
                                tip,
                            ))
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
                    .child(list),
            )
    }

    /// Sort by `key`, or flip the direction if already sorted by it.
    fn sort_by(&mut self, key: SortKey, cx: &mut Context<Self>) {
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

    /// Hook every action up to the root element.
    fn actions(&self, root: Div, cx: &mut Context<Self>) -> Div {
        root.on_action(cx.listener(|this, _: &OpenRecording, _, cx| this.open_recording(cx)))
            .on_action(cx.listener(|this, _: &ShowLive, _, cx| this.show(View::Live, cx)))
            .on_action(cx.listener(|this, _: &ShowRecording, _, cx| this.show(View::Replay, cx)))
            .on_action(cx.listener(|this, _: &NextHost, _, cx| this.step_host(true, cx)))
            .on_action(cx.listener(|this, _: &PreviousHost, _, cx| this.step_host(false, cx)))
            .on_action(cx.listener(|this, _: &FocusFilter, window, cx| {
                this.filter.update(cx, |f, cx| f.focus(window, cx));
            }))
            .on_action(cx.listener(|this, _: &Dismiss, window, cx| {
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
            }))
            .on_action(cx.listener(|this, _: &ToggleShortcuts, _, cx| {
                this.show_shortcuts = !this.show_shortcuts;
                cx.notify();
            }))
            .on_action(
                cx.listener(|this, _: &ToggleKernelThreads, _, cx| this.toggle_kernel_threads(cx)),
            )
            .on_action(cx.listener(|this, _: &ToggleThreads, _, cx| this.toggle_threads(cx)))
            .on_action(cx.listener(|this, _: &ToggleTree, _, cx| this.toggle_tree(cx)))
            .on_action(cx.listener(|this, _: &ExpandAll, _, cx| this.expand_all(cx)))
            .on_action(cx.listener(|this, _: &CollapseAll, _, cx| this.collapse_all(cx)))
            .on_action(cx.listener(|this, _: &SortByCpu, _, cx| this.sort_by(SortKey::Cpu, cx)))
            .on_action(cx.listener(|this, _: &SortByMemory, _, cx| this.sort_by(SortKey::Res, cx)))
            .on_action(cx.listener(|this, _: &SortByVirt, _, cx| this.sort_by(SortKey::Virt, cx)))
            .on_action(cx.listener(|this, _: &SortByShr, _, cx| this.sort_by(SortKey::Shr, cx)))
            .on_action(cx.listener(|this, _: &SortByPid, _, cx| this.sort_by(SortKey::Pid, cx)))
            .on_action(cx.listener(|this, _: &SortByUser, _, cx| this.sort_by(SortKey::User, cx)))
            .on_action(
                cx.listener(|this, _: &SortByCommand, _, cx| this.sort_by(SortKey::Command, cx)),
            )
            .on_action(cx.listener(|this, _: &CursorUp, _, cx| this.move_cursor(-1, cx)))
            .on_action(cx.listener(|this, _: &CursorDown, _, cx| this.move_cursor(1, cx)))
            .on_action(cx.listener(|this, _: &CursorPageUp, _, cx| {
                this.move_cursor(-actions::PAGE_ROWS, cx)
            }))
            .on_action(cx.listener(|this, _: &CursorPageDown, _, cx| {
                this.move_cursor(actions::PAGE_ROWS, cx)
            }))
            .on_action(cx.listener(|this, _: &ToggleGraph, _, cx| this.toggle_cursor(cx)))
            .on_action(cx.listener(|this, _: &ClearGraph, _, cx| this.clear_graph(cx)))
            .on_action(cx.listener(|this, _: &About, window, cx| this.open_about(window, cx)))
            .on_action(cx.listener(|this, _: &ToggleDarkTheme, window, cx| {
                use gpui_kit::component::{Theme, ThemeMode};
                let mode = if cx.theme().is_dark() {
                    ThemeMode::Light
                } else {
                    ThemeMode::Dark
                };
                Theme::change(mode, Some(window), cx);
                this.theme_chosen = true;
            }))
            .on_action(cx.listener(|this, _: &ToggleLogs, _, cx| {
                this.panel = if this.panel == Panel::Logs {
                    Panel::Graph
                } else {
                    Panel::Logs
                };
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ToggleGraphPanel, _, cx| {
                this.graph_visible = !this.graph_visible;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &GraphCpu, _, cx| this.set_metric(Metric::Cpu, cx)))
            .on_action(cx.listener(|this, _: &GraphRss, _, cx| this.set_metric(Metric::Rss, cx)))
            .on_action(cx.listener(|this, _: &GraphVirt, _, cx| this.set_metric(Metric::Virt, cx)))
            .on_action(cx.listener(|this, _: &GraphShr, _, cx| this.set_metric(Metric::Shr, cx)))
            .on_action(cx.listener(|this, _: &GraphMem, _, cx| this.set_metric(Metric::MemPct, cx)))
            .on_action(
                cx.listener(|this, _: &GraphThreads, _, cx| this.set_metric(Metric::Threads, cx)),
            )
            .on_action(cx.listener(|this, _: &CycleGraphWindow, _, cx| {
                let i = graph::WINDOWS_S
                    .iter()
                    .position(|&w| w == this.graph_window_s)
                    .map_or(0, |i| (i + 1) % graph::WINDOWS_S.len());
                this.graph_window_s = graph::WINDOWS_S[i];
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &TogglePause, _, _| {
                if this.view == View::Replay {
                    this.control(Control::TogglePause);
                }
            }))
            .on_action(cx.listener(|this, _: &Faster, _, _| this.change_speed(true)))
            .on_action(cx.listener(|this, _: &Slower, _, _| this.change_speed(false)))
            .on_action(cx.listener(|this, _: &SeekBackward, _, _| {
                this.seek_by(-(actions::SEEK_SHORT_S as i64))
            }))
            .on_action(
                cx.listener(|this, _: &SeekForward, _, _| {
                    this.seek_by(actions::SEEK_SHORT_S as i64)
                }),
            )
            .on_action(cx.listener(|this, _: &SeekBackwardLong, _, _| {
                this.seek_by(-(actions::SEEK_LONG_S as i64))
            }))
            .on_action(cx.listener(|this, _: &SeekForwardLong, _, _| {
                this.seek_by(actions::SEEK_LONG_S as i64)
            }))
            .on_action(cx.listener(|this, _: &SeekStart, _, _| this.seek_to(|st| st.start_ns)))
            .on_action(cx.listener(|this, _: &SeekEnd, _, _| this.seek_to(|st| st.end_ns)))
    }

    /// Overlay listing every shortcut, grouped as in [`actions::SHORTCUTS`],
    /// then what the mouse does ([`actions::MOUSE`]).
    fn render_shortcuts(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut groups: Vec<(&str, Vec<(String, &str)>)> = Vec::new();
        for s in actions::SHORTCUTS {
            let keys = s
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
        let play_label = if st.finished && st.paused {
            "Replay"
        } else if st.paused {
            "Play"
        } else {
            "Pause"
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
                    Button::new("play")
                        .label(play_label)
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

/// The guide prefix for a tree line's children, from the line's own guides.
fn child_prefix(guides: &str) -> String {
    if let Some(p) = guides.strip_suffix("├─ ") {
        format!("{p}│  ")
    } else if let Some(p) = guides.strip_suffix("└─ ") {
        format!("{p}   ")
    } else {
        String::new()
    }
}

/// The COMMAND cell: in tree mode, guide lines, a clickable expand/collapse
/// marker, and a summary of what a collapsed subtree hides.
fn command_cell(
    line: &Line,
    i: usize,
    this: &WeakEntity<AppState>,
    theme: &gpui_kit::component::Theme,
) -> impl IntoElement + use<> {
    let cell = div()
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
            .w(px(14.))
            .cursor_pointer()
            .text_color(theme.foreground)
            .child(if t.collapsed { "▸" } else { "▾" })
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
            .w(px(14.))
    };
    cell.child(
        div()
            .flex_none()
            .text_color(theme.muted_foreground)
            .child(t.guides.clone()),
    )
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
const LOG_PRI_COL: f32 = 52.;
const LOG_SOURCE_COL: f32 = 160.;
const LOG_PID_COL: f32 = 56.;

/// A syslog priority's label and colour: errors and worse red, warnings
/// orange, notices plain, info and debug muted.
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

/// A size in KiB as table text; "–" when the agent didn't report it.
fn size_cell(kib: Option<u64>) -> String {
    kib.map_or_else(|| "–".into(), |k| format::bytes(k as f64 * 1024.0))
}

fn command(p: &ProcRow) -> String {
    p.cmdline
        .clone()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("[{}]", p.comm))
}

impl Render for AppState {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mono_char = mono_char_width(window, cx);
        self.refresh_graph_names();
        self.refresh_details();
        let panel_shown = self.panel_shown();
        // Keep the panel within the window if the window shrank.
        let max_graph = (window.viewport_size().height - px(GRAPH_MIN_LIST)).max(px(GRAPH_MIN));
        self.graph_height = self.graph_height.clamp(px(GRAPH_MIN), max_graph);
        let theme = cx.theme().clone();
        let toolbar = self.render_toolbar(cx);
        let sidebar = self.render_sidebar(cx);
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
                            .child(self.render_procs(host, mono_char, cx)),
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
                    View::Live => "Waiting for agents…",
                    View::Replay => "Loading recording…",
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
        cx.update(|cx| {
            gpui_kit::init(cx);
            crate::actions::init(cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: point(px(0.), px(0.)),
                    size: size(px(1200.), px(800.)),
                })),
                ..Default::default()
            };
            let start = Start {
                live: None,
                replay: None,
                recording_to: Some(std::env::temp_dir()),
            };
            gpui_kit::open_window(options, cx, |window, cx| {
                cx.new(|cx| AppState::new(start, window, cx))
            })
            .expect("open test window")
        })
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

    #[gpui_kit::test]
    fn shortcuts_change_view_state(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        cx.update_window(window, |_, window, cx| {
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
            window.input("bash", cx);
        });
        app.read_with(cx, |app, cx| {
            assert!(!app.tree, "t is typed into the filter, not a shortcut");
            assert_eq!(app.filter.read(cx).value().as_ref(), "tbash");
        });

        // Enter returns focus to the app; single-key shortcuts work again.
        step(cx, &|window, cx| window.press("enter", cx));
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
        app.read_with(cx, |app, _| {
            let f = app.graph_hover.expect("hovering sets the crosshair");
            assert!((f - 0.5).abs() < 0.05, "{f}");
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
        step(cx, &|window, cx| window.press("t", cx));
        app.read_with(cx, |app, _| assert!(app.tree));

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

        // Graph keys follow the column order.
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
                            .map(|t| t.guides.clone())
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
        // Off by default; with an agent that doesn't send threads, say so.
        assert!(table(&app, cx).iter().all(|(_, th, _)| !th));
        step(cx, &|window, cx| window.press("ctrl-h", cx));
        app.read_with(cx, |app, cx| {
            let host = &app.hosts()[&1];
            let s = app.status_line(host, &app.table_lines(host, cx), cx);
            assert!(s.contains("start this host's agent with --threads"), "{s}");
        });

        send_threads(&app, cx);
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
        })
        .unwrap();
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
    fn the_view_menu_switches_between_light_and_dark(cx: &mut TestAppContext) {
        use gpui_kit::component::ActiveTheme as _;
        let (window, app) = open(cx);
        let dark = |cx: &mut TestAppContext| cx.update(|cx| cx.theme().is_dark());
        let before = dark(cx);
        cx.update_window(window, |_, w, cx| {
            w.dispatch_action(Box::new(crate::actions::ToggleDarkTheme), cx)
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(dark(cx), !before);
        app.read_with(cx, |app, _| {
            assert!(app.theme_chosen, "no longer following the system")
        });
        cx.update_window(window, |_, w, cx| {
            w.dispatch_action(Box::new(crate::actions::ToggleDarkTheme), cx)
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(dark(cx), before);
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
            assert_eq!(pick.description(), Some("Graph this process (G)"));
            w.click(("pick", 0usize), cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            let pick = w.find(("pick", 0usize));
            assert_eq!(pick.description(), Some("Remove from the graph (G)"));
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
        // Opens the recording for real (in the background), but plays it
        // with a handle driven by hand rather than an engine thread.
        fn open_without_engine(
            path: &std::path::Path,
            _speed: f64,
        ) -> anyhow::Result<ReplayHandle> {
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
    fn the_logs_tab_says_when_a_host_sends_none(cx: &mut TestAppContext) {
        let (window, app) = open(cx);
        host_with_logs(&app, cx, &[]);
        app.update(cx, |a, _| {
            a.live_hosts.get_mut(&1).unwrap().logs = Default::default()
        });
        cx.update_window(window, |_, w, cx| {
            w.press("l", cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(window, |_, w, cx| {
            w.render_frame(cx);
            assert_eq!(
                w.find("logs-status")
                    .description()
                    .map(|d| d.to_string())
                    .as_deref(),
                Some("No logs from this host: start its agent with --logs")
            );
        })
        .unwrap();
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

        // Nothing under the cursor yet. (The panel is closed while nothing
        // is picked; the Logs tab opens it.)
        step(cx, &|w, cx| w.press("l", cx));
        step(cx, &|w, cx| w.click("tab-details", cx));
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
            w.press("l", cx);
        });
        step(cx, &|w, cx| w.click("tab-details", cx));
        // Its child, then that one's parent.
        step(cx, &|w, cx| w.click(("details-child", 0usize), cx));
        app.read_with(cx, |a, _| assert_eq!(a.cursor, Some(key(11))));
        step(cx, &|w, cx| w.click("details-parent", cx));
        app.read_with(cx, |a, _| assert_eq!(a.cursor, Some(key(10))));
        // Graph it, and take it out again.
        step(cx, &|w, cx| w.click("details-graph", cx));
        app.read_with(cx, |a, _| {
            assert_eq!(picked(a), [SeriesTarget::Process(key(10))]);
            assert_eq!(a.panel, Panel::Details, "stays on Details");
        });
        step(cx, &|w, cx| w.click("details-graph", cx));
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
