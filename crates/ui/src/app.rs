//! Top-level gpui entity: owns the live and replay host models and renders
//! the toolbar, host list, header, process table and replay timeline.

use std::collections::{BTreeMap, HashMap, HashSet};
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
    Control, Feed, HISTORY_LEN, HostModel, LogKind, LogRow, Metric, ProcRow, ReplayHandle,
    ReplayStatus, SeriesTarget, ThreadRow, TreeLine,
};
use sysmon_proto::ProcKey;

use crate::actions::{self, *};
use crate::format;
use crate::graph;
use crate::selection::{self, Selection};
use crate::widgets::{bar, sparkline};

const ROW_HEIGHT: f32 = 20.;
/// Width of the VIRT, RES and SHR columns; fits "1023.9 MiB".
const SIZE_COL: f32 = 80.;
/// The USER column fits the longest name shown, within these many characters;
/// longer names are shortened in the middle.
const USER_MIN_CHARS: usize = 4;
const USER_MAX_CHARS: usize = 16;
const MENU_BAR_HEIGHT: f32 = 30.;
/// Initial height of the graph panel below the process list.
const GRAPH_HEIGHT: f32 = 260.;
/// Smallest graph panel, and room always left for the rest of the window.
const GRAPH_MIN: f32 = 140.;
const GRAPH_MIN_LIST: f32 = 300.;
/// Slider resolution: positions are mapped onto 0..TIMELINE_STEPS.
const TIMELINE_STEPS: f32 = 10_000.;
const SPEEDS: [f64; 5] = [1., 4., 16., 64., 256.];
/// A live host not heard from for this long is dropped, history and all.
const FORGET_AFTER_NS: u64 = 3600 * 1_000_000_000;
/// At most this many live hosts are kept; past it, the one silent longest
/// goes. Each can hold tens of MB of history, and without a key anyone can
/// send datagrams under made-up host IDs.
const MAX_LIVE_HOSTS: usize = 256;

/// What the app starts with; built in `main` before the window opens.
pub struct Start {
    pub live: Option<flume::Receiver<Event>>,
    pub replay: Option<ReplayHandle>,
    pub replay_label: String,
    pub data_dir: PathBuf,
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
    _feed: Task<()>,
}

pub struct AppState {
    view: View,
    live_enabled: bool,
    live_hosts: BTreeMap<u64, HostModel>,
    /// When the monitor last got anything from each live host (its clock).
    live_heard: HashMap<u64, u64>,
    replay: Option<ReplaySession>,
    next_session: u64,
    data_dir: PathBuf,
    selected: Option<u64>,
    sort: (SortKey, bool),
    /// Show processes as a tree grouped by parent.
    tree: bool,
    /// Leave kernel threads out of the table (on by default).
    hide_kernel: bool,
    /// List each process's threads (off by default; needs `agent --threads`).
    show_threads: bool,
    collapsed: HashSet<ProcKey>,
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
    /// name processes that have exited.
    graph_names: HashMap<ProcKey, String>,
    /// Height of the graph panel; drag the divider above it to change it.
    graph_height: Pixels,
    /// While dragging the divider: pointer y and panel height at the start.
    graph_drag: Option<(Pixels, Pixels)>,
    /// The bottom panel shows the host's logs instead of the graph.
    show_logs: bool,
    /// Keep the newest log line in view; scrolling up stops it.
    log_follow: bool,
    log_scroll: UniformListScrollHandle,
    /// The highlighted log line, by its receive and log times (which survive
    /// the model being rebuilt by a seek, unlike row ids).
    log_cursor: Option<(u64, u64)>,
    filter: Entity<InputState>,
    timeline: Entity<SliderState>,
    scrubbing: bool,
    /// The recording being opened, if any.
    opening: Option<String>,
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
}

impl AppState {
    pub fn new(start: Start, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let filter = cx.new(|cx| InputState::new(window, cx).placeholder("Filter processes"));
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
                        let now = sysmon_ingest::unix_now_ns();
                        for event in batch {
                            this.apply_live(event, now);
                        }
                        this.forget_hosts(now);
                        if this.view == View::Live {
                            this.ensure_selection();
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
                });
                if alive.is_err() {
                    break;
                }
            }
        }));

        let subscriptions = vec![
            cx.subscribe_in(
                &filter,
                window,
                |this, _, event: &InputEvent, window, cx| {
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
                },
            ),
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
            view: View::Live,
            live_enabled: start.live.is_some(),
            live_hosts: BTreeMap::new(),
            live_heard: HashMap::new(),
            replay: None,
            next_session: 0,
            data_dir: start.data_dir,
            selected: None,
            sort: (SortKey::Cpu, true),
            tree: false,
            hide_kernel: true,
            show_threads: false,
            collapsed: HashSet::new(),
            selections: HashMap::new(),
            cursor: None,
            graph_metric: Metric::Cpu,
            graph_window_s: graph::WINDOWS_S[2],
            graph_visible: true,
            graph_hover: None,
            graph_bounds: Default::default(),

            graph_names: HashMap::new(),
            graph_height: px(GRAPH_HEIGHT),
            graph_drag: None,
            show_logs: false,
            log_follow: true,
            log_scroll: UniformListScrollHandle::new(),
            log_cursor: None,
            filter,
            timeline,
            scrubbing: false,
            opening: None,
            shown_status: None,
            scroll: UniformListScrollHandle::new(),
            error: None,
            _tasks: tasks,
            _subscriptions: subscriptions,
        };
        if let Some(handle) = start.replay {
            this.start_session(handle, start.replay_label, cx);
        }
        this
    }

    fn hosts(&self) -> &BTreeMap<u64, HostModel> {
        match (self.view, &self.replay) {
            (View::Replay, Some(s)) => &s.hosts,
            _ => &self.live_hosts,
        }
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

    fn ensure_selection(&mut self) {
        let hosts = self.hosts();
        if self.selected.is_none_or(|id| !hosts.contains_key(&id)) {
            self.selected = self.host_order().first().copied();
        }
    }

    // ---- replay ---------------------------------------------------------

    fn start_session(&mut self, handle: ReplayHandle, label: String, cx: &mut Context<Self>) {
        let id = self.next_session;
        self.next_session += 1;
        let feed = handle.feed.clone();
        let task = cx.spawn(async move |this, cx| {
            while let Ok(first) = feed.recv_async().await {
                let batch: Vec<Feed> = std::iter::once(first).chain(feed.try_iter()).collect();
                let alive = this.update(cx, |this, cx| {
                    let Some(s) = this.replay.as_mut().filter(|s| s.id == id) else {
                        return;
                    };
                    for item in batch {
                        match item {
                            Feed::Reset => s.hosts.clear(),
                            Feed::Event(e) => apply(&mut s.hosts, e),
                        }
                    }
                    if this.view == View::Replay {
                        this.ensure_selection();
                        cx.notify();
                    }
                });
                if alive.is_err() {
                    break;
                }
            }
        });
        // Dropping the previous session's handle stops its engine thread.
        self.replay = Some(ReplaySession {
            id,
            handle,
            label,
            hosts: BTreeMap::new(),
            _feed: task,
        });
        self.view = View::Replay;
        self.selected = None;
        self.error = None;
        cx.notify();
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
        let label = path.display().to_string();
        self.opening = Some(label.clone());
        self.error = None;
        cx.notify();
        let opened = cx.background_spawn(async move { crate::pipeline::open_replay(&path, speed) });
        cx.spawn(async move |this, cx| {
            let result = opened.await;
            let _ = this.update(cx, |this, cx| {
                // Only the latest request counts.
                if this.opening.as_ref() != Some(&label) {
                    return;
                }
                this.opening = None;
                match result {
                    Ok(handle) => this.start_session(handle, label, cx),
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
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::Live;
                        this.ensure_selection();
                        cx.notify();
                    })),
            );
        }
        if let Some(s) = &self.replay {
            bar = bar
                .child(
                    Button::new("view-replay")
                        .label("Recording")
                        .small()
                        .when(self.view == View::Replay, |b| b.primary())
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.view = View::Replay;
                            this.ensure_selection();
                            cx.notify();
                        })),
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
            .child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(self.data_dir.display().to_string()),
            )
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut list = div()
            .flex()
            .flex_col()
            .w(px(190.))
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
            let detail = match silence {
                Some(ns) if self.view == View::Live => format!("silent {}", format::duration(ns)),
                _ => format!("{loss:.1}% incomplete"),
            };
            list = list.child(
                div()
                    .id(("host", id as usize))
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .when(selected, |d| d.bg(theme.accent))
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
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(detail),
                    ),
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
        let interval_ns = host.info.as_ref().map_or(1000, |i| i.interval_ms) as u64 * 1_000_000;
        let since = now.saturating_sub(host.last_received_ns);
        (host.last_received_ns == 0 || since > 3 * interval_ns).then_some(since)
    }

    fn render_header(host: &HostModel, cx: &Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let s = &host.snapshot;
        let history = |f: fn(&sysmon_model::HistoryPoint) -> f32| -> Vec<f32> {
            host.history.iter().map(f).collect()
        };
        let mem = s.mem;
        let mem_pct = if mem.total > 0 {
            // From the network: available can be bogus (above total).
            mem.total.saturating_sub(mem.available) as f32 / mem.total as f32 * 100.0
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
            sparkline(series, max, HISTORY_LEN.min(240), theme.secondary).into_any_element()
        };
        let text = |t: String| div().child(t).into_any_element();
        let tail = |mut v: Vec<f32>| {
            let skip = v.len().saturating_sub(240);
            v.drain(..skip);
            v
        };

        let cpu = s.cpu_pct.first().copied().unwrap_or(0.0);
        let mut cores = div().flex().flex_wrap().gap_x_3().gap_y_1();
        for (i, pct) in s.cpu_pct.iter().enumerate().skip(1) {
            cores = cores.child(
                div()
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
                        spark(
                            vec![(tail(history(|p| p.cpu_pct)), theme.primary)],
                            Some(100.0),
                        ),
                    ))
                    .child(metric(
                        "Memory",
                        text(format!("{mem_pct:.1}%")),
                        Some(text(format!(
                            "{} / {}  swap {}",
                            format::bytes(mem.total.saturating_sub(mem.available) as f64 * 1024.0),
                            format::bytes(mem.total as f64 * 1024.0),
                            format::bytes(swap_used as f64 * 1024.0)
                        ))),
                        spark(
                            vec![(tail(history(|p| p.mem_used_kib as f32)), theme.success)],
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
                                (tail(history(|p| p.net_rx_bytes_per_s as f32)), in_color),
                                (tail(history(|p| p.net_tx_bytes_per_s as f32)), out_color),
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
                                (tail(history(|p| p.disk_read_bytes_per_s as f32)), in_color),
                                (
                                    tail(history(|p| p.disk_write_bytes_per_s as f32)),
                                    out_color,
                                ),
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
        let proc_matches = |p: &ProcRow| {
            !filtering
                || p.comm.to_lowercase().contains(&needle)
                || p.cmdline
                    .as_ref()
                    .is_some_and(|c| c.to_lowercase().contains(&needle))
                || p.user
                    .as_ref()
                    .is_some_and(|u| u.to_lowercase().contains(&needle))
                || p.key.pid.to_string() == needle
        };
        let thread_matches = |t: &ThreadRow| {
            !filtering || t.comm.to_lowercase().contains(&needle) || t.key.pid.to_string() == needle
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
        let shown_threads = |p: &ProcRow| -> Vec<ThreadRow> {
            let own = proc_matches(p);
            threads_of
                .get(&p.key.pid)
                .map(|ts| {
                    ts.iter()
                        .filter(|t| own || thread_matches(t))
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
        for t in sysmon_model::tree::build(&rows, filter, &self.collapsed) {
            let row = rows[t.row].clone();
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

    /// e.g. "113 shown · 359 kernel threads hidden · 1218 threads · 2 graphed".
    fn status_line(&self, host: &HostModel, shown: usize) -> String {
        let mut parts = vec![format!("{shown} shown")];
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
                parts.push(format!("{} threads", host.snapshot.threads.len()));
            } else {
                parts.push("threads not reported: start this host's agent with --threads".into());
            }
        }
        if let Some(sel) = self.selection().filter(|s| !s.is_empty()) {
            parts.push(format!("{} graphed", sel.len()));
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
        let this = cx.entity().downgrade();
        // As wide as the longest name shown (all rows, so it doesn't change
        // while scrolling), within USER_MIN_CHARS..=USER_MAX_CHARS.
        let user_chars = rows
            .iter()
            .map(|l| user_name(&l.row).chars().count())
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
            .child(div().w(px(14.)))
            .child(header_cell(SortKey::Pid, "PID", Some(64.), cx))
            .child(header_cell(
                SortKey::User,
                "USER",
                Some(f32::from(user_w)),
                cx,
            ))
            .child(div().w(px(16.)).child("S"))
            .child(header_cell(SortKey::Cpu, "%CPU", Some(60.), cx))
            .child(header_cell(SortKey::Virt, "VIRT", Some(SIZE_COL), cx))
            .child(header_cell(SortKey::Res, "RES", Some(SIZE_COL), cx))
            .child(header_cell(SortKey::Shr, "SHR", Some(SIZE_COL), cx))
            .child(div().w(px(44.)).child("%MEM"))
            .child(header_cell(SortKey::Threads, "THR", Some(48.), cx))
            .child(header_cell(SortKey::Command, "COMMAND", None, cx));

        let count = rows.len();
        let list = uniform_list("procs", count, move |range, _, _| {
            range
                .map(|i| {
                    let line = &rows[i];
                    let p = &line.row;
                    let th = line.thread.as_ref();
                    let dim = th.is_some()
                        || line.context
                        || th.map_or(p.stale, |t| t.stale)
                        || line.tree.as_ref().is_some_and(|t| !t.matched);
                    let slot = picked.get(&line.key()).copied();
                    let dash = || "–".to_string();
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
                        .flex()
                        .gap_2()
                        .px_2()
                        .h(px(ROW_HEIGHT))
                        .items_center()
                        .text_xs()
                        .font_family(mono.clone())
                        .when(i % 2 == 1, |d| d.bg(theme.muted.opacity(0.3)))
                        .when(cursor == Some(line.key()), |d| d.bg(theme.accent))
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
                                .on_click(on_pick),
                        )
                        .child(div().w(px(64.)).child(line.key().pid.to_string()))
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
                                .w(px(16.))
                                .child(th.map_or(p.state, |t| t.state).to_string()),
                        )
                        .child(
                            div()
                                .w(px(60.))
                                .child(format!("{:.1}", th.map_or(p.cpu_pct, |t| t.cpu_pct))),
                        )
                        // A thread's memory is its process's, shown on that row.
                        .child(div().w(px(SIZE_COL)).child(match th {
                            Some(_) => dash(),
                            None => size_cell(p.virt_kib),
                        }))
                        .child(div().w(px(SIZE_COL)).child(match th {
                            Some(_) => dash(),
                            None => size_cell(Some(p.rss_kib)),
                        }))
                        .child(div().w(px(SIZE_COL)).child(match th {
                            Some(_) => dash(),
                            None => size_cell(p.shr_kib),
                        }))
                        .child(div().w(px(44.)).child(match th {
                            Some(_) => dash(),
                            None => format!("{:.1}", p.rss_kib as f32 / mem_total * 100.0),
                        }))
                        .child(div().w(px(48.)).child(match th {
                            Some(_) => dash(),
                            None => p.threads.to_string(),
                        }))
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
                            .when(self.tree, |b| b.primary())
                            .when(!self.tree, |b| b.ghost())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.tree = !this.tree;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("kernel-toggle")
                            .label("Hide kernel threads")
                            .small()
                            .when(self.hide_kernel, |b| b.primary())
                            .when(!self.hide_kernel, |b| b.ghost())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.hide_kernel = !this.hide_kernel;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("threads-toggle")
                            .label("Show threads")
                            .small()
                            .when(self.show_threads, |b| b.primary())
                            .when(!self.show_threads, |b| b.ghost())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_threads = !this.show_threads;
                                cx.notify();
                            })),
                    )
                    .when(self.tree, |d| {
                        d.child(
                            Button::new("expand-all")
                                .label("Expand all")
                                .small()
                                .ghost()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.collapsed.clear();
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("collapse-all")
                                .label("Collapse all")
                                .small()
                                .ghost()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.collapse_all();
                                    cx.notify();
                                })),
                        )
                    })
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(self.status_line(host, count)),
                    ),
            )
            .child(header)
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

    /// Move the cursor by `delta` rows in the table's current order.
    fn move_cursor(&mut self, delta: isize, cx: &mut Context<Self>) {
        let Some(host) = self.selected.and_then(|id| self.hosts().get(&id)) else {
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
        let Some(host) = self.selected.and_then(|id| self.hosts().get(&id)) else {
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

    /// Whether the bottom panel is open, with the graph or the logs.
    fn panel_shown(&self) -> bool {
        self.show_logs || self.graph_shown()
    }

    fn graph_shown(&self) -> bool {
        self.graph_visible && self.selection().is_some_and(|s| !s.is_empty())
    }

    /// Remember the command of each graphed process while it's still running.
    fn refresh_graph_names(&mut self) {
        let Some(host) = self.selected.and_then(|id| self.hosts().get(&id)) else {
            return;
        };
        let Some(sel) = self.selection() else {
            return;
        };
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
        self.graph_names.extend(names);
    }

    fn render_graph(&self, host: &HostModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let metric = self.graph_metric;
        let picks: Vec<selection::Picked> = self
            .selection()
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let end = host.proc_history.back().map_or(0, |f| f.ts_unix_ns);
        let start = end.saturating_sub(self.graph_window_s * 1_000_000_000);
        let lines: Vec<graph::Line> = picks
            .iter()
            .map(|p| graph::Line {
                color: selection::color(p.slot),
                points: host.series(p.target, metric, start),
            })
            .collect();
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
                    .when(m == metric, |b| b.primary())
                    .when(m != metric, |b| b.ghost())
                    .on_click(cx.listener(move |this, _, _, cx| this.set_metric(m, cx))),
            );
        }
        toolbar = toolbar.child(div().w(px(12.)));
        for (i, w) in graph::WINDOWS_S.into_iter().enumerate() {
            toolbar = toolbar.child(
                Button::new(("window", i))
                    .label(format!("{} min", w / 60))
                    .small()
                    .when(w == self.graph_window_s, |b| b.primary())
                    .when(w != self.graph_window_s, |b| b.ghost())
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
            .w(px(64.))
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
                    lines: lines
                        .iter()
                        .map(|l| graph::Line {
                            color: l.color,
                            points: l.points.clone(),
                        })
                        .collect(),
                    start_ns: start,
                    end_ns: end,
                    y_max,
                    hover_ns,
                    grid: theme.border,
                    crosshair: theme.muted_foreground,
                },
                self.graph_bounds.clone(),
            ));
        let x_labels = div()
            .flex()
            .justify_between()
            .pl(px(64.))
            .text_xs()
            .text_color(theme.muted_foreground)
            .child(format::time(start))
            .child(hover_ns.map(format::time).unwrap_or_default())
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
        for (p, line) in picks.iter().zip(&lines) {
            let key = p.target.key();
            let name = self
                .graph_names
                .get(&key)
                .cloned()
                .unwrap_or_else(|| "?".into());
            let latest = host.latest(p.target, metric);
            let label = match p.target {
                SeriesTarget::Process(_) => format!("{} {name}", key.pid),
                SeriesTarget::Subtree(_) => {
                    let n = latest.map_or(0, |(_, n)| n);
                    format!("{} {name} + subtree ({n})", key.pid)
                }
                SeriesTarget::Thread(_) => format!("{} {name}", key.pid),
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
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(s) = this.selection_mut() {
                                    s.remove(key);
                                }
                                this.report_full(Ok(()));
                                cx.notify();
                            })),
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

    /// Graph / Logs, at the left of the bottom panel's toolbar.
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
                    .when(!self.show_logs, |b| b.primary())
                    .when(self.show_logs, |b| b.ghost())
                    // There's nothing to graph until processes are picked.
                    .disabled(!picked)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_logs = false;
                        this.graph_visible = true;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("tab-logs")
                    .label("Logs")
                    .small()
                    .when(self.show_logs, |b| b.primary())
                    .when(!self.show_logs, |b| b.ghost())
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_logs = true;
                        cx.notify();
                    })),
            )
    }

    fn render_logs(&self, host: &HostModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let mono = theme.mono_font_family.clone();
        let border = theme.border;
        let rows: Rc<Vec<LogRow>> = Rc::new(host.logs.rows().iter().cloned().collect());
        let count = rows.len();
        if self.log_follow && count > 0 {
            self.log_scroll
                .scroll_to_item(count - 1, ScrollStrategy::Bottom);
        }
        let status = if host.logs.enabled() {
            format!("{count} lines")
        } else {
            "No logs from this host: start its agent with --logs".into()
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
                        this.show_logs = false;
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
            .child(div().w(px(LOG_TIME_COL)).child("TIME"))
            .child(div().w(px(LOG_PRI_COL)).child("PRI"))
            .child(div().w(px(LOG_SOURCE_COL)).child("UNIT"))
            .child(div().w(px(LOG_PID_COL)).child("PID"))
            .child(div().flex_1().child("MESSAGE"));

        let this = cx.entity().downgrade();
        let cursor = self.log_cursor;
        let list = uniform_list("logs", count, move |range, _, _| {
            range
                .map(|i| {
                    let row = &rows[i];
                    let key = (row.received_ns, row.ts_unix_ns);
                    let on_click = {
                        let this = this.clone();
                        move |_: &ClickEvent, _: &mut Window, cx: &mut App| {
                            let _ = this.update(cx, |app, cx| {
                                app.log_cursor = Some(key);
                                // Keep the clicked line where it is.
                                app.log_follow = false;
                                cx.notify();
                            });
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
                        .when(cursor == Some(key), |d| d.bg(theme.accent))
                        .child(
                            div()
                                .flex_none()
                                .w(px(LOG_TIME_COL))
                                .child(format::time(row.ts_unix_ns)),
                        );
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
                            .child(
                                div()
                                    .flex_none()
                                    .w(px(LOG_SOURCE_COL))
                                    .flex()
                                    .child(clipped(("log-source", i), source, source_tip)),
                            )
                            .child(
                                div()
                                    .flex_none()
                                    .w(px(LOG_PID_COL))
                                    .child(e.pid.map_or_else(|| "–".into(), |p| p.to_string())),
                            )
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

    fn seek_by(&self, delta_s: i64) {
        if self.view != View::Replay {
            return;
        }
        if let Some(st) = self.status() {
            let delta = delta_s.unsigned_abs() * 1_000_000_000;
            let ts = if delta_s < 0 {
                st.position_ns.saturating_sub(delta)
            } else {
                st.position_ns.saturating_add(delta)
            };
            self.control(Control::Seek(ts.clamp(st.start_ns, st.end_ns)));
        }
    }

    fn change_speed(&self, faster: bool) {
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
                if this.show_shortcuts {
                    this.show_shortcuts = false;
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
            .on_action(cx.listener(|this, _: &ToggleKernelThreads, _, cx| {
                this.hide_kernel = !this.hide_kernel;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ToggleThreads, _, cx| {
                this.show_threads = !this.show_threads;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ToggleTree, _, cx| {
                this.tree = !this.tree;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ExpandAll, _, cx| {
                this.collapsed.clear();
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &CollapseAll, _, cx| {
                this.collapse_all();
                cx.notify();
            }))
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
            .on_action(cx.listener(|this, _: &CursorPageUp, _, cx| this.move_cursor(-20, cx)))
            .on_action(cx.listener(|this, _: &CursorPageDown, _, cx| this.move_cursor(20, cx)))
            .on_action(cx.listener(|this, _: &ToggleGraph, _, cx| this.toggle_cursor(cx)))
            .on_action(cx.listener(|this, _: &ClearGraph, _, cx| this.clear_graph(cx)))
            .on_action(cx.listener(|this, _: &About, window, cx| this.open_about(window, cx)))
            .on_action(cx.listener(|this, _: &ToggleLogs, _, cx| {
                this.show_logs = !this.show_logs;
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
            .on_action(cx.listener(|this, _: &SeekStart, _, _| {
                if let Some(st) = this.status().filter(|_| this.view == View::Replay) {
                    this.control(Control::Seek(st.start_ns));
                }
            }))
            .on_action(cx.listener(|this, _: &SeekEnd, _, _| {
                if let Some(st) = this.status().filter(|_| this.view == View::Replay) {
                    this.control(Control::Seek(st.end_ns));
                }
            }))
    }

    /// Overlay listing every shortcut, grouped as in [`actions::SHORTCUTS`].
    fn render_shortcuts(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut groups: Vec<(&str, Vec<&actions::Shortcut>)> = Vec::new();
        for s in actions::SHORTCUTS {
            match groups.last_mut() {
                Some((g, list)) if *g == s.group => list.push(s),
                _ => groups.push((s.group, vec![s])),
            }
        }
        let mut columns = div().flex().gap_8();
        for (group, list) in groups {
            let mut col = div().flex().flex_col().gap_1().child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .pb_1()
                    .child(group),
            );
            for s in list {
                let keys = s
                    .keys
                    .iter()
                    .map(|k| actions::display_key(k))
                    .collect::<Vec<_>>()
                    .join("  ");
                col = col.child(
                    div()
                        .flex()
                        .gap_3()
                        .text_xs()
                        .child(
                            div()
                                .w(px(110.))
                                .font_family(theme.mono_font_family.clone())
                                .text_color(theme.primary)
                                .child(keys),
                        )
                        .child(s.description),
                );
            }
            columns = columns.child(col);
        }
        div()
            .id("shortcuts-overlay")
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

    /// Collapse every process that has children in the selected host.
    fn collapse_all(&mut self) {
        let Some(host) = self.selected.and_then(|id| self.hosts().get(&id)) else {
            return;
        };
        let parents: HashSet<u32> = host.snapshot.procs.iter().map(|p| p.ppid).collect();
        self.collapsed = host
            .snapshot
            .procs
            .iter()
            .filter(|p| parents.contains(&p.key.pid))
            .map(|p| p.key)
            .collect();
    }

    fn render_timeline(&self, cx: &mut Context<Self>) -> Option<impl IntoElement + use<>> {
        if self.view != View::Replay {
            return None;
        }
        let st = self.status()?;
        let theme = cx.theme();
        let mono = theme.mono_font_family.clone();
        let mut speeds = div().flex().gap_1();
        for (i, &speed) in SPEEDS.iter().enumerate() {
            speeds = speeds.child(
                Button::new(("speed", i))
                    .label(format!("{speed}×"))
                    .small()
                    .when((st.speed - speed).abs() < f64::EPSILON, |b| b.primary())
                    .when((st.speed - speed).abs() >= f64::EPSILON, |b| b.ghost())
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
                .child(div().flex_1().child(Slider::new(&self.timeline)))
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
    /// The process (for a thread line, the thread's process).
    row: ProcRow,
    tree: Option<TreeLine>,
    thread: Option<ThreadRow>,
    /// Shown only because something under it matched the filter.
    context: bool,
}

impl Line {
    fn process(row: ProcRow, tree: Option<TreeLine>, context: bool) -> Self {
        Self {
            row,
            tree,
            thread: None,
            context,
        }
    }

    fn thread(row: ProcRow, thread: ThreadRow, tree: Option<TreeLine>) -> Self {
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
    let text = clipped(("cmd", i), label, tip);
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
                    if !this.collapsed.remove(&key) {
                        this.collapsed.insert(key);
                    }
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
        let panel_shown = self.panel_shown();
        // Keep the panel within the window if the window shrank.
        let max_graph = (window.viewport_size().height - px(GRAPH_MIN_LIST)).max(px(GRAPH_MIN));
        self.graph_height = self.graph_height.clamp(px(GRAPH_MIN), max_graph);
        let theme = cx.theme().clone();
        let toolbar = self.render_toolbar(cx);
        let sidebar = self.render_sidebar(cx);
        let timeline = self.render_timeline(cx);

        let main = match self.selected.and_then(|id| self.hosts().get(&id)) {
            Some(host) => {
                let graph = panel_shown.then(|| {
                    if self.show_logs {
                        self.render_logs(host, cx).into_any_element()
                    } else {
                        self.render_graph(host, cx).into_any_element()
                    }
                });
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .child(Self::render_header(host, cx))
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
        AppState, FORGET_AFTER_NS, MAX_LIVE_HOSTS, Selection, SortKey, Start, View, apply,
    };
    use gpui_kit::Modifiers;
    use sysmon_model::SeriesTarget;
    use sysmon_proto::ProcKey;

    fn picked(app: &AppState) -> Vec<SeriesTarget> {
        app.selection()
            .map(|s| s.iter().map(|p| p.target).collect())
            .unwrap_or_default()
    }

    fn key(pid: u32) -> ProcKey {
        ProcKey { pid, starttime: 0 }
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
                replay_label: String::new(),
                data_dir: std::env::temp_dir(),
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
                host_id: 1,
                boot_id: 1,
                seq,
                system: Some(sysmon_proto::SystemSample {
                    ts_unix_ns: 1_000_000_000 * (1 + seq as u64),
                    ..Default::default()
                }),
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
                complete: true,
                received_ns: 0,
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
        app.read_with(cx, |app, _| {
            let s = app.status_line(&app.hosts()[&1], 4);
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
        app.read_with(cx, |app, _| {
            let s = app.status_line(&app.hosts()[&1], 4);
            assert!(s.contains("start this host's agent with --threads"), "{s}");
        });

        send_threads(&app, cx);
        let t = table(&app, cx);
        assert_eq!(pids(&t), [1, 10, 101, 102, 11, 20]);
        assert_eq!(
            t.iter().map(|(_, th, _)| *th).collect::<Vec<_>>(),
            [false, false, true, true, false, false]
        );
        app.read_with(cx, |app, _| {
            assert!(app.status_line(&app.hosts()[&1], 6).contains("2 threads"));
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
            assert_eq!(app.graph_names[&key(101)], "worker-a (thread of 10)");
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
            let frame = sysmon_proto::Frame {
                host_id: 1,
                boot_id: 1,
                seq: 0,
                system: Some(sysmon_proto::SystemSample {
                    ts_unix_ns: 1_000_000_000,
                    // Available above total, as a buggy or hostile agent might send.
                    mem: sysmon_proto::MemInfo {
                        total: 1000,
                        available: 2000,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                procs: vec![],
                threads: vec![],
                complete: true,
                received_ns: 0,
            };
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
            app.ensure_selection();
            cx.notify();
        });
        cx.update_window(window, |_, window, cx| window.render_frame(cx))
            .unwrap();
    }

    #[gpui_kit::test]
    fn silence_is_judged_by_the_monitors_clock_not_the_agents(cx: &mut TestAppContext) {
        let (_window, app) = open(cx);
        let now = sysmon_ingest::unix_now_ns();
        let sample = |agent_ts: u64, received: u64| sysmon_proto::Frame {
            host_id: 1,
            boot_id: 1,
            seq: 0,
            system: Some(sysmon_proto::SystemSample {
                ts_unix_ns: agent_ts,
                ..Default::default()
            }),
            procs: vec![],
            threads: vec![],
            complete: true,
            received_ns: received,
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
                host_id: 1,
                boot_id: 1,
                seq: 0,
                system: Some(sysmon_proto::SystemSample {
                    ts_unix_ns: 1_000_000_000,
                    ..Default::default()
                }),
                procs,
                threads: vec![],
                complete: true,
                received_ns: 0,
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
            let threads = [10u32, 11, 12]
                .map(|tid| sysmon_proto::ThreadSample {
                    tgid: 10,
                    tid,
                    starttime: 0,
                    state: b'S',
                    utime: 0,
                    stime: 0,
                    comm: format!("t{tid}"),
                })
                .to_vec();
            let frame = sysmon_proto::Frame {
                host_id: 1,
                boot_id: 1,
                seq: 0,
                system: Some(sysmon_proto::SystemSample {
                    ts_unix_ns: 1_000_000_000,
                    ..Default::default()
                }),
                procs: vec![proc],
                threads,
                complete: true,
                received_ns: 0,
            };
            apply(&mut app.live_hosts, sysmon_ingest::Event::Frame(frame));
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
                let frame = sysmon_proto::Frame {
                    host_id: 1,
                    boot_id: 1,
                    seq,
                    system: Some(sysmon_proto::SystemSample {
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
                    }),
                    procs: vec![],
                    threads: vec![],
                    complete: true,
                    received_ns: 0,
                };
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
                host_id: 1,
                boot_id: 1,
                seq: 0,
                system: Some(sysmon_proto::SystemSample {
                    ts_unix_ns: 1_000_000_000,
                    ..Default::default()
                }),
                procs: vec![],
                threads: vec![],
                complete: true,
                received_ns: 1,
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
        assert!(app.read_with(cx, |a, _| a.show_logs));

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
        assert!(!app.read_with(cx, |a, _| a.show_logs));
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
}
