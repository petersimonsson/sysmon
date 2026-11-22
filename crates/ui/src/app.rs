//! Top-level gpui entity: owns the live and replay host models and renders
//! the toolbar, host list, header, process table and replay timeline.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::menu::AppMenuBar;
use gpui_kit::component::slider::{Slider, SliderEvent, SliderState};
use gpui_kit::component::{ActiveTheme as _, Sizable as _};
use gpui_kit::prelude::*;
use gpui_kit::*;
use sysmon_ingest::Event;
use sysmon_model::{
    Control, Feed, HISTORY_LEN, HostModel, ProcRow, ReplayHandle, ReplayStatus, TreeLine,
};
use sysmon_proto::ProcKey;

use crate::actions::{self, *};
use crate::format;
use crate::widgets::{bar, sparkline};

const ROW_HEIGHT: f32 = 20.;
const MENU_BAR_HEIGHT: f32 = 30.;
/// Slider resolution: positions are mapped onto 0..TIMELINE_STEPS.
const TIMELINE_STEPS: f32 = 10_000.;
const SPEEDS: [f64; 5] = [1., 4., 16., 64., 256.];

/// What the app starts with; built in `main` before the window opens.
pub struct Start {
    pub live: Option<flume::Receiver<Event>>,
    pub replay: Option<ReplayHandle>,
    pub replay_label: String,
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Live,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Pid,
    User,
    Cpu,
    Mem,
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
    replay: Option<ReplaySession>,
    next_session: u64,
    data_dir: PathBuf,
    selected: Option<u64>,
    sort: (SortKey, bool),
    /// Show processes as a tree grouped by parent.
    tree: bool,
    collapsed: HashSet<ProcKey>,
    filter: Entity<InputState>,
    timeline: Entity<SliderState>,
    scrubbing: bool,
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
                        for event in batch {
                            apply(&mut this.live_hosts, event);
                        }
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
        // Keep the replay position and timeline moving between frames.
        tasks.push(cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(200))
                    .await;
                let alive = this.update_in(cx, |this, window, cx| {
                    if this.view == View::Replay {
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
            replay: None,
            next_session: 0,
            data_dir: start.data_dir,
            selected: None,
            sort: (SortKey::Cpu, true),
            tree: false,
            collapsed: HashSet::new(),
            filter,
            timeline,
            scrubbing: false,
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

    fn ensure_selection(&mut self) {
        let hosts = self.hosts();
        if self.selected.is_none_or(|id| !hosts.contains_key(&id)) {
            self.selected = hosts.keys().next().copied();
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
        let speed = self.status().map_or(1.0, |s| s.speed);
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(paths))) = paths.await else {
                return;
            };
            let Some(path) = paths.into_iter().next() else {
                return;
            };
            let _ = this.update(cx, |this, cx| {
                match crate::pipeline::open_replay(&path, speed) {
                    Ok(handle) => this.start_session(handle, path.display().to_string(), cx),
                    Err(e) => {
                        this.error = Some(format!("{e:#}"));
                        cx.notify();
                    }
                }
            });
        })
        .detach();
    }

    fn status(&self) -> Option<ReplayStatus> {
        self.replay.as_ref().map(|s| s.handle.status())
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
            .when_some(self.error.clone(), |b, e| {
                b.child(div().text_xs().text_color(theme.danger).child(e))
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
        let now = match self.view {
            View::Live => sysmon_ingest::unix_now_ns(),
            View::Replay => self.status().map_or(0, |s| s.position_ns),
        };
        for (&id, host) in self.hosts() {
            let selected = self.selected == Some(id);
            let loss = if host.frames_received == 0 {
                0.0
            } else {
                host.frames_incomplete as f32 / host.frames_received as f32 * 100.0
            };
            let interval_ns = host.info.as_ref().map_or(1000, |i| i.interval_ms) as u64 * 1_000_000;
            let stale = now.saturating_sub(host.last_seen_ns) > 3 * interval_ns;
            let detail = if stale && self.view == View::Live {
                format!(
                    "silent {}",
                    format::duration(now.saturating_sub(host.last_seen_ns))
                )
            } else {
                format!("{loss:.1}% incomplete")
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
                            .child(host.name()),
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

    fn render_header(host: &HostModel, cx: &Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let s = &host.snapshot;
        let history = |f: fn(&sysmon_model::HistoryPoint) -> f32| -> Vec<f32> {
            host.history.iter().map(f).collect()
        };
        let mem = s.mem;
        let mem_pct = if mem.total > 0 {
            (mem.total - mem.available) as f32 / mem.total as f32 * 100.0
        } else {
            0.0
        };
        let swap_used = mem.swap_total.saturating_sub(mem.swap_free);
        let rx: f64 = s.net.iter().map(|n| n.rx_bytes_per_s).sum();
        let tx: f64 = s.net.iter().map(|n| n.tx_bytes_per_s).sum();
        let rd: f64 = s.disks.iter().map(|d| d.read_bytes_per_s).sum();
        let wr: f64 = s.disks.iter().map(|d| d.write_bytes_per_s).sum();

        let metric = |title: &'static str, line1: String, line2: String, chart: AnyElement| {
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
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(line2),
                )
        };
        let spark = |values: Vec<f32>, max: Option<f32>, color: Hsla| {
            sparkline(values, max, HISTORY_LEN.min(240), color, theme.secondary).into_any_element()
        };
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
                        format!("{cpu:.1}%"),
                        format!("load {:.2} {:.2} {:.2}", s.load[0], s.load[1], s.load[2]),
                        spark(tail(history(|p| p.cpu_pct)), Some(100.0), theme.primary),
                    ))
                    .child(metric(
                        "Memory",
                        format!("{mem_pct:.1}%"),
                        format!(
                            "{} / {}  swap {}",
                            format::bytes(mem.total.saturating_sub(mem.available) as f64 * 1024.0),
                            format::bytes(mem.total as f64 * 1024.0),
                            format::bytes(swap_used as f64 * 1024.0)
                        ),
                        spark(
                            tail(history(|p| p.mem_used_kib as f32)),
                            Some(mem.total.max(1) as f32),
                            theme.success,
                        ),
                    ))
                    .child(metric(
                        "Network",
                        format!("↓ {}", format::bytes_per_s(rx)),
                        format!("↑ {}", format::bytes_per_s(tx)),
                        spark(
                            tail(history(|p| p.net_rx_bytes_per_s as f32)),
                            None,
                            theme.info,
                        ),
                    ))
                    .child(metric(
                        "Disk",
                        format!("R {}", format::bytes_per_s(rd)),
                        format!("W {}", format::bytes_per_s(wr)),
                        spark(
                            tail(history(|p| {
                                (p.disk_read_bytes_per_s + p.disk_write_bytes_per_s) as f32
                            })),
                            None,
                            theme.warning,
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
                                "{} processes · sample {}",
                                s.procs.len(),
                                format::datetime_utc(s.ts_unix_ns)
                            )),
                    ),
            )
            .child(cores)
    }

    /// The rows to show, in order. In tree mode every row is kept (so
    /// ancestors of filter matches can be shown) and each line carries its
    /// tree position; otherwise only filter matches are kept.
    fn table_lines(&self, host: &HostModel, cx: &App) -> Vec<Line> {
        let needle = self.filter.read(cx).value().to_lowercase();
        let matches = |p: &ProcRow| {
            needle.is_empty()
                || p.comm.to_lowercase().contains(&needle)
                || p.cmdline
                    .as_ref()
                    .is_some_and(|c| c.to_lowercase().contains(&needle))
                || p.user
                    .as_ref()
                    .is_some_and(|u| u.to_lowercase().contains(&needle))
                || p.key.pid.to_string() == needle
        };
        let mut rows: Vec<ProcRow> = host
            .snapshot
            .procs
            .iter()
            .filter(|p| self.tree || matches(p))
            .cloned()
            .collect();
        let (key, desc) = self.sort;
        rows.sort_by(|a, b| {
            let ord = match key {
                SortKey::Pid => a.key.pid.cmp(&b.key.pid),
                SortKey::User => a.user.cmp(&b.user).then(a.uid.cmp(&b.uid)),
                SortKey::Cpu => a.cpu_pct.total_cmp(&b.cpu_pct),
                SortKey::Mem => a.rss_kib.cmp(&b.rss_kib),
                SortKey::Threads => a.threads.cmp(&b.threads),
                SortKey::Command => command(a).cmp(&command(b)),
            };
            let ord = if desc { ord.reverse() } else { ord };
            ord.then(a.key.pid.cmp(&b.key.pid))
        });

        if !self.tree {
            return rows
                .into_iter()
                .map(|row| Line { row, tree: None })
                .collect();
        }
        let filter: Option<&dyn Fn(&ProcRow) -> bool> =
            (!needle.is_empty()).then_some(&matches as &dyn Fn(&ProcRow) -> bool);
        sysmon_model::tree::build(&rows, filter, &self.collapsed)
            .into_iter()
            .map(|t| Line {
                row: rows[t.row].clone(),
                tree: Some(t),
            })
            .collect()
    }

    fn render_procs(&self, host: &HostModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let mono = theme.mono_font_family.clone();
        let rows = Rc::new(self.table_lines(host, cx));
        let this = cx.entity().downgrade();
        let mem_total = host.snapshot.mem.total.max(1) as f32;

        let (sort_key, desc) = self.sort;
        let header_cell =
            |key: SortKey, label: &'static str, width: Option<f32>, cx: &mut Context<Self>| {
                let arrow = (key == sort_key).then_some(if desc { "▼" } else { "▲" });
                // A non-wrapping row keeps the indicator beside the label.
                let cell = div()
                    .id(label)
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
            .child(header_cell(SortKey::Pid, "PID", Some(64.), cx))
            .child(header_cell(SortKey::User, "USER", Some(80.), cx))
            .child(div().w(px(16.)).child("S"))
            .child(header_cell(SortKey::Cpu, "%CPU", Some(60.), cx))
            .child(header_cell(SortKey::Mem, "RSS", Some(72.), cx))
            .child(div().w(px(44.)).child("%MEM"))
            .child(header_cell(SortKey::Threads, "THR", Some(48.), cx))
            .child(header_cell(SortKey::Command, "COMMAND", None, cx));

        let count = rows.len();
        let list = uniform_list("procs", count, move |range, _, _| {
            range
                .map(|i| {
                    let line = &rows[i];
                    let p = &line.row;
                    let dim = p.stale || line.tree.as_ref().is_some_and(|t| !t.matched);
                    div()
                        .flex()
                        .gap_2()
                        .px_2()
                        .h(px(ROW_HEIGHT))
                        .items_center()
                        .text_xs()
                        .font_family(mono.clone())
                        .when(i % 2 == 1, |d| d.bg(theme.muted.opacity(0.3)))
                        .when(dim, |d| d.text_color(theme.muted_foreground))
                        .child(div().w(px(64.)).child(p.key.pid.to_string()))
                        .child(
                            div().w(px(80.)).overflow_hidden().child(
                                p.user
                                    .clone()
                                    .or_else(|| p.uid.map(|u| u.to_string()))
                                    .unwrap_or_else(|| "-".into()),
                            ),
                        )
                        .child(div().w(px(16.)).child(p.state.to_string()))
                        .child(div().w(px(60.)).child(format!("{:.1}", p.cpu_pct)))
                        .child(
                            div()
                                .w(px(72.))
                                .child(format::bytes(p.rss_kib as f64 * 1024.0)),
                        )
                        .child(
                            div()
                                .w(px(44.))
                                .child(format!("{:.1}", p.rss_kib as f32 / mem_total * 100.0)),
                        )
                        .child(div().w(px(48.)).child(p.threads.to_string()))
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
                            .child(format!("{count} shown")),
                    ),
            )
            .child(header)
            .child(list)
    }

    /// Sort by `key`, or flip the direction if already sorted by it.
    fn sort_by(&mut self, key: SortKey, cx: &mut Context<Self>) {
        self.sort = if self.sort.0 == key {
            (key, !self.sort.1)
        } else {
            // Numbers sort high-to-low first, text A-to-Z.
            (
                key,
                matches!(key, SortKey::Cpu | SortKey::Mem | SortKey::Threads),
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
        let ids: Vec<u64> = self.hosts().keys().copied().collect();
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
                } else {
                    this.filter.update(cx, |f, cx| f.set_value("", window, cx));
                }
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ToggleShortcuts, _, cx| {
                this.show_shortcuts = !this.show_shortcuts;
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
            .on_action(cx.listener(|this, _: &SortByMemory, _, cx| this.sort_by(SortKey::Mem, cx)))
            .on_action(cx.listener(|this, _: &SortByPid, _, cx| this.sort_by(SortKey::Pid, cx)))
            .on_action(cx.listener(|this, _: &SortByUser, _, cx| this.sort_by(SortKey::User, cx)))
            .on_action(
                cx.listener(|this, _: &SortByCommand, _, cx| this.sort_by(SortKey::Command, cx)),
            )
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
                        .child(format::datetime_utc(st.start_ns)),
                )
                .child(div().flex_1().child(Slider::new(&self.timeline)))
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format::datetime_utc(st.end_ns)),
                )
                .child(
                    div()
                        .text_sm()
                        .font_family(mono.clone())
                        .child(format::datetime_utc(st.position_ns)),
                ),
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

/// One row of the process table.
struct Line {
    row: ProcRow,
    tree: Option<TreeLine>,
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
    let Some(t) = &line.tree else {
        return cell.child(command(&line.row));
    };
    let twisty = if t.has_children {
        let key = line.row.key;
        let this = this.clone();
        div()
            .id(("twisty", i))
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
        div().id(("twisty", i)).flex_none().w(px(14.))
    };
    cell.child(
        div()
            .flex_none()
            .text_color(theme.muted_foreground)
            .child(t.guides.clone()),
    )
    .child(twisty)
    .child(div().flex_none().child(command(&line.row)))
    .when(t.collapsed, |d| {
        d.child(
            div()
                .flex_none()
                .ml_2()
                .text_color(theme.muted_foreground)
                .child(format!(
                    "+{} · {:.1}% CPU · {}",
                    t.hidden,
                    t.hidden_cpu_pct,
                    format::bytes(t.hidden_rss_kib as f64 * 1024.0)
                )),
        )
    })
}

fn command(p: &ProcRow) -> String {
    p.cmdline
        .clone()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("[{}]", p.comm))
}

impl Render for AppState {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let toolbar = self.render_toolbar(cx);
        let sidebar = self.render_sidebar(cx);
        let timeline = self.render_timeline(cx);

        let main = match self.selected.and_then(|id| self.hosts().get(&id)) {
            Some(host) => div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .child(Self::render_header(host, cx))
                .child(self.render_procs(host, cx)),
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
    use super::{AppState, SortKey, Start, View, apply};
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
            assert_eq!(app.read(cx).sort, (SortKey::Mem, true));
            window.press("shift-m", cx);
            assert_eq!(
                app.read(cx).sort,
                (SortKey::Mem, false),
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
        app.update(cx, |app, cx| {
            let frame = sysmon_proto::Frame {
                host_id: 1,
                boot_id: 1,
                seq: 0,
                system: Some(sysmon_proto::SystemSample::default()),
                procs: Vec::new(),
                complete: true,
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
}
