//! Top-level gpui entity: owns the live and replay host models and renders
//! the toolbar, host list, header, process table and replay timeline.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::slider::{Slider, SliderEvent, SliderState};
use gpui_kit::component::{ActiveTheme as _, Sizable as _};
use gpui_kit::prelude::*;
use gpui_kit::*;
use sysmon_ingest::Event;
use sysmon_model::{Control, Feed, HISTORY_LEN, HostModel, ProcRow, ReplayHandle, ReplayStatus};

use crate::format;
use crate::widgets::{bar, sparkline};

const ROW_HEIGHT: f32 = 20.;
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
    filter: Entity<InputState>,
    timeline: Entity<SliderState>,
    scrubbing: bool,
    scroll: UniformListScrollHandle,
    error: Option<String>,
    _tasks: Vec<Task<()>>,
    _subscriptions: Vec<Subscription>,
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
            cx.subscribe_in(&filter, window, |_, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    cx.notify();
                }
            }),
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

        let mut this = Self {
            view: View::Live,
            live_enabled: start.live.is_some(),
            live_hosts: BTreeMap::new(),
            replay: None,
            next_session: 0,
            data_dir: start.data_dir,
            selected: None,
            sort: (SortKey::Cpu, true),
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

    fn sorted_rows(&self, host: &HostModel, cx: &App) -> Vec<ProcRow> {
        let needle = self.filter.read(cx).value().to_lowercase();
        let mut rows: Vec<ProcRow> = host
            .snapshot
            .procs
            .iter()
            .filter(|p| {
                needle.is_empty()
                    || p.comm.to_lowercase().contains(&needle)
                    || p.cmdline
                        .as_ref()
                        .is_some_and(|c| c.to_lowercase().contains(&needle))
                    || p.user
                        .as_ref()
                        .is_some_and(|u| u.to_lowercase().contains(&needle))
                    || p.key.pid.to_string() == needle
            })
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
        rows
    }

    fn render_procs(&self, host: &HostModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let mono = theme.mono_font_family.clone();
        let rows = Rc::new(self.sorted_rows(host, cx));
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
                        this.sort = if this.sort.0 == key {
                            (key, !this.sort.1)
                        } else {
                            // Numbers sort high-to-low first, text A-to-Z.
                            (
                                key,
                                matches!(key, SortKey::Cpu | SortKey::Mem | SortKey::Threads),
                            )
                        };
                        cx.notify();
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
                    let p = &rows[i];
                    div()
                        .flex()
                        .gap_2()
                        .px_2()
                        .h(px(ROW_HEIGHT))
                        .items_center()
                        .text_xs()
                        .font_family(mono.clone())
                        .when(i % 2 == 1, |d| d.bg(theme.muted.opacity(0.3)))
                        .when(p.stale, |d| d.text_color(theme.muted_foreground))
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
                        .child(div().flex_1().overflow_hidden().child(command(p)))
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
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("{count} shown")),
                    ),
            )
            .child(header)
            .child(list)
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

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(toolbar)
            .child(div().flex().flex_1().min_h_0().child(sidebar).child(main))
            .children(timeline)
    }
}
