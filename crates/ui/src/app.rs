//! Top-level gpui entity: owns one `HostModel` per host and renders the
//! host list, the header and the process table.

use std::collections::BTreeMap;

use gpui_kit::component::ActiveTheme as _;
use gpui_kit::prelude::*;
use gpui_kit::*;
use sysmon_ingest::Event;
use sysmon_model::{HostModel, ProcRow};

/// Rows shown in the process table.
/// TODO: replace with a virtualized `uniform_list` and sortable columns.
const MAX_ROWS: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Live,
    Replay,
}

pub struct AppState {
    mode: Mode,
    hosts: BTreeMap<u64, HostModel>,
    selected: Option<u64>,
}

impl AppState {
    pub fn new(events: flume::Receiver<Event>, mode: Mode, cx: &mut Context<Self>) -> Self {
        // Bridge from the background threads: wait for one event, then drain
        // whatever else is queued so a burst becomes a single repaint.
        cx.spawn(async move |this, cx| {
            while let Ok(first) = events.recv_async().await {
                let batch: Vec<Event> = std::iter::once(first).chain(events.try_iter()).collect();
                let alive = this.update(cx, |state, cx| {
                    for event in batch {
                        state.apply(event);
                    }
                    cx.notify();
                });
                if alive.is_err() {
                    break;
                }
            }
        })
        .detach();

        Self {
            mode,
            hosts: BTreeMap::new(),
            selected: None,
        }
    }

    fn apply(&mut self, event: Event) {
        let host_id = match &event {
            Event::Frame(f) => f.host_id,
            Event::HostInfo { host_id, .. } | Event::ProcMeta { host_id, .. } => *host_id,
        };
        self.hosts
            .entry(host_id)
            .or_insert_with(|| HostModel::new(host_id))
            .apply(event);
        self.selected.get_or_insert(host_id);
    }

    fn host_name(host: &HostModel) -> String {
        host.info
            .as_ref()
            .map(|i| i.hostname.clone())
            .unwrap_or_else(|| format!("{:016x}", host.host_id))
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let mut list = div()
            .flex()
            .flex_col()
            .w(px(200.))
            .h_full()
            .p_2()
            .gap_1()
            .border_r_1()
            .border_color(theme.border)
            .child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(match self.mode {
                        Mode::Live => "LIVE",
                        Mode::Replay => "REPLAY",
                    }),
            );
        for (&id, host) in &self.hosts {
            let selected = self.selected == Some(id);
            let loss = if host.frames_received == 0 {
                0.0
            } else {
                host.frames_incomplete as f32 / host.frames_received as f32 * 100.0
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
                    .child(Self::host_name(host))
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(format!("{loss:.1}% incomplete")),
                    ),
            );
        }
        list
    }

    fn render_header(host: &HostModel, cx: &Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let s = &host.snapshot;
        let bar = |label: String, pct: f32| {
            div()
                .flex()
                .items_center()
                .gap_2()
                .text_xs()
                .child(div().w(px(56.)).child(label))
                .child(
                    div()
                        .w(px(160.))
                        .h(px(8.))
                        .rounded_sm()
                        .bg(theme.secondary)
                        .child(
                            div()
                                .h_full()
                                .rounded_sm()
                                .bg(theme.primary)
                                .w(relative(pct.clamp(0.0, 100.0) / 100.0)),
                        ),
                )
                .child(format!("{pct:5.1}%"))
        };

        let mut cores = div().flex().flex_wrap().gap_x_4().gap_y_1();
        for (i, pct) in s.cpu_pct.iter().enumerate().skip(1) {
            cores = cores.child(bar(format!("cpu{}", i - 1), *pct));
        }

        let mem = s.mem;
        let mem_pct = if mem.total > 0 {
            (mem.total - mem.available) as f32 / mem.total as f32 * 100.0
        } else {
            0.0
        };
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
                    .gap_6()
                    .child(bar("cpu".into(), s.cpu_pct.first().copied().unwrap_or(0.0)))
                    .child(bar("mem".into(), mem_pct))
                    .child(div().text_xs().child(format!(
                        "load {:.2} {:.2} {:.2}   {} procs",
                        s.load[0],
                        s.load[1],
                        s.load[2],
                        s.procs.len()
                    ))),
            )
            .child(cores)
    }

    fn render_procs(host: &HostModel, cx: &Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let mut rows: Vec<&ProcRow> = host.snapshot.procs.iter().collect();
        rows.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct));

        let row = |cells: [String; 6]| {
            let [pid, user, cpu, mem, state, cmd] = cells;
            div()
                .flex()
                .gap_2()
                .text_xs()
                .font_family("monospace")
                .child(div().w(px(64.)).child(pid))
                .child(div().w(px(56.)).child(user))
                .child(div().w(px(56.)).child(cpu))
                .child(div().w(px(80.)).child(mem))
                .child(div().w(px(16.)).child(state))
                .child(div().flex_1().overflow_hidden().child(cmd))
        };

        let mut table = div()
            .id("procs")
            .flex()
            .flex_col()
            .flex_1()
            .p_2()
            .overflow_y_scroll()
            .child(
                row(["PID", "UID", "%CPU", "RSS MiB", "S", "COMMAND"].map(String::from))
                    .text_color(theme.muted_foreground),
            );
        for p in rows.into_iter().take(MAX_ROWS) {
            table = table.child(row([
                p.key.pid.to_string(),
                p.uid.map_or_else(|| "-".into(), |u| u.to_string()),
                format!("{:.1}", p.cpu_pct),
                format!("{:.1}", p.rss_kib as f64 / 1024.0),
                p.state.to_string(),
                p.cmdline
                    .clone()
                    .filter(|c| !c.is_empty())
                    .unwrap_or_else(|| format!("[{}]", p.comm)),
            ]));
        }
        table
    }
}

impl Render for AppState {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let main = match self.selected.and_then(|id| self.hosts.get(&id)) {
            Some(host) => div()
                .flex()
                .flex_col()
                .flex_1()
                .child(Self::render_header(host, cx))
                .child(Self::render_procs(host, cx)),
            None => div()
                .flex()
                .flex_1()
                .items_center()
                .justify_center()
                .text_color(theme.muted_foreground)
                .child(match self.mode {
                    Mode::Live => "Waiting for agents…",
                    Mode::Replay => "Loading recording…",
                }),
        };

        div()
            .flex()
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(self.render_sidebar(cx))
            .child(main)
    }
}
