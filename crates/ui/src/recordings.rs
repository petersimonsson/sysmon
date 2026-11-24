//! The Open Recording dialog: every recording in the data directory, one
//! row per boot of each machine, with the time it covers and its gaps.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::{ActiveTheme as _, Sizable as _};
use gpui_kit::prelude::*;
use gpui_kit::*;
use sysmon_model::Recording;

use crate::format;
use crate::icons::{IconName, icon};
use crate::widgets::Highlighted as _;

/// A boot whose data ends this close to now is taken to be still recording:
/// the recorder writes out what it holds every 10 s.
const LIVE_WITHIN_NS: u64 = 120_000_000_000;
const ROW_H: f32 = 30.;
const COVERAGE_W: f32 = 140.;

/// Called with what to open: a boot's directory, or a host's for all of its
/// boots.
pub type OnOpen = Rc<dyn Fn(PathBuf, &mut Window, &mut App)>;

enum Scan {
    Running,
    Failed(String),
    Done(Vec<Recording>),
}

/// A line of the list: a machine, then its boots, newest first.
#[derive(Debug, Clone, PartialEq)]
enum Row {
    Host {
        name: String,
        host_id: u64,
        boots: usize,
        path: PathBuf,
    },
    /// An index into the scan's recordings.
    Boot(usize),
}

pub struct RecordingsView {
    dir: PathBuf,
    /// The monitor is recording live to `dir`.
    live: bool,
    scan: Scan,
    filter: Entity<InputState>,
    /// The row picked, by what it opens.
    selected: Option<PathBuf>,
    list: UniformListScrollHandle,
    on_open: OnOpen,
    _subscription: Subscription,
}

impl RecordingsView {
    pub fn new(
        dir: PathBuf,
        live: bool,
        on_open: OnOpen,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let filter = cx.new(|cx| InputState::new(window, cx).placeholder("Filter by machine"));
        let subscription = cx.subscribe(&filter, |this: &mut Self, _, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Change) {
                this.keep_selection_visible(cx);
                cx.notify();
            }
        });
        let scan_dir = dir.clone();
        let scanned = cx.background_spawn(async move { sysmon_model::catalog::scan(&scan_dir) });
        cx.spawn(async move |this, cx| {
            let result = scanned.await;
            let _ = this.update(cx, |this, cx| {
                this.scan = match result {
                    Ok(found) => Scan::Done(found),
                    // Nothing recorded yet.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Scan::Done(Vec::new()),
                    Err(e) => Scan::Failed(e.to_string()),
                };
                this.keep_selection_visible(cx);
                cx.notify();
            });
        })
        .detach();
        Self {
            dir,
            live,
            scan: Scan::Running,
            filter,
            selected: None,
            list: UniformListScrollHandle::new(),
            on_open,
            _subscription: subscription,
        }
    }

    pub fn filter(&self) -> &Entity<InputState> {
        &self.filter
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn recordings(&self) -> &[Recording] {
        match &self.scan {
            Scan::Done(found) => found,
            _ => &[],
        }
    }

    fn rows(&self, cx: &App) -> Vec<Row> {
        let needle = self.filter.read(cx).value().to_lowercase();
        let found = self.recordings();
        let matches = |r: &Recording| {
            needle.is_empty()
                || r.name().to_lowercase().contains(&needle)
                || format!("{:016x}", r.host_id).contains(&needle)
        };
        // Hosts in the order of their newest boot; the scan sorts newest first.
        let mut hosts: Vec<u64> = Vec::new();
        for r in found.iter().filter(|r| matches(r)) {
            if !hosts.contains(&r.host_id) {
                hosts.push(r.host_id);
            }
        }
        let mut rows = Vec::new();
        for host in hosts {
            let boots: Vec<usize> = (0..found.len())
                .filter(|&i| found[i].host_id == host)
                .collect();
            let newest = &found[boots[0]];
            rows.push(Row::Host {
                name: newest.name(),
                host_id: host,
                boots: boots.len(),
                path: newest.path.parent().unwrap_or(&newest.path).to_path_buf(),
            });
            rows.extend(boots.into_iter().map(Row::Boot));
        }
        rows
    }

    fn row_path<'a>(&'a self, row: &'a Row) -> &'a Path {
        match row {
            Row::Host { path, .. } => path,
            Row::Boot(i) => &self.recordings()[*i].path,
        }
    }

    /// Keep a row picked that the filter still shows: the first boot if the
    /// picked one went.
    fn keep_selection_visible(&mut self, cx: &App) {
        let rows = self.rows(cx);
        let shown = |p: &Path| rows.iter().any(|r| self.row_path(r) == p);
        if self.selected.as_deref().is_some_and(shown) {
            return;
        }
        self.selected = rows
            .iter()
            .find(|r| matches!(r, Row::Boot(_)))
            .map(|r| self.row_path(r).to_path_buf());
    }

    fn step(&mut self, down: bool, cx: &mut Context<Self>) {
        let rows = self.rows(cx);
        if rows.is_empty() {
            return;
        }
        let at = self
            .selected
            .as_deref()
            .and_then(|p| rows.iter().position(|r| self.row_path(r) == p));
        let next = match at {
            None => 0,
            Some(i) if down => (i + 1).min(rows.len() - 1),
            Some(i) => i.saturating_sub(1),
        };
        self.selected = Some(self.row_path(&rows[next]).to_path_buf());
        self.list.scroll_to_item(next, ScrollStrategy::Nearest);
        cx.notify();
    }

    /// Open the picked row of `view`, if there is one.
    pub fn open(view: &Entity<Self>, window: &mut Window, cx: &mut App) {
        let me = view.read(cx);
        let (on_open, picked) = (me.on_open.clone(), me.selected.clone());
        if let Some(path) = picked {
            on_open(path, window, cx);
        }
    }

    fn open_selected(&self, window: &mut Window, cx: &mut App) {
        if let Some(path) = self.selected.clone() {
            (self.on_open)(path, window, cx);
        }
    }

    fn render_boot(&self, row: usize, r: &Recording, theme: &gpui_kit::component::Theme) -> Div {
        let now = sysmon_ingest::unix_now_ns();
        let recording = self.live && now.saturating_sub(r.end_ns()) < LIVE_WITHIN_NS;
        let gaps = r.spans.len() - 1;
        let gap_text = match gaps {
            0 => "no gaps".to_string(),
            n => format!(
                "{n} gap{}, {} missing",
                if n == 1 { "" } else { "s" },
                format::duration(r.missing_ns())
            ),
        };
        div()
            .flex()
            .items_center()
            .gap_3()
            .pl(px(22.))
            .child(
                div()
                    .id(("recording-span", row))
                    .test_support()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .child(format::span(r.start_ns(), r.end_ns())),
            )
            .child(
                div()
                    .w(px(64.))
                    .flex_none()
                    .text_right()
                    .child(format::duration(r.end_ns() - r.start_ns())),
            )
            .child(coverage(r, theme))
            .child(
                div()
                    .w(px(150.))
                    .flex_none()
                    .whitespace_nowrap()
                    .text_color(if gaps == 0 {
                        theme.muted_foreground
                    } else {
                        theme.warning
                    })
                    .child(gap_text),
            )
            .child(
                div()
                    .w(px(72.))
                    .flex_none()
                    .text_right()
                    .text_color(theme.muted_foreground)
                    .child(format::bytes(r.bytes as f64)),
            )
            .child(
                div()
                    .w(px(70.))
                    .flex_none()
                    .flex()
                    .justify_end()
                    .when(recording, |d| {
                        d.child(
                            div()
                                .id(("recording-live", row))
                                .test_support()
                                .px_1()
                                .rounded_sm()
                                .text_color(theme.danger)
                                .border_1()
                                .border_color(theme.danger)
                                .child("recording"),
                        )
                    }),
            )
    }
}

/// How much of the boot's time has data: the stretches recorded, across
/// its whole span.
fn coverage(r: &Recording, theme: &gpui_kit::component::Theme) -> Div {
    let (start, end) = (r.start_ns(), r.end_ns());
    let total = (end - start).max(1) as f32;
    let mut bar = div()
        .relative()
        .w(px(COVERAGE_W))
        .flex_none()
        .h(px(8.))
        .rounded_sm()
        .bg(theme.muted);
    for &(a, b) in &r.spans {
        let left = (a - start) as f32 / total;
        // At least a sliver, so a short stretch still shows.
        let width = ((b - a) as f32 / total).max(2. / COVERAGE_W);
        bar = bar.child(
            div()
                .absolute()
                .top_0()
                .bottom_0()
                .left(relative(left.min(1. - width)))
                .w(relative(width))
                .rounded_sm()
                .bg(theme.primary),
        );
    }
    bar
}

impl Render for RecordingsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let rows = Rc::new(self.rows(cx));
        let this = cx.entity().downgrade();

        let body: AnyElement = match &self.scan {
            Scan::Running => message(format!("Reading {}…", self.dir.display()), &theme),
            Scan::Failed(e) => {
                message(format!("Couldn't read {}: {e}", self.dir.display()), &theme)
            }
            Scan::Done(found) if found.is_empty() => message(
                format!(
                    "No recordings in {}. Use Browse… to open one from elsewhere.",
                    self.dir.display()
                ),
                &theme,
            ),
            Scan::Done(_) if rows.is_empty() => message("No machine matches.".into(), &theme),
            Scan::Done(found) => {
                let found = Rc::new(found.clone());
                let selected = self.selected.clone();
                let view = cx.entity();
                uniform_list("recordings", rows.len(), {
                    let theme = theme.clone();
                    move |range, _, cx| {
                        let me = view.read(cx);
                        range
                            .map(|i| {
                                let row = &rows[i];
                                let path = me.row_path(row).to_path_buf();
                                let content = match row {
                                    Row::Host {
                                        name,
                                        host_id,
                                        boots,
                                        ..
                                    } => div()
                                        .flex()
                                        .items_baseline()
                                        .gap_2()
                                        .child(
                                            div()
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_sm()
                                                .child(name.clone()),
                                        )
                                        .child(div().text_color(theme.muted_foreground).child(
                                            format!(
                                                "{host_id:016x} · {boots} boot{}",
                                                if *boots == 1 { "" } else { "s" }
                                            ),
                                        )),
                                    Row::Boot(b) => me.render_boot(i, &found[*b], &theme),
                                };
                                let this = this.clone();
                                let picked = selected.as_ref() == Some(&path);
                                div()
                                    .id(("recording-row", i))
                                    .test_support()
                                    .h(px(ROW_H))
                                    .px_2()
                                    .flex()
                                    .flex_col()
                                    .justify_center()
                                    .text_xs()
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .highlighted(picked, &theme)
                                    .child(content)
                                    .on_click(move |ev, window, cx| {
                                        let _ = this.update(cx, |this, cx| {
                                            this.selected = Some(path.clone());
                                            cx.notify();
                                            if ev.click_count() >= 2 {
                                                this.open_selected(window, cx);
                                            }
                                        });
                                    })
                            })
                            .collect()
                    }
                })
                .track_scroll(&self.list)
                .flex_1()
                .into_any_element()
            }
        };

        div()
            .id("recordings")
            .test_support()
            .flex()
            .flex_col()
            .gap_3()
            .h(px(480.))
            // Enter is the dialog's Confirm, which opens the picked row.
            .capture_key_down(cx.listener(|this, ev: &KeyDownEvent, _, cx| {
                match ev.keystroke.key.as_str() {
                    "up" => this.step(false, cx),
                    "down" => this.step(true, cx),
                    _ => return,
                }
                cx.stop_propagation();
            }))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div().w(px(260.)).child(
                            Input::new(&self.filter)
                                .small()
                                .prefix(icon(IconName::Search))
                                .cleanable(true),
                        ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(format!("In {}", self.dir.display())),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .border_1()
                    .border_color(theme.border)
                    .rounded_md()
                    .p_1()
                    .child(body),
            )
    }
}

fn message(text: String, theme: &gpui_kit::component::Theme) -> AnyElement {
    div()
        .id("recordings-message")
        .test_support()
        .p_3()
        .text_sm()
        .text_color(theme.muted_foreground)
        .child(text)
        .into_any_element()
}
