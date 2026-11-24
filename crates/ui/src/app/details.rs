//! The bottom panel's Details tab: everything known about the process under
//! the table's cursor. It follows the cursor, and keeps showing a process
//! that has exited (its last row, marked "exited") until the cursor moves.

use gpui_kit::component::Theme;
use sysmon_model::LogRow;
use sysmon_proto::LogEntry;

use super::*;

/// Children, threads and log lines listed at most; the rest are counted.
const DETAILS_LIST_MAX: usize = 100;
/// Width of the label column of the facts.
const FACT_LABEL_W: f32 = 64.;
/// Width of one metric tile.
const METRIC_W: f32 = 170.;

/// The process the Details tab last showed, kept for when it exits.
#[derive(Debug, Clone)]
pub(super) struct DetailsMemo {
    /// View and host it belongs to.
    at: (View, u64),
    /// The cursor's key: the process's, or one of its threads'.
    cursor: ProcKey,
    row: ProcRow,
    started_unix_ns: Option<u64>,
    /// Sample time it was last seen at.
    seen_ns: u64,
}

/// What the tab shows about the process.
struct Shown<'a> {
    row: &'a ProcRow,
    /// `None` once it has exited.
    live: Option<sysmon_model::ProcDetails<'a>>,
    started_unix_ns: Option<u64>,
    seen_ns: u64,
}

/// The kernel's process states, as `ps(1)` names them.
fn state_name(state: char) -> &'static str {
    match state {
        'R' => "running",
        'S' => "sleeping",
        'D' => "waiting on I/O",
        'Z' => "zombie",
        'T' => "stopped",
        't' => "stopped by a tracer",
        'X' => "dead",
        'I' => "idle",
        'P' => "parked",
        'W' => "paging",
        'K' => "wakekill",
        _ => "unknown",
    }
}

impl AppState {
    /// Remember the cursor's process while it's running, so the tab can
    /// still show it after it exits.
    pub(super) fn refresh_details(&mut self) {
        let (Some(cursor), Some(host)) = (self.cursor, self.current_host()) else {
            return;
        };
        let at = (self.view, host.host_id);
        if let Some(d) = host.details(cursor) {
            let memo = DetailsMemo {
                at,
                cursor,
                row: d.row.clone(),
                started_unix_ns: d.started_unix_ns,
                seen_ns: host.snapshot.ts_unix_ns,
            };
            self.details_memo = Some(memo);
        }
    }

    fn details_shown<'a>(&'a self, host: &'a HostModel) -> Option<Shown<'a>> {
        let cursor = self.cursor?;
        if let Some(d) = host.details(cursor) {
            return Some(Shown {
                row: d.row,
                started_unix_ns: d.started_unix_ns,
                seen_ns: host.snapshot.ts_unix_ns,
                live: Some(d),
            });
        }
        let memo = self
            .details_memo
            .as_ref()
            .filter(|m| m.at == (self.view, host.host_id) && m.cursor == cursor)?;
        Some(Shown {
            row: &memo.row,
            live: None,
            started_unix_ns: memo.started_unix_ns,
            seen_ns: memo.seen_ns,
        })
    }

    /// Switch to the Logs tab with the line `key` (receive time, log time)
    /// selected and in view.
    fn open_log_line(&mut self, key: (u64, u64), cx: &mut Context<Self>) {
        self.panel = Panel::Logs;
        self.log_clicked(key, cx);
        self.log_reveal.set(true);
    }

    pub(super) fn render_details(
        &self,
        host: &HostModel,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let theme = cx.theme().clone();
        let shown = self.details_shown(host);
        let title = match &shown {
            Some(s) => format!("{} · PID {}", proc_name(s.row), s.row.key.pid),
            None => String::new(),
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
                    .id("details-title")
                    .test_support()
                    .text_sm()
                    .aria_description(title.clone())
                    .child(title),
            )
            .when(shown.as_ref().is_some_and(|s| s.live.is_none()), |d| {
                d.child(
                    div()
                        .id("details-exited")
                        .test_support()
                        .text_xs()
                        .text_color(theme.danger)
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(icon(IconName::CircleX).text_color(theme.danger))
                        .child("exited"),
                )
            })
            .child(div().flex_1())
            .when_some(shown.as_ref().filter(|s| s.live.is_some()), |d, s| {
                let target = SeriesTarget::Process(s.row.key);
                let slot = self
                    .selection()
                    .and_then(|sel| sel.iter().find(|p| p.target == target))
                    .map(|p| p.slot);
                let picked = slot.is_some();
                d.child(
                    // While graphed it says so, with its line's colour as
                    // in the table's checkbox (a filled button alone looked
                    // like the selected tab beside it).
                    Button::new("details-graph")
                        .icon(icon(IconName::ChartLine))
                        .label(if picked { "Graphed" } else { "Graph" })
                        .small()
                        .map(|b| if picked { b.outline() } else { b.ghost() })
                        .children(slot.map(|slot| {
                            div()
                                .id("details-graph-color")
                                .test_support()
                                .size(px(8.))
                                .rounded_full()
                                .bg(selection::color(slot))
                        }))
                        .tooltip(if picked {
                            "Take the process out of the graph"
                        } else {
                            "Add the process to the graph"
                        })
                        .on_click(cx.listener(move |this, _, _, cx| this.toggle_pick(target, cx))),
                )
            })
            .child(
                Button::new("details-hide")
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

        let body = match shown {
            None => div()
                .id("details-empty")
                .test_support()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child("Move the cursor to a process (click a row, or ↑/↓) to see its details")
                .into_any_element(),
            Some(s) => div()
                .flex()
                .flex_1()
                .min_h_0()
                .gap_4()
                .px_2()
                .pb_2()
                .child(Self::details_facts(host, &s, &theme, cx))
                .child(Self::details_metrics(host, &s, &theme))
                .child(Self::details_lists(host, &s, &theme, cx))
                .into_any_element(),
        };

        div()
            .id("details-panel")
            .test_support()
            .flex()
            .flex_col()
            .size_full()
            .border_t_1()
            .border_color(theme.border)
            .child(toolbar)
            .child(body)
    }

    /// PID, parent, user, state, times and the command line.
    fn details_facts(
        host: &HostModel,
        s: &Shown,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let row = s.row;
        let fact = |id: &'static str, label: &'static str, value: String| {
            div()
                .flex()
                .gap_2()
                .child(
                    div()
                        .flex_none()
                        .w(px(FACT_LABEL_W))
                        .text_color(theme.muted_foreground)
                        .child(label),
                )
                .child(
                    div()
                        .id(id)
                        .test_support()
                        .flex_1()
                        .min_w_0()
                        .aria_description(format!("{label} {value}"))
                        .child(value),
                )
        };
        let parent_row = s.live.as_ref().and_then(|d| d.parent);
        let parent = match parent_row {
            Some(p) => format!("{} {}", p.key.pid, proc_name(p)),
            None if row.ppid == 0 => "–".into(),
            None => row.ppid.to_string(),
        };
        // Click the parent to move the cursor to it.
        let hover = theme.muted;
        let parent_fact = div()
            .flex()
            .gap_2()
            .child(
                div()
                    .flex_none()
                    .w(px(FACT_LABEL_W))
                    .text_color(theme.muted_foreground)
                    .child("Parent"),
            )
            .child(
                div()
                    .id("details-parent")
                    .test_support()
                    .flex_1()
                    .min_w_0()
                    .aria_description(format!("Parent {parent}"))
                    .child(parent)
                    .when_some(parent_row.map(|p| p.key.pid), |d, pid| {
                        d.cursor_pointer()
                            .hover(move |st| st.bg(hover))
                            .on_click(cx.listener(move |this, _, _, cx| this.show_process(pid, cx)))
                    }),
            );
        let user = match (&row.user, row.uid) {
            (Some(name), Some(uid)) => format!("{name} ({uid})"),
            (None, Some(uid)) => uid.to_string(),
            _ => "–".into(),
        };
        let mut state = format!("{} – {}", row.state, state_name(row.state));
        if row.kernel_thread {
            state.push_str(", kernel thread");
        }
        if row.stale {
            state.push_str(" (last sample lost)");
        }
        let started = s
            .started_unix_ns
            .map_or_else(|| "– (agent too old)".into(), format::datetime);
        let running = s.started_unix_ns.map_or_else(
            || "–".into(),
            |t| format::duration(s.seen_ns.saturating_sub(t)),
        );
        let threads = match s.live.as_ref() {
            // Only when they differ: "7 (7 listed)" said the same twice.
            Some(d) if host.sends_threads() && d.threads.len() + 1 != row.threads as usize => {
                format!("{} ({} listed)", row.threads, d.threads.len() + 1)
            }
            _ => row.threads.to_string(),
        };
        div()
            .id("details-facts")
            .test_support()
            .flex_none()
            .w(px(340.))
            .flex()
            .flex_col()
            .gap_0p5()
            .overflow_y_scroll()
            .text_xs()
            .child(fact("details-pid", "PID", row.key.pid.to_string()))
            .child(parent_fact)
            .child(fact("details-user", "User", user))
            .child(fact("details-state", "State", state))
            .child({
                let zone = s
                    .started_unix_ns
                    .map(|t| format!("Local time ({})", format::utc_offset(t)));
                div()
                    .id("details-started-zone")
                    .when_some(zone, |d, zone| {
                        d.tooltip(move |window, cx| Tooltip::new(zone.clone()).build(window, cx))
                    })
                    .child(fact("details-started", "Started", started))
            })
            .child(fact("details-running", "Running", running))
            .child(fact("details-threads", "Threads", threads))
            .child(
                div()
                    .mt_1()
                    .text_color(theme.muted_foreground)
                    .child("Command"),
            )
            .child({
                let cmd = command(row);
                div()
                    .id("details-cmdline")
                    .test_support()
                    .font_family(theme.mono_font_family.clone())
                    .aria_description(cmd.clone())
                    .child(cmd)
            })
    }

    /// Each metric's latest value with its last 10 minutes.
    fn details_metrics(host: &HostModel, s: &Shown, theme: &Theme) -> impl IntoElement + use<> {
        let target = SeriesTarget::Process(s.row.key);
        let since = host.proc_history.front().map_or(0, |f| f.ts_unix_ns);
        let mut grid = div()
            .id("details-metrics")
            .test_support()
            .flex_none()
            .w(px(METRIC_W * 2. + 12.))
            .flex()
            .flex_wrap()
            .gap_3()
            .content_start()
            .overflow_y_scroll();
        for (i, m) in Metric::ALL.into_iter().enumerate() {
            let points = host.series(target, m, since);
            let values = spark_values(&points);
            let latest = s
                .live
                .as_ref()
                .and_then(|_| host.latest(target, m))
                .map(|(v, _)| v);
            let figure = latest.map_or_else(|| "–".into(), |v| graph::format_value(m, v));
            grid = grid.child(
                div()
                    .id(("details-metric", i))
                    .test_support()
                    .w(px(METRIC_W))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .text_xs()
                    .aria_description(format!("{} {figure}", m.label()))
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .child(div().text_color(theme.muted_foreground).child(m.label()))
                            .child(figure),
                    )
                    .child(sparkline(
                        vec![(values, selection::color(0))],
                        // Each on its own scale: a busy process can use more
                        // than one core, and small figures would sit flat.
                        None,
                        HISTORY_LEN,
                        theme.secondary,
                    )),
            );
        }
        grid
    }

    /// Children, threads and the process's log lines.
    fn details_lists(
        host: &HostModel,
        s: &Shown,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let hover = theme.muted;
        let mono = theme.mono_font_family.clone();
        // Every row is `flex_none`: the column scrolls, and a row that may
        // shrink is squeezed to nothing when the panel is short (`truncate`
        // clips it, which lets its height go down to zero).
        let heading = |text: String| {
            div()
                .flex_none()
                .mt_1()
                .text_color(theme.muted_foreground)
                .child(text)
        };
        let item = |id: (&'static str, usize), text: String| {
            div()
                .id(id)
                .test_support()
                .flex_none()
                .font_family(mono.clone())
                .truncate()
                .aria_description(text.clone())
                .child(text)
        };
        let more = |n: usize| {
            (n > DETAILS_LIST_MAX).then(|| {
                div()
                    .flex_none()
                    .text_color(theme.muted_foreground)
                    .child(format!("and {} more", n - DETAILS_LIST_MAX))
            })
        };
        let mut col = div()
            .id("details-lists")
            .test_support()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_0p5()
            .overflow_y_scroll()
            .text_xs();

        if let Some(d) = &s.live {
            col = col.child(heading(format!("Children ({})", d.children.len())));
            for (i, c) in d.children.iter().take(DETAILS_LIST_MAX).enumerate() {
                // Click a child to move the cursor to it.
                let pid = c.key.pid;
                col = col.child(
                    item(
                        ("details-child", i),
                        format!("{:>7}  {:>5.1}%  {}", pid, c.cpu_pct, command(c)),
                    )
                    .cursor_pointer()
                    .hover(move |st| st.bg(hover))
                    .on_click(cx.listener(move |this, _, _, cx| this.show_process(pid, cx))),
                );
            }
            col = col.children(more(d.children.len()));
            if host.sends_threads() {
                col = col.child(heading(format!("Threads ({})", d.threads.len())));
                for (i, t) in d.threads.iter().take(DETAILS_LIST_MAX).enumerate() {
                    col = col.child(item(
                        ("details-thread", i),
                        format!(
                            "{:>7}  {:>5.1}%  {}  {}",
                            t.key.pid, t.cpu_pct, t.state, t.comm
                        ),
                    ));
                }
                col = col.children(more(d.threads.len()));
            }
        }

        if host.logs.enabled() {
            let lines: Vec<(&LogRow, &LogEntry)> = host
                .logs
                .for_pid(s.row.key.pid, s.started_unix_ns)
                .rev()
                .filter_map(|r| match &r.kind {
                    LogKind::Line(e) => Some((r, e)),
                    _ => None,
                })
                .collect();
            col = col.child(heading(format!(
                "Log lines, newest first ({})",
                lines.len()
            )));
            for (i, &(r, e)) in lines.iter().take(DETAILS_LIST_MAX).enumerate() {
                // Click a line to find it in the Logs tab.
                let key = (r.received_ns, r.ts_unix_ns);
                let first = e.message.lines().next().unwrap_or("");
                col = col.child(
                    div()
                        .id(("details-log", i))
                        .test_support()
                        .flex_none()
                        .cursor_pointer()
                        .hover(move |st| st.bg(hover))
                        .on_click(cx.listener(move |this, _, _, cx| this.open_log_line(key, cx)))
                        .flex()
                        .gap_2()
                        .font_family(mono.clone())
                        .aria_description(e.message.clone())
                        .child(div().flex_none().child(format::day_time(e.ts_unix_ns)))
                        .child(priority_cell(e.priority, theme))
                        .child(div().flex_1().min_w_0().truncate().child(first.to_string())),
                );
            }
            col = col.children(more(lines.len()));
        }
        col
    }
}

/// A sparkline's values from a graph line: from the first sample the
/// process was in, with gaps (lost chunks) holding the last value.
fn spark_values(points: &[(u64, Option<f32>)]) -> Vec<f32> {
    let mut last = None;
    points
        .iter()
        .filter_map(|&(_, v)| {
            last = v.or(last);
            last
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::spark_values;

    #[test]
    fn sparks_start_with_the_process_and_bridge_gaps() {
        let p = [(0, None), (1, Some(2.0)), (2, None), (3, Some(4.0))];
        assert_eq!(spark_values(&p), [2.0, 2.0, 4.0]);
        assert!(spark_values(&[(0, None)]).is_empty());
    }
}
