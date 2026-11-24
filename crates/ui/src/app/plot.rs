//! The graph panel's chart, axis labels and legend, as a view of their own.
//!
//! Moving the pointer over the chart moves the crosshair and changes the
//! legend's values, and nothing else. When that notified the whole app, every
//! mouse move built the window again (the process table alone is most of a
//! frame), which kept a core busy while the pointer was over the chart. As a
//! view of its own, only this is built again, and the rest of the window is
//! drawn from the last frame.

use super::*;

/// What the app hands the plot each time it renders.
pub(super) struct PlotData {
    pub lines: Rc<Vec<graph::Line>>,
    pub start_ns: u64,
    pub end_ns: u64,
    pub y_max: f32,
    pub metric: Metric,
    /// The selected log line's time, marked on the chart.
    pub log_mark: Option<u64>,
    /// One per line, in the same order.
    pub legend: Vec<LegendEntry>,
}

pub(super) struct LegendEntry {
    pub slot: usize,
    pub key: ProcKey,
    pub label: String,
    /// The newest value, if the process is still there.
    pub latest: Option<f32>,
}

pub(super) struct GraphPlot {
    app: WeakEntity<AppState>,
    data: Option<PlotData>,
    /// The sample under the pointer (its time), if it's over the chart.
    pub(super) hover: Option<u64>,
    bounds: graph::ChartBounds,
}

impl GraphPlot {
    pub(super) fn new(app: WeakEntity<AppState>) -> Self {
        Self {
            app,
            data: None,
            hover: None,
            bounds: Default::default(),
        }
    }

    /// New figures from the app; drawn when it draws.
    pub(super) fn set(&mut self, data: PlotData) {
        self.data = Some(data);
    }

    /// The sample nearest to `f` of the way across the chart. The values
    /// only change from one sample to the next, so the crosshair snaps to
    /// them, and moving the pointer within one draws nothing again.
    fn sample_at(data: &PlotData, f: f32) -> u64 {
        let t = data.start_ns + ((data.end_ns - data.start_ns) as f64 * f as f64) as u64;
        let Some(points) = data.lines.iter().map(|l| &l.points).max_by_key(|p| p.len()) else {
            return t;
        };
        let i = points.partition_point(|p| p.0 < t);
        [i.checked_sub(1), Some(i)]
            .into_iter()
            .flatten()
            .filter_map(|i| points.get(i).map(|p| p.0))
            .min_by_key(|ts| ts.abs_diff(t))
            .unwrap_or(t)
    }
}

impl Render for GraphPlot {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let Some(data) = &self.data else {
            return div().into_any_element();
        };
        let metric = data.metric;
        let (start, end) = (data.start_ns, data.end_ns);
        let hover_ns = self.hover;

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
            .child(graph::format_value(metric, data.y_max))
            .child(graph::format_value(metric, data.y_max / 2.0))
            .child(graph::format_value(metric, 0.0));
        let plot = div()
            .id("graph-plot")
            .test_support()
            .flex_1()
            .h_full()
            .border_1()
            .border_color(theme.border)
            .on_mouse_move(cx.listener(|this, ev: &MouseMoveEvent, _, cx| {
                if let (Some(b), Some(data)) = (this.bounds.get(), &this.data) {
                    let f = f32::from(ev.position.x - b.origin.x) / f32::from(b.size.width);
                    let at = Some(Self::sample_at(data, f.clamp(0.0, 1.0)));
                    if this.hover != at {
                        this.hover = at;
                        cx.notify();
                    }
                }
            }))
            .on_hover(cx.listener(|this, hovered: &bool, _, cx| {
                if !*hovered && this.hover.take().is_some() {
                    cx.notify();
                }
            }))
            .child(graph::chart(
                graph::ChartSpec {
                    lines: data.lines.clone(),
                    start_ns: start,
                    end_ns: end,
                    y_max: data.y_max,
                    hover_ns,
                    mark: data.log_mark.map(|ts| (ts, theme.warning)),
                    grid: theme.border,
                    crosshair: theme.muted_foreground,
                },
                self.bounds.clone(),
            ));
        let x_labels = div()
            .flex()
            .justify_between()
            .pl(px(AXIS_LABELS_W))
            .text_xs()
            .text_color(theme.muted_foreground)
            .child(format::time(start))
            .child(match (hover_ns, data.log_mark) {
                (Some(h), _) => div().child(format::time(h)).into_any_element(),
                // The selected log line's time, drawn as a line on the chart.
                (None, Some(ts)) if (start..=end).contains(&ts) => {
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
        for (entry, line) in data.legend.iter().zip(data.lines.iter()) {
            let value = match hover_ns {
                Some(t) => graph::value_at(&line.points, t),
                None => entry.latest,
            };
            let value = match (value, entry.latest) {
                (Some(v), _) => graph::format_value(metric, v),
                (None, None) => "exited".into(),
                (None, Some(_)) => "–".into(),
            };
            let (key, app) = (entry.key, self.app.clone());
            legend = legend.child(
                div()
                    .id(("legend", entry.slot))
                    .test_support()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_none().size(px(10.)).rounded_sm().bg(line.color))
                    .child(clipped(
                        ("legend-label", entry.slot),
                        entry.label.clone(),
                        entry.label.clone(),
                    ))
                    .child(
                        div()
                            .flex_none()
                            .font_family(theme.mono_font_family.clone())
                            .child(value),
                    )
                    .child(
                        div()
                            .id(("legend-remove", entry.slot))
                            .test_support()
                            .flex_none()
                            .px_1()
                            .cursor_pointer()
                            .text_color(theme.muted_foreground)
                            .aria_description("Remove from the graph")
                            .tooltip(|window, cx| {
                                Tooltip::new("Remove from the graph").build(window, cx)
                            })
                            .child(icon(IconName::X))
                            .on_click(move |_, _, cx| {
                                let _ = app.update(cx, |app, cx| app.remove_pick(key, cx));
                            }),
                    ),
            );
        }

        div()
            .flex()
            .size_full()
            .child(chart)
            .child(legend)
            .into_any_element()
    }
}
