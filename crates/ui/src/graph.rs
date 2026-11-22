//! The multi-line chart in the graph panel, and the pure helpers behind it.

use std::cell::Cell;
use std::rc::Rc;

use gpui_kit::*;
use sysmon_model::Metric;

use crate::format;

/// Time windows offered for the graph, in seconds.
pub const WINDOWS_S: [u64; 3] = [60, 300, 600];

/// One line to draw.
pub struct Line {
    pub color: Hsla,
    pub points: Vec<(u64, Option<f32>)>,
}

/// Round up to 1, 2 or 5 × 10ⁿ so axis labels are readable.
pub fn nice_ceiling(v: f32) -> f32 {
    if v <= 0.0 || !v.is_finite() {
        return 1.0;
    }
    let mag = 10f32.powf(v.log10().floor());
    let n = v / mag;
    let step = if n <= 1.0 {
        1.0
    } else if n <= 2.0 {
        2.0
    } else if n <= 5.0 {
        5.0
    } else {
        10.0
    };
    step * mag
}

/// The top of the y axis for these lines.
pub fn y_max(metric: Metric, lines: &[Line]) -> f32 {
    let max = lines
        .iter()
        .flat_map(|l| l.points.iter().filter_map(|(_, v)| *v))
        .fold(0.0f32, f32::max);
    match metric {
        // Keep 0-100 % as the frame unless something is above it (a busy
        // multi-threaded process can use several cores).
        Metric::Cpu => nice_ceiling(max.max(100.0)),
        Metric::MemPct => nice_ceiling(max.max(1.0)),
        Metric::Threads => nice_ceiling(max.max(4.0)),
        Metric::Virt | Metric::Rss | Metric::Shr => nice_size_ceiling(max.max(1024.0)),
    }
}

/// Like [`nice_ceiling`] for sizes in KiB, in binary units, so the axis
/// reads 500 MiB or 2 GiB rather than 9.5 GiB.
pub fn nice_size_ceiling(kib: f32) -> f32 {
    let mut unit = 1.0f32;
    while kib / unit >= 1024.0 {
        unit *= 1024.0;
    }
    let n = nice_ceiling(kib / unit);
    // 1000 KiB would read oddly; go to the next unit instead.
    if n >= 1000.0 { unit * 1024.0 } else { n * unit }
}

/// Split a line into runs of consecutive present values.
pub fn segments(points: &[(u64, Option<f32>)]) -> Vec<Vec<(u64, f32)>> {
    let mut out: Vec<Vec<(u64, f32)>> = Vec::new();
    let mut current = Vec::new();
    for &(ts, v) in points {
        match v {
            Some(v) => current.push((ts, v)),
            None if !current.is_empty() => out.push(std::mem::take(&mut current)),
            None => {}
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The value of a line at the sample nearest `ts`.
pub fn value_at(points: &[(u64, Option<f32>)], ts: u64) -> Option<f32> {
    let i = points.partition_point(|(t, _)| *t < ts);
    let candidates = [i.checked_sub(1), Some(i)];
    candidates
        .into_iter()
        .flatten()
        .filter_map(|j| points.get(j))
        .min_by_key(|(t, _)| t.abs_diff(ts))
        .and_then(|(_, v)| *v)
}

pub fn format_value(metric: Metric, v: f32) -> String {
    match metric {
        Metric::Cpu | Metric::MemPct => format!("{v:.1}%"),
        Metric::Virt | Metric::Rss | Metric::Shr => format::bytes(v as f64 * 1024.0),
        Metric::Threads => format!("{v:.0}"),
    }
}

/// Where the chart was laid out last frame, so mouse positions can be
/// turned into times.
pub type ChartBounds = Rc<Cell<Option<Bounds<Pixels>>>>;

/// What to draw: `lines` over `[start_ns, end_ns]` scaled to `[0, y_max]`,
/// with an optional crosshair at `hover_ns`.
pub struct ChartSpec {
    pub lines: Vec<Line>,
    pub start_ns: u64,
    pub end_ns: u64,
    pub y_max: f32,
    pub hover_ns: Option<u64>,
    /// A time to mark with a vertical line (the selected log line), and its colour.
    pub mark: Option<(u64, Hsla)>,
    pub grid: Hsla,
    pub crosshair: Hsla,
}

/// Paint a chart; its bounds are written to `bounds_out` for hit testing.
pub fn chart(spec: ChartSpec, bounds_out: ChartBounds) -> impl IntoElement {
    let ChartSpec {
        lines,
        start_ns,
        end_ns,
        y_max,
        hover_ns,
        mark,
        grid,
        crosshair,
    } = spec;
    canvas(
        move |bounds, _, _| bounds_out.set(Some(bounds)),
        move |bounds, (), window, _| {
            let span = end_ns.saturating_sub(start_ns).max(1) as f32;
            let x = |ts: u64| {
                bounds.origin.x
                    + bounds.size.width * (ts.saturating_sub(start_ns) as f32 / span).min(1.0)
            };
            let y =
                |v: f32| bounds.origin.y + bounds.size.height * (1.0 - (v / y_max).clamp(0.0, 1.0));

            for frac in [0.0, 0.5, 1.0] {
                let gy = bounds.origin.y + bounds.size.height * frac;
                let mut p = PathBuilder::stroke(px(1.));
                p.move_to(point(bounds.origin.x, gy));
                p.line_to(point(bounds.origin.x + bounds.size.width, gy));
                if let Ok(p) = p.build() {
                    window.paint_path(p, grid);
                }
            }

            for line in &lines {
                for seg in segments(&line.points) {
                    if let [(ts, v)] = seg[..] {
                        // A lone sample between gaps: draw a dot.
                        window.paint_quad(fill(
                            Bounds::centered_at(point(x(ts), y(v)), size(px(3.), px(3.))),
                            line.color,
                        ));
                        continue;
                    }
                    let mut p = PathBuilder::stroke(px(1.5));
                    p.move_to(point(x(seg[0].0), y(seg[0].1)));
                    for &(ts, v) in &seg[1..] {
                        p.line_to(point(x(ts), y(v)));
                    }
                    if let Ok(p) = p.build() {
                        window.paint_path(p, line.color);
                    }
                }
            }

            if let Some((m, color)) = mark
                && (start_ns..=end_ns).contains(&m)
            {
                let mx = x(m);
                let mut p = PathBuilder::stroke(px(2.));
                p.move_to(point(mx, bounds.origin.y));
                p.line_to(point(mx, bounds.origin.y + bounds.size.height));
                if let Ok(p) = p.build() {
                    window.paint_path(p, color);
                }
            }

            if let Some(h) = hover_ns {
                let hx = x(h);
                let mut p = PathBuilder::stroke(px(1.));
                p.move_to(point(hx, bounds.origin.y));
                p.line_to(point(hx, bounds.origin.y + bounds.size.height));
                if let Ok(p) = p.build() {
                    window.paint_path(p, crosshair);
                }
                for line in &lines {
                    if let Some(v) = value_at(&line.points, h) {
                        window.paint_quad(fill(
                            Bounds::centered_at(point(hx, y(v)), size(px(6.), px(6.))),
                            line.color,
                        ));
                    }
                }
            }
        },
    )
    .size_full()
}

#[cfg(test)]
mod tests {
    // Explicit imports: the gpui glob would shadow `#[test]`.
    use super::{Line, nice_ceiling, nice_size_ceiling, segments, value_at, y_max};
    use gpui_kit::hsla;
    use sysmon_model::Metric;

    #[test]
    fn nice_numbers() {
        assert_eq!(nice_ceiling(0.0), 1.0);
        assert_eq!(nice_ceiling(3.0), 5.0);
        assert_eq!(nice_ceiling(100.0), 100.0);
        assert_eq!(nice_ceiling(101.0), 200.0);
        assert_eq!(nice_ceiling(0.12), 0.2);
        assert_eq!(nice_ceiling(7300.0), 10_000.0);
    }

    #[test]
    fn size_axis_uses_binary_units() {
        const MIB: f32 = 1024.0;
        assert_eq!(nice_size_ceiling(300.0 * MIB), 500.0 * MIB);
        assert_eq!(nice_size_ceiling(1.5 * MIB * 1024.0), 2.0 * MIB * 1024.0);
        assert_eq!(nice_size_ceiling(900.0 * MIB), MIB * 1024.0);
        assert_eq!(nice_size_ceiling(3.0), 5.0);
    }

    #[test]
    fn cpu_axis_is_at_least_100() {
        let line = |v: f32| Line {
            color: hsla(0., 0., 0., 1.),
            points: vec![(0, Some(v))],
        };
        assert_eq!(y_max(Metric::Cpu, &[line(12.0)]), 100.0);
        assert_eq!(y_max(Metric::Cpu, &[line(350.0)]), 500.0);
    }

    #[test]
    fn gaps_split_lines() {
        let pts = [
            (1, Some(1.0)),
            (2, Some(2.0)),
            (3, None),
            (4, Some(4.0)),
            (5, None),
            (6, None),
        ];
        assert_eq!(segments(&pts), [vec![(1, 1.0), (2, 2.0)], vec![(4, 4.0)]]);
        assert_eq!(value_at(&pts, 2), Some(2.0));
        assert_eq!(value_at(&pts, 4), Some(4.0));
        assert_eq!(value_at(&pts, 3), None, "nearest sample is a gap");
        assert_eq!(value_at(&pts, 100), None);
    }
}
