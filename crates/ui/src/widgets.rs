//! Small drawing helpers: usage bars and sparklines.

use gpui_kit::*;

/// A horizontal bar filled to `pct` (0..=100).
pub fn bar(pct: f32, width: Pixels, track: Hsla, fill: Hsla) -> impl IntoElement {
    div().w(width).h(px(8.)).rounded_sm().bg(track).child(
        div()
            .h_full()
            .rounded_sm()
            .bg(fill)
            .w(relative(pct.clamp(0.0, 100.0) / 100.0)),
    )
}

/// A line chart of `values` scaled to `max` (or to the largest value when
/// `max` is `None`), newest on the right.
pub fn sparkline(
    values: Vec<f32>,
    max: Option<f32>,
    capacity: usize,
    color: Hsla,
    track: Hsla,
) -> impl IntoElement {
    let max = max
        .unwrap_or_else(|| values.iter().copied().fold(0.0, f32::max))
        .max(f32::EPSILON);
    div().w(px(160.)).h(px(28.)).rounded_sm().bg(track).child(
        canvas(
            |_, _, _| (),
            move |bounds, (), window, _| {
                if values.len() < 2 {
                    return;
                }
                let step = bounds.size.width / (capacity.max(2) - 1) as f32;
                let x0 = bounds.origin.x + bounds.size.width - step * (values.len() - 1) as f32;
                let y = |v: f32| {
                    let frac = (v / max).clamp(0.0, 1.0);
                    bounds.origin.y + bounds.size.height * (1.0 - frac) - px(1.) * (1.0 - frac)
                };
                let mut path = PathBuilder::stroke(px(1.5));
                path.move_to(point(x0, y(values[0])));
                for (i, v) in values.iter().enumerate().skip(1) {
                    path.line_to(point(x0 + step * i as f32, y(*v)));
                }
                if let Ok(path) = path.build() {
                    window.paint_path(path, color);
                }
            },
        )
        .size_full(),
    )
}
