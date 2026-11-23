//! Small drawing helpers: usage bars, sparklines, and the look of buttons
//! that pick one of several options or switch something on.

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::*;

/// A button drawn as chosen (primary) or not (ghost). Not `toggled`:
/// gpui-kit's `Button::toggled` only sets the accessible pressed state.
pub trait Chosen {
    fn chosen(self, on: bool) -> Self;
}

impl Chosen for Button {
    fn chosen(self, on: bool) -> Self {
        if on { self.primary() } else { self.ghost() }
    }
}

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

/// A line chart of one or more series, each `(values, colour)`, newest on
/// the right. All share one scale: `max`, or the largest value of any series
/// when `max` is `None`. Later series are drawn on top.
pub fn sparkline(
    series: Vec<(Vec<f32>, Hsla)>,
    max: Option<f32>,
    capacity: usize,
    track: Hsla,
) -> impl IntoElement {
    let max = max
        .unwrap_or_else(|| {
            series
                .iter()
                .flat_map(|(v, _)| v.iter().copied())
                .fold(0.0, f32::max)
        })
        .max(f32::EPSILON);
    // At least 160 px; as wide as the tile when its text is wider.
    div()
        .w_full()
        .min_w(px(160.))
        .h(px(28.))
        .rounded_sm()
        .bg(track)
        .child(
            canvas(
                |_, _, _| (),
                move |bounds, (), window, _| {
                    let step = bounds.size.width / (capacity.max(2) - 1) as f32;
                    let y = |v: f32| {
                        let frac = (v / max).clamp(0.0, 1.0);
                        bounds.origin.y + bounds.size.height * (1.0 - frac) - px(1.) * (1.0 - frac)
                    };
                    for (values, color) in &series {
                        if values.len() < 2 {
                            continue;
                        }
                        let x0 =
                            bounds.origin.x + bounds.size.width - step * (values.len() - 1) as f32;
                        let mut path = PathBuilder::stroke(px(1.5));
                        path.move_to(point(x0, y(values[0])));
                        for (i, v) in values.iter().enumerate().skip(1) {
                            path.line_to(point(x0 + step * i as f32, y(*v)));
                        }
                        if let Ok(path) = path.build() {
                            window.paint_path(path, *color);
                        }
                    }
                },
            )
            .size_full(),
        )
}
