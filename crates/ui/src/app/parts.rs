//! The slow-to-build parts of the window, each drawn as a cached view.
//!
//! The process table (sixty-odd rows of a dozen cells) and the sidebar
//! were built inside the app's own view, so anything that changed in the
//! window built them again —
//! every mouse move over the graph, every tick of the replay timeline.
//! As cached views they're built again only when the app is notified
//! (new data, sort, filter, cursor…), and otherwise drawn from the last
//! frame. Moving the pointer over the graph notifies only the graph's own
//! view ([`super::plot`]), so these are left as they are.
//!
//! A cached view is laid out at a size given from outside, so only parts
//! that fill a box of known size can be one: not the header, whose height
//! is that of its content (it collapsed to nothing and the table drew over
//! it).

use super::*;

#[derive(Clone, Copy)]
pub(super) enum Part {
    Table,
    Sidebar,
}

pub(super) struct PartView {
    app: WeakEntity<AppState>,
    part: Part,
    _redraw: Subscription,
}

impl PartView {
    /// Drawn again whenever `app` is notified. Reading the app from inside
    /// this view's render doesn't count as depending on it, so without the
    /// subscription the part was drawn once and never again.
    pub(super) fn new(app: &Entity<AppState>, part: Part, cx: &mut Context<Self>) -> Self {
        Self {
            app: app.downgrade(),
            part,
            _redraw: cx.observe(app, |_, _, cx| cx.notify()),
        }
    }

    /// How it's laid out where the app places it.
    pub(super) fn style(part: Part) -> StyleRefinement {
        match part {
            Part::Table => StyleRefinement::default().size_full().flex().flex_col(),
            Part::Sidebar => StyleRefinement::default()
                .w(px(SIDEBAR_W))
                .h_full()
                .flex_none(),
        }
    }
}

impl Render for PartView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let part = self.part;
        let mono_char = mono_char_width(window, cx);
        let inner = self
            .app
            .update(cx, |app, cx| {
                let app: &AppState = app;
                match (part, app.current_host()) {
                    (Part::Table, Some(host)) => {
                        app.render_procs(host, mono_char, cx).into_any_element()
                    }
                    (Part::Sidebar, _) => app.render_sidebar(cx).into_any_element(),
                    (_, None) => div().into_any_element(),
                }
            })
            .unwrap_or_else(|_| div().into_any_element());
        // A box of definite size where the part fills its place, so the
        // table's list gets the height left under its toolbar and header.
        match part {
            Part::Table => div().size_full().flex().flex_col().child(inner),
            Part::Sidebar => div().h_full().child(inner),
        }
    }
}
