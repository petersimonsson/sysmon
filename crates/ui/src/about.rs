//! The About dialog: version, sysmon's licenses, and the license notices of
//! every third-party crate in the binary.

use std::rc::Rc;

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::button::Button;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::{ActiveTheme as _, Sizable as _};
use gpui_kit::prelude::*;
use gpui_kit::*;

use crate::notices::{self, CRATES, CrateNotice};
use crate::widgets::{Chosen as _, Highlighted as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shown {
    Mit,
    Apache,
    Crate(usize),
}

pub struct AboutView {
    shown: Shown,
    filter: Entity<InputState>,
    list: UniformListScrollHandle,
    status: Option<String>,
    _subscription: Subscription,
}

impl AboutView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let filter =
            cx.new(|cx| InputState::new(window, cx).placeholder("Filter crates or licenses"));
        let subscription = cx.subscribe(&filter, |_, _, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Change) {
                cx.notify();
            }
        });
        Self {
            shown: Shown::Mit,
            filter,
            list: UniformListScrollHandle::new(),
            status: None,
            _subscription: subscription,
        }
    }

    fn matching(&self, cx: &App) -> Vec<usize> {
        let needle = self.filter.read(cx).value().to_lowercase();
        CRATES
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                needle.is_empty()
                    || c.name.to_lowercase().contains(&needle)
                    || c.license.to_lowercase().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn save_all(&mut self, cx: &mut Context<Self>) {
        let dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let path = cx.prompt_for_new_path(&dir, Some("THIRD_PARTY_LICENSES.txt"));
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(path))) = path.await else {
                return;
            };
            let status = match std::fs::write(&path, notices::full_text()) {
                Ok(()) => format!("Saved to {}", path.display()),
                Err(e) => format!("Couldn't save {}: {e}", path.display()),
            };
            let _ = this.update(cx, |this, cx| {
                this.status = Some(status);
                cx.notify();
            });
        })
        .detach();
    }

    fn render_text(&self, cx: &App) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mono = theme.mono_font_family.clone();
        let (title, subtitle, files): (String, String, Vec<(String, &'static str)>) =
            match self.shown {
                Shown::Mit => (
                    format!("{} — MIT License", notices::NAME),
                    "LICENSE-MIT".into(),
                    vec![(String::new(), notices::LICENSE_MIT)],
                ),
                Shown::Apache => (
                    format!("{} — Apache License 2.0", notices::NAME),
                    "LICENSE-APACHE".into(),
                    vec![(String::new(), notices::LICENSE_APACHE)],
                ),
                Shown::Crate(i) => {
                    let c: &CrateNotice = &CRATES[i];
                    (
                        format!("{} {}", c.name, c.version),
                        if c.repository.is_empty() {
                            c.license.to_string()
                        } else {
                            format!("{} · {}", c.license, c.repository)
                        },
                        c.files
                            .iter()
                            .map(|(name, idx)| (name.to_string(), notices::text(*idx)))
                            .collect(),
                    )
                }
            };
        let mut body = div()
            .id("about-text")
            .test_support()
            .flex()
            .flex_col()
            .gap_3()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .p_3()
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .bg(theme.muted.opacity(0.3))
            .text_xs()
            .font_family(mono);
        for (name, text) in files {
            if !name.is_empty() {
                body = body.child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme.muted_foreground)
                        .child(name),
                );
            }
            body = body.child(div().child(text));
        }
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .gap_2()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(title))
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(subtitle),
                    ),
            )
            .child(body)
    }
}

impl Render for AboutView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let matching = Rc::new(self.matching(cx));
        let shown = self.shown;
        let this = cx.entity().downgrade();

        let header = div()
            .flex()
            .items_end()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_xl()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!("{} {}", notices::NAME, notices::VERSION)),
                    )
                    .child(div().text_sm().text_color(theme.muted_foreground).child(
                        "A top-like system monitor for remote machines, with recording and replay.",
                    ))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .text_sm()
                            .child(format!("Licensed under {}:", notices::LICENSE))
                            .child(
                                Button::new("about-mit")
                                    .label("MIT")
                                    .small()
                                    .chosen(shown == Shown::Mit)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.shown = Shown::Mit;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("about-apache")
                                    .label("Apache-2.0")
                                    .small()
                                    .chosen(shown == Shown::Apache)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.shown = Shown::Apache;
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .child(div().flex_1())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .items_end()
                    .gap_1()
                    .child(
                        Button::new("about-save")
                            .label("Save all notices…")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.save_all(cx))),
                    )
                    .children(
                        self.status
                            .clone()
                            .map(|s| div().text_xs().text_color(theme.muted_foreground).child(s)),
                    ),
            );

        let count = matching.len();
        let list = uniform_list("about-crates", count, {
            let theme = theme.clone();
            move |range, _, _| {
                range
                    .map(|row| {
                        let i = matching[row];
                        let c = &CRATES[i];
                        let this = this.clone();
                        div()
                            .id(("about-crate", row))
                            .test_support()
                            .flex()
                            .justify_between()
                            .gap_2()
                            .px_2()
                            .h(px(22.))
                            .items_center()
                            .text_xs()
                            .rounded_sm()
                            .cursor_pointer()
                            .highlighted(shown == Shown::Crate(i), &theme)
                            .child(
                                div()
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .child(format!("{} {}", c.name, c.version)),
                            )
                            .child(
                                div()
                                    .flex_none()
                                    .text_color(theme.muted_foreground)
                                    .child(c.license),
                            )
                            .on_click(move |_, _, cx| {
                                let _ = this.update(cx, |this, cx| {
                                    this.shown = Shown::Crate(i);
                                    cx.notify();
                                });
                            })
                    })
                    .collect()
            }
        })
        .track_scroll(&self.list)
        .flex_1();

        let sidebar = div()
            .flex()
            .flex_col()
            .gap_2()
            .w(px(330.))
            .flex_none()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(format!("Third-party software ({} crates)", CRATES.len())),
            )
            .child(Input::new(&self.filter).small().cleanable(true))
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
                    .child(list),
            );

        div()
            .id("about")
            .test_support()
            .flex()
            .flex_col()
            .gap_4()
            .h(px(560.))
            .child(header)
            .child(
                div()
                    .flex()
                    .gap_4()
                    .flex_1()
                    .min_h_0()
                    .child(sidebar)
                    .child(self.render_text(cx)),
            )
    }
}
