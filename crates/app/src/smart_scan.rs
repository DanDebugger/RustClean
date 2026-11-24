//! Smart Scan: one read-only pass over every module plus the security audit,
//! summarised with suggested next steps. Nothing is removed from here; each
//! suggestion opens the module where the user reviews and confirms.

use egui::{RichText, Ui};
use rustclean_core::format_bytes;

use crate::app::Loaded;
use crate::navigation::Page;
use crate::theme::{self, palette};
use crate::widgets::{self, Tone};

struct Row {
    title: &'static str,
    page: Page,
    busy: bool,
    available: bool,
    /// (items, safe bytes, reclaimable bytes)
    result: Option<(usize, Option<u64>, u64)>,
    unit: &'static str,
}

/// Returns a page to open, if the user clicked one.
pub fn ui(ui: &mut Ui, state: &mut Loaded) -> Option<Page> {
    let p = palette(ui);
    let mut go = None;
    let busy = state.any_busy();

    let mut start = false;
    widgets::header_with_action(
        ui,
        Some("Overview"),
        "Smart Scan",
        Some("One read-only pass over every module. Nothing is removed."),
        |ui| {
            if busy {
                ui.spinner();
                ui.label(RichText::new("Scanning…").color(p.muted));
            } else if ui
                .add(theme::primary_button(ui, "Run Smart Scan"))
                .clicked()
            {
                start = true;
            }
        },
    );
    if start {
        state.quick_scan(ui.ctx());
    }

    let rows = [
        Row {
            title: "Junk",
            page: Page::JunkCleaner,
            busy: state.junk.is_busy(),
            available: state.junk.is_available(),
            result: state.junk.summary().map(|(n, s, r)| (n, Some(s), r)),
            unit: "files",
        },
        Row {
            title: "Browser (Chrome)",
            page: Page::BrowserCleaner,
            busy: state.browser.is_busy(),
            available: state.browser.is_available(),
            result: state.browser.summary().map(|(n, s, r)| (n, Some(s), r)),
            unit: "files",
        },
        Row {
            title: "Developer caches",
            page: Page::DeveloperCleaner,
            busy: state.developer.is_busy(),
            available: state.developer.is_available(),
            result: state.developer.summary().map(|(n, s, r)| (n, Some(s), r)),
            unit: "files",
        },
        Row {
            title: "Docker",
            page: Page::Docker,
            busy: state.docker.is_busy(),
            available: state.docker.has_engine(),
            result: state.docker.summary().map(|(n, s, r)| (n, Some(s), r)),
            unit: "items",
        },
    ];

    let reclaimable: u64 = rows.iter().filter_map(|r| r.result.map(|x| x.2)).sum();
    let safe: u64 = rows.iter().filter_map(|r| r.result.and_then(|x| x.1)).sum();
    let any_result = rows.iter().any(|r| r.result.is_some());

    let mut out = None;
    egui::ScrollArea::vertical()
        .id_salt("smart_scan_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let cols = if ui.available_width() >= 640.0 { 2 } else { 1 };
            let security = state.security.summary();
            let security_busy = state.security.is_busy();
            widgets::card_grid(ui, 2, cols, 12.0, |ui, i| {
                theme::card(ui).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.set_min_height(112.0);
                    if i == 0 {
                        ui.label(RichText::new("Space you can reclaim").color(p.muted));
                        ui.label(
                            RichText::new(if any_result {
                                format_bytes(reclaimable)
                            } else {
                                "—".into()
                            })
                            .size(36.0)
                            .strong()
                            .color(p.text),
                        );
                        if any_result {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!(
                                        "{} marked Safe · the rest needs your review",
                                        format_bytes(safe)
                                    ))
                                    .color(p.safe.0),
                                )
                                .wrap(),
                            );
                        }
                    } else {
                        ui.label(RichText::new("Security").color(p.muted));
                        match security {
                            Some((items, warn, notice)) => {
                                ui.label(
                                    RichText::new(format!("{items} background items checked"))
                                        .size(18.0)
                                        .strong(),
                                );
                                ui.horizontal_wrapped(|ui| {
                                    widgets::pill(
                                        ui,
                                        format!("{warn} to review"),
                                        if warn > 0 { Tone::Review } else { Tone::Safe },
                                    );
                                    widgets::pill(ui, format!("{notice} notices"), Tone::Info);
                                });
                            }
                            None if security_busy => {
                                ui.spinner();
                            }
                            None => {
                                ui.label(RichText::new("Not run").size(18.0).strong());
                            }
                        }
                    }
                });
            });
            out = rows_ui(ui, &rows);
        });
    if out.is_some() {
        go = out;
    }
    go
}

fn rows_ui(ui: &mut Ui, rows: &[Row]) -> Option<Page> {
    let p = palette(ui);
    let mut go = None;
    for row in rows {
        theme::card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let (status, tone) = match (row.available, row.busy, row.result) {
                (false, _, _) => ("Not available", Tone::Unknown),
                (_, true, _) => ("Scanning", Tone::Info),
                (_, _, Some(_)) => ("Done", Tone::Safe),
                _ => ("Not scanned", Tone::Unknown),
            };
            // Title + status, with the action on the right.
            ui.horizontal(|ui| {
                ui.label(RichText::new(row.title).strong().size(15.0));
                widgets::pill(ui, status, tone);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(row.available, egui::Button::new("Review →"))
                        .clicked()
                    {
                        go = Some(row.page);
                    }
                });
            });
            if let Some((n, safe, total)) = row.result {
                ui.add_space(4.0);
                let metrics = [
                    ("Found", format!("{n} {}", row.unit)),
                    ("Safe", safe.map(format_bytes).unwrap_or_else(|| "—".into())),
                    ("Reclaimable", format_bytes(total)),
                ];
                let cols = 3;
                widgets::card_grid(ui, metrics.len(), cols, 8.0, |ui, i| {
                    metric(ui, metrics[i].0, &metrics[i].1);
                });
            }
        });
        ui.add_space(6.0);
    }

    theme::card(ui).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.vertical(|ui| {
                ui.set_width(180.0);
                ui.label(RichText::new("Security Center").strong().size(15.0));
                widgets::pill(ui, "Read-only", Tone::Info);
            });
            ui.label(
                RichText::new(
                    "Login items and background agents: leftovers, inline scripts, programs in temporary folders.",
                )
                .color(p.muted),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Open →").clicked() {
                    go = Some(Page::SecurityCenter);
                }
            });
        });
    });
    go
}

fn metric(ui: &mut Ui, label: &str, value: &str) {
    let p = palette(ui);
    ui.vertical(|ui| {
        ui.label(RichText::new(label).small().color(p.muted));
        ui.label(RichText::new(value).strong().size(16.0));
    });
}
