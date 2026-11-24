//! Dashboard page.

use std::path::Path;

use egui::{Color32, CornerRadius, RichText, Ui};
use rustclean_core::format_bytes;
use sysinfo::Disks;

use crate::app::Loaded;
use crate::navigation::Page;
use crate::theme::{self, palette};
use crate::widgets::{self, Tone};

#[derive(Debug, Clone, Copy)]
pub struct DiskInfo {
    pub total: u64,
    pub available: u64,
}

impl DiskInfo {
    /// Capacity of the startup volume. On APFS the system and data volumes
    /// share one container, so "/" reports the container's figures.
    pub fn read() -> Option<Self> {
        let disks = Disks::new_with_refreshed_list();
        let root = if cfg!(windows) {
            Path::new("C:\\")
        } else {
            Path::new("/")
        };
        disks
            .list()
            .iter()
            .find(|d| d.mount_point() == root)
            .map(|d| DiskInfo {
                total: d.total_space(),
                available: d.available_space(),
            })
    }
}

/// Module colours for the disk bar (distinct in hue *and* lightness).
const SEGMENTS: [(Page, &str, Color32); 4] = [
    (Page::Docker, "Docker", Color32::from_rgb(0x1D, 0x4E, 0xD8)),
    (
        Page::BrowserCleaner,
        "Chrome",
        Color32::from_rgb(0xC2, 0x41, 0x0C),
    ),
    (
        Page::DeveloperCleaner,
        "Developer",
        Color32::from_rgb(0x0E, 0x74, 0x90),
    ),
    (
        Page::JunkCleaner,
        "Junk",
        Color32::from_rgb(0xCA, 0x8A, 0x04),
    ),
];

fn module_value(state: &Loaded, page: Page) -> (Option<u64>, bool) {
    match page {
        Page::Docker => (state.docker.reclaimable(), state.docker.is_busy()),
        Page::BrowserCleaner => (state.browser.reclaimable(), state.browser.is_busy()),
        Page::DeveloperCleaner => (state.developer.reclaimable(), state.developer.is_busy()),
        Page::JunkCleaner => (state.junk.reclaimable(), state.junk.is_busy()),
        Page::AppCaches => (state.app_caches.reclaimable(), state.app_caches.is_busy()),
        Page::LargeFiles => (state.large_files.reclaimable(), state.large_files.is_busy()),
        Page::AppCleaner => (state.leftovers.reclaimable(), state.leftovers.is_busy()),
        _ => (None, false),
    }
}

/// Columns for a card grid at this width.
pub fn grid_columns(width: f32) -> usize {
    if width >= 980.0 {
        4
    } else if width >= 520.0 {
        2
    } else {
        1
    }
}

/// Returns a page to navigate to, if a card was clicked.
pub fn ui(ui: &mut Ui, state: &mut Loaded) -> Option<Page> {
    let p = palette(ui);
    let mut go = None;
    let busy = state.any_busy();
    let last = state
        .file_pages()
        .iter()
        .filter_map(|pg| pg.last_scan)
        .chain(state.docker.last_scan)
        .max();
    let subtitle = match last {
        Some(t) => format!(
            "Last scan {} · nothing is removed without your confirmation",
            widgets::time_ago(t)
        ),
        None => {
            "Run Smart Scan to see what can be cleaned. Scanning never removes anything.".into()
        }
    };
    let mut start = false;
    widgets::header_with_action(ui, Some("Overview"), "Dashboard", Some(&subtitle), |ui| {
        if busy {
            ui.spinner();
            ui.label(RichText::new("Scanning…").color(p.muted));
        } else if ui
            .add(theme::primary_button(
                ui,
                &format!("{}  Smart Scan", egui_phosphor::regular::SPARKLE),
            ))
            .clicked()
        {
            start = true;
        }
    });
    if start {
        state.quick_scan(ui.ctx());
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            hero(ui, state, &mut go);
            ui.add_space(14.0);

            // Module cards.
            let cards: [(Page, &str, String); 4] = [
                (Page::Docker, "Docker", docker_line(state)),
                (
                    Page::BrowserCleaner,
                    "Chrome",
                    "Caches only; bookmarks, passwords and history are always protected".into(),
                ),
                (
                    Page::DeveloperCleaner,
                    "Developer caches",
                    "npm, Cargo, Go, Gradle, Maven, Homebrew and more".into(),
                ),
                (
                    Page::JunkCleaner,
                    "Junk",
                    "App and updater caches, logs, crash reports, installers".into(),
                ),
            ];
            let cols = grid_columns(ui.available_width());
            widgets::card_grid(ui, cards.len(), cols, 12.0, |ui, i| {
                let (page, title, line) = &cards[i];
                let (v, b) = module_value(state, *page);
                if module_card(ui, page.icon(), title, v, b, line).clicked() {
                    go = Some(*page);
                }
            });

            let cols2 = if ui.available_width() >= 760.0 { 2 } else { 1 };
            let mut sec_click = false;
            widgets::card_grid(ui, 2, cols2, 12.0, |ui, i| {
                if i == 0 {
                    sec_click |= security_card(ui, state);
                } else {
                    activity_card(ui, state);
                }
            });
            if sec_click {
                go = Some(Page::SecurityCenter);
            }
        });
    go
}

fn docker_line(state: &Loaded) -> String {
    match state.docker.summary() {
        Some((n, safe, _)) => format!("{n} items · {} safe to remove", format_bytes(safe)),
        None if state.docker.has_engine() => "Images, stopped containers and build cache".into(),
        None => "No Docker engine found".into(),
    }
}

fn hero(ui: &mut Ui, state: &Loaded, go: &mut Option<Page>) {
    let p = palette(ui);
    let mut total = 0;
    let mut any = false;
    let mut safe = 0;
    for pg in [&state.junk, &state.browser, &state.developer] {
        if let Some((_, s, r)) = pg.summary() {
            total += r;
            safe += s;
            any = true;
        }
    }
    if let Some((_, s, r)) = state.docker.summary() {
        total += r;
        safe += s;
        any = true;
    }
    theme::card(ui)
        .inner_margin(egui::Margin::same(22))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let narrow = ui.available_width() < 560.0;
            let text = |ui: &mut Ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("Space you can reclaim").color(p.muted));
                    ui.label(
                        RichText::new(if any {
                            format_bytes(total)
                        } else {
                            "—".into()
                        })
                        .size(if narrow { 34.0 } else { 44.0 })
                        .strong()
                        .color(p.text),
                    );
                    if any {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!("{} marked Safe", format_bytes(safe)))
                                    .strong()
                                    .color(p.safe.0),
                            );
                            ui.label(RichText::new("· the rest needs your review").color(p.muted));
                        });
                    }
                });
            };
            if narrow {
                text(ui);
            } else {
                ui.horizontal(|ui| {
                    text(ui);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if any && ui.button("Review everything").clicked() {
                            *go = Some(Page::SmartScan);
                        }
                    });
                });
            }
            ui.add_space(14.0);
            if let Some(d) = state.disk {
                disk_bar(ui, state, d);
            }
        });
}

fn disk_bar(ui: &mut Ui, state: &Loaded, d: DiskInfo) {
    let p = palette(ui);
    let total = d.total.max(1) as f32;
    let used = d.total.saturating_sub(d.available);
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 14.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(7), p.border);
    let mut x = rect.left();
    let mut module_sum = 0u64;
    let mut segs: Vec<(Color32, f32)> = Vec::new();
    for (page, _, color) in SEGMENTS {
        if let (Some(v), _) = module_value(state, page) {
            module_sum += v;
            segs.push((color, v as f32 / total * w));
        }
    }
    segs.push((
        p.muted.gamma_multiply(0.6),
        used.saturating_sub(module_sum) as f32 / total * w,
    ));
    let clip = painter.with_clip_rect(rect);
    for (i, (color, width)) in segs.iter().enumerate() {
        let width = width.max(if i < segs.len() - 1 { 3.0 } else { 0.0 });
        let r =
            egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(width, rect.height()));
        clip.rect_filled(r, CornerRadius::ZERO, *color);
        x += width;
    }
    // Round the outer corners by redrawing the frame edge.
    painter.rect_stroke(
        rect,
        CornerRadius::same(7),
        egui::Stroke::new(2.0, p.surface),
        egui::StrokeKind::Outside,
    );
    ui.add_space(8.0);
    ui.horizontal_wrapped(|ui| {
        for (page, name, color) in SEGMENTS {
            if let (Some(v), _) = module_value(state, page) {
                legend(ui, color, &format!("{name} {}", format_bytes(v)));
            }
        }
        legend(
            ui,
            p.muted.gamma_multiply(0.6),
            &format!(
                "Other used {}",
                format_bytes(used.saturating_sub(module_sum))
            ),
        );
        legend(ui, p.border, &format!("Free {}", format_bytes(d.available)));
    });
}

fn legend(ui: &mut Ui, color: Color32, text: &str) {
    let p = palette(ui);
    // One label per item so the wrapping layout can move it as a unit.
    let mut job = egui::text::LayoutJob::default();
    job.append(
        "■\u{a0}",
        0.0,
        egui::TextFormat::simple(egui::FontId::proportional(14.0), color),
    );
    let joined = text.replace(' ', "\u{a0}");
    job.append(
        &joined,
        0.0,
        egui::TextFormat::simple(egui::FontId::proportional(14.0), p.text2),
    );
    job.append("   ", 0.0, egui::TextFormat::default());
    ui.label(job);
}

fn module_card(
    ui: &mut Ui,
    icon: &str,
    title: &str,
    value: Option<u64>,
    busy: bool,
    line: &str,
) -> egui::Response {
    let p = palette(ui);
    theme::card(ui)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(132.0);
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon).size(18.0).color(p.accent));
                ui.label(RichText::new(title).strong().color(p.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if busy {
                        ui.spinner();
                    }
                });
            });
            ui.label(
                RichText::new(match value {
                    Some(v) => format_bytes(v),
                    None => "Not scanned".into(),
                })
                .size(26.0)
                .strong()
                .color(if value.is_some() { p.text } else { p.muted }),
            );
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.add(egui::Label::new(RichText::new(line).small().color(p.muted)).wrap());
            });
            ui.label(RichText::new("Review →").strong().color(p.accent));
        })
        .response
        .interact(egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn security_card(ui: &mut Ui, state: &Loaded) -> bool {
    let p = palette(ui);
    let mut open = false;
    theme::card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(RichText::new(egui_phosphor::regular::SHIELD_CHECK).size(18.0).color(p.accent));
            ui.label(RichText::new("Security Center").strong().size(15.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                open = ui.button("Open →").clicked();
            });
        });
        match state.security.summary() {
            Some((items, warn, notice)) => {
                row(ui, "Background items checked", &items.to_string());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Signals").color(p.text2));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        widgets::pill(ui, format!("{notice} notices"), Tone::Info);
                        widgets::pill(ui, format!("{warn} to review"), if warn > 0 { Tone::Review } else { Tone::Safe });
                    });
                });
            }
            None => {
                ui.label(RichText::new("Checks what starts automatically on your computer. Run Smart Scan to include it.").color(p.muted));
            }
        }
        let (files, bytes) = state.quarantine.total();
        row(ui, "In quarantine", &if files > 0 { format!("{files} files · {}", format_bytes(bytes)) } else { "Empty".into() });
    });
    open
}

fn activity_card(ui: &mut Ui, state: &Loaded) {
    let p = palette(ui);
    theme::card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(RichText::new(egui_phosphor::regular::CLOCK).size(18.0).color(p.accent));
            ui.label(RichText::new("Activity").strong().size(15.0));
        });
        if state.activity.is_empty() {
            ui.label(RichText::new("Scans and cleanups from this session appear here. Every cleanup is also written to the operation log.").color(p.muted));
        }
        for (at, text) in state.activity.iter().rev().take(5) {
            ui.horizontal(|ui| {
                ui.label(RichText::new("•").color(p.muted));
                ui.vertical(|ui| {
                    ui.add(egui::Label::new(RichText::new(text).color(p.text)).wrap());
                    ui.label(RichText::new(widgets::time_ago(*at)).small().color(p.muted));
                });
            });
        }
    });
}

fn row(ui: &mut Ui, k: &str, v: &str) {
    let p = palette(ui);
    ui.horizontal(|ui| {
        ui.label(RichText::new(k).color(p.text2));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(v).strong());
        });
    });
}
