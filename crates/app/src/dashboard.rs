//! Dashboard page.

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
            // The Windows drive is not always C:.
            let drive = std::env::var("SystemDrive")
                .ok()
                .filter(|d| d.len() == 2 && d.ends_with(':'))
                .unwrap_or_else(|| "C:".into());
            std::path::PathBuf::from(format!("{drive}\\"))
        } else {
            std::path::PathBuf::from("/")
        };
        disks
            .list()
            .iter()
            .find(|d| d.mount_point() == root.as_path())
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
            widgets::card_grid_aligned(
                ui,
                "module_cards",
                cards.len(),
                cols,
                12.0,
                |ui, i, pad| {
                    let (page, title, line) = &cards[i];
                    let (v, b) = module_value(state, *page);
                    let resp = module_card(ui, page.icon(), title, v, b, line, pad);
                    if resp.clicked() {
                        go = Some(*page);
                    }
                    resp
                },
            );

            let cols2 = if ui.available_width() >= 760.0 { 2 } else { 1 };
            let mut sec_click = false;
            widgets::card_grid_aligned(ui, "summary_cards", 2, cols2, 12.0, |ui, i, pad| {
                if i == 0 {
                    let (clicked, resp) = security_card(ui, state, pad);
                    sec_click |= clicked;
                    resp
                } else {
                    activity_card(ui, state, pad)
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
        other_used_color(p),
        used.saturating_sub(module_sum) as f32 / total * w,
    ));
    // Tiny modules still get a visible sliver.
    let widths: Vec<f32> = segs
        .iter()
        .enumerate()
        .map(|(i, (_, w))| w.max(if i < segs.len() - 1 { 3.0 } else { 0.0 }))
        .collect();
    let used_w = widths.iter().sum::<f32>().min(rect.width());
    // The whole used span in the first colour with a rounded left end (and
    // right end when the disk is full); later segments are drawn square on
    // top. The first segment keeps the rounded cap however thin it is.
    let full = used_w >= rect.width() - 0.5;
    let cap = CornerRadius {
        nw: 7,
        sw: 7,
        ne: if full { 7 } else { 0 },
        se: if full { 7 } else { 0 },
    };
    if let Some((first, _)) = segs.first() {
        let span = egui::Rect::from_min_size(rect.min, egui::vec2(used_w, rect.height()));
        painter.rect_filled(span, cap, *first);
    }
    for (i, ((color, _), width)) in segs.iter().zip(&widths).enumerate() {
        if i > 0 {
            let r = egui::Rect::from_min_size(
                egui::pos2(x, rect.top()),
                egui::vec2(*width, rect.height()),
            )
            .intersect(rect);
            let corners = if full && x + width >= rect.right() - 0.5 {
                CornerRadius {
                    ne: 7,
                    se: 7,
                    ..CornerRadius::ZERO
                }
            } else {
                CornerRadius::ZERO
            };
            painter.rect_filled(r, corners, *color);
        }
        x += width;
    }
    ui.add_space(8.0);
    ui.horizontal_wrapped(|ui| {
        for (page, name, color) in SEGMENTS {
            if let (Some(v), _) = module_value(state, page) {
                legend(ui, color, &format!("{name} {}", format_bytes(v)));
            }
        }
        legend(
            ui,
            other_used_color(p),
            &format!(
                "Other used {}",
                format_bytes(used.saturating_sub(module_sum))
            ),
        );
        legend(ui, p.border, &format!("Free {}", format_bytes(d.available)));
    });
}

/// "Other used" grey. Opaque, so it looks the same whatever is drawn
/// beneath it (the bar paints the used span first).
fn other_used_color(p: &crate::theme::Palette) -> Color32 {
    p.border.lerp_to_gamma(p.muted, 0.6)
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
    pad: f32,
) -> egui::Response {
    let p = palette(ui);
    theme::card(ui)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
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
            // Extra height goes above the link, so links line up in a row.
            ui.add_space(pad);
            ui.label(RichText::new("Review →").strong().color(p.accent));
        })
        .response
        .interact(egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Returns (open clicked, card response).
fn security_card(ui: &mut Ui, state: &Loaded, pad: f32) -> (bool, egui::Response) {
    let p = palette(ui);
    let mut open = false;
    let resp = theme::card(ui).show(ui, |ui| {
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
        ui.add_space(pad);
    });
    (open, resp.response)
}

fn activity_card(ui: &mut Ui, state: &Loaded, pad: f32) -> egui::Response {
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
            // Top-aligned: the bullet sits on the first line of the entry.
            ui.horizontal_top(|ui| {
                ui.label(RichText::new("•").color(p.muted));
                ui.vertical(|ui| {
                    ui.add(egui::Label::new(RichText::new(text).color(p.text)).wrap());
                    ui.label(RichText::new(widgets::time_ago(*at)).small().color(p.muted));
                });
            });
        }
        ui.add_space(pad);
    })
    .response
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
