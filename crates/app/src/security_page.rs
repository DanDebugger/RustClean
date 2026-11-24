//! Security Center: read-only checks. Nothing on this page changes the
//! system.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use egui::{RichText, Ui};
use rustclean_safety::platform;
use rustclean_security::{PersistenceReport, Risk, scan_persistence};

use crate::jobs::{Job, Poll};
use crate::theme::{self, palette};
use crate::widgets::{self, Tone};

pub struct SecurityPage {
    home: PathBuf,
    job: Option<Job<PersistenceReport>>,
    report: Option<PersistenceReport>,
    pub last_scan: Option<SystemTime>,
    selected: Option<usize>,
    error: Option<String>,
}

fn risk_tone(r: Risk) -> Tone {
    match r {
        Risk::Ok => Tone::Safe,
        Risk::Notice => Tone::Info,
        Risk::Warning => Tone::Review,
    }
}

impl SecurityPage {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            job: None,
            report: None,
            last_scan: None,
            selected: None,
            error: None,
        }
    }

    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    /// (items, items needing review, notices) from the last scan.
    pub fn summary(&self) -> Option<(usize, usize, usize)> {
        self.report
            .as_ref()
            .map(|r| (r.items.len(), r.count(Risk::Warning), r.count(Risk::Notice)))
    }

    pub fn start_scan(&mut self, ctx: &egui::Context) {
        if self.job.is_some() {
            return;
        }
        let home = self.home.clone();
        match Job::spawn("security-scan", ctx.clone(), move |_| {
            scan_persistence(&home)
        }) {
            Ok(j) => {
                self.job = Some(j);
                self.error = None;
            }
            Err(e) => self.error = Some(format!("could not start scan: {e}")),
        }
    }

    pub fn poll_jobs(&mut self) {
        if let Some(job) = &self.job {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(r) => {
                    self.report = Some(r);
                    self.last_scan = Some(SystemTime::now());
                    self.selected = None;
                    self.job = None;
                }
                Poll::Crashed => {
                    self.job = None;
                    self.error = Some("The security scan stopped unexpectedly.".into());
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if self.is_busy() {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
        let mut start = false;
        let busy = self.job.is_some();
        widgets::header_with_action(
            ui,
            Some("Security"),
            "Security Center",
            Some("Read-only checks. Nothing here changes your system."),
            |ui| {
                if busy {
                    ui.spinner();
                } else if ui
                    .add(theme::primary_button(ui, "Run security scan"))
                    .clicked()
                {
                    start = true;
                }
            },
        );
        if start {
            self.start_scan(&ctx);
        }
        if let Some(e) = &self.error {
            widgets::error(ui, e);
        }

        egui::ScrollArea::vertical()
            .id_salt("security_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Score ring + summary tiles.
                let (items, warn, notice) = self.summary().unwrap_or((0, 0, 0));
                let scanned = self.report.is_some();
                let v = |n: usize| if scanned { n.to_string() } else { "—".into() };
                let last = self
                    .last_scan
                    .map(widgets::time_ago)
                    .unwrap_or_else(|| "Never".into());
                let tiles: [(&str, String, &str); 4] = [
                    ("Background items", v(items), "start automatically"),
                    ("To review", v(warn), "patterns common in malware"),
                    ("Notices", v(notice), "e.g. leftovers"),
                    ("Last run", last, platform::CURRENT.name()),
                ];
                let wide = ui.available_width() >= 760.0;
                let draw_tiles = |ui: &mut Ui| {
                    let cols = if ui.available_width() >= 640.0 { 4 } else { 2 };
                    widgets::card_grid(ui, tiles.len(), cols, 10.0, |ui, i| {
                        let (t, val, d) = &tiles[i];
                        widgets::stat_card(ui, t, val, Some(d));
                    });
                };
                if wide {
                    ui.horizontal_top(|ui| {
                        score_ring(ui, scanned, items, warn, notice);
                        ui.vertical(|ui| draw_tiles(ui));
                    });
                } else {
                    ui.vertical_centered(|ui| score_ring(ui, scanned, items, warn, notice));
                    ui.add_space(8.0);
                    draw_tiles(ui);
                }
                ui.add_space(4.0);
                if ui.available_width() >= 760.0 {
                    widgets::card_grid(ui, 2, 2, 12.0, |ui, i| {
                        if i == 0 {
                            self.checks_ui(ui);
                        } else {
                            self.detail_ui(ui);
                        }
                    });
                } else {
                    self.detail_ui(ui);
                    ui.add_space(8.0);
                    self.checks_ui(ui);
                    ui.add_space(8.0);
                }
                self.table_ui(ui);
            });
    }

    fn checks_ui(&self, ui: &mut Ui) {
        let p = palette(ui);
        theme::card(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(RichText::new("Checks").strong().size(16.0));
            let checks: [(&str, &str, Tone, &str); 5] = [
                (
                    "Login items & background agents",
                    "What starts automatically, the program it runs, and signals such as inline scripts, temporary-folder programs or missing programs.",
                    Tone::Safe,
                    "Available",
                ),
                (
                    "App signatures & notarization",
                    "Verifies installed apps with the operating system's code-signing checks.",
                    Tone::Unknown,
                    "Planned",
                ),
                (
                    "Browser extensions",
                    "Lists Chrome extensions and highlights broad permissions. Removal stays in Chrome.",
                    Tone::Unknown,
                    "Planned",
                ),
                (
                    "Privacy permissions",
                    "Which apps can read all files, record the screen or control the computer.",
                    Tone::Unknown,
                    "Planned",
                ),
                (
                    "Malware signatures",
                    "Opt-in YARA-X rule scan of downloads and persistence items.",
                    Tone::Unknown,
                    "Planned",
                ),
            ];
            for (title, desc, tone, status) in checks {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(title).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        widgets::pill(ui, status, tone);
                    });
                });
                ui.label(RichText::new(desc).small().color(p.muted));
            }
        });
    }

    fn detail_ui(&self, ui: &mut Ui) {
        let p = palette(ui);
        theme::card(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let item = self
                .selected
                .and_then(|i| self.report.as_ref()?.items.get(i));
            let Some(item) = item else {
                ui.label(RichText::new("Details").strong().size(16.0));
                ui.label(RichText::new("Select an item to see what it runs and why it was flagged.").color(p.muted));
                ui.add_space(6.0);
                ui.label(RichText::new("Signals are not verdicts: legitimate tools sometimes use the same patterns. Nothing is removed from this page.").small().color(p.muted));
                return;
            };
            ui.horizontal(|ui| {
                ui.label(RichText::new(&item.label).strong().size(16.0));
                widgets::pill(ui, item.risk().label(), risk_tone(item.risk()));
            });
            egui::Grid::new("sec_detail").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label(RichText::new("Type").color(p.muted));
                ui.label(item.source.label());
                ui.end_row();
                ui.label(RichText::new("Definition").color(p.muted));
                ui.label(RichText::new(item.definition.display().to_string()).monospace().small());
                ui.end_row();
                ui.label(RichText::new("Program").color(p.muted));
                ui.label(
                    RichText::new(
                        item.program
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "—".into()),
                    )
                    .monospace()
                    .small(),
                );
                ui.end_row();
                if !item.arguments.is_empty() {
                    ui.label(RichText::new("Arguments").color(p.muted));
                    ui.label(RichText::new(item.arguments.join(" ")).monospace().small());
                    ui.end_row();
                }
                ui.label(RichText::new("Starts").color(p.muted));
                ui.label(match (item.disabled, item.runs_at_load) {
                    (true, _) => "Disabled",
                    (false, true) => "At login / always",
                    (false, false) => "On demand",
                });
                ui.end_row();
            });
            if !item.findings.is_empty() {
                ui.add_space(6.0);
                for f in &item.findings {
                    widgets::pill(ui, f.describe(), risk_tone(f.risk()));
                }
            }
            ui.add_space(6.0);
            if ui.button("Copy definition path").clicked() {
                ui.ctx().copy_text(item.definition.display().to_string());
            }
        });
    }

    fn table_ui(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else {
            theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label("Run a security scan to list everything that starts automatically.");
            });
            return;
        };
        if !report.unreadable_locations.is_empty() {
            widgets::warning(
                ui,
                format!(
                    "{} location(s) could not be read: {}",
                    report.unreadable_locations.len(),
                    report
                        .unreadable_locations
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        let p = palette(ui);
        let mut clicked = None;
        theme::card(ui)
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                for (i, item) in report.items.iter().enumerate() {
                    let active = self.selected == Some(i);
                    let resp = egui::Frame::new()
                        .fill(if active {
                            p.accent_soft
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .corner_radius(egui::CornerRadius::same(8))
                        .inner_margin(egui::Margin::symmetric(10, 8))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal_wrapped(|ui| {
                                widgets::pill(ui, item.risk().label(), risk_tone(item.risk()));
                                ui.label(RichText::new(&item.label).strong().color(p.text));
                                ui.label(RichText::new(item.source.label()).small().color(p.muted));
                            });
                            let s: Vec<String> =
                                item.findings.iter().map(|f| f.describe()).collect();
                            if !s.is_empty() {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(s.join("; ")).small().color(p.text2),
                                    )
                                    .wrap(),
                                );
                            }
                        })
                        .response
                        .interact(egui::Sense::click());
                    if resp.clicked() {
                        clicked = Some(i);
                    }
                }
            });
        if clicked.is_some() {
            self.selected = if clicked == self.selected {
                None
            } else {
                clicked
            };
        }
    }
}

/// A ring showing the share of background items without signals.
fn score_ring(ui: &mut Ui, scanned: bool, items: usize, warn: usize, notice: usize) {
    let p = palette(ui);
    let size = 112.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter_at(rect.expand(2.0));
    let c = rect.center();
    let r = size / 2.0 - 8.0;
    painter.circle_stroke(c, r, egui::Stroke::new(10.0, p.border));
    let (frac, color) = if scanned && items > 0 {
        let ok = items - warn - notice;
        let color = if warn > 0 {
            p.review.0
        } else if notice > 0 {
            p.info.0
        } else {
            p.safe.0
        };
        (ok as f32 / items as f32, color)
    } else {
        (0.0, p.border)
    };
    if frac > 0.0 {
        let steps = 64;
        let start = -std::f32::consts::FRAC_PI_2;
        let pts: Vec<egui::Pos2> = (0..=steps)
            .map(|i| {
                let a = start + std::f32::consts::TAU * frac * i as f32 / steps as f32;
                c + egui::vec2(a.cos(), a.sin()) * r
            })
            .collect();
        painter.add(egui::Shape::line(pts, egui::Stroke::new(10.0, color)));
    }
    let (big, small) = if scanned {
        (
            format!("{}%", (frac * 100.0).round() as u32),
            "no signals".to_string(),
        )
    } else {
        ("—".to_string(), "not run".to_string())
    };
    painter.text(
        c - egui::vec2(0.0, 8.0),
        egui::Align2::CENTER_CENTER,
        big,
        egui::FontId::proportional(22.0),
        p.text,
    );
    painter.text(
        c + egui::vec2(0.0, 14.0),
        egui::Align2::CENTER_CENTER,
        small,
        egui::FontId::proportional(11.5),
        p.muted,
    );
}
