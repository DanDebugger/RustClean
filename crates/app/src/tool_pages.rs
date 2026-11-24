//! Storage Analyzer and Quarantine pages.

use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use egui::{RichText, Ui};
use rustclean_core::format_bytes;
use rustclean_safety::{
    ProtectionRules, QuarantineSession, app_data_dir, list_quarantine_sessions,
    purge_quarantine_session, restore_quarantine,
};
use rustclean_storage::{FolderSize, folder_sizes};

use crate::dashboard::DiskInfo;
use crate::jobs::{Job, Poll};
use crate::theme::{self, palette};
use crate::widgets::{self, Tone};

/// Storage Analyzer: drill-down folder sizes (read-only).
pub struct StoragePage {
    home: PathBuf,
    current: PathBuf,
    job: Option<Job<Vec<FolderSize>>>,
    sizes: Option<Vec<FolderSize>>,
}

impl StoragePage {
    pub fn new(home: PathBuf) -> Self {
        Self {
            current: home.clone(),
            home,
            job: None,
            sizes: None,
        }
    }

    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    fn analyse(&mut self, ctx: &egui::Context, dir: PathBuf) {
        if self.job.is_some() {
            return;
        }
        self.current = dir.clone();
        self.sizes = None;
        if let Ok(j) = Job::spawn("storage", ctx.clone(), move |p| folder_sizes(&dir, p)) {
            self.job = Some(j);
        }
    }

    pub fn poll_jobs(&mut self) {
        if let Some(j) = &self.job {
            match j.poll() {
                Poll::Pending => {}
                Poll::Done(v) => {
                    self.sizes = Some(v);
                    self.job = None;
                }
                Poll::Crashed => self.job = None,
            }
        }
    }

    pub fn ui(&mut self, ui: &mut Ui, disk: Option<DiskInfo>) {
        let ctx = ui.ctx().clone();
        let p = palette(ui);
        if self.is_busy() {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
        widgets::page_header(
            ui,
            Some("Analysis"),
            "Storage Analyzer",
            Some("See what takes up space. Read-only: use the cleaners to remove things."),
        );
        if let Some(d) = disk {
            let used = d.total.saturating_sub(d.available);
            theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(
                    RichText::new(format!(
                        "{} used of {} · {} free",
                        format_bytes(used),
                        format_bytes(d.total),
                        format_bytes(d.available)
                    ))
                    .strong(),
                );
                let frac = if d.total > 0 {
                    used as f32 / d.total as f32
                } else {
                    0.0
                };
                ui.add(egui::ProgressBar::new(frac).fill(p.accent));
            });
            ui.add_space(8.0);
        }
        ui.horizontal_wrapped(|ui| {
            if self.current != self.home
                && ui.button("↑ Up").clicked()
                && let Some(parent) = self.current.parent().map(|p| p.to_path_buf())
            {
                self.analyse(&ctx, parent);
            }
            ui.label(
                RichText::new(self.current.display().to_string())
                    .monospace()
                    .color(p.text2),
            );
            if let Some(j) = &self.job {
                ui.spinner();
                ui.label(format!(
                    "{} files · {}",
                    j.progress.items(),
                    format_bytes(j.progress.bytes())
                ));
                if ui.button("Cancel").clicked() {
                    j.progress.cancel();
                }
            } else {
                let label = if self.sizes.is_some() {
                    "Analyze again"
                } else {
                    "Analyze home folder"
                };
                if ui.add(theme::primary_button(ui, label)).clicked() {
                    let dir = self.current.clone();
                    self.analyse(&ctx, dir);
                }
            }
        });
        ui.add_space(6.0);
        let Some(sizes) = &self.sizes else {
            return;
        };
        let max = sizes.first().map(|s| s.size).unwrap_or(1).max(1);
        let mut open = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                theme::card(ui).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    for s in sizes.iter().take(200) {
                        let name = s
                            .path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        ui.horizontal(|ui| {
                            let w = (ui.available_width() * 0.35).clamp(120.0, 320.0);
                            let label = if s.is_dir { format!("{name}/") } else { name };
                            let resp = ui.add_sized(
                                [w, 20.0],
                                egui::Button::new(RichText::new(label).color(p.text)).frame(false),
                            );
                            if s.is_dir && resp.on_hover_text("Open this folder").clicked() {
                                open = Some(s.path.clone());
                            }
                            let frac = s.size as f32 / max as f32;
                            let bar_w = (ui.available_width() - 110.0).max(40.0);
                            ui.add_sized(
                                [bar_w, 10.0],
                                egui::ProgressBar::new(frac).fill(p.accent).corner_radius(4),
                            );
                            ui.label(RichText::new(format_bytes(s.size)).strong());
                        });
                    }
                });
            });
        if let Some(dir) = open {
            self.analyse(&ctx, dir);
        }
    }
}

enum QuarantineJob {
    Restore(Job<Result<String, String>>),
    Purge(Job<Result<String, String>>),
}

/// Quarantine: restore or permanently delete earlier cleanups.
pub struct QuarantinePage {
    home: PathBuf,
    rules: ProtectionRules,
    sessions: Vec<QuarantineSession>,
    confirm_purge: Option<PathBuf>,
    job: Option<QuarantineJob>,
    message: Option<(String, Tone)>,
}

impl QuarantinePage {
    pub fn new(home: PathBuf, rules: ProtectionRules) -> Self {
        let sessions = list_quarantine_sessions(&app_data_dir(&home));
        Self {
            home,
            rules,
            sessions,
            confirm_purge: None,
            job: None,
            message: None,
        }
    }

    pub fn refresh(&mut self) {
        self.sessions = list_quarantine_sessions(&app_data_dir(&self.home));
    }

    pub fn total(&self) -> (usize, u64) {
        self.sessions
            .iter()
            .fold((0, 0), |(f, b), s| (f + s.files, b + s.bytes))
    }

    pub fn poll_jobs(&mut self) {
        let done = match &self.job {
            Some(QuarantineJob::Restore(j)) | Some(QuarantineJob::Purge(j)) => match j.poll() {
                Poll::Pending => None,
                Poll::Done(Ok(m)) => Some((m, Tone::Safe)),
                Poll::Done(Err(e)) => Some((e, Tone::Protected)),
                Poll::Crashed => Some((
                    "The operation stopped unexpectedly.".into(),
                    Tone::Protected,
                )),
            },
            None => None,
        };
        if let Some(m) = done {
            self.message = Some(m);
            self.job = None;
            self.refresh();
        }
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let p = palette(ui);
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
        widgets::page_header(
            ui,
            Some("Settings"),
            "Quarantine",
            Some(
                "Files you cleaned with \"Quarantine\". Restore them, or delete them for good to free the space.",
            ),
        );
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.refresh();
            }
            let (files, bytes) = self.total();
            ui.label(format!(
                "{files} files · {} in quarantine",
                format_bytes(bytes)
            ));
            if self.job.is_some() {
                ui.spinner();
            }
        });
        if let Some((m, tone)) = &self.message {
            widgets::pill(ui, m.clone(), *tone);
        }
        ui.add_space(6.0);
        if self.sessions.is_empty() {
            theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("Nothing in quarantine.").color(p.muted));
            });
            return;
        }
        let mut action: Option<(bool, PathBuf)> = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for s in &self.sessions {
                theme::card(ui).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        let when = UNIX_EPOCH + Duration::from_secs(s.created_unix);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(format!("Cleanup {}", widgets::time_ago(when))).strong());
                            ui.label(
                                RichText::new(format!("{} files · {}", s.files, format_bytes(s.bytes)))
                                    .color(p.muted),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let idle = self.job.is_none();
                            if ui
                                .add_enabled(idle, egui::Button::new("Delete permanently…"))
                                .clicked()
                            {
                                action = Some((false, s.dir.clone()));
                            }
                            if ui
                                .add_enabled(idle && s.files > 0, theme::primary_button(ui, "Restore"))
                                .on_hover_text("Puts every file back where it was. Never overwrites a file.")
                                .clicked()
                            {
                                action = Some((true, s.dir.clone()));
                            }
                        });
                    });
                });
                ui.add_space(6.0);
            }
        });
        match action {
            Some((true, dir)) => {
                let rules = self.rules.clone();
                if let Ok(j) = Job::spawn("restore", ctx.clone(), move |_| {
                    restore_quarantine(&dir, &rules)
                        .map(|r| {
                            format!(
                                "Restored {} files · {} kept because the original location is in use · {} failed",
                                r.restored.len(),
                                r.conflicts.len(),
                                r.failed.len()
                            )
                        })
                        .map_err(|e| format!("Restore failed: {e}"))
                }) {
                    self.job = Some(QuarantineJob::Restore(j));
                }
            }
            Some((false, dir)) => self.confirm_purge = Some(dir),
            None => {}
        }
        self.purge_dialog(&ctx);
    }

    fn purge_dialog(&mut self, ctx: &egui::Context) {
        let Some(dir) = self.confirm_purge.clone() else {
            return;
        };
        let modal = egui::Modal::new(egui::Id::new("purge_confirm")).show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 48.0).clamp(300.0, 520.0));
            ui.label(RichText::new("Delete these files permanently?").size(18.0).strong());
            ui.label("They will be gone for good and the space is freed immediately. This cannot be undone.");
            ui.add_space(8.0);
            let mut a = None;
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    a = Some(false);
                }
                let danger = egui::Button::new(
                    RichText::new("Delete permanently").strong().color(egui::Color32::WHITE),
                )
                .fill(egui::Color32::from_rgb(180, 35, 24));
                if ui.add(danger).clicked() {
                    a = Some(true);
                }
            });
            a
        });
        match modal.inner {
            Some(true) => {
                self.confirm_purge = None;
                let data = app_data_dir(&self.home);
                if let Ok(j) = Job::spawn("purge", ctx.clone(), move |_| {
                    purge_quarantine_session(&data, &dir)
                        .map(|()| "Deleted permanently.".to_string())
                        .map_err(|e| format!("Could not delete: {e}"))
                }) {
                    self.job = Some(QuarantineJob::Purge(j));
                }
            }
            Some(false) => self.confirm_purge = None,
            None if modal.should_close() => self.confirm_purge = None,
            None => {}
        }
    }
}
