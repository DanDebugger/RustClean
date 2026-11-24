//! Docker page: engine-API cleanup of containers, images, volumes and build
//! cache. Removals are irreversible, so a real run needs an explicit
//! acknowledgement on top of the usual confirmation.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use egui::{Button, Checkbox, Color32, Id, Modal, RichText, ScrollArea, Ui};
use egui_extras::{Column, TableBuilder};
use rustclean_containers::{
    DockerCleanupReport, DockerOutcome, DockerPlan, DockerReport, Endpoint, ItemKind,
    discover_endpoints, execute, scan,
};
use rustclean_core::{SafetyClass, format_bytes};

use crate::jobs::{Job, Poll};
use crate::scan_page::open_operation_log;
use crate::widgets;

const KINDS: [ItemKind; 4] = [
    ItemKind::Container,
    ItemKind::Image,
    ItemKind::Volume,
    ItemKind::BuildCache,
];

struct ConfirmState {
    plan: DockerPlan,
    review_ack: bool,
    irreversible_ack: bool,
}

pub struct DockerPage {
    home: PathBuf,
    endpoints: Vec<Endpoint>,
    endpoint_idx: usize,
    allow_volumes: bool,

    scan_job: Option<Job<Result<DockerReport, String>>>,
    report: Option<DockerReport>,
    pub last_scan: Option<SystemTime>,
    selected: Vec<bool>,
    kind_filter: Option<ItemKind>,

    confirm: Option<ConfirmState>,
    clean_job: Option<(Job<Result<DockerCleanupReport, String>>, usize)>,
    result: Option<DockerCleanupReport>,
    error: Option<String>,
}

impl DockerPage {
    pub fn new(home: PathBuf) -> Self {
        let endpoints = discover_endpoints(&home);
        Self {
            home,
            endpoints,
            endpoint_idx: 0,
            allow_volumes: false,
            scan_job: None,
            report: None,
            last_scan: None,
            selected: Vec::new(),
            kind_filter: None,
            confirm: None,
            clean_job: None,
            result: None,
            error: None,
        }
    }

    /// Test helper: show a given report without contacting Docker.
    #[cfg(test)]
    pub fn set_report_for_test(&mut self, report: DockerReport) {
        self.selected = report
            .items
            .iter()
            .map(|i| i.class == SafetyClass::Safe)
            .collect();
        self.report = Some(report);
    }

    /// Test helper: open the confirmation dialog for the current selection.
    #[cfg(test)]
    pub fn open_confirm_for_test(&mut self) {
        if let Some(report) = &self.report {
            let plan = DockerPlan::from_selection(
                report
                    .items
                    .iter()
                    .zip(&self.selected)
                    .filter(|(_, s)| **s)
                    .map(|(i, _)| i),
                false,
            );
            self.confirm = Some(ConfirmState {
                plan,
                review_ack: false,
                irreversible_ack: false,
            });
        }
    }

    pub fn is_busy(&self) -> bool {
        self.scan_job.is_some() || self.clean_job.is_some()
    }

    /// (items, Safe bytes, selectable bytes) from the last scan.
    pub fn summary(&self) -> Option<(usize, u64, u64)> {
        let r = self.report.as_ref()?;
        let safe = r
            .items
            .iter()
            .filter(|i| i.class == SafetyClass::Safe)
            .map(|i| i.size)
            .sum();
        Some((r.items.len(), safe, r.reclaimable()))
    }

    pub fn reclaimable(&self) -> Option<u64> {
        self.report.as_ref().map(DockerReport::reclaimable)
    }

    pub fn has_engine(&self) -> bool {
        !self.endpoints.is_empty()
    }

    pub fn start_scan(&mut self, ctx: &egui::Context) {
        if self.is_busy() {
            return;
        }
        self.endpoints = discover_endpoints(&self.home);
        let Some(ep) = self
            .endpoints
            .get(self.endpoint_idx)
            .or(self.endpoints.first())
            .cloned()
        else {
            self.error = Some("No Docker engine socket found.".into());
            return;
        };
        self.error = None;
        let allow_volumes = self.allow_volumes;
        match Job::spawn("docker-scan", ctx.clone(), move |_| {
            scan(&ep, allow_volumes).map_err(|e| e.to_string())
        }) {
            Ok(j) => self.scan_job = Some(j),
            Err(e) => self.error = Some(format!("could not start scan: {e}")),
        }
    }

    pub fn poll_jobs(&mut self, ctx: &egui::Context) {
        if let Some(job) = &self.scan_job {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(Ok(report)) => {
                    self.selected = vec![false; report.items.len()];
                    self.report = Some(report);
                    self.last_scan = Some(SystemTime::now());
                    self.scan_job = None;
                }
                Poll::Done(Err(e)) => {
                    self.scan_job = None;
                    self.error = Some(e);
                }
                Poll::Crashed => {
                    self.scan_job = None;
                    self.error = Some("The Docker scan stopped unexpectedly.".into());
                }
            }
        }
        if let Some((job, _)) = &self.clean_job {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(Ok(report)) => {
                    self.clean_job = None;
                    let real = !report.dry_run;
                    self.result = Some(report);
                    if real {
                        // Engine state changed; show the current truth.
                        self.start_scan(ctx);
                    }
                }
                Poll::Done(Err(e)) => {
                    self.clean_job = None;
                    self.error = Some(e);
                }
                Poll::Crashed => {
                    self.clean_job = None;
                    self.error = Some(
                        "Docker cleanup stopped unexpectedly. Rescan to see the current state."
                            .into(),
                    );
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if self.is_busy() {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
        if self.report.is_some() {
            egui::Panel::bottom("docker_footer")
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    left: 0,
                    right: 0,
                    top: 8,
                    bottom: 4,
                }))
                .show(ui, |ui| self.footer_ui(ui));
        }

        widgets::page_header(ui, Some("Cleanup"), "Docker", None);
        self.header_ui(ui, &ctx);
        if let Some(e) = &self.error {
            widgets::error(ui, e);
        }
        if self.report.is_some() {
            ui.add_space(6.0);
            self.summary_ui(ui);
            ui.add_space(6.0);
            self.table_ui(ui);
        }
        self.confirm_dialog(&ctx);
        self.result_dialog(&ctx);
    }

    fn header_ui(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        if self.endpoints.is_empty() {
            ui.label("No Docker engine found (checked OrbStack, Docker Desktop, Colima, Rancher Desktop, /var/run/docker.sock and DOCKER_HOST).");
        }
        ui.horizontal(|ui| {
            if !self.endpoints.is_empty() {
                ui.label(RichText::new("Engine").weak());
                let current = &self.endpoints[self.endpoint_idx.min(self.endpoints.len() - 1)];
                egui::ComboBox::from_id_salt("docker_endpoint")
                    .selected_text(format!("{} ({})", current.name, current.socket.display()))
                    .show_ui(ui, |ui| {
                        for (i, ep) in self.endpoints.iter().enumerate() {
                            ui.selectable_value(
                                &mut self.endpoint_idx,
                                i,
                                format!("{} ({})", ep.name, ep.socket.display()),
                            );
                        }
                    });
            }
            if self.scan_job.is_some() {
                ui.spinner();
                ui.label("Asking Docker for disk usage…");
            } else if let Some((job, total)) = &self.clean_job {
                ui.spinner();
                ui.label(format!("Removing… {} of {total}", job.progress.items()));
                if ui.button("Cancel").clicked() {
                    job.progress.cancel();
                }
            } else {
                let label = if self.report.is_some() {
                    "Rescan"
                } else {
                    "Scan Docker"
                };
                if ui
                    .add_enabled(!self.endpoints.is_empty(), Button::new(label))
                    .clicked()
                {
                    self.start_scan(ctx);
                }
            }
        });
        let before = self.allow_volumes;
        ui.checkbox(
            &mut self.allow_volumes,
            "Allow selecting unused volumes (volume data cannot be recovered)",
        );
        if before != self.allow_volumes && self.report.is_some() {
            self.start_scan(ctx);
        }
        ui.label(
            RichText::new(
                "RustClean uses the Docker API only and never touches Docker's disk image. \
                 Running containers, images they use and volumes in use are never offered. \
                 Docker removals cannot be undone.",
            )
            .small()
            .weak(),
        );
    }

    fn summary_ui(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else { return };
        let p = crate::theme::palette(ui);
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{}{} · Docker estimates {} reclaimable now",
                    report.endpoint.name,
                    report
                        .server_version
                        .as_deref()
                        .map(|v| format!(" (Docker {v})"))
                        .unwrap_or_default(),
                    format_bytes(report.totals.values().map(|t| t.reclaimable).sum()),
                ))
                .color(p.text2),
            )
            .wrap(),
        );
        ui.add_space(4.0);
        let mut new_filter = None;
        let kind_filter = self.kind_filter;
        if ui.available_width() < 640.0 {
            // Phone width: compact filter chips instead of tiles.
            ui.horizontal_wrapped(|ui| {
                if widgets::chip(ui, kind_filter.is_none(), "All").clicked() {
                    new_filter = Some(None);
                }
                for kind in KINDS {
                    let t = report.totals.get(&kind).cloned().unwrap_or_default();
                    let active = kind_filter == Some(kind);
                    let label = format!("{} · {}", kind.label(), format_bytes(t.reclaimable));
                    if widgets::chip(ui, active, &label).clicked() {
                        new_filter = Some(if active { None } else { Some(kind) });
                    }
                }
            });
            ui.add_space(6.0);
            if let Some(f) = new_filter {
                self.kind_filter = f;
            }
            return;
        }
        let cols = crate::dashboard::grid_columns(ui.available_width());
        widgets::card_grid(ui, KINDS.len(), cols, 10.0, |ui, i| {
            let kind = KINDS[i];
            let t = report.totals.get(&kind).cloned().unwrap_or_default();
            let selectable: u64 = report
                .items
                .iter()
                .filter(|it| it.kind == kind && it.class.is_selectable())
                .map(|it| it.size)
                .sum();
            let active = kind_filter == Some(kind);
            let frame = crate::theme::card(ui).fill(if active { p.accent_soft } else { p.surface });
            let resp = frame
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(kind.label()).strong().color(if active {
                        p.accent
                    } else {
                        p.text
                    }));
                    ui.label(
                        RichText::new(format_bytes(t.reclaimable))
                            .size(22.0)
                            .strong(),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} total · {} selectable",
                            t.count,
                            format_bytes(selectable)
                        ))
                        .small()
                        .color(p.muted),
                    );
                })
                .response
                .interact(egui::Sense::click())
                .on_hover_text("Show only this type");
            if resp.clicked() {
                new_filter = Some(if active { None } else { Some(kind) });
            }
        });
        ui.add(
            egui::Label::new(
                RichText::new("\"Selectable\" includes images that are freed only if their stopped containers are removed too.")
                    .small()
                    .color(p.muted),
            )
            .wrap(),
        );
        if let Some(f) = new_filter {
            self.kind_filter = f;
        }
    }

    fn table_ui(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else { return };
        let p = crate::theme::palette(ui);
        let visible: Vec<usize> = report
            .items
            .iter()
            .enumerate()
            .filter(|(_, i)| self.kind_filter.is_none_or(|k| i.kind == k))
            .map(|(n, _)| n)
            .collect();
        let narrow = ui.available_width() < 640.0;
        let body_h = ui.text_style_height(&egui::TextStyle::Body);
        let small_h = ui.text_style_height(&egui::TextStyle::Small);
        let selected = &mut self.selected;
        crate::theme::card(ui)
            .inner_margin(egui::Margin::same(0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if narrow {
                    let row_h = body_h + small_h + 34.0;
                    egui::ScrollArea::vertical()
                        .id_salt("docker_list")
                        .auto_shrink([false, false])
                        .show_rows(ui, row_h, visible.len(), |ui, range| {
                            for &idx in &visible[range] {
                                let item = &report.items[idx];
                                egui::Frame::new()
                                    .inner_margin(egui::Margin::symmetric(12, 8))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.set_height(row_h - 17.0);
                                        ui.horizontal(|ui| {
                                            if item.class.is_selectable() {
                                                ui.checkbox(&mut selected[idx], "");
                                            } else {
                                                ui.add_enabled(
                                                    false,
                                                    Checkbox::new(&mut false, ""),
                                                );
                                            }
                                            ui.vertical(|ui| {
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(&item.name)
                                                            .strong()
                                                            .color(p.text),
                                                    )
                                                    .truncate(),
                                                );
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(format!(
                                                            "{} · {}",
                                                            item.kind.label(),
                                                            item.detail
                                                        ))
                                                        .small()
                                                        .color(p.muted),
                                                    )
                                                    .truncate(),
                                                );
                                                ui.horizontal(|ui| {
                                                    ui.label(
                                                        RichText::new(format_bytes(item.size))
                                                            .strong(),
                                                    );
                                                    let r = widgets::class_pill(ui, item.class);
                                                    if let Some(reason) = &item.reason {
                                                        r.on_hover_text(reason);
                                                    }
                                                });
                                            });
                                        });
                                    });
                            }
                        });
                    return;
                }
                let row_h = body_h + small_h + 14.0;
                TableBuilder::new(ui)
                    .striped(false)
                    .resizable(false)
                    .auto_shrink([false, false])
                    .min_scrolled_height(0.0)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::exact(34.0))
                    .column(Column::remainder().at_least(160.0).clip(true))
                    .column(Column::exact(84.0))
                    .column(Column::exact(120.0))
                    .header(30.0, |mut h| {
                        for t in ["", "Item", "Size", "Safety"] {
                            h.col(|ui| {
                                ui.label(RichText::new(t).small().strong().color(p.muted));
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_h, visible.len(), |mut row| {
                            let idx = visible[row.index()];
                            let item = &report.items[idx];
                            row.col(|ui| {
                                ui.add_space(8.0);
                                if item.class.is_selectable() {
                                    ui.checkbox(&mut selected[idx], "");
                                } else {
                                    ui.add_enabled(false, Checkbox::new(&mut false, ""));
                                }
                            });
                            row.col(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(&item.name).color(p.text))
                                        .on_hover_text(&item.id);
                                    ui.label(
                                        RichText::new(format!(
                                            "{} · {}",
                                            item.kind.label(),
                                            item.detail
                                        ))
                                        .small()
                                        .color(p.muted),
                                    );
                                });
                            });
                            row.col(|ui| {
                                ui.label(format_bytes(item.size));
                            });
                            row.col(|ui| {
                                let r = widgets::class_pill(ui, item.class);
                                if let Some(reason) = &item.reason {
                                    r.on_hover_text(reason);
                                }
                            });
                        });
                    });
            });
    }

    fn footer_ui(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else { return };
        let (n, bytes) = report
            .items
            .iter()
            .zip(&self.selected)
            .filter(|(_, s)| **s)
            .fold((0usize, 0u64), |(n, b), (i, _)| (n + 1, b + i.size));
        let busy = self.is_busy();
        let mut open = false;
        let (select_safe, deselect) = widgets::action_bar(
            ui,
            &format!("{n} selected · {}", format_bytes(bytes)),
            |ui| {
                let label = format!("Remove {n} selected…");
                open = ui
                    .add_enabled(n > 0 && !busy, crate::theme::primary_button(ui, &label))
                    .clicked();
            },
        );
        if select_safe {
            for (i, s) in report.items.iter().zip(self.selected.iter_mut()) {
                if i.class == SafetyClass::Safe {
                    *s = true;
                }
            }
        }
        if deselect {
            self.selected.iter_mut().for_each(|s| *s = false);
        }
        if open {
            let plan = DockerPlan::from_selection(
                report
                    .items
                    .iter()
                    .zip(&self.selected)
                    .filter(|(_, s)| **s)
                    .map(|(i, _)| i),
                false,
            );
            self.confirm = Some(ConfirmState {
                plan,
                review_ack: false,
                irreversible_ack: false,
            });
        }
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(state) = &mut self.confirm else {
            return;
        };
        let plan = &state.plan;
        let review = plan.review_count();
        let width = (ctx.content_rect().width() - 48.0).clamp(320.0, 720.0);
        let modal = Modal::new(Id::new("docker_confirm")).show(ctx, |ui| {
            ui.set_width(width);
            ui.label(
                RichText::new(format!("Remove {} Docker items?", plan.items().len()))
                    .size(20.0)
                    .strong(),
            );
            ui.label(
                RichText::new(format!(
                    "About {} will be freed. Docker items do not go to the Trash: this cannot be undone. Docker itself refuses anything still in use.",
                    format_bytes(plan.total_size())
                ))
                .color(Color32::from_rgb(220, 60, 60)),
            );
            if plan.rejected() > 0 {
                widgets::warning(
                    ui,
                    format!("{} selected items are protected and will be skipped.", plan.rejected()),
                );
            }
            ui.add_space(6.0);
            let row_h = ui.text_style_height(&egui::TextStyle::Small) + 4.0;
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ScrollArea::both()
                    .max_height(240.0)
                    .auto_shrink([false, true])
                    .show_rows(ui, row_h, plan.items().len(), |ui, range| {
                        for i in &plan.items()[range] {
                            let marker = if i.class == SafetyClass::Review { "[review] " } else { "" };
                            ui.label(
                                RichText::new(format!(
                                    "{marker}{:<11} {}  {}  ({})",
                                    i.kind.slug(),
                                    i.name,
                                    i.detail,
                                    format_bytes(i.size)
                                ))
                                .small()
                                .monospace(),
                            );
                        }
                    });
            });
            ui.label(
                RichText::new("Order: containers, then images, then volumes, then build cache.")
                    .small()
                    .weak(),
            );
            ui.add_space(6.0);
            if review > 0 {
                ui.checkbox(
                    &mut state.review_ack,
                    format!("I checked the {review} items marked Review"),
                );
            }
            ui.checkbox(
                &mut state.irreversible_ack,
                "I understand these Docker items cannot be recovered",
            );
            ui.add_space(8.0);
            let reviewed = review == 0 || state.review_ack;
            let mut action = None;
            ui.horizontal_wrapped(|ui| {
                if ui.button("Cancel").clicked() {
                    action = Some(0);
                }
                if ui
                    .add_enabled(reviewed, Button::new("Simulate first"))
                    .on_hover_text("Asks Docker about every item without removing anything")
                    .clicked()
                {
                    action = Some(1);
                }
                let danger = Button::new(
                    RichText::new("Remove permanently").strong().color(Color32::WHITE),
                )
                .fill(Color32::from_rgb(180, 35, 24));
                if ui
                    .add_enabled(reviewed && state.irreversible_ack, danger)
                    .clicked()
                {
                    action = Some(2);
                }
            });
            action
        });
        match modal.inner {
            Some(2) => self.execute_confirmed(ctx, false),
            Some(1) => self.execute_confirmed(ctx, true),
            Some(_) => self.confirm = None,
            None if modal.should_close() => self.confirm = None,
            None => {}
        }
    }

    fn execute_confirmed(&mut self, ctx: &egui::Context, simulate: bool) {
        let Some(mut state) = self.confirm.take() else {
            return;
        };
        state.plan.dry_run = simulate;
        let approved = match state.plan.approve(state.review_ack, state.irreversible_ack) {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        let Some(ep) = self.report.as_ref().map(|r| r.endpoint.clone()) else {
            return;
        };
        let total = approved.items().len();
        let home = self.home.clone();
        match Job::spawn("docker-clean", ctx.clone(), move |progress| {
            let log = open_operation_log(&home);
            execute(&ep, &approved, progress, log.as_ref()).map_err(|e| e.to_string())
        }) {
            Ok(j) => self.clean_job = Some((j, total)),
            Err(e) => self.error = Some(format!("could not start removal: {e}")),
        }
    }

    fn result_dialog(&mut self, ctx: &egui::Context) {
        let Some(r) = &self.result else { return };
        let modal = Modal::new(Id::new("docker_result")).show(ctx, |ui| {
            ui.set_width(680.0);
            let removed = r.count(|o| matches!(o, DockerOutcome::Removed { .. }));
            let would = r.count(|o| matches!(o, DockerOutcome::WouldRemove));
            let skipped = r.count(|o| matches!(o, DockerOutcome::Skipped(_)));
            let failed = r.count(|o| matches!(o, DockerOutcome::Failed(_)));
            let not_attempted = r.count(|o| matches!(o, DockerOutcome::NotAttempted));
            if r.dry_run {
                ui.heading("Dry run complete");
                ui.label(format!(
                    "{would} items (~{}) would be removed. Nothing was changed.",
                    format_bytes(r.bytes_affected())
                ));
            } else {
                ui.heading("Docker cleanup complete");
                ui.label(
                    RichText::new(format!(
                        "{removed} items removed (~{} reclaimed).",
                        format_bytes(r.bytes_affected())
                    ))
                    .strong(),
                );
            }
            if skipped + failed + not_attempted > 0 {
                widgets::warning(
                    ui,
                    format!("{skipped} skipped, {failed} failed, {not_attempted} not attempted."),
                );
                ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    for res in &r.results {
                        let msg = match &res.outcome {
                            DockerOutcome::Skipped(e) => {
                                format!("skipped {} {}: {e}", res.item.kind.slug(), res.item.name)
                            }
                            DockerOutcome::Failed(e) => {
                                format!("failed  {} {}: {e}", res.item.kind.slug(), res.item.name)
                            }
                            _ => continue,
                        };
                        ui.label(RichText::new(msg).small().monospace());
                    }
                });
            }
            ui.add_space(8.0);
            ui.button("Done").clicked()
        });
        if modal.inner || modal.should_close() {
            self.result = None;
        }
    }
}
