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
    /// The chosen engine, by socket: indices shift when engines start or
    /// stop between scans.
    endpoint_socket: Option<PathBuf>,
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
            endpoint_socket: None,
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

    /// Index of the chosen engine in `endpoints` (the first if the chosen
    /// one is gone).
    fn endpoint_index(&self) -> usize {
        self.endpoint_socket
            .as_ref()
            .and_then(|s| self.endpoints.iter().position(|e| &e.socket == s))
            .unwrap_or(0)
    }

    /// Shows a new scan result. Keeps what was selected if it still exists
    /// and is still selectable (classes may change between scans); removed
    /// items simply disappear.
    fn apply_report(&mut self, report: DockerReport) {
        let keep = self.selected_keys();
        self.selected = report
            .items
            .iter()
            .map(|i| i.class.is_selectable() && keep.contains(&(i.kind, i.id.clone())))
            .collect();
        self.report = Some(report);
    }

    /// Selection keyed by item, so it survives a rescan (kind + id).
    fn selected_keys(&self) -> std::collections::HashSet<(ItemKind, String)> {
        let Some(r) = &self.report else {
            return Default::default();
        };
        r.items
            .iter()
            .zip(&self.selected)
            .filter(|(_, s)| **s)
            .map(|(i, _)| (i.kind, i.id.clone()))
            .collect()
    }

    pub fn start_scan(&mut self, ctx: &egui::Context) {
        if self.is_busy() {
            return;
        }
        self.endpoints = discover_endpoints(&self.home);
        let Some(ep) = self.endpoints.get(self.endpoint_index()).cloned() else {
            self.error = Some("No Docker engine socket found.".into());
            return;
        };
        self.error = None;
        self.endpoint_socket = Some(ep.socket.clone());
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
                    self.apply_report(report);
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
        let any_selected = self.selected.iter().any(|s| *s);
        if self.report.is_some() && (any_selected || self.clean_job.is_some()) {
            egui::Panel::bottom("docker_footer")
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    left: 0,
                    right: 0,
                    top: 8,
                    bottom: 4,
                }))
                .show(ui, |ui| self.footer_ui(ui));
        }

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
        let p = crate::theme::palette(ui);
        let subtitle = match &self.report {
            Some(r) => format!(
                "{}{} · nothing is removed without your confirmation",
                r.endpoint.name,
                r.server_version
                    .as_deref()
                    .map(|v| format!(" (Docker {v})"))
                    .unwrap_or_default()
            ),
            None => "Scanning only asks Docker for disk usage; nothing is removed.".into(),
        };
        let mut scan = false;
        let busy = self.is_busy();
        let has_engine = !self.endpoints.is_empty();
        let label = if self.report.is_some() {
            format!("{}  Rescan", egui_phosphor::regular::ARROW_CLOCKWISE)
        } else {
            format!("{}  Scan Docker", egui_phosphor::regular::MAGNIFYING_GLASS)
        };
        widgets::header_with_action(ui, Some("Cleanup"), "Docker", Some(&subtitle), |ui| {
            if busy {
                ui.spinner();
            } else if ui
                .add_enabled(has_engine, crate::theme::primary_button(ui, &label))
                .clicked()
            {
                scan = true;
            }
        });

        if self.endpoints.is_empty() {
            widgets::callout(
                ui,
                "No Docker engine found (checked OrbStack, Docker Desktop, Colima, Rancher Desktop, /var/run/docker.sock and DOCKER_HOST). Start Docker, then scan again.",
                widgets::Tone::Unknown,
            );
        }
        ui.horizontal_wrapped(|ui| {
            if !self.endpoints.is_empty() {
                ui.label(RichText::new("Engine").color(p.muted));
                let current = self.endpoint_index();
                let mut chosen = current;
                // Name only (paths are long); the socket is on hover.
                let width = (ui.available_width() - 16.0).clamp(120.0, 260.0);
                egui::ComboBox::from_id_salt("docker_endpoint")
                    .selected_text(&self.endpoints[current].name)
                    .width(width)
                    .show_ui(ui, |ui| {
                        for (i, ep) in self.endpoints.iter().enumerate() {
                            ui.selectable_value(&mut chosen, i, &ep.name)
                                .on_hover_text(ep.socket.display().to_string());
                        }
                    })
                    .response
                    .on_hover_text(self.endpoints[current].socket.display().to_string());
                if chosen != current {
                    // Results belong to one engine: never show (or act on)
                    // another engine's list under the new name.
                    self.endpoint_socket = Some(self.endpoints[chosen].socket.clone());
                    self.report = None;
                    self.selected.clear();
                    self.kind_filter = None;
                    scan = true;
                }
            }
            if self.scan_job.is_some() {
                ui.label(RichText::new("Asking Docker for disk usage…").color(p.muted));
            } else if let Some((job, total)) = &self.clean_job {
                ui.label(format!("Removing… {} of {total}", job.progress.items()));
                if ui.button("Cancel").clicked() {
                    job.progress.cancel();
                }
            }
        });
        let before = self.allow_volumes;
        ui.checkbox(
            &mut self.allow_volumes,
            "Allow selecting unused volumes (volume data cannot be recovered)",
        );
        if before != self.allow_volumes && self.report.is_some() {
            scan = true;
        }
        ui.add(
            egui::Label::new(
                RichText::new(
                    "RustClean uses the Docker API only and never touches Docker's disk image. \
                     Running containers, images they use and volumes in use are never offered. \
                     Docker removals cannot be undone.",
                )
                .small()
                .color(p.muted),
            )
            .wrap(),
        );
        if scan && !busy {
            self.start_scan(ctx);
        }
    }

    fn summary_ui(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else { return };
        let p = crate::theme::palette(ui);
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "Docker estimates {} reclaimable now",
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
        let hidden = match self.kind_filter {
            Some(k) => report
                .items
                .iter()
                .zip(&self.selected)
                .filter(|(i, s)| **s && i.kind != k)
                .count(),
            None => 0,
        };
        let summary = if hidden > 0 {
            format!(
                "{n} selected · {} ({hidden} not shown by the current filter)",
                format_bytes(bytes)
            )
        } else {
            format!("{n} selected · {}", format_bytes(bytes))
        };
        let busy = self.is_busy();
        let mut open = false;
        let (select_safe, deselect) = widgets::action_bar(ui, &summary, |ui| {
            let label = format!("Remove {n} selected…");
            open = ui
                .add_enabled(n > 0 && !busy, crate::theme::primary_button(ui, &label))
                .clicked();
        });
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
                    "About {} will be freed. Docker items do not go to the {}: this cannot be undone. Docker itself refuses anything still in use.",
                    format_bytes(plan.total_size()),
                    widgets::trash_name()
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
        self.error = None;
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
        let width = (ctx.content_rect().width() - 48.0).clamp(300.0, 680.0);
        let modal = Modal::new(Id::new("docker_result")).show(ctx, |ui| {
            ui.set_width(width);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustclean_containers::DockerItem;

    fn item(kind: ItemKind, id: &str, class: SafetyClass) -> DockerItem {
        DockerItem {
            kind,
            id: id.into(),
            name: id.into(),
            detail: String::new(),
            size: 10,
            class,
            reason: None,
        }
    }

    fn ep(name: &str) -> Endpoint {
        Endpoint {
            name: name.into(),
            socket: PathBuf::from(format!("/tmp/{name}.sock")),
        }
    }

    fn report(items: Vec<DockerItem>) -> DockerReport {
        DockerReport {
            endpoint: ep("a"),
            server_version: None,
            items,
            totals: Default::default(),
        }
    }

    fn page() -> DockerPage {
        let tmp = tempfile::tempdir().unwrap();
        let mut p = DockerPage::new(tmp.path().to_path_buf());
        p.endpoints = vec![ep("a"), ep("b")];
        p
    }

    #[test]
    fn selection_survives_a_rescan_but_not_a_class_change() {
        let mut p = page();
        p.apply_report(report(vec![
            item(ItemKind::Image, "i1", SafetyClass::Safe),
            item(ItemKind::Image, "i2", SafetyClass::Safe),
            item(ItemKind::Container, "c1", SafetyClass::Review),
        ]));
        p.selected = vec![true, true, true];
        // After a removal: i1 gone, i2 now in use, c1 unchanged, new item.
        p.apply_report(report(vec![
            item(ItemKind::Image, "new", SafetyClass::Safe),
            item(ItemKind::Image, "i2", SafetyClass::Protected),
            item(ItemKind::Container, "c1", SafetyClass::Review),
        ]));
        assert_eq!(p.selected, vec![false, false, true]);
    }

    #[test]
    fn engine_is_remembered_by_socket_not_position() {
        let mut p = page();
        p.endpoint_socket = Some(ep("b").socket);
        assert_eq!(p.endpoint_index(), 1);
        // Another engine appears in front: still "b".
        p.endpoints.insert(0, ep("c"));
        assert_eq!(p.endpoint_index(), 2);
        // "b" stops: fall back to the first, never out of range.
        p.endpoints.retain(|e| e.name != "b");
        assert_eq!(p.endpoint_index(), 0);
    }
}
