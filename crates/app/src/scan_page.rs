//! Generic page for any file-based [`CleanupModule`] (Chrome, Junk,
//! Developer).
//!
//! Flow: detect → scan (read-only) → select → confirm (plan approval) →
//! clean (re-validated, reversible) → report.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use egui::{Button, Checkbox, Id, Modal, RichText, ScrollArea, Ui};
use egui_extras::{Column, TableBuilder};
use rustclean_core::{
    Cleaner, CleanupModule, CleanupPlan, CleanupReport, ItemOutcome, OperationLog, RemovalMethod,
    Remover, SafetyClass, ScanReport, Scanner, format_bytes,
};
use rustclean_safety::{
    ProtectionRules, QuarantineRemover, RemovalError, TrashRemover, app_data_dir, app_log_dir,
};

use crate::jobs::{Job, Poll};
use crate::theme::{self, palette};
use crate::widgets::{self, Tone};

const TOAST_FOR: Duration = Duration::from_secs(6);
/// Width of the detail panel in wide/medium layouts.
const DETAIL_W: f32 = 290.0;
/// Height limit of the detail panel when it sits above the file list.
const DETAIL_STACKED_H: f32 = 240.0;

/// Layout by available content width.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Breakpoint {
    Wide,
    Medium,
    Narrow,
}

impl Breakpoint {
    pub fn of(width: f32) -> Self {
        if width >= 960.0 {
            Breakpoint::Wide
        } else if width >= 640.0 {
            Breakpoint::Medium
        } else {
            Breakpoint::Narrow
        }
    }
}

/// Safety filter chips.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClassFilter {
    All,
    /// Safe and not recently modified (see `rustclean_core::recommend`).
    Recommended,
    Safe,
    Review,
    /// Protected or Unknown: shown for transparency, never removable.
    Locked,
}

impl ClassFilter {
    fn matches(self, c: SafetyClass, recommended: bool) -> bool {
        match self {
            ClassFilter::All => true,
            ClassFilter::Recommended => recommended,
            ClassFilter::Safe => c == SafetyClass::Safe,
            ClassFilter::Review => c == SafetyClass::Review,
            ClassFilter::Locked => !c.is_selectable(),
        }
    }
    fn label(self) -> &'static str {
        match self {
            ClassFilter::All => "All",
            ClassFilter::Recommended => "Recommended",
            ClassFilter::Safe => "Safe",
            ClassFilter::Review => "Review",
            ClassFilter::Locked => "Not removable",
        }
    }
    fn icon(self) -> &'static str {
        use egui_phosphor::regular as i;
        match self {
            ClassFilter::All => i::LIST_BULLETS,
            ClassFilter::Recommended => i::SPARKLE,
            ClassFilter::Safe => i::SHIELD_CHECK,
            ClassFilter::Review => i::EYE,
            ClassFilter::Locked => i::LOCK,
        }
    }
}

const WARNING_CHECK_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
enum ConfirmAction {
    Cancel,
    Simulate,
    Clean,
}

struct ConfirmState {
    plan: CleanupPlan,
    review_ack: bool,
    warning_ack: bool,
}

struct CleanOutcome {
    report: CleanupReport,
    quarantine_dir: Option<PathBuf>,
    log_path: Option<PathBuf>,
}

/// Current state of the file shown in the detail panel, read (lstat only)
/// when the panel opens. Purely informational: the cleaner re-validates
/// every file itself before acting.
struct LiveInfo {
    path: PathBuf,
    created: Option<SystemTime>,
    accessed: Option<SystemTime>,
    state: LiveState,
}

#[derive(Debug, PartialEq, Eq)]
enum LiveState {
    Unchanged,
    /// Size, modification time or identity differ from the scan.
    Changed,
    Missing,
    Unreadable(String),
}

impl LiveInfo {
    fn read(c: &rustclean_core::Candidate) -> Self {
        let (created, accessed, state) = match std::fs::symlink_metadata(&c.path) {
            Ok(m) => {
                let now = rustclean_safety::FileFingerprint::from_metadata(&m);
                let changed = now.size != c.fingerprint.size
                    || now.modified != c.fingerprint.modified
                    || now.inode != c.fingerprint.inode
                    || now.device != c.fingerprint.device;
                (
                    m.created().ok(),
                    m.accessed().ok(),
                    if changed {
                        LiveState::Changed
                    } else {
                        LiveState::Unchanged
                    },
                )
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None, LiveState::Missing),
            Err(e) => (None, None, LiveState::Unreadable(e.to_string())),
        };
        Self {
            path: c.path.clone(),
            created,
            accessed,
            state,
        }
    }
}

/// Used for dry runs so that no Trash/quarantine resources are touched.
/// The cleaner never calls `remove` in a dry run; if it ever did, this
/// refuses.
struct DryRunRemover(RemovalMethod);

impl Remover for DryRunRemover {
    fn method(&self) -> RemovalMethod {
        self.0
    }
    fn remove(&self, _: &Path) -> Result<Option<PathBuf>, RemovalError> {
        Err(RemovalError::Io(std::io::Error::other(
            "dry run: removal refused",
        )))
    }
}

pub struct ScanPage {
    id: &'static str,
    module: Box<dyn CleanupModule>,
    home: PathBuf,
    rules: ProtectionRules,
    active_warning: Option<String>,
    last_warning_check: Option<Instant>,

    scan_job: Option<Job<ScanReport>>,
    report: Option<ScanReport>,
    pub last_scan: Option<SystemTime>,
    selected: Vec<bool>,
    /// Parallel to `report.candidates`; computed once per scan.
    recommended: Vec<bool>,
    category_filter: Option<String>,
    class_filter: ClassFilter,
    search: String,
    visible: Vec<usize>,
    detail: Option<usize>,
    live: Option<LiveInfo>,
    toast: Option<(String, Instant)>,
    event: Option<String>,

    method: RemovalMethod,
    confirm: Option<ConfirmState>,
    clean_job: Option<(Job<Result<CleanOutcome, String>>, usize)>,
    result: Option<CleanOutcome>,
    error: Option<String>,
    /// Set after a real cleanup so the dashboard refreshes disk figures.
    pub disk_changed: bool,
}

impl ScanPage {
    /// `id` must be unique per page (used for egui widget IDs).
    pub fn new(
        id: &'static str,
        module: Box<dyn CleanupModule>,
        home: PathBuf,
        rules: ProtectionRules,
    ) -> Self {
        Self {
            id,
            module,
            home,
            rules,
            active_warning: None,
            last_warning_check: None,
            scan_job: None,
            report: None,
            last_scan: None,
            selected: Vec::new(),
            recommended: Vec::new(),
            category_filter: None,
            class_filter: ClassFilter::All,
            search: String::new(),
            visible: Vec::new(),
            detail: None,
            live: None,
            toast: None,
            event: None,
            method: RemovalMethod::Trash,
            confirm: None,
            clean_job: None,
            result: None,
            error: None,
            disk_changed: false,
        }
    }

    /// (files, Safe bytes, reclaimable bytes) from the last scan.
    pub fn summary(&self) -> Option<(usize, u64, u64)> {
        let r = self.report.as_ref()?;
        let safe = r
            .candidates
            .iter()
            .filter(|c| c.class == SafetyClass::Safe)
            .map(|c| c.disk_usage)
            .sum();
        Some((r.candidates.len(), safe, r.reclaimable()))
    }

    pub fn is_available(&self) -> bool {
        self.module.is_available()
    }

    /// Estimated reclaimable bytes from the last scan.
    pub fn reclaimable(&self) -> Option<u64> {
        self.report.as_ref().map(ScanReport::reclaimable)
    }

    pub fn is_busy(&self) -> bool {
        self.scan_job.is_some() || self.clean_job.is_some()
    }

    pub fn start_scan(&mut self, ctx: &egui::Context) {
        if self.is_busy() {
            return;
        }
        self.module.refresh();
        if !self.module.is_available() {
            self.error = Some("Nothing to scan: see details above.".into());
            return;
        }
        self.error = None;
        self.result = None;
        let spec = self.module.prepare_scan();
        let rules = self.rules.clone();
        let job = Job::spawn(&format!("{}-scan", self.id), ctx.clone(), move |progress| {
            let report =
                Scanner::new(rules).scan(spec.targets, spec.classifier.as_deref(), progress);
            match spec.post_process {
                Some(post) if !report.cancelled => post(report, progress),
                _ => report,
            }
        });
        match job {
            Ok(job) => self.scan_job = Some(job),
            Err(e) => self.error = Some(format!("could not start scan: {e}")),
        }
    }

    /// Call every frame regardless of which page is visible, so background
    /// scans started from the dashboard complete.
    pub fn poll_jobs(&mut self) {
        if let Some(job) = &self.scan_job {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(mut report) => {
                    report
                        .candidates
                        .sort_by(|a, b| b.disk_usage.cmp(&a.disk_usage));
                    self.selected = vec![false; report.candidates.len()];
                    let now = SystemTime::now();
                    self.recommended = report
                        .candidates
                        .iter()
                        .map(|c| rustclean_core::is_recommended(c, now))
                        .collect();
                    self.report = Some(report);
                    self.last_scan = Some(SystemTime::now());
                    self.scan_job = None;
                    self.category_filter = None;
                    self.detail = None;
                    self.recompute_visible();
                    if let Some(r) = &self.report {
                        self.event = Some(format!(
                            "Scan · {} · {} files in {:.1} s",
                            self.module.title(),
                            r.candidates.len(),
                            r.elapsed.as_secs_f32()
                        ));
                    }
                }
                Poll::Crashed => {
                    self.scan_job = None;
                    self.error =
                        Some("The scan stopped unexpectedly. See logs for details.".into());
                }
            }
        }
        if let Some((job, _)) = &self.clean_job {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(Ok(outcome)) => {
                    self.clean_job = None;
                    let r = &outcome.report;
                    let verb = match (r.dry_run, r.method) {
                        (true, _) => "Simulated",
                        (false, RemovalMethod::Trash) => "Moved to Trash",
                        (false, RemovalMethod::Quarantine) => "Quarantined",
                    };
                    let n = if r.dry_run {
                        r.would_remove()
                    } else {
                        r.removed()
                    };
                    self.event = Some(format!(
                        "{verb} · {} · {n} files, {}",
                        self.module.title(),
                        format_bytes(r.bytes_affected())
                    ));
                    let clean_run = !r.dry_run && r.skipped() + r.failed() + r.not_attempted() == 0;
                    if !r.dry_run {
                        self.forget_removed(&outcome.report);
                        self.disk_changed = true;
                    }
                    if clean_run {
                        let r = &outcome.report;
                        self.toast = Some((
                            format!(
                                "{} {} files ({}). {}",
                                verb,
                                r.removed(),
                                format_bytes(r.bytes_affected()),
                                if r.method == RemovalMethod::Trash {
                                    "Empty the Trash to free the space."
                                } else {
                                    "Restore from Quarantine any time."
                                }
                            ),
                            Instant::now(),
                        ));
                    } else {
                        self.result = Some(outcome);
                    }
                }
                Poll::Done(Err(e)) => {
                    self.clean_job = None;
                    self.error = Some(e);
                }
                Poll::Crashed => {
                    self.clean_job = None;
                    self.error = Some(
                        "Cleanup stopped unexpectedly. Rescan to see the current state; \
                         see the operation log for what was processed."
                            .into(),
                    );
                }
            }
        }
    }

    /// Drops removed files from the result list after a real cleanup.
    fn forget_removed(&mut self, report: &CleanupReport) {
        // Result paths are the planned (scan-time) paths, so they match.
        let removed: HashSet<&Path> = report
            .results
            .iter()
            .filter(|r| matches!(r.outcome, ItemOutcome::Removed { .. }))
            .map(|r| r.path.as_path())
            .collect();
        let Some(scan) = &mut self.report else { return };
        // Indices shift when rows are dropped: remember the open file by
        // path so the detail panel keeps showing the same file (or closes
        // if that file was removed).
        let detail_path = self
            .detail
            .and_then(|i| scan.candidates.get(i))
            .map(|c| c.path.clone());
        let mut keep = Vec::with_capacity(scan.candidates.len());
        let mut keep_sel = Vec::with_capacity(scan.candidates.len());
        let mut keep_rec = Vec::with_capacity(scan.candidates.len());
        // Keep the parallel vectors aligned whatever happened before.
        self.selected.resize(scan.candidates.len(), false);
        self.recommended.resize(scan.candidates.len(), false);
        for ((c, sel), rec) in scan
            .candidates
            .drain(..)
            .zip(self.selected.drain(..))
            .zip(self.recommended.drain(..))
        {
            if !removed.contains(c.path.as_path()) {
                keep.push(c);
                keep_sel.push(sel);
                keep_rec.push(rec);
            }
        }
        scan.candidates = keep;
        self.selected = keep_sel;
        self.recommended = keep_rec;
        self.detail = detail_path.and_then(|p| scan.candidates.iter().position(|c| c.path == p));
        self.live = None;
        self.recompute_visible();
    }

    /// Selects (or clears) every selectable file currently shown by the
    /// filters. Review files may be selected; the confirmation still
    /// requires their explicit acknowledgement.
    fn set_visible_selected(&mut self, on: bool) {
        let Some(r) = &self.report else { return };
        for &i in &self.visible {
            if r.candidates[i].class.is_selectable() {
                self.selected[i] = on;
            }
        }
    }

    /// Selected files that the current filters hide.
    fn hidden_selected(&self) -> usize {
        let visible: HashSet<usize> = self.visible.iter().copied().collect();
        self.selected
            .iter()
            .enumerate()
            .filter(|(i, s)| **s && !visible.contains(i))
            .count()
    }

    /// Unselects the given paths (from the confirmation's file list) and
    /// rebuilds the pending plan from what is left. Closes the dialog when
    /// nothing remains.
    fn exclude_from_confirm(&mut self, paths: &[PathBuf]) {
        let Some(r) = &self.report else { return };
        let drop: HashSet<&Path> = paths.iter().map(PathBuf::as_path).collect();
        for (c, s) in r.candidates.iter().zip(self.selected.iter_mut()) {
            if drop.contains(c.path.as_path()) {
                *s = false;
            }
        }
        let Some(state) = &mut self.confirm else {
            return;
        };
        let selected = r
            .candidates
            .iter()
            .zip(&self.selected)
            .filter(|(_, s)| **s)
            .map(|(c, _)| c);
        let plan = CleanupPlan::from_selection(selected, state.plan.method, false);
        if plan.items().is_empty() {
            self.confirm = None;
        } else {
            // Acknowledgements stay valid: the plan only got smaller.
            state.plan = plan;
        }
    }

    fn recompute_visible(&mut self) {
        let needle = self.search.trim().to_lowercase();
        self.visible = match &self.report {
            None => Vec::new(),
            Some(r) => r
                .candidates
                .iter()
                .enumerate()
                .filter(|(i, c)| {
                    self.category_filter
                        .as_ref()
                        .is_none_or(|f| &c.category == f)
                        && self
                            .class_filter
                            .matches(c.class, self.recommended.get(*i).copied().unwrap_or(false))
                        && (needle.is_empty()
                            || c.path.to_string_lossy().to_lowercase().contains(&needle))
                })
                .map(|(i, _)| i)
                .collect(),
        };
        if self.detail.is_some_and(|d| !self.visible.contains(&d)) {
            self.detail = None;
        }
    }

    fn refresh_warning(&mut self, ctx: &egui::Context) {
        if self
            .last_warning_check
            .is_none_or(|t| t.elapsed() >= WARNING_CHECK_INTERVAL)
        {
            self.active_warning = self.module.active_warning();
            self.last_warning_check = Some(Instant::now());
        }
        ctx.request_repaint_after(WARNING_CHECK_INTERVAL);
    }

    /// (files, bytes) recommended for deletion.
    fn recommended_totals(&self) -> (usize, u64) {
        let Some(r) = &self.report else { return (0, 0) };
        r.candidates
            .iter()
            .zip(&self.recommended)
            .filter(|(_, rec)| **rec)
            .fold((0, 0), |(n, b), (c, _)| (n + 1, b + c.disk_usage))
    }

    /// Selects exactly the recommended files (adds to the selection).
    fn select_recommended(&mut self) {
        for (s, rec) in self.selected.iter_mut().zip(&self.recommended) {
            if *rec {
                *s = true;
            }
        }
    }

    /// "Smart recommendation" card above the results.
    fn recommendation_banner(&mut self, ui: &mut Ui) {
        let (n, bytes) = self.recommended_totals();
        if n == 0 {
            return;
        }
        let all_selected = self
            .selected
            .iter()
            .zip(&self.recommended)
            .all(|(s, rec)| !*rec || *s);
        let p = palette(ui);
        let (fg, bg) = p.safe;
        let mut select = false;
        let mut show = false;
        egui::Frame::new()
            .fill(bg)
            .stroke(egui::Stroke::new(1.0, fg.gamma_multiply(0.35)))
            .corner_radius(egui::CornerRadius::same(12))
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(egui_phosphor::regular::SPARKLE)
                            .color(fg)
                            .size(16.0),
                    );
                    ui.label(
                        RichText::new(format!(
                            "Recommended: {n} {} ({}) are safe to delete",
                            if n == 1 { "file" } else { "files" },
                            format_bytes(bytes)
                        ))
                        .strong()
                        .color(fg),
                    );
                    ui.label(
                        RichText::new("Safe cache data, unchanged for at least a day.")
                            .small()
                            .color(fg),
                    );
                    if ui
                        .add_enabled(!all_selected, Button::new(format!(
                            "{}  Select recommended",
                            egui_phosphor::regular::CHECK_SQUARE
                        )))
                        .on_hover_text("Adds these files to your selection; you still confirm before anything moves")
                        .clicked()
                    {
                        select = true;
                    }
                    if self.class_filter != ClassFilter::Recommended
                        && ui.button(format!("{}  Show only these", egui_phosphor::regular::FUNNEL)).clicked()
                    {
                        show = true;
                    }
                });
            });
        ui.add_space(6.0);
        if select {
            self.select_recommended();
        }
        if show {
            self.class_filter = ClassFilter::Recommended;
            self.recompute_visible();
        }
    }

    fn selection_totals(&self) -> (usize, u64) {
        let Some(r) = &self.report else { return (0, 0) };
        r.candidates
            .iter()
            .zip(&self.selected)
            .filter(|(_, s)| **s)
            .fold((0, 0), |(n, b), (c, _)| (n + 1, b + c.disk_usage))
    }

    /// Test helper: select the first `n` Safe files and show the first one's
    /// details.
    #[cfg(test)]
    pub fn select_for_test(&mut self, n: usize) {
        if let Some(r) = &self.report {
            let mut left = n;
            for (i, c) in r.candidates.iter().enumerate() {
                if left > 0 && c.class == SafetyClass::Safe {
                    self.selected[i] = true;
                    if self.detail.is_none() {
                        self.detail = Some(i);
                    }
                    left -= 1;
                }
            }
        }
    }

    #[cfg(test)]
    pub fn close_confirm_for_test(&mut self) {
        self.confirm = None;
    }

    /// A line for the activity feed, taken once.
    pub fn take_event(&mut self) -> Option<String> {
        self.event.take()
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        self.refresh_warning(&ctx);
        if self.is_busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let layout = Breakpoint::of(ui.available_width());

        if self.report.is_some() {
            egui::Panel::bottom(Id::new((self.id, "footer")))
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    left: 0,
                    right: 0,
                    top: 8,
                    bottom: 4,
                }))
                .show(ui, |ui| self.action_bar(ui));
        }

        self.header_ui(ui, &ctx, layout);
        if layout == Breakpoint::Wide {
            self.body_ui(ui, layout);
        } else {
            ScrollArea::vertical()
                .id_salt((self.id, "page"))
                .auto_shrink([false, false])
                .show(ui, |ui| self.body_ui(ui, layout));
        }

        self.confirm_dialog(&ctx);
        self.result_dialog(&ctx);
        self.toast_ui(&ctx);
    }

    /// Warnings, recommendation and results (everything below the header).
    fn body_ui(&mut self, ui: &mut Ui, layout: Breakpoint) {
        if let Some(e) = &self.error {
            widgets::error(ui, e);
        }
        if let Some(w) = &self.active_warning {
            widgets::banner(ui, w, Tone::Review);
        }
        if let Some(r) = &self.report {
            let running = r
                .candidates
                .iter()
                .filter(|c| c.reason.as_deref().is_some_and(|x| x.contains("running")))
                .count();
            if running > 0 {
                widgets::banner(
                    ui,
                    &format!(
                        "{running} {} to apps that are running, so {} marked Review. Quit those apps and rescan to clean them safely.",
                        if running == 1 {
                            "file belongs"
                        } else {
                            "files belong"
                        },
                        if running == 1 { "it is" } else { "they are" }
                    ),
                    Tone::Review,
                );
            }
        }

        self.recommendation_banner(ui);

        if self.report.is_some() {
            ui.add_space(4.0);
            match layout {
                Breakpoint::Wide => {
                    let h = ui.available_height();
                    ui.horizontal_top(|ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(210.0, h),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| self.categories_list(ui),
                        );
                        let gap = ui.spacing().item_spacing.x;
                        let center = (ui.available_width() - DETAIL_W - gap).max(320.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(center, h),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                self.filter_row(ui);
                                self.table(ui, false);
                            },
                        );
                        ui.allocate_ui_with_layout(
                            egui::vec2(DETAIL_W, h),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| self.detail_card(ui, h),
                        );
                    });
                }
                Breakpoint::Medium | Breakpoint::Narrow => {
                    // Stacked: the page scrolls (see `ui`), and the file list
                    // gets a fixed share of the window instead of whatever is
                    // left below the banners and details.
                    self.category_chips(ui);
                    self.filter_row(ui);
                    if self.detail.is_some() {
                        self.detail_card(ui, DETAIL_STACKED_H);
                        ui.add_space(6.0);
                    }
                    let h = (ui.ctx().content_rect().height() * 0.7).max(320.0);
                    let w = ui.available_width();
                    ui.allocate_ui_with_layout(
                        egui::vec2(w, h),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_height(h);
                            ui.set_max_height(h);
                            self.table(ui, layout == Breakpoint::Narrow);
                        },
                    );
                }
            }
        }
    }

    fn header_ui(&mut self, ui: &mut Ui, ctx: &egui::Context, layout: Breakpoint) {
        let p = palette(ui);
        let subtitle = match &self.report {
            Some(r) => format!(
                "{} files · {} found · {} can be cleaned",
                r.candidates.len(),
                format_bytes(r.total_disk_usage()),
                format_bytes(r.reclaimable())
            ),
            None => "Scanning only looks; nothing is removed until you confirm.".into(),
        };
        let title = self.module.title().to_string();
        widgets::header_with_action(ui, Some("Cleanup"), &title, Some(&subtitle), |ui| {
            if let Some(job) = &self.scan_job {
                if ui.button("Cancel").clicked() {
                    job.progress.cancel();
                }
                ui.spinner();
            } else if let Some((job, _)) = &self.clean_job {
                if ui.button("Cancel").clicked() {
                    job.progress.cancel();
                }
                ui.spinner();
            } else {
                let label = if self.report.is_some() {
                    format!("{}  Rescan", egui_phosphor::regular::ARROW_CLOCKWISE)
                } else {
                    format!("{}  Scan now", egui_phosphor::regular::MAGNIFYING_GLASS)
                };
                if ui
                    .add_enabled(
                        self.module.is_available(),
                        theme::primary_button(ui, &label),
                    )
                    .clicked()
                {
                    self.start_scan(ctx);
                }
            }
        });
        if let Some(job) = &self.scan_job {
            ui.label(
                RichText::new(format!(
                    "Scanning… {} files, {}",
                    job.progress.items(),
                    format_bytes(job.progress.bytes())
                ))
                .color(p.muted),
            );
        } else if let Some((job, total)) = &self.clean_job {
            let done = job.progress.items() as f32 / (*total).max(1) as f32;
            ui.add(
                egui::ProgressBar::new(done)
                    .text(format!("Cleaning… {} of {total}", job.progress.items()))
                    .fill(p.accent),
            );
        }
        let open = self.report.is_none() && layout != Breakpoint::Narrow;
        egui::CollapsingHeader::new(RichText::new("What this scans").color(p.text2))
            .id_salt((self.id, "about"))
            .default_open(open)
            .show(ui, |ui| {
                egui::Grid::new((self.id, "details"))
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        for (k, v) in self.module.details() {
                            ui.label(RichText::new(k).color(p.muted));
                            ui.add(egui::Label::new(v).wrap());
                            ui.end_row();
                        }
                    });
                for note in self.module.notes() {
                    ui.add(egui::Label::new(RichText::new(note).small().color(p.muted)).wrap());
                }
                if let Some(r) = &self.report
                    && !r.issues.is_empty()
                {
                    ui.label(
                        RichText::new(format!("{} locations could not be read", r.issues.len()))
                            .small()
                            .color(p.muted),
                    );
                }
            });
    }

    fn toggle_category(&mut self, cat: &str, on: bool) {
        if let Some(report) = &self.report {
            for (c, s) in report.candidates.iter().zip(self.selected.iter_mut()) {
                if c.category == cat && c.class.is_selectable() {
                    *s = on;
                }
            }
        }
    }

    fn set_category_filter(&mut self, f: Option<String>) {
        self.category_filter = f;
        self.recompute_visible();
    }

    /// Wide layout: vertical category list with selection checkboxes.
    fn categories_list(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else { return };
        let summaries = report.by_category();
        let p = palette(ui);
        let mut sel: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (c, s) in report.candidates.iter().zip(&self.selected) {
            if c.class.is_selectable() {
                let e = sel.entry(c.category.clone()).or_default();
                e.0 += 1;
                e.1 += usize::from(*s);
            }
        }
        let total = report.total_disk_usage();
        let mut toggle = None;
        let mut filter = None;
        theme::card(ui)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("CATEGORIES").small().strong().color(p.muted));
                let all_active = self.category_filter.is_none();
                if widgets::list_row(ui, all_active, None, "All", &format_bytes(total)).clicked() {
                    filter = Some(None);
                }
                for s in &summaries {
                    let (selectable, selected) = sel.get(&s.category).copied().unwrap_or((0, 0));
                    let state = if selectable == 0 {
                        None
                    } else if selected == selectable {
                        Some(Some(true))
                    } else if selected == 0 {
                        Some(Some(false))
                    } else {
                        Some(None)
                    };
                    let active = self.category_filter.as_deref() == Some(s.category.as_str());
                    let resp = widgets::list_row(
                        ui,
                        active,
                        Some(state),
                        &s.category,
                        &format_bytes(s.disk_usage),
                    );
                    if resp.secondary_clicked() || resp.double_clicked() {
                        toggle = Some((s.category.clone(), selected != selectable));
                    } else if resp.clicked() {
                        // Clicking the checkbox area toggles; the label filters.
                        let pos = resp.interact_pointer_pos().map(|p| p.x - resp.rect.left());
                        if pos.is_some_and(|x| x < 30.0) && selectable > 0 {
                            toggle = Some((s.category.clone(), selected != selectable));
                        } else {
                            filter = Some(if active {
                                None
                            } else {
                                Some(s.category.clone())
                            });
                        }
                    }
                }
            });
        if let Some((cat, on)) = toggle {
            self.toggle_category(&cat, on);
        }
        if let Some(f) = filter {
            self.set_category_filter(f);
        }
    }

    /// Medium/narrow layout: wrapping category chips.
    fn category_chips(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else { return };
        let summaries = report.by_category();
        let mut filter = None;
        ui.horizontal_wrapped(|ui| {
            if widgets::chip(ui, self.category_filter.is_none(), "All categories").clicked() {
                filter = Some(None);
            }
            for s in &summaries {
                let active = self.category_filter.as_deref() == Some(s.category.as_str());
                let label = format!("{} · {}", s.category, format_bytes(s.disk_usage));
                if widgets::chip(ui, active, &label).clicked() {
                    filter = Some(if active {
                        None
                    } else {
                        Some(s.category.clone())
                    });
                }
            }
        });
        if let Some(f) = filter {
            self.set_category_filter(f);
        }
    }

    /// Safety filter chips and the search box.
    fn filter_row(&mut self, ui: &mut Ui) {
        let Some(report) = &self.report else { return };
        let recommended = &self.recommended;
        let count = |f: ClassFilter| {
            report
                .candidates
                .iter()
                .zip(recommended)
                .filter(|(c, r)| f.matches(c.class, **r))
                .count()
        };
        let counts = [
            (ClassFilter::All, count(ClassFilter::All)),
            (ClassFilter::Recommended, count(ClassFilter::Recommended)),
            (ClassFilter::Safe, count(ClassFilter::Safe)),
            (ClassFilter::Review, count(ClassFilter::Review)),
            (ClassFilter::Locked, count(ClassFilter::Locked)),
        ];
        let selectable_shown = self
            .visible
            .iter()
            .filter(|&&i| report.candidates[i].class.is_selectable())
            .count();
        let selected_shown = self.visible.iter().filter(|&&i| self.selected[i]).count();
        let mut changed = false;
        let mut select_shown = None;
        ui.horizontal_wrapped(|ui| {
            for (f, n) in counts {
                if n == 0 && f != ClassFilter::All {
                    continue;
                }
                if widgets::chip(
                    ui,
                    self.class_filter == f,
                    &format!("{}  {} {n}", f.icon(), f.label()),
                )
                    .clicked()
                {
                    self.class_filter = f;
                    changed = true;
                }
            }
            let search = egui::TextEdit::singleline(&mut self.search)
                .hint_text("Filter by name or path")
                .desired_width(200.0_f32.min(ui.available_width().max(120.0)));
            if ui.add(search).changed() {
                changed = true;
            }
            // Works in every layout: filter by category, safety or name,
            // then select exactly what is listed.
            if ui
                .add_enabled(
                    selected_shown < selectable_shown,
                    Button::new(format!(
                        "{}  Select shown ({selectable_shown})",
                        egui_phosphor::regular::CHECK_SQUARE
                    ))
                    .small(),
                )
                .on_hover_text(
                    "Select every removable file in this list. Review files still need confirmation.",
                )
                .clicked()
            {
                select_shown = Some(true);
            }
            if selected_shown > 0
                && ui
                    .add(Button::new(format!("{}  Unselect shown", egui_phosphor::regular::SQUARE)).small())
                    .clicked()
            {
                select_shown = Some(false);
            }
        });
        if changed {
            self.recompute_visible();
        }
        if let Some(on) = select_shown {
            self.set_visible_selected(on);
        }
        ui.add_space(4.0);
    }

    /// File list: a table on wide/medium screens, stacked cards on narrow.
    fn table(&mut self, ui: &mut Ui, compact: bool) {
        let Some(report) = &self.report else { return };
        let p = palette(ui);
        if self.visible.is_empty() {
            theme::card(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("No files match these filters.").color(p.muted));
            });
            return;
        }
        let selected = &mut self.selected;
        let recommended = &self.recommended;
        let is_rec = |i: usize| recommended.get(i).copied().unwrap_or(false);
        let visible = &self.visible;
        let detail = self.detail;
        let home = self.home.as_path();
        let mut clicked = None;
        let body_h = ui.text_style_height(&egui::TextStyle::Body);
        let small_h = ui.text_style_height(&egui::TextStyle::Small);
        theme::card(ui)
            .inner_margin(egui::Margin::same(0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if compact {
                    let row_h = body_h + small_h + 30.0;
                    ScrollArea::vertical()
                        .id_salt((self.id, "list"))
                        .auto_shrink([false, false])
                        .show_rows(ui, row_h, visible.len(), |ui, range| {
                            for &idx in &visible[range] {
                                let c = &report.candidates[idx];
                                let resp = widgets::file_card(
                                    ui,
                                    &mut selected[idx],
                                    c,
                                    detail == Some(idx),
                                    is_rec(idx),
                                    row_h,
                                    home,
                                );
                                if resp.clicked() {
                                    clicked = Some(idx);
                                }
                            }
                        });
                } else {
                    let row_h = body_h + small_h + 14.0;
                    ui.push_id((self.id, "table"), |ui| {
                        TableBuilder::new(ui)
                            .striped(false)
                            .resizable(false)
                            .sense(egui::Sense::click())
                            .auto_shrink([false, false])
                            .min_scrolled_height(0.0)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::exact(34.0))
                            .column(Column::remainder().at_least(160.0).clip(true))
                            .column(Column::exact(84.0))
                            .column(Column::exact(124.0).clip(true))
                            .header(30.0, |mut h| {
                                for t in ["", "Name and location", "Size", "Safety"] {
                                    h.col(|ui| {
                                        ui.label(RichText::new(t).small().strong().color(p.muted));
                                    });
                                }
                            })
                            .body(|body| {
                                body.rows(row_h, visible.len(), |mut row| {
                                    let idx = visible[row.index()];
                                    let c = &report.candidates[idx];
                                    row.set_selected(detail == Some(idx));
                                    row.col(|ui| {
                                        ui.add_space(8.0);
                                        if c.class.is_selectable() {
                                            ui.checkbox(&mut selected[idx], "");
                                        } else {
                                            ui.add_enabled(false, Checkbox::new(&mut false, ""));
                                        }
                                    });
                                    row.col(|ui| {
                                        ui.vertical(|ui| {
                                            widgets::file_name_label(
                                                ui,
                                                &c.file_name(),
                                                is_rec(idx),
                                            );
                                            ui.label(
                                                RichText::new(widgets::short_path(&c.path, home))
                                                    .small()
                                                    .monospace()
                                                    .color(p.muted),
                                            );
                                        });
                                    });
                                    row.col(|ui| {
                                        ui.label(format_bytes(c.disk_usage));
                                    });
                                    row.col(|ui| {
                                        widgets::class_pill(ui, c.class);
                                    });
                                    if row.response().clicked() {
                                        clicked = Some(idx);
                                    }
                                });
                            });
                    });
                }
            });
        if let Some(i) = clicked {
            self.detail = if self.detail == Some(i) {
                None
            } else {
                Some(i)
            };
        }
    }

    /// Details of the clicked file, including *why* it has its class.
    ///
    /// `max_h` bounds the card: the header (name, safety, recommendation and
    /// actions) is always visible and the rest scrolls, so the card can never
    /// push the file list off screen or cover the action bar.
    fn detail_card(&mut self, ui: &mut Ui, max_h: f32) {
        use egui_phosphor::regular as icon;
        let p = palette(ui);
        let Some(report) = &self.report else { return };
        let c = self.detail.and_then(|i| report.candidates.get(i));
        if let Some(c) = c
            && self.live.as_ref().is_none_or(|l| l.path != c.path)
        {
            self.live = Some(LiveInfo::read(c));
        }
        let live = self
            .live
            .as_ref()
            .filter(|l| c.is_some_and(|c| c.path == l.path));
        let method = self.method;
        let id = self.id;
        let home = self.home.as_path();
        let mut close = false;
        let mut refresh = false;
        theme::card(ui)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let Some(c) = c else {
                    ui.label(
                        RichText::new(format!("{}  Details", icon::INFO))
                            .strong()
                            .size(15.0),
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Click a file to see what it is, where it lives and whether it is safe to delete.",
                            )
                            .color(p.muted),
                        )
                        .wrap(),
                    );
                    return;
                };
                let top = ui.cursor().top();

                // Header: name + close, then safety and actions.
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(icon::FILE)
                            .size(16.0)
                            .color(p.text2),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button(icon::X)
                            .on_hover_text("Close details")
                            .clicked()
                        {
                            close = true;
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(c.file_name()).strong().size(15.0))
                                    .truncate(),
                            )
                            .on_hover_text(c.path.display().to_string());
                        });
                    });
                });
                let rec = rustclean_core::recommend(c, SystemTime::now());
                ui.horizontal_wrapped(|ui| {
                    widgets::class_pill(ui, c.class);
                    if rec.is_recommended() {
                        widgets::pill(
                            ui,
                            format!("{}  Recommended", icon::SPARKLE),
                            Tone::Safe,
                        )
                        .on_hover_text(rec.reason());
                    }
                    ui.label(RichText::new(format_bytes(c.disk_usage)).strong());
                });
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .small_button(format!("{}  {}", icon::FOLDER_OPEN, widgets::reveal_label()))
                        .clicked()
                    {
                        widgets::reveal_in_file_manager(&c.path);
                    }
                    if ui
                        .small_button(format!("{}  Copy path", icon::COPY))
                        .clicked()
                    {
                        ui.ctx().copy_text(c.path.display().to_string());
                    }
                    if ui
                        .small_button(icon::ARROW_CLOCKWISE)
                        .on_hover_text("Check the file again")
                        .clicked()
                    {
                        refresh = true;
                    }
                });
                ui.separator();

                let used = ui.cursor().top() - top;
                ScrollArea::vertical()
                    .id_salt((id, "detail_scroll"))
                    .max_height((max_h - used - 40.0).max(80.0))
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        let why = c.reason.clone().unwrap_or_else(|| match c.class {
                            SafetyClass::Safe => {
                                "Rebuilt automatically when it is needed again.".into()
                            }
                            SafetyClass::Review => {
                                "Check that you no longer need this before removing it.".into()
                            }
                            _ => "RustClean never removes this.".into(),
                        });
                        widgets::callout(
                            ui,
                            &format!("{}  Why {}: {why}", widgets::class_icon(c.class), c.class.label()),
                            widgets::class_tone(c.class),
                        );
                        match live.map(|l| &l.state) {
                            Some(LiveState::Changed) => widgets::warning(
                                ui,
                                "Changed since the scan. It will be skipped; rescan to include the new version.",
                            ),
                            Some(LiveState::Missing) => widgets::warning(
                                ui,
                                "No longer exists (the app may have removed it).",
                            ),
                            Some(LiveState::Unreadable(e)) => {
                                widgets::warning(ui, format!("Cannot be read right now: {e}"))
                            }
                            _ => {}
                        }
                        ui.add_space(4.0);
                        egui::Grid::new((id, "detail"))
                            .num_columns(2)
                            .spacing([10.0, 5.0])
                            .show(ui, |ui| {
                                let row = |ui: &mut Ui, k: &str, v: String| {
                                    ui.label(RichText::new(k).color(p.muted));
                                    ui.add(egui::Label::new(v).wrap());
                                    ui.end_row();
                                };
                                row(
                                    ui,
                                    "Advice",
                                    if rec.is_recommended() {
                                        format!("Delete: {}", rec.reason())
                                    } else {
                                        format!("Keep for now: {}", rec.reason())
                                    },
                                );
                                row(ui, "App / group", c.category.clone());
                                if let Some(ctx) = &c.context {
                                    row(ui, "Source", ctx.clone());
                                }
                                row(ui, "Kind", widgets::file_kind(&c.path).into());
                                if c.size != c.disk_usage {
                                    row(
                                        ui,
                                        "Size",
                                        format!(
                                            "{} on disk ({} of data)",
                                            format_bytes(c.disk_usage),
                                            format_bytes(c.size)
                                        ),
                                    );
                                }
                                if let Some(m) = c.fingerprint.modified {
                                    row(ui, "Modified", widgets::date_and_age(m));
                                }
                                if let Some(t) = live.and_then(|l| l.created) {
                                    row(ui, "Created", widgets::date_and_age(t));
                                }
                                if let Some(t) = live.and_then(|l| l.accessed) {
                                    row(ui, "Last opened", widgets::date_and_age(t));
                                }
                                row(ui, "Found in", widgets::tilde_path(&c.target_root, home));
                                row(
                                    ui,
                                    "Removal",
                                    match method {
                                        RemovalMethod::Trash => {
                                            "Moved to the Trash (restorable)".into()
                                        }
                                        RemovalMethod::Quarantine => {
                                            "Moved to RustClean quarantine (restorable)".into()
                                        }
                                    },
                                );
                            });
                        ui.add_space(4.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(widgets::tilde_path(&c.path, home))
                                    .small()
                                    .monospace()
                                    .color(p.text2),
                            )
                            .wrap(),
                        );
                        let impact = match c.class {
                            SafetyClass::Safe => {
                                "If removed: the app recreates it when needed; the first launch or load may be a little slower."
                            }
                            SafetyClass::Review => {
                                "If removed: it may not come back, or the app may lose offline data or history it kept here."
                            }
                            _ => "Not removable: RustClean will skip it even if selected.",
                        };
                        ui.add(
                            egui::Label::new(RichText::new(impact).small().color(p.muted)).wrap(),
                        );
                    });
            });
        if close {
            self.detail = None;
        }
        if close || refresh {
            self.live = None;
        }
    }

    /// The dark floating action bar.
    fn action_bar(&mut self, ui: &mut Ui) {
        let (n, bytes) = self.selection_totals();
        let hidden = self.hidden_selected();
        let busy = self.is_busy();
        let id = self.id;
        let mut open = false;
        let method = &mut self.method;
        let summary = if hidden > 0 {
            format!(
                "{n} selected · {} ({hidden} not shown by the current filter)",
                format_bytes(bytes)
            )
        } else {
            format!("{n} selected · {}", format_bytes(bytes))
        };
        let (select_safe, clear) = widgets::action_bar(ui, &summary, |ui| {
            let p = palette(ui);
            let label = format!("{}  Clean {n} selected…", egui_phosphor::regular::BROOM);
            open = ui
                .add_enabled(n > 0 && !busy, theme::primary_button(ui, &label))
                .clicked();
            egui::ComboBox::from_id_salt((id, "removal_method"))
                .selected_text(RichText::new(method.label()).color(p.text))
                .show_ui(ui, |ui| {
                    for m in [RemovalMethod::Trash, RemovalMethod::Quarantine] {
                        ui.selectable_value(method, m, m.label());
                    }
                })
                .response
                .on_hover_text(
                    "Both are reversible: restore from the Trash, or from Quarantine in RustClean.",
                );
        });
        if select_safe && let Some(r) = &self.report {
            for (c, s) in r.candidates.iter().zip(self.selected.iter_mut()) {
                if c.class == SafetyClass::Safe {
                    *s = true;
                }
            }
        }
        if clear {
            self.selected.iter_mut().for_each(|s| *s = false);
        }
        if open {
            self.open_confirm();
        }
    }

    fn toast_ui(&mut self, ctx: &egui::Context) {
        let Some((text, at)) = &self.toast else {
            return;
        };
        if at.elapsed() > TOAST_FOR {
            self.toast = None;
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(250));
        widgets::toast(ctx, Id::new((self.id, "toast")), text);
    }

    /// Opens the confirmation dialog for the current selection.
    pub fn open_confirm(&mut self) {
        let Some(r) = &self.report else { return };
        let selected = r
            .candidates
            .iter()
            .zip(&self.selected)
            .filter(|(_, s)| **s)
            .map(|(c, _)| c);
        let plan = CleanupPlan::from_selection(selected, self.method, false);
        if plan.items().is_empty() {
            return;
        }
        self.active_warning = self.module.active_warning();
        self.last_warning_check = Some(Instant::now());
        self.result = None;
        self.confirm = Some(ConfirmState {
            plan,
            review_ack: false,
            warning_ack: false,
        });
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let warning = self.active_warning.clone();
        let id = self.id;
        let home = self.home.as_path();
        let mut exclude: Vec<PathBuf> = Vec::new();
        let Some(state) = &mut self.confirm else {
            return;
        };
        let plan = &state.plan;
        let review = plan.review_count();
        let needs_warning_ack = warning.is_some();
        let width = (ctx.content_rect().width() - 48.0).clamp(320.0, 720.0);

        let modal = Modal::new(Id::new((id, "confirm"))).show(ctx, |ui| {
            ui.set_width(width);
            let p = crate::theme::palette(ui);
            let verb = match plan.method {
                RemovalMethod::Trash => "move to the Trash",
                RemovalMethod::Quarantine => "move to RustClean quarantine",
            };
            ui.label(
                RichText::new(format!(
                    "Clean {} files ({})?",
                    plan.items().len(),
                    format_bytes(plan.total_disk_usage())
                ))
                .size(20.0)
                .strong(),
            );
            ui.label(
                RichText::new(format!(
                    "RustClean will check each file again, then {verb}. You can undo this: {}",
                    match plan.method {
                        RemovalMethod::Trash => "put files back from the Trash. Space is freed when you empty the Trash.",
                        RemovalMethod::Quarantine => "restore from Quarantine in RustClean.",
                    }
                ))
                .color(p.muted),
            );
            if !plan.rejected().is_empty() {
                widgets::warning(
                    ui,
                    format!(
                        "{} selected files are protected or unknown and will be skipped.",
                        plan.rejected().len()
                    ),
                );
            }
            ui.add_space(6.0);

            let mut by_cat: BTreeMap<&str, (usize, u64)> = BTreeMap::new();
            for i in plan.items() {
                let e = by_cat.entry(i.category.as_str()).or_default();
                e.0 += 1;
                e.1 += i.disk_usage;
            }
            for (cat, (n, b)) in by_cat {
                ui.label(format!(
                    "•  {cat}: {n} {}, {}",
                    if n == 1 { "file" } else { "files" },
                    format_bytes(b)
                ));
            }
            ui.add_space(4.0);
            egui::CollapsingHeader::new(format!(
                "Review every file ({}) — untick any you want to keep",
                plan.items().len()
            ))
            .id_salt((id, "paths"))
            .default_open(plan.items().len() <= 50)
            .show(ui, |ui| {
                let row_h = ui.text_style_height(&egui::TextStyle::Body)
                    + ui.text_style_height(&egui::TextStyle::Small)
                    + 8.0;
                ScrollArea::vertical()
                    .max_height(260.0)
                    .auto_shrink([false, true])
                    .show_rows(ui, row_h, plan.items().len(), |ui, range| {
                        for item in &plan.items()[range] {
                            ui.horizontal(|ui| {
                                ui.set_height(row_h - 4.0);
                                let mut keep_in_plan = true;
                                if ui
                                    .checkbox(&mut keep_in_plan, "")
                                    .on_hover_text("Untick to keep this file")
                                    .changed()
                                {
                                    exclude.push(item.path.clone());
                                }
                                ui.vertical(|ui| {
                                    let name = item
                                        .path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().into_owned())
                                        .unwrap_or_default();
                                    // Line 1: name (truncates) · size · safety.
                                    // Right-aligned parts are laid out first so
                                    // they never overlap the name.
                                    ui.horizontal(|ui| {
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                widgets::class_pill(ui, item.class);
                                                ui.label(
                                                    RichText::new(format_bytes(item.disk_usage))
                                                        .strong(),
                                                );
                                                ui.with_layout(
                                                    egui::Layout::left_to_right(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        ui.add(
                                                            egui::Label::new(name).truncate(),
                                                        );
                                                    },
                                                );
                                            },
                                        );
                                    });
                                    // Line 2: app · folder.
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(format!(
                                                "{} · {}",
                                                item.category,
                                                widgets::short_path(&item.path, home)
                                            ))
                                            .small()
                                            .color(p.muted),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(item.path.display().to_string());
                                });
                            });
                        }
                    });
            });
            ui.add_space(6.0);
            if review > 0 {
                ui.checkbox(
                    &mut state.review_ack,
                    format!("I checked the {review} files marked Review and want them removed too"),
                );
            }
            if needs_warning_ack && let Some(w) = &warning {
                widgets::warning(ui, w);
                ui.checkbox(&mut state.warning_ack, "Clean anyway");
            }
            ui.add_space(8.0);
            let can_clean =
                (review == 0 || state.review_ack) && (!needs_warning_ack || state.warning_ack);
            let mut action = None;
            ui.horizontal_wrapped(|ui| {
                if ui.button("Cancel").clicked() {
                    action = Some(ConfirmAction::Cancel);
                }
                if ui
                    .add_enabled(review == 0 || state.review_ack, Button::new("Simulate first"))
                    .on_hover_text("Checks every file without moving anything")
                    .clicked()
                {
                    action = Some(ConfirmAction::Simulate);
                }
                let label = match state.plan.method {
                    RemovalMethod::Trash => format!("Move {} files to Trash", state.plan.items().len()),
                    RemovalMethod::Quarantine => {
                        format!("Quarantine {} files", state.plan.items().len())
                    }
                };
                if ui
                    .add_enabled(can_clean, crate::theme::primary_button(ui, &label))
                    .clicked()
                {
                    action = Some(ConfirmAction::Clean);
                }
            });
            action
        });

        if !exclude.is_empty() {
            // The plan changed under the buttons: show the smaller plan
            // first rather than acting on a click from the same frame.
            self.exclude_from_confirm(&exclude);
            return;
        }
        match modal.inner {
            Some(ConfirmAction::Clean) => self.execute_confirmed(ctx, false),
            Some(ConfirmAction::Simulate) => self.execute_confirmed(ctx, true),
            Some(ConfirmAction::Cancel) => self.confirm = None,
            None if modal.should_close() => self.confirm = None,
            None => {}
        }
    }

    fn execute_confirmed(&mut self, ctx: &egui::Context, simulate: bool) {
        let Some(mut state) = self.confirm.take() else {
            return;
        };
        state.plan.dry_run = simulate;
        // Re-check right before acting: the condition may have appeared
        // since the dialog opened.
        if !state.plan.dry_run && !state.warning_ack {
            let now = self.module.active_warning();
            self.last_warning_check = Some(Instant::now());
            if now.is_some() {
                self.active_warning = now;
                self.confirm = Some(state);
                return;
            }
        }
        let approved = match state.plan.approve(state.review_ack) {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        let total = approved.items().len();
        let rules = self.rules.clone();
        let home = self.home.clone();
        let job = Job::spawn(
            &format!("{}-clean", self.id),
            ctx.clone(),
            move |progress| {
                let method = approved.method;
                let (remover, quarantine_dir): (Box<dyn Remover>, Option<PathBuf>) = if approved
                    .dry_run
                {
                    (Box::new(DryRunRemover(method)), None)
                } else {
                    match method {
                        RemovalMethod::Trash => (Box::new(TrashRemover::new()), None),
                        RemovalMethod::Quarantine => {
                            let q = QuarantineRemover::new_session(&app_data_dir(&home)).map_err(
                                |e| format!("could not create quarantine directory: {e}"),
                            )?;
                            let dir = q.session_dir().to_path_buf();
                            (Box::new(q), Some(dir))
                        }
                    }
                };
                let log = open_operation_log(&home);
                let log_path = log.as_ref().map(|l| l.path().to_path_buf());
                let report = Cleaner::new(rules, remover, log).execute(&approved, progress);
                Ok(CleanOutcome {
                    report,
                    quarantine_dir,
                    log_path,
                })
            },
        );
        match job {
            Ok(job) => self.clean_job = Some((job, total)),
            Err(e) => self.error = Some(format!("could not start cleanup: {e}")),
        }
    }

    fn result_dialog(&mut self, ctx: &egui::Context) {
        let Some(outcome) = &self.result else { return };
        let r = &outcome.report;
        let width = (ctx.content_rect().width() - 48.0).clamp(320.0, 720.0);
        let modal = Modal::new(Id::new((self.id, "result"))).show(ctx, |ui| {
            ui.set_width(width);
            if r.dry_run {
                ui.label(RichText::new("Simulation complete").size(20.0).strong());
                ui.label(format!(
                    "All checks done: {} files ({}) can be cleaned. Nothing was moved yet.",
                    r.would_remove(),
                    format_bytes(r.bytes_affected())
                ));
            } else {
                ui.label(RichText::new("Cleanup complete").size(20.0).strong());
                ui.label(
                    RichText::new(format!(
                        "{} files ({}) — {}.",
                        r.removed(),
                        format_bytes(r.bytes_affected()),
                        match r.method {
                            RemovalMethod::Trash => "moved to Trash",
                            RemovalMethod::Quarantine => "moved to quarantine",
                        }
                    ))
                    .strong(),
                );
                if r.method == RemovalMethod::Trash {
                    ui.label(RichText::new("Empty the Trash to reclaim the space. Files can be recovered from the Trash until then.").weak());
                }
            }
            if let Some(dir) = &outcome.quarantine_dir {
                ui.label(format!("Quarantine: {}", dir.display()));
            }
            if r.skipped() + r.failed() + r.not_attempted() > 0 {
                ui.add_space(4.0);
                widgets::warning(
                    ui,
                    format!(
                        "{} skipped (failed re-validation), {} failed, {} not attempted (cancelled).",
                        r.skipped(),
                        r.failed(),
                        r.not_attempted()
                    ),
                );
                let problems: Vec<String> = r
                    .results
                    .iter()
                    .filter_map(|i| match &i.outcome {
                        ItemOutcome::Skipped(e) => {
                            Some(format!("skipped  {}: {e}", i.path.display()))
                        }
                        ItemOutcome::Failed(e) => {
                            Some(format!("failed   {}: {e}", i.path.display()))
                        }
                        _ => None,
                    })
                    .collect();
                let row_h = ui.text_style_height(&egui::TextStyle::Small) + 4.0;
                ScrollArea::both()
                    .max_height(200.0)
                    .auto_shrink([false, true])
                    .show_rows(ui, row_h, problems.len(), |ui, range| {
                        for p in &problems[range] {
                            ui.label(RichText::new(p).small().monospace());
                        }
                    });
            }
            if let Some(log) = &outcome.log_path {
                ui.label(
                    RichText::new(format!("Operation log: {}", log.display()))
                        .small()
                        .weak(),
                );
            }
            ui.add_space(8.0);
            let mut action = None;
            ui.horizontal(|ui| {
                if ui.button("Done").clicked() {
                    action = Some(false);
                }
                if r.dry_run
                    && r.would_remove() > 0
                    && ui
                        .add(crate::theme::primary_button(ui, "Clean now…"))
                        .clicked()
                {
                    action = Some(true);
                }
            });
            action
        });
        match modal.inner {
            Some(true) => self.open_confirm(),
            Some(false) => self.result = None,
            None if modal.should_close() => self.result = None,
            None => {}
        }
    }
}

pub fn open_operation_log(home: &Path) -> Option<OperationLog> {
    match OperationLog::open(app_log_dir(home).join("operations.jsonl")) {
        Ok(l) => Some(l),
        Err(e) => {
            tracing::warn!(error = %e, "operation log unavailable");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustclean_core::{Candidate, ScanSpec};
    use rustclean_safety::FileFingerprint;

    struct Stub;
    impl CleanupModule for Stub {
        fn title(&self) -> &str {
            "Stub"
        }
        fn refresh(&mut self) {}
        fn is_available(&self) -> bool {
            true
        }
        fn details(&self) -> Vec<(String, String)> {
            Vec::new()
        }
        fn notes(&self) -> Vec<String> {
            Vec::new()
        }
        fn prepare_scan(&self) -> ScanSpec {
            ScanSpec::new(Vec::new(), None)
        }
        fn active_warning(&self) -> Option<String> {
            None
        }
    }

    fn cand(name: &str, category: &str, class: SafetyClass) -> Candidate {
        Candidate {
            path: PathBuf::from(format!("/h/c/{name}")),
            size: 1,
            disk_usage: 1,
            category: category.into(),
            context: None,
            class,
            reason: None,
            fingerprint: FileFingerprint {
                size: 1,
                modified: None,
                inode: 0,
                device: 0,
            },
            target_root: PathBuf::from("/h/c"),
        }
    }

    /// a(Safe,A) b(Review,A) c(Protected,A) d(Safe,B)
    fn page() -> ScanPage {
        let mut p = ScanPage::new(
            "test",
            Box::new(Stub),
            PathBuf::from("/h"),
            ProtectionRules::for_home("/h"),
        );
        p.report = Some(ScanReport {
            candidates: vec![
                cand("a", "A", SafetyClass::Safe),
                cand("b", "A", SafetyClass::Review),
                cand("c", "A", SafetyClass::Protected),
                cand("d", "B", SafetyClass::Safe),
            ],
            ..Default::default()
        });
        p.selected = vec![false; 4];
        p.recommended = vec![false; 4];
        p.recompute_visible();
        p
    }

    fn removed_report(paths: &[&str]) -> CleanupReport {
        CleanupReport {
            session: "t".into(),
            dry_run: false,
            method: RemovalMethod::Trash,
            results: paths
                .iter()
                .map(|n| rustclean_core::ItemResult {
                    path: PathBuf::from(format!("/h/c/{n}")),
                    size: 1,
                    disk_usage: 1,
                    outcome: ItemOutcome::Removed { new_location: None },
                })
                .collect(),
            cancelled: false,
        }
    }

    #[test]
    fn select_shown_respects_filters_and_never_selects_locked_files() {
        let mut p = page();
        p.set_category_filter(Some("A".into()));
        p.set_visible_selected(true);
        assert_eq!(p.selected, vec![true, true, false, false]);
        // The selection survives a filter change and is reported as hidden.
        p.set_category_filter(Some("B".into()));
        assert_eq!(p.hidden_selected(), 2);
        p.set_visible_selected(false);
        assert_eq!(p.selected, vec![true, true, false, false]);
    }

    #[test]
    fn recommended_files_are_old_safe_files_only() {
        let mut p = page();
        let old = Some(SystemTime::now() - 3 * rustclean_core::DAY);
        let r = p.report.as_mut().unwrap();
        for c in &mut r.candidates {
            c.fingerprint.modified = old;
        }
        // "d" was just written: may be in use.
        r.candidates[3].fingerprint.modified = Some(SystemTime::now());
        let now = SystemTime::now();
        p.recommended = r
            .candidates
            .iter()
            .map(|c| rustclean_core::is_recommended(c, now))
            .collect();
        assert_eq!(p.recommended, vec![true, false, false, false]);
        assert_eq!(p.recommended_totals(), (1, 1));
        p.select_recommended();
        assert_eq!(p.selected, vec![true, false, false, false]);
        p.class_filter = ClassFilter::Recommended;
        p.recompute_visible();
        assert_eq!(p.visible, vec![0]);
        // Alignment survives a cleanup.
        p.forget_removed(&removed_report(&["b"]));
        assert_eq!(p.recommended, vec![true, false, false]);
    }

    #[test]
    fn detail_follows_the_same_file_after_cleanup() {
        let mut p = page();
        p.detail = Some(3); // "d"
        p.forget_removed(&removed_report(&["a"]));
        let r = p.report.as_ref().unwrap();
        assert_eq!(r.candidates.len(), 3);
        assert_eq!(r.candidates[p.detail.unwrap()].file_name(), "d");
        // The open file itself removed: the panel closes.
        p.forget_removed(&removed_report(&["d"]));
        assert_eq!(p.detail, None);
    }

    #[test]
    fn excluding_files_in_the_confirmation_shrinks_the_plan() {
        let mut p = page();
        p.selected = vec![true, true, false, true];
        p.open_confirm();
        assert_eq!(p.confirm.as_ref().unwrap().plan.items().len(), 3);
        p.confirm.as_mut().unwrap().review_ack = true;
        p.exclude_from_confirm(&[PathBuf::from("/h/c/b")]);
        let state = p.confirm.as_ref().unwrap();
        assert_eq!(state.plan.items().len(), 2);
        assert_eq!(state.plan.review_count(), 0);
        assert_eq!(p.selected, vec![true, false, false, true]);
        // Excluding everything closes the dialog.
        p.exclude_from_confirm(&[PathBuf::from("/h/c/a"), PathBuf::from("/h/c/d")]);
        assert!(p.confirm.is_none());
        assert!(p.selected.iter().all(|s| !s));
    }
}
