//! Application shell: sidebar + pages.

use std::path::PathBuf;

use egui::{RichText, Ui};
use rustclean_apps::LeftoversModule;
use rustclean_browser::ChromeModule;
use rustclean_duplicates::DuplicatesModule;
use rustclean_junk::{AppCachesModule, DeveloperModule, JunkModule};
use rustclean_safety::{ProtectionRules, app_data_dir, app_log_dir, home_dir};
use rustclean_storage::LargeFilesModule;

use crate::antivirus_page::AntivirusPage;
use crate::dashboard::{self, DiskInfo};
use crate::docker_page::DockerPage;
use crate::navigation::{self, Page};
use crate::scan_page::ScanPage;
use crate::security_page::SecurityPage;
use crate::tool_pages::{QuarantinePage, StoragePage};
use crate::{smart_scan, theme, widgets};
use rustclean_core::format_bytes;

pub struct RustCleanApp {
    pub(crate) page: Page,
    pub(crate) state: Option<Loaded>,
}

/// How often disk figures are re-read, so freed space (emptying the Trash,
/// Docker removals, quarantine purges, other apps) shows up without a restart.
const DISK_REFRESH: std::time::Duration = std::time::Duration::from_secs(3);

pub struct Loaded {
    home: PathBuf,
    rules: ProtectionRules,
    pub disk: Option<DiskInfo>,
    disk_read_at: std::time::Instant,
    pub junk: ScanPage,
    pub app_caches: ScanPage,
    pub browser: ScanPage,
    pub developer: ScanPage,
    pub docker: DockerPage,
    pub security: SecurityPage,
    pub antivirus: AntivirusPage,
    pub large_files: ScanPage,
    pub duplicates: ScanPage,
    pub leftovers: ScanPage,
    pub storage: StoragePage,
    pub quarantine: QuarantinePage,
    /// Session activity feed (time, text).
    pub activity: Vec<(std::time::SystemTime, String)>,
}

impl Loaded {
    fn new(home: PathBuf) -> Self {
        let rules = ProtectionRules::for_home(&home);
        let page = |id, module: Box<dyn rustclean_core::CleanupModule>| {
            ScanPage::new(id, module, home.clone(), rules.clone())
        };
        Self {
            junk: page("junk", Box::new(JunkModule::new(home.clone()))),
            app_caches: page("appcache", Box::new(AppCachesModule::new(home.clone()))),
            browser: page("chrome", Box::new(ChromeModule::new(home.clone()))),
            developer: page("developer", Box::new(DeveloperModule::new(home.clone()))),
            docker: DockerPage::new(home.clone()),
            security: SecurityPage::new(home.clone()),
            antivirus: AntivirusPage::new(home.clone()),
            large_files: page("large", Box::new(LargeFilesModule::new(home.clone()))),
            duplicates: page("dupes", Box::new(DuplicatesModule::new(home.clone()))),
            leftovers: page("leftovers", Box::new(LeftoversModule::new(home.clone()))),
            storage: StoragePage::new(home.clone()),
            quarantine: QuarantinePage::new(home.clone(), rules.clone()),
            activity: Vec::new(),
            disk: DiskInfo::read(),
            disk_read_at: std::time::Instant::now(),
            home,
            rules,
        }
    }

    pub fn file_pages(&self) -> [&ScanPage; 7] {
        [
            &self.junk,
            &self.app_caches,
            &self.browser,
            &self.developer,
            &self.large_files,
            &self.duplicates,
            &self.leftovers,
        ]
    }

    pub fn any_busy(&self) -> bool {
        self.file_pages().iter().any(|p| p.is_busy())
            || self.docker.is_busy()
            || self.security.is_busy()
            || self.antivirus.is_busy()
            || self.storage.is_busy()
    }

    /// Right-aligned sidebar text per page.
    fn badge(&self, page: Page) -> Option<String> {
        match page {
            Page::JunkCleaner => self.junk.reclaimable().map(format_bytes),
            Page::AppCaches => self.app_caches.reclaimable().map(format_bytes),
            Page::BrowserCleaner => self.browser.reclaimable().map(format_bytes),
            Page::DeveloperCleaner => self.developer.reclaimable().map(format_bytes),
            Page::Docker => self.docker.reclaimable().map(format_bytes),
            Page::LargeFiles => self.large_files.reclaimable().map(format_bytes),
            Page::DuplicateFinder => self.duplicates.reclaimable().map(format_bytes),
            Page::AppCleaner => self.leftovers.reclaimable().map(format_bytes),
            Page::Quarantine => {
                let (files, bytes) = self.quarantine.total();
                (files > 0).then(|| format_bytes(bytes))
            }
            Page::SecurityCenter => self
                .security
                .summary()
                .map(|(_, warn, notice)| (warn + notice).to_string()),
            Page::Antivirus => self.antivirus.badge(),
            _ => None,
        }
    }

    /// Smart Scan: every module's read-only scan plus the security audit.
    pub fn quick_scan(&mut self, ctx: &egui::Context) {
        self.security.start_scan(ctx);
        self.junk.start_scan(ctx);
        self.browser.start_scan(ctx);
        self.developer.start_scan(ctx);
        self.leftovers.start_scan(ctx);
        self.large_files.start_scan(ctx);
        if self.docker.has_engine() {
            self.docker.start_scan(ctx);
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let mut disk_changed = false;
        for p in [
            &mut self.junk,
            &mut self.app_caches,
            &mut self.browser,
            &mut self.developer,
            &mut self.large_files,
            &mut self.duplicates,
            &mut self.leftovers,
        ] {
            p.poll_jobs();
            disk_changed |= std::mem::take(&mut p.disk_changed);
            if let Some(e) = p.take_event() {
                self.activity.push((std::time::SystemTime::now(), e));
            }
        }
        self.storage.poll_jobs();
        self.quarantine.poll_jobs();
        self.docker.poll_jobs(ctx);
        self.security.poll_jobs();
        self.antivirus.tick(ctx);
        self.antivirus.poll_jobs();
        if disk_changed {
            self.quarantine.refresh();
        }
        // Live disk figures: right after a cleanup, and every few seconds
        // otherwise (space is freed outside RustClean too, e.g. by emptying
        // the Trash). Reading capacity is cheap and read-only.
        if disk_changed || self.disk_read_at.elapsed() >= DISK_REFRESH {
            self.disk = DiskInfo::read();
            self.disk_read_at = std::time::Instant::now();
        }
        ctx.request_repaint_after(DISK_REFRESH);
        if self.any_busy() {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}

impl RustCleanApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::with_home(cc, home_dir())
    }

    /// Builds the app for a given home directory (tests use a temporary one).
    pub fn with_home(cc: &eframe::CreationContext<'_>, home: Option<PathBuf>) -> Self {
        theme::apply(&cc.egui_ctx);
        if let Some(h) = &home {
            cc.egui_ctx.set_theme(theme::load_preference(h));
        }
        let state = home.map(Loaded::new);
        if state.is_none() {
            tracing::error!("HOME is not set or not absolute; RustClean cannot run safely");
        }
        Self {
            page: Page::Dashboard,
            state,
        }
    }
}

impl eframe::App for RustCleanApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let appearance_before = ui.ctx().options(|o| o.theme_preference);
        let p = theme::palette(ui);
        let state = &self.state;
        let page = &mut self.page;
        let width = ui.ctx().content_rect().width();
        let compact = width < 860.0;
        if compact {
            egui::Panel::top("topnav")
                .frame(
                    egui::Frame::new()
                        .fill(p.surface)
                        .stroke(egui::Stroke::new(1.0, p.border))
                        .inner_margin(egui::Margin::symmetric(14, 8)),
                )
                .show(ui, |ui| navigation::top_bar(ui, page));
        } else {
            egui::Panel::left("sidebar")
                .resizable(false)
                .exact_size(if width < 1100.0 { 216.0 } else { 232.0 })
                .frame(
                    egui::Frame::new()
                        .fill(p.surface)
                        .stroke(egui::Stroke::new(1.0, p.border))
                        .inner_margin(egui::Margin::symmetric(12, 8)),
                )
                .show(ui, |ui| {
                    navigation::sidebar(
                        ui,
                        page,
                        |pg| state.as_ref().and_then(|s| s.badge(pg)),
                        state
                            .as_ref()
                            .and_then(|s| s.disk)
                            .map(|d| (d.total, d.available)),
                    )
                });
        }

        let pad = if compact { 14 } else { 28 };
        let central = egui::Frame::new()
            .fill(p.bg)
            .inner_margin(egui::Margin::symmetric(pad, 18));
        egui::CentralPanel::default().frame(central).show(ui, |ui| {
            let Some(state) = &mut self.state else {
                crate::widgets::error(
                    ui,
                    "Could not determine your home directory ($HOME). RustClean will not scan or clean anything.",
                );
                return;
            };
            state.poll(ui.ctx());
            match self.page {
                Page::Dashboard => {
                    if let Some(go) = dashboard::ui(ui, state) {
                        self.page = go;
                    }
                }
                Page::SmartScan => {
                    if let Some(go) = smart_scan::ui(ui, state) {
                        self.page = go;
                    }
                }
                Page::SecurityCenter => state.security.ui(ui),
                Page::Antivirus => state.antivirus.ui(ui),
                Page::BackupSync => backup_ui(ui),
                Page::JunkCleaner => state.junk.ui(ui),
                Page::AppCaches => state.app_caches.ui(ui),
                Page::BrowserCleaner => state.browser.ui(ui),
                Page::DeveloperCleaner => state.developer.ui(ui),
                Page::LargeFiles => state.large_files.ui(ui),
                Page::DuplicateFinder => state.duplicates.ui(ui),
                Page::AppCleaner => state.leftovers.ui(ui),
                Page::StorageAnalyzer => state.storage.ui(ui, state.disk),
                Page::Quarantine => state.quarantine.ui(ui),
                Page::Docker => state.docker.ui(ui),
                Page::Protection => protection_ui(ui, state),
                Page::About => about_ui(ui, state),
                other => planned_ui(ui, other),
            }
        });
        let appearance = ui.ctx().options(|o| o.theme_preference);
        if appearance != appearance_before
            && let Some(state) = &self.state
        {
            theme::save_preference(&state.home, appearance);
        }
    }
}

fn protection_ui(ui: &mut Ui, state: &Loaded) {
    widgets::page_header(ui, Some("Settings"), "Protection", None);
    ui.label(
        "RustClean never removes anything in these locations, nor any folder that contains them:",
    );
    ui.add_space(6.0);
    egui::ScrollArea::vertical().show(ui, |ui| {
        for p in state.rules.protected_locations() {
            ui.label(RichText::new(p.display().to_string()).monospace());
        }
        ui.add_space(10.0);
        ui.label("In addition:");
        for rule in [
            "Symbolic links are never followed and never removed.",
            "Only regular files are removed; folders are left in place.",
            "Every file is re-validated immediately before removal and skipped if it changed since the scan.",
            &format!("Files are moved to the {} or RustClean quarantine, never deleted outright.", widgets::trash_name()),
            "Unknown and Protected files cannot be selected.",
            "Operating-system caches are not scanned.",
            "Chrome bookmarks, passwords, history, cookies, extensions and profiles are always protected.",
            "Developer caches are included only where removing any subset of files is harmless.",
            "Docker is cleaned only through the Docker API, never by touching its disk image; running containers, images in use and volumes in use are never offered.",
        ] {
            ui.label(format!("• {rule}"));
        }
    });
}

fn about_ui(ui: &mut Ui, state: &Loaded) {
    widgets::page_header(ui, Some("Settings"), "About RustClean", None);
    ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
    ui.add_space(6.0);
    ui.add(egui::Label::new(format!(
        "A fast, privacy-focused disk cleaner for {} written entirely in Rust. RustClean makes no network connections; Docker is reached only through its local connection.",
        rustclean_safety::platform::CURRENT.name()
    )).wrap());
    ui.add_space(6.0);
    ui.label(format!(
        "Quarantine: {}",
        app_data_dir(&state.home).join("Quarantine").display()
    ));
    ui.label(format!(
        "Operation log: {}",
        app_log_dir(&state.home).join("operations.jsonl").display()
    ));
}

/// Placeholder: the design (storage, sync target) is not decided yet, so the
/// page deliberately promises nothing.
fn backup_ui(ui: &mut Ui) {
    widgets::page_header(ui, Some("Security"), "Backup & Sync", Some("Coming soon"));
}

fn planned_ui(ui: &mut Ui, page: Page) {
    widgets::page_header(ui, None, page.title(), None);
    ui.label("This module is planned for a future release.");
}
