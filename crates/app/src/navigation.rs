//! Sidebar navigation.

use egui::{CornerRadius, RichText, Sense, Ui};

use crate::theme::palette;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    SmartScan,
    JunkCleaner,
    AppCaches,
    AppCleaner,
    BrowserCleaner,
    DeveloperCleaner,
    Docker,
    SecurityCenter,
    StorageAnalyzer,
    DuplicateFinder,
    LargeFiles,
    Protection,
    Quarantine,
    ScanSettings,
    About,
}

const SECTIONS: &[(&str, &[Page])] = &[
    ("OVERVIEW", &[Page::Dashboard, Page::SmartScan]),
    (
        "CLEANUP",
        &[
            Page::JunkCleaner,
            Page::AppCaches,
            Page::BrowserCleaner,
            Page::DeveloperCleaner,
            Page::Docker,
            Page::AppCleaner,
        ],
    ),
    ("SECURITY", &[Page::SecurityCenter]),
    (
        "ANALYSIS",
        &[
            Page::StorageAnalyzer,
            Page::DuplicateFinder,
            Page::LargeFiles,
        ],
    ),
    (
        "SETTINGS",
        &[
            Page::Protection,
            Page::Quarantine,
            Page::ScanSettings,
            Page::About,
        ],
    ),
];

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Page::Dashboard => "Dashboard",
            Page::SmartScan => "Smart Scan",
            Page::JunkCleaner => "Junk Cleaner",
            Page::AppCaches => "App Caches",
            Page::AppCleaner => "App Leftovers",
            Page::BrowserCleaner => "Browser",
            Page::DeveloperCleaner => "Developer",
            Page::Docker => "Docker",
            Page::SecurityCenter => "Security Center",
            Page::StorageAnalyzer => "Storage Analyzer",
            Page::DuplicateFinder => "Duplicate Finder",
            Page::LargeFiles => "Large Files",
            Page::Protection => "Protection",
            Page::Quarantine => "Quarantine",
            Page::ScanSettings => "Scan Settings",
            Page::About => "About",
        }
    }

    /// Whether the page is implemented in this release.
    pub fn is_available(self) -> bool {
        matches!(
            self,
            Page::Dashboard
                | Page::SmartScan
                | Page::JunkCleaner
                | Page::AppCaches
                | Page::BrowserCleaner
                | Page::DeveloperCleaner
                | Page::Docker
                | Page::SecurityCenter
                | Page::AppCleaner
                | Page::StorageAnalyzer
                | Page::DuplicateFinder
                | Page::LargeFiles
                | Page::Protection
                | Page::Quarantine
                | Page::About
        )
    }
}

/// All pages in sidebar order (for the compact page picker).
pub fn all_pages() -> impl Iterator<Item = Page> {
    SECTIONS.iter().flat_map(|(_, pages)| pages.iter().copied())
}

/// Compact navigation for narrow windows: brand plus a page picker.
pub fn top_bar(ui: &mut Ui, current: &mut Page) {
    let p = palette(ui);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(egui_phosphor::regular::BROOM)
                .size(18.0)
                .color(p.accent),
        );
        ui.label(RichText::new("RustClean").strong().size(16.0).color(p.text));
        crate::theme::appearance_cycle_button(ui);
        // Leave room for nothing else: the picker takes what is left.
        let w = (ui.available_width() - 8.0).clamp(120.0, 200.0);
        egui::ComboBox::from_id_salt("page_picker")
            .selected_text(format!("{}  {}", current.icon(), current.title()))
            .width(w)
            .show_ui(ui, |ui| {
                for page in all_pages().filter(|pg| pg.is_available()) {
                    ui.selectable_value(
                        current,
                        page,
                        format!("{}  {}", page.icon(), page.title()),
                    );
                }
            });
    });
}

impl Page {
    pub fn icon(self) -> &'static str {
        use egui_phosphor::regular as i;
        match self {
            Page::Dashboard => i::SQUARES_FOUR,
            Page::SmartScan => i::SPARKLE,
            Page::JunkCleaner => i::TRASH,
            Page::AppCaches => i::STACK,
            Page::AppCleaner => i::APP_WINDOW,
            Page::BrowserCleaner => i::GLOBE,
            Page::DeveloperCleaner => i::CODE,
            Page::Docker => i::CUBE,
            Page::SecurityCenter => i::SHIELD_CHECK,
            Page::StorageAnalyzer => i::CHART_PIE,
            Page::DuplicateFinder => i::COPY,
            Page::LargeFiles => i::FILE_ARROW_DOWN,
            Page::Protection => i::LOCK,
            Page::Quarantine => i::ARCHIVE,
            Page::ScanSettings => i::GEAR,
            Page::About => i::INFO,
        }
    }
}

/// Draws the sidebar. `badge` supplies right-aligned text per page (sizes,
/// counts); `disk` is (total, available) bytes.
pub fn sidebar(
    ui: &mut Ui,
    current: &mut Page,
    badge: impl Fn(Page) -> Option<String>,
    disk: Option<(u64, u64)>,
) {
    let p = palette(ui);
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(p.accent)
            .corner_radius(CornerRadius::same(9))
            .inner_margin(egui::Margin::symmetric(7, 5))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(egui_phosphor::regular::BROOM)
                        .size(18.0)
                        .color(p.on_accent),
                );
            });
        ui.vertical(|ui| {
            ui.label(RichText::new("RustClean").strong().size(15.0).color(p.text));
            ui.label(RichText::new("v0.1 · local only").small().color(p.muted));
        });
    });
    ui.add_space(6.0);
    crate::theme::appearance_switch(ui);
    let disk_h = if disk.is_some() { 118.0 } else { 0.0 };
    egui::ScrollArea::vertical()
        .max_height((ui.available_height() - disk_h).max(120.0))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for (section, pages) in SECTIONS {
                ui.add_space(10.0);
                ui.label(RichText::new(*section).small().strong().color(p.muted));
                for &page in *pages {
                    if nav_item(ui, page, *current == page, badge(page)) {
                        *current = page;
                    }
                }
            }
        });
    if let Some((total, avail)) = disk {
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(10.0);
            crate::theme::card(ui)
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let used = total.saturating_sub(avail);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Disk").small().color(p.muted));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{} free",
                                    rustclean_core::format_bytes(avail)
                                ))
                                .small()
                                .strong(),
                            );
                        });
                    });
                    let frac = if total > 0 {
                        used as f32 / total as f32
                    } else {
                        0.0
                    };
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .desired_height(6.0)
                            .fill(p.text2)
                            .corner_radius(3),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} of {} used",
                            rustclean_core::format_bytes(used),
                            rustclean_core::format_bytes(total)
                        ))
                        .small()
                        .color(p.muted),
                    );
                });
        });
    }
}

/// One full-width navigation row. Returns true when clicked.
fn nav_item(ui: &mut Ui, page: Page, active: bool, badge: Option<String>) -> bool {
    let p = palette(ui);
    let available = page.is_available();
    let (fill, fg) = if active {
        (p.accent_soft, p.accent)
    } else {
        (
            egui::Color32::TRANSPARENT,
            if available { p.text2 } else { p.muted },
        )
    };
    let resp = egui::Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(page.icon()).size(15.0).color(fg));
                let title = RichText::new(page.title()).color(fg);
                ui.label(if active { title.strong() } else { title });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let text = if available {
                        badge
                    } else {
                        Some("soon".into())
                    };
                    if let Some(t) = text {
                        ui.label(RichText::new(t).small().color(p.muted));
                    }
                });
            });
        })
        .response
        .interact(Sense::click());
    let resp = if available {
        resp
    } else {
        resp.on_hover_text("Planned for a future release")
    };
    resp.clicked()
}
