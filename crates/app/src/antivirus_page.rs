//! Antivirus: read-only status of the protection the system already has
//! (Gatekeeper, XProtect, Microsoft Defender or another registered
//! antivirus, ClamAV). RustClean does not scan files for viruses and never
//! changes protection settings itself: "Open settings" hands over to the
//! system's own settings screen, where the system asks for permission.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use egui::{Color32, RichText, Ui};
use rustclean_security::{ProtectionCheck, ProtectionReport, ProtectionStatus, scan_protection};

use crate::jobs::{Job, Poll};
use crate::theme::{self, palette};
use crate::widgets::{self, Tone};

/// The user's choices for this page, saved in RustClean's own data folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntivirusSettings {
    /// Run the (read-only) check when RustClean starts.
    pub check_on_start: bool,
    /// Show "n off" next to Antivirus in the sidebar.
    pub sidebar_badge: bool,
    /// Count informational items (e.g. the macOS firewall) as problems.
    pub strict: bool,
}

impl Default for AntivirusSettings {
    fn default() -> Self {
        Self {
            check_on_start: false,
            sidebar_badge: true,
            strict: false,
        }
    }
}

impl AntivirusSettings {
    fn file(home: &Path) -> PathBuf {
        rustclean_safety::app_data_dir(home).join("antivirus-settings")
    }

    fn parse(text: &str) -> Self {
        let mut s = Self::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let on = v.trim() == "true";
            match k.trim() {
                "check_on_start" => s.check_on_start = on,
                "sidebar_badge" => s.sidebar_badge = on,
                "strict" => s.strict = on,
                _ => {}
            }
        }
        s
    }

    fn render(&self) -> String {
        format!(
            "check_on_start={}\nsidebar_badge={}\nstrict={}\n",
            self.check_on_start, self.sidebar_badge, self.strict
        )
    }

    /// Saved settings; defaults when missing or unreadable.
    pub fn load(home: &Path) -> Self {
        std::fs::read_to_string(Self::file(home))
            .map(|t| Self::parse(&t))
            .unwrap_or_default()
    }

    /// Best effort: a failure only means the choice is not remembered.
    pub fn save(&self, home: &Path) {
        let file = Self::file(home);
        let result = file
            .parent()
            .map_or(Ok(()), rustclean_safety::platform::create_private_dir)
            .and_then(|()| std::fs::write(&file, self.render()));
        if let Err(e) = result {
            tracing::warn!(error = %e, "could not save antivirus settings");
        }
    }
}

pub struct AntivirusPage {
    home: PathBuf,
    settings: AntivirusSettings,
    started: bool,
    job: Option<Job<ProtectionReport>>,
    report: Option<ProtectionReport>,
    pub last_check: Option<SystemTime>,
    error: Option<String>,
}

fn status_icon(s: ProtectionStatus, informational: bool) -> (&'static str, Tone) {
    use egui_phosphor::regular as i;
    match s {
        ProtectionStatus::On => (i::SHIELD_CHECK, Tone::Safe),
        ProtectionStatus::Off if informational => (i::INFO, Tone::Info),
        ProtectionStatus::Off => (i::SHIELD_WARNING, Tone::Review),
        ProtectionStatus::Unknown => (i::QUESTION, Tone::Unknown),
    }
}

fn status_text(s: ProtectionStatus) -> &'static str {
    match s {
        ProtectionStatus::On => "On",
        ProtectionStatus::Off => "Off",
        ProtectionStatus::Unknown => "Unknown",
    }
}

/// Whether a check counts as a problem under the user's settings.
fn is_problem(c: &ProtectionCheck, strict: bool) -> bool {
    c.status == ProtectionStatus::Off && (strict || !c.informational)
}

/// One-line summary for the banner at the top of the page.
fn summary(r: &ProtectionReport, strict: bool) -> (String, Tone) {
    let problems = r.checks.iter().filter(|c| is_problem(c, strict)).count();
    let unknown = r.count(ProtectionStatus::Unknown);
    let total = r.checks.len();
    if total == 0 {
        (
            "No protection checks are available on this system.".into(),
            Tone::Unknown,
        )
    } else if problems > 0 {
        (
            format!(
                "{problems} of {total} {} attention. See below for what to do.",
                if problems == 1 {
                    "protection needs"
                } else {
                    "protections need"
                }
            ),
            Tone::Review,
        )
    } else if unknown > 0 {
        (
            format!("Nothing is off, but {unknown} of {total} could not be checked."),
            Tone::Unknown,
        )
    } else {
        (
            "Your system's protection is on. Nothing needs your attention.".into(),
            Tone::Safe,
        )
    }
}

/// Why a protection matters, in plain language.
fn why_it_matters(name: &str) -> &'static str {
    match name {
        "Gatekeeper" => {
            "Blocks apps that are not from the App Store or an identified developer until you approve them."
        }
        "System Integrity Protection" => {
            "Stops any app, even one with your password, from changing core parts of macOS."
        }
        "XProtect" => {
            "Apple's built-in malware scanner; macOS updates its definitions automatically."
        }
        "Application Firewall" => {
            "Controls which apps may accept incoming network connections. Useful on public Wi-Fi."
        }
        "ClamAV" => {
            "An open-source virus scanner you installed; it scans only when you or a service runs it."
        }
        _ => "Scans files and downloads for malware in real time.",
    }
}

/// How to change a protection: an OS settings screen RustClean can open, or
/// a hint when there is none. Opening settings changes nothing by itself.
enum SettingsLink {
    Open {
        label: &'static str,
        target: &'static str,
    },
    Hint(&'static str),
    None,
}

fn settings_link(name: &str) -> SettingsLink {
    if cfg!(target_os = "macos") {
        match name {
            "Gatekeeper" | "XProtect" => SettingsLink::Open {
                label: "Open Privacy & Security",
                target: "x-apple.systempreferences:com.apple.preference.security",
            },
            "Application Firewall" => SettingsLink::Open {
                label: "Open Firewall settings",
                target: "x-apple.systempreferences:com.apple.preference.security?Firewall",
            },
            "System Integrity Protection" => {
                SettingsLink::Hint("Can only be changed from macOS Recovery; keep it on.")
            }
            _ => SettingsLink::None,
        }
    } else if cfg!(windows) {
        SettingsLink::Open {
            label: "Open Windows Security",
            target: "windowsdefender:",
        }
    } else {
        SettingsLink::None
    }
}

/// Opens an OS settings screen. Absolute program paths only.
fn open_settings(target: &str) {
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("/usr/bin/open")
            .arg(target)
            .spawn()
    } else if cfg!(windows) {
        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| r"C:\Windows".into());
        std::process::Command::new(root.join("explorer.exe"))
            .arg(target)
            .spawn()
    } else {
        return;
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not open system settings");
    }
}

impl AntivirusPage {
    pub fn new(home: PathBuf) -> Self {
        let settings = AntivirusSettings::load(&home);
        Self {
            home,
            settings,
            started: false,
            job: None,
            report: None,
            last_check: None,
            error: None,
        }
    }

    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    /// Sidebar text: problems found, if the user wants the badge.
    pub fn badge(&self) -> Option<String> {
        if !self.settings.sidebar_badge {
            return None;
        }
        let r = self.report.as_ref()?;
        let n = r
            .checks
            .iter()
            .filter(|c| is_problem(c, self.settings.strict))
            .count();
        (n > 0).then(|| format!("{n} off"))
    }

    /// Called every frame: runs the start-up check once if enabled.
    pub fn tick(&mut self, ctx: &egui::Context) {
        if !self.started {
            self.started = true;
            if self.settings.check_on_start {
                self.start_check(ctx);
            }
        }
    }

    pub fn start_check(&mut self, ctx: &egui::Context) {
        if self.job.is_some() {
            return;
        }
        match Job::spawn("protection-check", ctx.clone(), |_| scan_protection()) {
            Ok(j) => {
                self.job = Some(j);
                self.error = None;
            }
            Err(e) => self.error = Some(format!("could not start the check: {e}")),
        }
    }

    pub fn poll_jobs(&mut self) {
        if let Some(job) = &self.job {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(r) => {
                    self.report = Some(r);
                    self.last_check = Some(SystemTime::now());
                    self.job = None;
                }
                Poll::Crashed => {
                    self.job = None;
                    self.error = Some("The protection check stopped unexpectedly.".into());
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        // The check is quick and read-only: run it the first time the page
        // is opened.
        if self.report.is_none() && self.job.is_none() && self.error.is_none() {
            self.start_check(&ctx);
        }
        if self.is_busy() {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
        let p = palette(ui);
        let busy = self.is_busy();
        let mut start = false;
        let subtitle = match self.last_check {
            Some(t) => format!(
                "Checked {} · read-only, nothing is changed",
                widgets::time_ago(t)
            ),
            None => "Read-only: shows the protection your system already has.".into(),
        };
        widgets::header_with_action(ui, Some("Security"), "Antivirus", Some(&subtitle), |ui| {
            if busy {
                ui.spinner();
                ui.label(RichText::new("Checking…").color(p.muted));
            } else if ui
                .add(theme::primary_button(
                    ui,
                    &format!("{}  Check again", egui_phosphor::regular::ARROW_CLOCKWISE),
                ))
                .clicked()
            {
                start = true;
            }
        });
        if start {
            self.start_check(&ctx);
        }
        if let Some(e) = &self.error {
            widgets::error(ui, e);
        }

        let before = self.settings;
        egui::ScrollArea::vertical()
            .id_salt("antivirus_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if let Some(report) = &self.report {
                    self.overview_ui(ui, report);
                    ui.add_space(4.0);
                    self.attention_ui(ui, report);
                    self.checks_ui(ui, report);
                }
                self.settings_ui(ui);
                if let Some(report) = &self.report {
                    for note in &report.notes {
                        ui.add(egui::Label::new(RichText::new(note).small().color(p.muted)).wrap());
                    }
                }
            });
        if self.settings != before {
            self.settings.save(&self.home);
        }
    }

    /// Ring diagram + summary tiles.
    fn overview_ui(&self, ui: &mut Ui, report: &ProtectionReport) {
        let strict = self.settings.strict;
        let total = report.checks.len();
        let on = report.count(ProtectionStatus::On);
        let problems = report
            .checks
            .iter()
            .filter(|c| is_problem(c, strict))
            .count();
        let unknown = report.count(ProtectionStatus::Unknown);
        let info_off = report.count(ProtectionStatus::Off) - problems;
        let (text, tone) = summary(report, strict);
        widgets::callout(ui, &text, tone);
        ui.add_space(8.0);
        let last = self
            .last_check
            .map(widgets::time_ago)
            .unwrap_or_else(|| "Never".into());
        let tiles: [(&str, String, &str); 4] = [
            (
                "Protections on",
                format!("{on} of {total}"),
                "built into your system",
            ),
            (
                "Needs attention",
                problems.to_string(),
                "off, and it matters",
            ),
            (
                "Informational",
                (info_off + unknown).to_string(),
                "off by default, or unknown",
            ),
            (
                "Last checked",
                last,
                rustclean_safety::platform::CURRENT.name(),
            ),
        ];
        let draw_tiles = |ui: &mut Ui| {
            let cols = if ui.available_width() >= 640.0 { 4 } else { 2 };
            widgets::card_grid(ui, tiles.len(), cols, 10.0, |ui, i| {
                let (t, v, d) = &tiles[i];
                widgets::stat_card(ui, t, v, Some(d));
            });
        };
        if ui.available_width() >= 760.0 {
            ui.horizontal_top(|ui| {
                protection_ring(ui, on, problems, total);
                ui.vertical(draw_tiles);
            });
        } else {
            ui.vertical_centered(|ui| protection_ring(ui, on, problems, total));
            ui.add_space(8.0);
            draw_tiles(ui);
        }
    }

    /// The problems only, each with what to do about it.
    fn attention_ui(&self, ui: &mut Ui, report: &ProtectionReport) {
        let strict = self.settings.strict;
        let problems: Vec<&ProtectionCheck> = report
            .checks
            .iter()
            .filter(|c| is_problem(c, strict))
            .collect();
        if problems.is_empty() {
            return;
        }
        let p = palette(ui);
        let (fg, bg) = p.review;
        egui::Frame::new()
            .fill(bg)
            .stroke(egui::Stroke::new(1.0, fg.gamma_multiply(0.35)))
            .corner_radius(egui::CornerRadius::same(12))
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(format!(
                        "{}  Needs your attention",
                        egui_phosphor::regular::WARNING
                    ))
                    .strong()
                    .color(fg),
                );
                for c in problems {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(format!("•  {}:", c.name)).strong().color(fg));
                        ui.label(RichText::new(why_it_matters(&c.name)).color(fg));
                        if let SettingsLink::Open { label, target } = settings_link(&c.name)
                            && ui
                                .button(format!("{}  {label}", egui_phosphor::regular::GEAR))
                                .clicked()
                        {
                            open_settings(target);
                        }
                    });
                }
            });
        ui.add_space(8.0);
    }

    fn checks_ui(&self, ui: &mut Ui, report: &ProtectionReport) {
        let p = palette(ui);
        let strict = self.settings.strict;
        ui.label(RichText::new("PROTECTIONS").small().strong().color(p.muted));
        let cols = if ui.available_width() >= 640.0 { 2 } else { 1 };
        widgets::card_grid_aligned(
            ui,
            "av_checks",
            report.checks.len(),
            cols,
            12.0,
            |ui, i, pad| {
                let c = &report.checks[i];
                let informational = c.informational && !strict;
                let (icon, tone) = status_icon(c.status, informational);
                let (fg, _) = match tone {
                    Tone::Safe => p.safe,
                    Tone::Review => p.review,
                    Tone::Info => p.info,
                    _ => p.unknown,
                };
                theme::card(ui)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icon).size(20.0).color(fg));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let pill = if informational && c.status == ProtectionStatus::Off
                                    {
                                        "Off · informational"
                                    } else {
                                        status_text(c.status)
                                    };
                                    widgets::pill(ui, pill, tone);
                                    ui.with_layout(
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&c.name).strong().color(p.text),
                                                )
                                                .truncate(),
                                            );
                                        },
                                    );
                                },
                            );
                        });
                        ui.add(egui::Label::new(RichText::new(&c.detail).color(p.text2)).wrap());
                        ui.add(
                            egui::Label::new(
                                RichText::new(why_it_matters(&c.name))
                                    .small()
                                    .color(p.muted),
                            )
                            .wrap(),
                        );
                        ui.add_space(pad);
                        match settings_link(&c.name) {
                            SettingsLink::Open { label, target } => {
                                if ui
                                    .button(format!("{}  {label}", egui_phosphor::regular::GEAR))
                                    .on_hover_text(
                                        "Opens your system's settings; RustClean changes nothing",
                                    )
                                    .clicked()
                                {
                                    open_settings(target);
                                }
                            }
                            SettingsLink::Hint(h) => {
                                ui.label(RichText::new(h).small().color(p.muted));
                            }
                            SettingsLink::None => {}
                        }
                    })
                    .response
            },
        );
    }

    /// The user's own choices for this page.
    fn settings_ui(&mut self, ui: &mut Ui) {
        let p = palette(ui);
        ui.add_space(4.0);
        theme::card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(egui_phosphor::regular::SLIDERS_HORIZONTAL)
                        .size(18.0)
                        .color(p.accent),
                );
                ui.label(RichText::new("Your settings").strong().size(15.0));
            });
            ui.checkbox(
                &mut self.settings.check_on_start,
                "Check protection when RustClean starts",
            )
            .on_hover_text("Read-only; takes a few seconds in the background");
            ui.checkbox(
                &mut self.settings.sidebar_badge,
                "Show a warning in the sidebar when a protection is off",
            );
            ui.checkbox(
                &mut self.settings.strict,
                "Treat informational items (like a firewall that is off by default) as problems",
            );
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "These settings only change what RustClean shows. To turn a protection on or off, use \"Open settings\": your system makes the change and asks for permission.",
                    )
                    .small()
                    .color(p.muted),
                )
                .wrap(),
            );
        });
        ui.add_space(8.0);
    }
}

/// Ring diagram: the share of protections that are on, coloured by whether
/// anything needs attention.
fn protection_ring(ui: &mut Ui, on: usize, problems: usize, total: usize) {
    let p = palette(ui);
    let size = 120.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter_at(rect.expand(2.0));
    let c = rect.center();
    let r = size / 2.0 - 9.0;
    painter.circle_stroke(c, r, egui::Stroke::new(12.0, p.border));
    let frac = if total > 0 {
        on as f32 / total as f32
    } else {
        0.0
    };
    let color: Color32 = if problems > 0 { p.review.0 } else { p.safe.0 };
    if frac > 0.0 {
        let steps = 64;
        let start = -std::f32::consts::FRAC_PI_2;
        let pts: Vec<egui::Pos2> = (0..=steps)
            .map(|i| {
                let a = start + std::f32::consts::TAU * frac * i as f32 / steps as f32;
                c + egui::vec2(a.cos(), a.sin()) * r
            })
            .collect();
        painter.add(egui::Shape::line(pts, egui::Stroke::new(12.0, color)));
    }
    painter.text(
        c - egui::vec2(0.0, 9.0),
        egui::Align2::CENTER_CENTER,
        format!("{on}/{total}"),
        egui::FontId::proportional(24.0),
        p.text,
    );
    painter.text(
        c + egui::vec2(0.0, 15.0),
        egui::Align2::CENTER_CENTER,
        if problems > 0 {
            "check below"
        } else {
            "protected"
        },
        egui::FontId::proportional(11.5),
        p.muted,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(status: ProtectionStatus, informational: bool) -> ProtectionCheck {
        ProtectionCheck {
            name: "x".into(),
            status,
            detail: String::new(),
            informational,
        }
    }

    fn report(checks: Vec<ProtectionCheck>) -> ProtectionReport {
        ProtectionReport {
            checks,
            notes: Vec::new(),
        }
    }

    #[test]
    fn summary_reports_problems_before_unknown() {
        use ProtectionStatus::*;
        let r = |c| summary(&report(c), false).1;
        assert!(matches!(r(vec![check(On, false)]), Tone::Safe));
        assert!(matches!(
            r(vec![check(Off, false), check(Unknown, false)]),
            Tone::Review
        ));
        assert!(matches!(
            r(vec![check(On, false), check(Unknown, false)]),
            Tone::Unknown
        ));
        assert!(matches!(r(vec![]), Tone::Unknown));
    }

    #[test]
    fn informational_items_count_only_in_strict_mode() {
        use ProtectionStatus::*;
        let r = report(vec![check(On, false), check(Off, true)]);
        assert!(matches!(summary(&r, false).1, Tone::Safe));
        assert!(matches!(summary(&r, true).1, Tone::Review));

        let tmp = tempfile::tempdir().unwrap();
        let mut page = AntivirusPage::new(tmp.path().to_path_buf());
        page.report = Some(r);
        assert_eq!(page.badge(), None);
        page.settings.strict = true;
        assert_eq!(page.badge().as_deref(), Some("1 off"));
        page.settings.sidebar_badge = false;
        assert_eq!(page.badge(), None);
    }

    #[test]
    fn settings_round_trip_and_ignore_garbage() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        assert_eq!(AntivirusSettings::load(home), AntivirusSettings::default());
        let s = AntivirusSettings {
            check_on_start: true,
            sidebar_badge: false,
            strict: true,
        };
        s.save(home);
        assert_eq!(AntivirusSettings::load(home), s);
        assert_eq!(
            AntivirusSettings::parse("junk\nstrict=maybe\nunknown=true"),
            AntivirusSettings::default()
        );
    }
}
