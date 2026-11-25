//! Small shared UI helpers built on the theme tokens.

use std::time::SystemTime;

use egui::{Color32, CornerRadius, Margin, Response, RichText, Ui};
use rustclean_core::SafetyClass;

use crate::theme::{self, palette};

#[derive(Clone, Copy)]
pub enum Tone {
    Safe,
    Review,
    Protected,
    Unknown,
    Info,
}

fn tone_colors(ui: &Ui, tone: Tone) -> (Color32, Color32) {
    let p = palette(ui);
    match tone {
        Tone::Safe => p.safe,
        Tone::Review => p.review,
        Tone::Protected => p.protected,
        Tone::Unknown => p.unknown,
        Tone::Info => p.info,
    }
}

/// A rounded status label. Colour is always paired with text. Drawn at its
/// natural size so it never stretches to a table row's height.
pub fn pill(ui: &mut Ui, text: impl Into<String>, tone: Tone) -> Response {
    let (fg, bg) = tone_colors(ui, tone);
    let font = egui::FontId::proportional(11.5);
    let galley = ui.painter().layout_no_wrap(text.into(), font, fg);
    let pad = egui::vec2(8.0, 3.0);
    let size = galley.size() + pad * 2.0;
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().rect_filled(rect, CornerRadius::same(255), bg);
        ui.painter().galley(rect.min + pad, galley, fg);
    }
    resp
}

/// Lays out `n` cards in a responsive grid of `cols` columns.
pub fn card_grid(
    ui: &mut Ui,
    n: usize,
    cols: usize,
    gap: f32,
    mut card: impl FnMut(&mut Ui, usize),
) {
    let cols = cols.max(1);
    let width = ui.available_width();
    let cw = ((width - gap * (cols as f32 - 1.0)) / cols as f32).floor();
    let mut i = 0;
    while i < n {
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for _ in 0..cols {
                if i >= n {
                    break;
                }
                ui.allocate_ui_with_layout(
                    egui::vec2(cw, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(cw);
                        card(ui, i);
                    },
                );
                i += 1;
            }
        });
        ui.add_space(gap);
    }
}

/// Like [`card_grid`], but cards in the same row get the same height.
///
/// `card(ui, i, pad)` draws card `i` and returns its response; it should add
/// `pad` points of space where extra height looks right (e.g. above a
/// bottom link, so links line up). Heights are measured each frame and the
/// padding applies from the next one; a changed padding re-runs the pass, so
/// nothing visibly jumps.
pub fn card_grid_aligned(
    ui: &mut Ui,
    id_salt: impl egui::AsIdSalt,
    n: usize,
    cols: usize,
    gap: f32,
    mut card: impl FnMut(&mut Ui, usize, f32) -> Response,
) {
    let id = ui.id().with(id_salt);
    let cols = cols.max(1);
    let pads: Vec<f32> = ui
        .ctx()
        .data(|d| d.get_temp::<Vec<f32>>(id))
        .filter(|p| p.len() == n)
        .unwrap_or_else(|| vec![0.0; n]);
    // Natural (unpadded) height of every card this frame.
    let mut natural = vec![0.0; n];
    card_grid(ui, n, cols, gap, |ui, i| {
        let pad = if cols > 1 { pads[i] } else { 0.0 };
        let resp = card(ui, i, pad);
        natural[i] = resp.rect.height() - pad;
    });
    let mut new_pads = vec![0.0; n];
    if cols > 1 {
        for row in natural.chunks(cols).enumerate() {
            let (r, heights) = row;
            let max = heights.iter().copied().fold(0.0, f32::max);
            for (j, h) in heights.iter().enumerate() {
                new_pads[r * cols + j] = (max - h).max(0.0).round();
            }
        }
    }
    if new_pads.iter().zip(&pads).any(|(a, b)| (a - b).abs() > 0.5) {
        ui.ctx().data_mut(|d| d.insert_temp(id, new_pads));
        ui.ctx().request_discard("equalise card heights");
    }
}

pub fn class_tone(class: SafetyClass) -> Tone {
    match class {
        SafetyClass::Safe => Tone::Safe,
        SafetyClass::Review => Tone::Review,
        SafetyClass::Unknown => Tone::Unknown,
        SafetyClass::Protected => Tone::Protected,
    }
}

/// Icon shown with each safety class, so classes are told apart without
/// relying on colour alone.
pub fn class_icon(class: SafetyClass) -> &'static str {
    use egui_phosphor::regular as i;
    match class {
        SafetyClass::Safe => i::SHIELD_CHECK,
        SafetyClass::Review => i::EYE,
        SafetyClass::Unknown => i::QUESTION,
        SafetyClass::Protected => i::LOCK,
    }
}

pub fn class_pill(ui: &mut Ui, class: SafetyClass) -> Response {
    pill(
        ui,
        format!("{}  {}", class_icon(class), class.label()),
        class_tone(class),
    )
}

/// An inline warning banner.
pub fn warning(ui: &mut Ui, text: impl Into<String>) {
    let (fg, bg) = tone_colors(ui, Tone::Review);
    egui::Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.label(RichText::new(format!("⚠  {}", text.into())).color(fg));
        });
}

pub fn error(ui: &mut Ui, text: impl Into<String>) {
    let (fg, bg) = tone_colors(ui, Tone::Protected);
    egui::Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.label(RichText::new(text.into()).color(fg));
        });
}

/// Page header: optional breadcrumb, title and subtitle.
pub fn page_header(ui: &mut Ui, crumb: Option<&str>, title: &str, subtitle: Option<&str>) {
    let p = palette(ui);
    if let Some(c) = crumb {
        ui.label(RichText::new(c).color(p.muted).small());
    }
    ui.label(RichText::new(title).size(24.0).strong().color(p.text));
    if let Some(s) = subtitle {
        ui.label(RichText::new(s).color(p.muted));
    }
    ui.add_space(6.0);
}

/// A card with a title, a large value and an optional detail line.
/// Returns the card's response (sense: click).
pub fn stat_card(ui: &mut Ui, title: &str, value: &str, detail: Option<&str>) -> Response {
    let p = palette(ui);
    theme::card(ui)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).color(p.muted));
            ui.label(RichText::new(value).size(26.0).strong().color(p.text));
            if let Some(d) = detail {
                ui.label(RichText::new(d).small().color(p.muted));
            }
        })
        .response
}

pub fn time_ago(t: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(t)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match secs {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", secs / 60),
        3600..86400 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86400),
    }
}

/// Full-width coloured banner with an icon.
pub fn banner(ui: &mut Ui, text: &str, tone: Tone) {
    let (fg, bg) = tone_colors(ui, tone);
    egui::Frame::new()
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, fg.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(egui_phosphor::regular::WARNING)
                        .color(fg)
                        .size(16.0),
                );
                ui.add(egui::Label::new(RichText::new(text).color(fg)).wrap());
            });
        });
    ui.add_space(6.0);
}

/// Coloured explanation box (e.g. "Why Safe: …").
pub fn callout(ui: &mut Ui, text: &str, tone: Tone) {
    let (fg, bg) = tone_colors(ui, tone);
    egui::Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(text).color(fg)).wrap());
        });
}

/// Page header with an action area on the right; stacks on narrow widths.
pub fn header_with_action(
    ui: &mut Ui,
    crumb: Option<&str>,
    title: &str,
    subtitle: Option<&str>,
    actions: impl FnOnce(&mut Ui),
) {
    if ui.available_width() < 560.0 {
        page_header(ui, crumb, title, subtitle);
        ui.horizontal_wrapped(actions);
        ui.add_space(4.0);
        return;
    }
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_max_width((ui.available_width() - 260.0).max(200.0));
            page_header(ui, crumb, title, subtitle);
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
    });
}

/// A rounded filter chip.
pub fn chip(ui: &mut Ui, active: bool, text: &str) -> Response {
    let p = palette(ui);
    let (fill, fg, stroke) = if active {
        (p.text, p.surface, p.text)
    } else {
        (p.surface, p.text2, p.border)
    };
    ui.add(
        egui::Button::new(RichText::new(text).color(fg))
            .fill(fill)
            .stroke(egui::Stroke::new(1.0, stroke))
            .corner_radius(CornerRadius::same(255))
            .min_size(egui::vec2(0.0, 28.0)),
    )
}

/// A category row: optional tri-state check (`Some(None)` = mixed), label,
/// right-aligned value. Clicking the first 30 px toggles.
pub fn list_row(
    ui: &mut Ui,
    active: bool,
    check: Option<Option<Option<bool>>>,
    label: &str,
    value: &str,
) -> Response {
    let p = palette(ui);
    let fill = if active {
        p.accent_soft
    } else {
        egui::Color32::TRANSPARENT
    };
    let fg = if active { p.accent } else { p.text2 };
    egui::Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                // Drawn as icons (not disabled checkboxes) so the state is
                // easy to read: the row itself handles the click.
                use egui_phosphor::regular as i;
                let mark = match check {
                    Some(Some(Some(true))) => {
                        Some((i::CHECK_SQUARE, p.accent, "Selected; click to clear"))
                    }
                    Some(Some(None)) => Some((
                        i::MINUS_SQUARE,
                        p.accent,
                        "Partly selected; click to select all",
                    )),
                    Some(Some(Some(false))) => {
                        Some((i::SQUARE, p.muted, "Click to select this category"))
                    }
                    Some(None) => Some((i::LOCK_SIMPLE, p.muted, "Nothing here can be removed")),
                    None => None,
                };
                if let Some((icon, color, tip)) = mark {
                    ui.label(RichText::new(icon).size(17.0).color(color))
                        .on_hover_text(tip);
                }
                // Value first (right-aligned), so a long label truncates
                // into the remaining space instead of overlapping it.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(value).small().color(p.muted));
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.add(egui::Label::new(RichText::new(label).color(fg)).truncate())
                            .on_hover_text(label);
                    });
                });
            });
        })
        .response
        .interact(egui::Sense::click())
}

/// `path` itself with the home directory shortened to `~`.
pub fn tilde_path(path: &std::path::Path, home: &std::path::Path) -> String {
    match path.strip_prefix(home) {
        Ok(rel) if rel.as_os_str().is_empty() => "~".into(),
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.display().to_string(),
    }
}

/// Plain-language file type from the extension.
pub fn file_kind(path: &std::path::Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        None => "Data file (no extension)",
        Some("log" | "txt" | "out") => "Log or text file",
        Some("ips" | "crash" | "diag" | "dmp" | "hang" | "spin") => "Crash or diagnostic report",
        Some("dmg" | "iso" | "img") => "Disk image",
        Some("pkg" | "mpkg" | "xip" | "msi" | "msix" | "exe" | "deb" | "rpm") => "Installer",
        Some("zip" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "tar" | "7z" | "rar") => "Archive",
        Some("db" | "sqlite" | "sqlite3" | "db-wal" | "db-shm" | "ldb") => "Database",
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "heic" | "tiff" | "bmp" | "ico" | "svg") => {
            "Image"
        }
        Some("mp4" | "mov" | "m4v" | "mkv" | "webm" | "avi") => "Video",
        Some("mp3" | "m4a" | "aac" | "wav" | "flac" | "ogg") => "Audio",
        Some("js" | "mjs" | "cjs" | "wasm") => "Script or compiled code",
        Some("json" | "plist" | "xml" | "yaml" | "yml" | "toml" | "ini") => "Structured data",
        Some("dylib" | "so" | "dll" | "jar" | "class" | "o" | "a" | "rlib" | "crate") => {
            "Library or package"
        }
        Some("html" | "htm" | "css") => "Web resource",
        Some("pdf") => "PDF document",
        Some("tmp" | "temp" | "part" | "crdownload" | "download") => {
            "Temporary or partial download"
        }
        Some(_) => "File",
    }
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `YYYY-MM-DD HH:MM` in local time (UTC, labelled, if unavailable).
pub fn format_local(t: SystemTime) -> String {
    let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) else {
        return "before 1970".into();
    };
    let secs = d.as_secs() as i64;
    #[cfg(unix)]
    {
        let tt = secs as libc::time_t;
        // SAFETY: `tm` is plain data; localtime_r writes only into it and
        // returns null on failure.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            return format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                i64::from(tm.tm_year) + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min
            );
        }
    }
    #[cfg(windows)]
    if let Some((y, mo, d, h, mi)) = windows_local_time(secs) {
        return format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}");
    }
    let (y, m, day) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Unix seconds → local (year, month, day, hour, minute) on Windows, using
/// the system's time-zone rules for that date (so DST is right for past
/// dates too). Declared by hand: two kernel32 calls do not justify a crate.
#[cfg(windows)]
fn windows_local_time(secs: i64) -> Option<(u16, u16, u16, u16, u16)> {
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn FileTimeToSystemTime(ft: *const FileTime, st: *mut SystemTime) -> i32;
        fn SystemTimeToTzSpecificLocalTime(
            tz: *const core::ffi::c_void,
            utc: *const SystemTime,
            local: *mut SystemTime,
        ) -> i32;
    }
    // FILETIME counts 100 ns intervals since 1601-01-01 (UTC).
    let ticks = u64::try_from(secs.checked_add(11_644_473_600)?)
        .ok()?
        .checked_mul(10_000_000)?;
    let ft = FileTime {
        low: ticks as u32,
        high: (ticks >> 32) as u32,
    };
    let mut utc = SystemTime::default();
    let mut local = SystemTime::default();
    // SAFETY: both structs are #[repr(C)] with the Win32 layouts; the calls
    // only write into the out-pointers and return 0 on failure. A null
    // time zone means "the current one".
    let ok = unsafe {
        FileTimeToSystemTime(&ft, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) != 0
    };
    ok.then_some((local.year, local.month, local.day, local.hour, local.minute))
}

/// "2026-11-24 14:05 (3 days ago)".
pub fn date_and_age(t: SystemTime) -> String {
    format!("{} ({})", format_local(t), time_ago(t))
}

/// Parent folder of `path` with the home directory shortened to `~`.
pub fn short_path(path: &std::path::Path, home: &std::path::Path) -> String {
    let parent = path.parent().unwrap_or(path);
    match parent.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => parent.display().to_string(),
    }
}

/// A file name, prefixed with the recommendation sparkle when
/// `recommended`. One text run, so it is no taller than a plain label.
pub fn file_name_label(ui: &mut Ui, name: &str, recommended: bool) -> Response {
    let p = palette(ui);
    let font = egui::TextStyle::Body.resolve(ui.style());
    let mut job = egui::text::LayoutJob::default();
    if recommended {
        job.append(
            &format!("{}  ", egui_phosphor::regular::SPARKLE),
            0.0,
            egui::TextFormat::simple(font.clone(), p.safe.0),
        );
    }
    job.append(name, 0.0, egui::TextFormat::simple(font, p.text));
    job.wrap = egui::text::TextWrapping::truncate_at_width(ui.available_width());
    let resp = ui.add(egui::Label::new(job).truncate());
    if recommended {
        resp.on_hover_text("Recommended: safe to delete")
    } else {
        resp
    }
}

/// One file as a stacked card row (narrow layout).
pub fn file_card(
    ui: &mut Ui,
    selected: &mut bool,
    c: &rustclean_core::Candidate,
    active: bool,
    recommended: bool,
    height: f32,
    home: &std::path::Path,
) -> Response {
    let p = palette(ui);
    let fill = if active { p.accent_soft } else { p.surface };
    egui::Frame::new()
        .fill(fill)
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_height(height - 17.0);
            ui.horizontal(|ui| {
                if c.class.is_selectable() {
                    ui.checkbox(selected, "");
                } else {
                    ui.add_enabled(false, egui::Checkbox::new(&mut false, ""));
                }
                ui.vertical(|ui| {
                    file_name_label(ui, &c.file_name(), recommended);
                    ui.add(
                        egui::Label::new(
                            RichText::new(short_path(&c.path, home))
                                .small()
                                .monospace()
                                .color(p.muted),
                        )
                        .truncate(),
                    );
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(rustclean_core::format_bytes(c.disk_usage)).strong(),
                        );
                        class_pill(ui, c.class);
                    });
                });
            });
        })
        .response
        .interact(egui::Sense::click())
}

/// What this system calls its trash: "Recycle Bin" on Windows.
pub fn trash_name() -> &'static str {
    trash_name_for(cfg!(windows))
}

fn trash_name_for(windows: bool) -> &'static str {
    if windows { "Recycle Bin" } else { "Trash" }
}

/// Removal method label using the system's own trash name.
pub fn method_label(m: rustclean_core::RemovalMethod) -> String {
    match m {
        rustclean_core::RemovalMethod::Trash => format!("Move to {}", trash_name()),
        rustclean_core::RemovalMethod::Quarantine => m.label().to_string(),
    }
}

pub fn reveal_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "Reveal in Finder"
    } else if cfg!(windows) {
        "Show in Explorer"
    } else {
        "Open folder"
    }
}

/// Shows a file in the system file manager. Read-only; nothing is changed.
pub fn reveal_in_file_manager(path: &std::path::Path) {
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("/usr/bin/open")
            .arg("-R")
            .arg(path)
            .spawn()
    } else if cfg!(windows) {
        let mut arg = std::ffi::OsString::from("/select,");
        arg.push(path.as_os_str());
        std::process::Command::new("explorer.exe").arg(arg).spawn()
    } else {
        std::process::Command::new("xdg-open")
            .arg(path.parent().unwrap_or(path))
            .spawn()
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not open file manager");
    }
}

/// A bottom-right toast.
pub fn toast(ctx: &egui::Context, id: egui::Id, text: &str) {
    egui::Area::new(id)
        .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-20.0, -96.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            let p = palette(ui);
            theme::card(ui)
                .shadow(egui::Shadow {
                    offset: [0, 10],
                    blur: 28,
                    spread: 0,
                    color: egui::Color32::from_black_alpha(45),
                })
                .show(ui, |ui| {
                    ui.set_max_width(340.0_f32.min(ctx.content_rect().width() - 40.0));
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(egui_phosphor::regular::CHECK_CIRCLE)
                                .color(p.safe.0)
                                .size(18.0),
                        );
                        ui.add(egui::Label::new(RichText::new(text).color(p.text)).wrap());
                    });
                });
        });
}

/// The dark floating action bar: summary and "Select all safe"/"Clear" on
/// the left, `right` (main actions) on the right; wraps on narrow widths.
/// Returns (select_all_safe, clear) clicks.
pub fn action_bar(ui: &mut Ui, summary: &str, right: impl FnOnce(&mut Ui)) -> (bool, bool) {
    let mut select_safe = false;
    let mut clear = false;
    egui::Frame::new()
        .fill(theme::INK)
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::symmetric(16, 10))
        .shadow(egui::Shadow {
            offset: [0, 8],
            blur: 24,
            spread: 0,
            color: egui::Color32::from_black_alpha(50),
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let link = |ui: &mut Ui, t: &str| {
                ui.add(
                    egui::Button::new(RichText::new(t).color(egui::Color32::from_gray(190)))
                        .frame(false),
                )
                .clicked()
            };
            let narrow = ui.available_width() < 520.0;
            let mut right = Some(right);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(summary).strong().color(egui::Color32::WHITE));
                select_safe = link(
                    ui,
                    &format!("{}  Select all safe", egui_phosphor::regular::CHECKS),
                );
                clear = link(ui, &format!("{}  Clear", egui_phosphor::regular::X));
                if !narrow && let Some(r) = right.take() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), r);
                }
            });
            if let Some(r) = right.take() {
                ui.add_space(4.0);
                ui.horizontal_wrapped(r);
            }
        });
    (select_safe, clear)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn local_dates_are_well_formed() {
        let s = format_local(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        assert!(s.starts_with("2023-11-1"), "{s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(
            format_local(UNIX_EPOCH - Duration::from_secs(5)),
            "before 1970"
        );
    }

    #[test]
    fn kinds_and_paths() {
        assert_eq!(
            file_kind(Path::new("/x/f_000001")),
            "Data file (no extension)"
        );
        assert_eq!(file_kind(Path::new("/x/Setup.DMG")), "Disk image");
        assert_eq!(
            file_kind(Path::new("/x/a.ips")),
            "Crash or diagnostic report"
        );
        let home = Path::new("/Users/a");
        assert_eq!(
            tilde_path(Path::new("/Users/a/Library/Caches"), home),
            "~/Library/Caches"
        );
        assert_eq!(tilde_path(home, home), "~");
        assert_eq!(tilde_path(Path::new("/tmp/x"), home), "/tmp/x");
    }

    #[test]
    fn trash_is_named_like_the_system_does() {
        assert_eq!(trash_name_for(true), "Recycle Bin");
        assert_eq!(trash_name_for(false), "Trash");
        let expected = if cfg!(windows) {
            "Move to Recycle Bin"
        } else {
            "Move to Trash"
        };
        assert_eq!(method_label(rustclean_core::RemovalMethod::Trash), expected);
    }
}
