//! RustClean visual theme: design tokens from the UI proposal, applied to
//! egui for both light and dark mode (egui follows the system setting).

use egui::{Color32, CornerRadius, Margin, Shadow, Stroke, Theme, Visuals};

pub struct Palette {
    pub bg: Color32,
    pub surface: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text2: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub on_accent: Color32,
    pub safe: (Color32, Color32),
    pub review: (Color32, Color32),
    pub protected: (Color32, Color32),
    pub unknown: (Color32, Color32),
    pub info: (Color32, Color32),
}

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

pub const LIGHT: Palette = Palette {
    bg: hex(0xF6F7F9),
    surface: hex(0xFFFFFF),
    border: hex(0xE4E7EC),
    text: hex(0x101828),
    text2: hex(0x344054),
    muted: hex(0x667085),
    accent: hex(0xC2410C),
    accent_soft: hex(0xFFF1EA),
    on_accent: hex(0xFFFFFF),
    safe: (hex(0x067647), hex(0xECFDF3)),
    review: (hex(0xB54708), hex(0xFFFAEB)),
    protected: (hex(0xB42318), hex(0xFEF3F2)),
    unknown: (hex(0x475467), hex(0xF2F4F7)),
    info: (hex(0x175CD3), hex(0xEFF8FF)),
};

pub const DARK: Palette = Palette {
    bg: hex(0x0C111D),
    surface: hex(0x161B26),
    border: hex(0x2A3140),
    text: hex(0xF5F5F6),
    text2: hex(0xCECFD2),
    muted: hex(0x94969C),
    accent: hex(0xF38744),
    accent_soft: hex(0x3A1D0F),
    on_accent: hex(0x0C111D),
    safe: (hex(0x47CD89), hex(0x053321)),
    review: (hex(0xFDB022), hex(0x4E1D09)),
    protected: (hex(0xF97066), hex(0x55160C)),
    unknown: (hex(0xCECFD2), hex(0x22262F)),
    info: (hex(0x84CAFF), hex(0x102A56)),
};

pub fn palette(ui: &egui::Ui) -> &'static Palette {
    if ui.visuals().dark_mode {
        &DARK
    } else {
        &LIGHT
    }
}

/// Dark ink used for the floating action bar (same in both themes).
pub const INK: Color32 = hex(0x101828);

pub const RADIUS_CARD: u8 = 14;
pub const RADIUS_CONTROL: u8 = 8;

fn visuals(p: &Palette, dark: bool) -> Visuals {
    let mut v = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.extreme_bg_color = p.surface;
    v.faint_bg_color = if dark { hex(0x1B2130) } else { hex(0xF9FAFB) };
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(16);
    v.menu_corner_radius = CornerRadius::same(10);
    v.window_shadow = Shadow {
        offset: [0, 12],
        blur: 32,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 120 } else { 40 }),
    };
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.warn_fg_color = p.review.0;
    v.error_fg_color = p.protected.0;
    v.override_text_color = None;

    let radius = CornerRadius::same(RADIUS_CONTROL);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text2);
    w.noninteractive.corner_radius = radius;
    for (state, fill, stroke) in [
        (&mut w.inactive, p.surface, p.border),
        (&mut w.hovered, p.accent_soft, p.accent),
        (&mut w.active, p.accent_soft, p.accent),
        (&mut w.open, p.surface, p.border),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::new(1.0, stroke);
        state.corner_radius = radius;
        state.expansion = 0.0;
    }
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    w.hovered.fg_stroke = Stroke::new(1.0, p.text);
    w.active.fg_stroke = Stroke::new(1.0, p.text);
    v
}

/// Fonts: the macOS system font when available (read from the OS at
/// runtime, never bundled), egui's default otherwise, plus Phosphor icons.
fn install_fonts(ctx: &egui::Context) {
    use egui::{FontData, FontDefinitions, FontFamily};
    let mut fonts = FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    if cfg!(target_os = "macos")
        && let Ok(bytes) = std::fs::read("/System/Library/Fonts/SFNS.ttf")
    {
        fonts.font_data.insert(
            "system".into(),
            std::sync::Arc::new(FontData::from_owned(bytes)),
        );
        if let Some(f) = fonts.families.get_mut(&FontFamily::Proportional) {
            f.insert(0, "system".into());
        }
    }
    ctx.set_fonts(fonts);
}

/// Applies the theme for both light and dark mode.
pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_visuals_of(Theme::Light, visuals(&LIGHT, false));
    ctx.set_visuals_of(Theme::Dark, visuals(&DARK, true));
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
        s.spacing.interact_size.y = 28.0;
        s.spacing.window_margin = Margin::same(20);
        use egui::{FontId, TextStyle};
        s.text_styles
            .insert(TextStyle::Heading, FontId::proportional(24.0));
        s.text_styles
            .insert(TextStyle::Body, FontId::proportional(14.0));
        s.text_styles
            .insert(TextStyle::Button, FontId::proportional(14.0));
        s.text_styles
            .insert(TextStyle::Small, FontId::proportional(11.5));
    });
}

/// A white (or dark-surface) card with a soft border.
pub fn card(ui: &egui::Ui) -> egui::Frame {
    let p = palette(ui);
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(RADIUS_CARD))
        .inner_margin(Margin::same(18))
}

/// The primary (accent) button.
pub fn primary_button(ui: &egui::Ui, text: &str) -> egui::Button<'static> {
    let p = palette(ui);
    egui::Button::new(
        egui::RichText::new(text.to_string())
            .color(p.on_accent)
            .strong(),
    )
    .fill(p.accent)
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(RADIUS_CONTROL))
    .min_size(egui::vec2(0.0, 32.0))
}

/// Where the light/dark choice is remembered (RustClean's own private data
/// folder, which is itself protected from cleanup).
fn preference_file(home: &std::path::Path) -> std::path::PathBuf {
    rustclean_safety::app_data_dir(home).join("appearance")
}

fn parse_preference(s: &str) -> egui::ThemePreference {
    match s.trim() {
        "light" => egui::ThemePreference::Light,
        "dark" => egui::ThemePreference::Dark,
        _ => egui::ThemePreference::System,
    }
}

fn preference_name(p: egui::ThemePreference) -> &'static str {
    match p {
        egui::ThemePreference::Light => "light",
        egui::ThemePreference::Dark => "dark",
        egui::ThemePreference::System => "system",
    }
}

/// Saved appearance; "follow the system" when missing or unreadable.
pub fn load_preference(home: &std::path::Path) -> egui::ThemePreference {
    std::fs::read_to_string(preference_file(home))
        .map(|s| parse_preference(&s))
        .unwrap_or(egui::ThemePreference::System)
}

/// Best effort: a failure only means the choice is not remembered.
pub fn save_preference(home: &std::path::Path, p: egui::ThemePreference) {
    let file = preference_file(home);
    let result = file
        .parent()
        .map_or(Ok(()), rustclean_safety::platform::create_private_dir)
        .and_then(|()| std::fs::write(&file, preference_name(p)));
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not save appearance preference");
    }
}

/// Compact System / Light / Dark switch. Applies the choice immediately.
pub fn appearance_switch(ui: &mut egui::Ui) {
    use egui::ThemePreference as T;
    use egui_phosphor::regular as i;
    let current = ui.ctx().options(|o| o.theme_preference);
    let p = palette(ui);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        for (pref, icon, tip) in [
            (T::System, i::DESKTOP, "Match the system appearance"),
            (T::Light, i::SUN, "Light mode"),
            (T::Dark, i::MOON, "Dark mode"),
        ] {
            let active = current == pref;
            let text =
                egui::RichText::new(icon)
                    .size(14.0)
                    .color(if active { p.accent } else { p.muted });
            let btn = egui::Button::new(text)
                .fill(if active {
                    p.accent_soft
                } else {
                    Color32::TRANSPARENT
                })
                .corner_radius(CornerRadius::same(RADIUS_CONTROL))
                .min_size(egui::vec2(30.0, 26.0));
            if ui.add(btn).on_hover_text(tip).clicked() && !active {
                ui.ctx().set_theme(pref);
            }
        }
    });
}

/// One-button variant for narrow top bars: cycles System → Light → Dark.
pub fn appearance_cycle_button(ui: &mut egui::Ui) {
    use egui::ThemePreference as T;
    use egui_phosphor::regular as i;
    let current = ui.ctx().options(|o| o.theme_preference);
    let (icon, next, tip) = match current {
        T::System => (i::DESKTOP, T::Light, "Appearance: system (click for light)"),
        T::Light => (i::SUN, T::Dark, "Appearance: light (click for dark)"),
        T::Dark => (i::MOON, T::System, "Appearance: dark (click for system)"),
    };
    let p = palette(ui);
    let btn = egui::Button::new(egui::RichText::new(icon).size(14.0).color(p.text2))
        .min_size(egui::vec2(30.0, 26.0));
    if ui.add(btn).on_hover_text(tip).clicked() {
        ui.ctx().set_theme(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preference_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        assert_eq!(load_preference(home), egui::ThemePreference::System);
        for p in [
            egui::ThemePreference::Dark,
            egui::ThemePreference::Light,
            egui::ThemePreference::System,
        ] {
            save_preference(home, p);
            assert_eq!(load_preference(home), p);
        }
        assert_eq!(parse_preference("garbage"), egui::ThemePreference::System);
    }
}
