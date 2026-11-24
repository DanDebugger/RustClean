//! RustClean desktop application.

// Release builds on Windows are GUI apps: no extra console window.
// Debug builds keep the console so `cargo run` still shows logs.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod dashboard;
mod docker_page;
mod jobs;
mod navigation;
mod scan_page;
mod security_page;
mod smart_scan;
mod theme;
mod tool_pages;
#[cfg(test)]
mod ui_snapshots;
mod widgets;

use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RustClean")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([360.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "RustClean",
        options,
        Box::new(|cc| Ok(Box::new(app::RustCleanApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("failed to start RustClean: {e}"))
}
