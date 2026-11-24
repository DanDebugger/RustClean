//! Headless, read-only check of Chrome detection and scanning.
//! Runs a dry-run cleanup of all Safe files; nothing is removed.
//!
//!     cargo run -p rustclean-browser --example chrome_dry_run

use rustclean_browser::{ChromeInstallation, is_chrome_running};
use rustclean_core::{
    Cleaner, CleanupPlan, Progress, RemovalMethod, Remover, SafetyClass, Scanner, format_bytes,
};
use rustclean_safety::{ProtectionRules, RemovalError, home_dir};
use std::path::{Path, PathBuf};

struct Refuse;
impl Remover for Refuse {
    fn method(&self) -> RemovalMethod {
        RemovalMethod::Trash
    }
    fn remove(&self, _: &Path) -> Result<Option<PathBuf>, RemovalError> {
        Err(RemovalError::Io(std::io::Error::other("dry run")))
    }
}

fn main() {
    let home = home_dir().expect("HOME");
    let Some(chrome) = ChromeInstallation::detect(&home) else {
        println!("Chrome not found");
        return;
    };
    println!("app bundle: {:?}", chrome.app_bundle);
    println!(
        "profiles:   {:?}",
        chrome
            .profiles
            .iter()
            .map(|p| p.label())
            .collect::<Vec<_>>()
    );
    println!("running:    {}", is_chrome_running());

    let rules = ProtectionRules::for_home(&home);
    let report = Scanner::new(rules.clone()).scan(
        chrome.scan_targets(),
        Some(&chrome.classifier()),
        &Progress::new(),
    );
    println!(
        "\nscanned {} files in {:?}, {} issues",
        report.candidates.len(),
        report.elapsed,
        report.issues.len()
    );
    for s in report.by_category() {
        println!(
            "  {:<24} {:>7} files  {:>10} on disk  {:>10} reclaimable",
            s.category,
            s.files,
            format_bytes(s.disk_usage),
            format_bytes(s.reclaimable)
        );
    }
    for class in [
        SafetyClass::Safe,
        SafetyClass::Review,
        SafetyClass::Unknown,
        SafetyClass::Protected,
    ] {
        let n = report
            .candidates
            .iter()
            .filter(|c| c.class == class)
            .count();
        println!("  {:<10} {n}", class.label());
    }
    println!(
        "estimated reclaimable: {}",
        format_bytes(report.reclaimable())
    );

    let safe = report
        .candidates
        .iter()
        .filter(|c| c.class == SafetyClass::Safe);
    let plan = CleanupPlan::from_selection(safe, RemovalMethod::Trash, true)
        .approve(false)
        .expect("approve");
    let result = Cleaner::new(rules, Box::new(Refuse), None).execute(&plan, &Progress::new());
    println!(
        "\ndry run: would remove {} ({}), skipped {}, failed {}",
        result.would_remove(),
        format_bytes(result.bytes_affected()),
        result.skipped(),
        result.failed()
    );
}
