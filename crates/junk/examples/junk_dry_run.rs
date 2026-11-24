//! Read-only: scans junk and developer caches and dry-runs Safe items.
//!
//!     cargo run --release -p rustclean-junk --example junk_dry_run

use rustclean_core::{
    Cleaner, CleanupModule, CleanupPlan, Progress, RemovalMethod, Remover, SafetyClass, Scanner,
    format_bytes,
};
use rustclean_junk::{DeveloperModule, JunkModule};
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

fn run(module: &dyn CleanupModule, rules: &ProtectionRules) {
    println!(
        "\n== {}  (warning: {:?})",
        module.title(),
        module.active_warning()
    );
    let spec = module.prepare_scan();
    let n_targets = spec.targets.len();
    let report = Scanner::new(rules.clone()).scan(
        spec.targets,
        spec.classifier.as_deref(),
        &Progress::new(),
    );
    println!(
        "{} targets, {} files in {:?}, {} unreadable",
        n_targets,
        report.candidates.len(),
        report.elapsed,
        report.issues.len()
    );
    for s in report.by_category() {
        println!(
            "  {:<24} {:>7} files {:>10} on disk {:>10} selectable",
            s.category,
            s.files,
            format_bytes(s.disk_usage),
            format_bytes(s.reclaimable)
        );
    }
    for c in [
        SafetyClass::Safe,
        SafetyClass::Review,
        SafetyClass::Unknown,
        SafetyClass::Protected,
    ] {
        print!(
            "  {}={} ",
            c.label(),
            report.candidates.iter().filter(|x| x.class == c).count()
        );
    }
    println!();
    let mut reasons = std::collections::BTreeMap::new();
    for c in report
        .candidates
        .iter()
        .filter(|c| c.class == SafetyClass::Review)
    {
        *reasons
            .entry(c.reason.clone().unwrap_or_default())
            .or_insert(0) += 1;
    }
    for (r, n) in reasons {
        println!("    review: {n:>6} × {r}");
    }
    let safe = report
        .candidates
        .iter()
        .filter(|c| c.class == SafetyClass::Safe);
    let plan = CleanupPlan::from_selection(safe, RemovalMethod::Trash, true);
    if plan.items().is_empty() {
        return;
    }
    let plan = plan.approve(false).unwrap();
    let r = Cleaner::new(rules.clone(), Box::new(Refuse), None).execute(&plan, &Progress::new());
    println!(
        "  dry run: would remove {} ({}), skipped {}, failed {}",
        r.would_remove(),
        format_bytes(r.bytes_affected()),
        r.skipped(),
        r.failed()
    );
    for i in r
        .results
        .iter()
        .filter(|i| matches!(i.outcome, rustclean_core::ItemOutcome::Skipped(_)))
        .take(5)
    {
        println!("    skipped {} : {:?}", i.path.display(), i.outcome);
    }
}

fn main() {
    let home = home_dir().expect("HOME");
    let rules = ProtectionRules::for_home(&home);
    run(&JunkModule::new(home.clone()), &rules);
    run(&DeveloperModule::new(home.clone()), &rules);
}
