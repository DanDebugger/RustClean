//! End-to-end check of a REAL cleanup through the Trash, on one throwaway
//! file this program creates. Nothing else is touched.
//!
//!     cargo run -p rustclean-core --example trash_e2e
use rustclean_core::{
    Cleaner, CleanupPlan, ItemOutcome, Progress, RemovalMethod, SafetyClass, ScanTarget, Scanner,
};
use rustclean_safety::{ProtectionRules, TrashRemover, home_dir, platform};

fn main() {
    let home = home_dir().expect("home");
    let dir = platform::user_cache_dir(&home).join("RustCleanTrashCheck");
    std::fs::create_dir_all(&dir).unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let file = dir.join(format!("rustclean-trash-check-{stamp}.txt"));
    std::fs::write(&file, b"RustClean end-to-end Trash check. Safe to delete.").unwrap();

    let rules = ProtectionRules::for_home(&home);
    let report = Scanner::new(rules.clone()).scan(
        vec![ScanTarget::new("Test", dir.clone(), SafetyClass::Safe)],
        None,
        &Progress::new(),
    );
    assert_eq!(report.candidates.len(), 1, "expected exactly the test file");
    let plan = CleanupPlan::from_selection(&report.candidates, RemovalMethod::Trash, false)
        .approve(false)
        .unwrap();
    let result =
        Cleaner::new(rules, Box::new(TrashRemover::new()), None).execute(&plan, &Progress::new());
    println!("file: {}", file.display());
    println!("outcome: {:?}", result.results[0].outcome);
    println!("still at original location: {}", file.exists());
    assert!(matches!(
        result.results[0].outcome,
        ItemOutcome::Removed { .. }
    ));
    std::fs::remove_dir(&dir).ok();
}
