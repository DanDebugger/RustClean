//! Read-only: large files and duplicate sets in your personal folders.
//!
//!     cargo run --release -p rustclean-duplicates --example find_dupes
use rustclean_core::{CleanupModule, Progress, SafetyClass, Scanner, format_bytes};
use rustclean_safety::{ProtectionRules, home_dir};

fn main() {
    let home = home_dir().expect("home");
    let rules = ProtectionRules::for_home(&home);
    let m = rustclean_duplicates::DuplicatesModule::new(home.clone());
    println!("{:?}", m.details());
    let spec = m.prepare_scan();
    let t = std::time::Instant::now();
    let p = Progress::new();
    let r = Scanner::new(rules).scan(spec.targets, spec.classifier.as_deref(), &p);
    println!(
        "scanned {} files ≥ 1 MiB in {:?}",
        r.candidates.len(),
        t.elapsed()
    );
    let r = (spec.post_process.unwrap())(r, &p);
    let sets = r
        .candidates
        .iter()
        .filter(|c| c.class == SafetyClass::Protected)
        .count();
    let extra: u64 = r
        .candidates
        .iter()
        .filter(|c| c.class == SafetyClass::Review)
        .map(|c| c.disk_usage)
        .sum();
    println!(
        "{sets} duplicate sets, {} extra copies, {} reclaimable, total {:?}",
        r.candidates.len() - sets,
        format_bytes(extra),
        t.elapsed()
    );
    for c in r.candidates.iter().take(6) {
        println!(
            "  {:<9} {:<40} {}",
            c.class.label(),
            c.context.clone().unwrap_or_default(),
            c.path.strip_prefix(&home).unwrap_or(&c.path).display()
        );
    }
}
