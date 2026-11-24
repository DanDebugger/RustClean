//! Read-only persistence audit of this machine.
//!
//!     cargo run -p rustclean-security --example persistence_audit

fn main() {
    let home = rustclean_safety::home_dir().expect("home directory");
    let report = rustclean_security::scan_persistence(&home);
    for i in &report.items {
        let signals: Vec<String> = i.findings.iter().map(|f| f.describe()).collect();
        println!(
            "{:<8} {:<14} {:<45} {}",
            i.risk().label(),
            i.source.label(),
            i.label,
            if signals.is_empty() {
                String::new()
            } else {
                signals.join("; ")
            }
        );
    }
    println!("unreadable locations: {:?}", report.unreadable_locations);
}
