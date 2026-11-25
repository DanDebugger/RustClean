//! Read-only built-in protection check of this machine.
//!
//!     cargo run -p rustclean-security --example protection_status

use rustclean_security::{ProtectionStatus, scan_protection};

fn main() {
    let report = scan_protection();
    for c in &report.checks {
        let status = match c.status {
            ProtectionStatus::On => "On",
            ProtectionStatus::Off => "Off",
            ProtectionStatus::Unknown => "Unknown",
        };
        println!("{:<8} {:<30} {}", status, c.name, c.detail);
    }
    println!(
        "on: {}  off: {}  unknown: {}",
        report.count(ProtectionStatus::On),
        report.count(ProtectionStatus::Off),
        report.count(ProtectionStatus::Unknown)
    );
    for n in &report.notes {
        println!("note: {n}");
    }
}
