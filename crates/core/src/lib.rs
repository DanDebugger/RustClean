//! RustClean core engines.
//!
//! The architecture deliberately separates discovery from removal:
//!
//! * [`scanner`] discovers and classifies files. It never modifies the
//!   filesystem.
//! * [`cleanup_plan`] turns a user selection into a plan that must be
//!   explicitly approved before it can be executed.
//! * [`cleaner`] executes an approved plan, re-validating every path and
//!   removing files only through a reversible [`Remover`].

pub mod classifier;
pub mod cleaner;
pub mod cleanup_plan;
pub mod module;
pub mod oplog;
pub mod recommend;
pub mod scanner;

pub use module::{CleanupModule, PostProcess, ScanSpec};
pub use scanner::DAY;

pub use classifier::{BaseClassifier, Classification, Classifier, SafetyClass};
pub use cleaner::{Cleaner, CleanupReport, ItemOutcome, ItemResult};
pub use cleanup_plan::{ApprovedPlan, CleanupPlan, PlanError, PlannedItem};
pub use oplog::OperationLog;
pub use recommend::{Recommendation, is_recommended, recommend};
pub use rustclean_safety::{RemovalMethod, Remover};
pub use scanner::{Candidate, CategorySummary, ScanIssue, ScanReport, ScanTarget, Scanner};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Shared progress counters and cancellation flag for long operations.
/// Safe to share between a worker thread and the UI.
#[derive(Debug, Default)]
pub struct Progress {
    items: AtomicU64,
    bytes: AtomicU64,
    cancel: AtomicBool,
}

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&self, items: u64, bytes: u64) {
        self.items.fetch_add(items, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn items(&self) -> u64 {
        self.items.load(Ordering::Relaxed)
    }
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// Formats a byte count using decimal units, as Finder does.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return format!("{bytes} bytes");
    }
    let mut value = bytes as f64;
    let mut unit = "bytes";
    for u in UNITS {
        if value < 1000.0 {
            break;
        }
        value /= 1000.0;
        unit = u;
    }
    format!("{value:.1} {unit}")
}

#[cfg(test)]
mod tests {
    use super::format_bytes;

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(0), "0 bytes");
        assert_eq!(format_bytes(999), "999 bytes");
        assert_eq!(format_bytes(1_000), "1.0 KB");
        assert_eq!(format_bytes(1_500_000), "1.5 MB");
        assert_eq!(format_bytes(2_340_000_000), "2.3 GB");
    }
}
