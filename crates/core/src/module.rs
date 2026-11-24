//! The interface every file-based cleanup module implements, so the UI can
//! drive Chrome, junk and developer cleanup through one flow.

use crate::classifier::Classifier;
use crate::scanner::ScanTarget;

use crate::Progress;
use crate::scanner::ScanReport;

/// Optional step run on the worker thread after the scan, e.g. duplicate
/// grouping. It may only drop candidates or make their classification
/// stricter; it never touches the filesystem except to read.
pub type PostProcess = Box<dyn FnOnce(ScanReport, &Progress) -> ScanReport + Send>;

/// Everything a scan needs; moved onto the worker thread.
pub struct ScanSpec {
    pub targets: Vec<ScanTarget>,
    pub classifier: Option<Box<dyn Classifier>>,
    pub post_process: Option<PostProcess>,
}

impl ScanSpec {
    pub fn new(targets: Vec<ScanTarget>, classifier: Option<Box<dyn Classifier>>) -> Self {
        Self {
            targets,
            classifier,
            post_process: None,
        }
    }
}

pub trait CleanupModule: Send {
    fn title(&self) -> &str;

    /// Re-detects the environment (installed apps, running processes).
    fn refresh(&mut self);

    /// Whether there is anything to scan at all.
    fn is_available(&self) -> bool;

    /// Key/value facts shown above the results, e.g. ("Profiles", "...").
    fn details(&self) -> Vec<(String, String)>;

    /// Short explanatory notes (what is protected, what is skipped).
    fn notes(&self) -> Vec<String>;

    /// Targets and classifier for a scan. Must not touch the filesystem
    /// beyond cheap directory listing.
    fn prepare_scan(&self) -> ScanSpec;

    /// A condition that makes cleaning risky right now (e.g. the browser is
    /// running). Checked periodically and again immediately before a real
    /// cleanup; when present the user must acknowledge it.
    fn active_warning(&self) -> Option<String>;
}
