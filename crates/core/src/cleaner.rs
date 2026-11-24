//! Cleaner engine: executes an approved plan.
//!
//! Every item is re-validated immediately before removal. Items that fail
//! validation are skipped, never forced. Removal always goes through a
//! reversible [`Remover`] (Trash or quarantine).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rustclean_safety::{PathValidator, ProtectionRules, RemovalMethod, Remover, ValidationError};

use crate::Progress;
use crate::cleanup_plan::ApprovedPlan;
use crate::oplog::OperationLog;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemOutcome {
    /// Removed; `new_location` is where the file now lives, if known.
    Removed { new_location: Option<PathBuf> },
    /// Dry run: validation passed and the file would be removed.
    WouldRemove,
    /// Validation failed; the file was left untouched.
    Skipped(ValidationError),
    /// Validation passed but the removal itself failed.
    Failed(String),
    /// The operation was cancelled before this item was processed.
    NotAttempted,
}

#[derive(Debug, Clone)]
pub struct ItemResult {
    pub path: PathBuf,
    pub size: u64,
    pub disk_usage: u64,
    pub outcome: ItemOutcome,
}

#[derive(Debug, Clone)]
pub struct CleanupReport {
    pub session: String,
    pub dry_run: bool,
    pub method: RemovalMethod,
    pub results: Vec<ItemResult>,
    pub cancelled: bool,
}

impl CleanupReport {
    fn count(&self, f: impl Fn(&ItemOutcome) -> bool) -> usize {
        self.results.iter().filter(|r| f(&r.outcome)).count()
    }
    pub fn removed(&self) -> usize {
        self.count(|o| matches!(o, ItemOutcome::Removed { .. }))
    }
    pub fn would_remove(&self) -> usize {
        self.count(|o| matches!(o, ItemOutcome::WouldRemove))
    }
    pub fn skipped(&self) -> usize {
        self.count(|o| matches!(o, ItemOutcome::Skipped(_)))
    }
    pub fn failed(&self) -> usize {
        self.count(|o| matches!(o, ItemOutcome::Failed(_)))
    }
    pub fn not_attempted(&self) -> usize {
        self.count(|o| matches!(o, ItemOutcome::NotAttempted))
    }
    /// Disk usage of removed (or, in a dry run, removable) files.
    pub fn bytes_affected(&self) -> u64 {
        self.results
            .iter()
            .filter(|r| {
                matches!(
                    r.outcome,
                    ItemOutcome::Removed { .. } | ItemOutcome::WouldRemove
                )
            })
            .map(|r| r.disk_usage)
            .sum()
    }
}

pub struct Cleaner {
    rules: ProtectionRules,
    remover: Box<dyn Remover>,
    log: Option<OperationLog>,
}

impl Cleaner {
    pub fn new(
        rules: ProtectionRules,
        remover: Box<dyn Remover>,
        log: Option<OperationLog>,
    ) -> Self {
        Self {
            rules,
            remover,
            log,
        }
    }

    pub fn execute(&self, plan: &ApprovedPlan, progress: &Progress) -> CleanupReport {
        let session = format!(
            "{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            std::process::id()
        );
        // Validation scope is exactly the roots the user's selection came
        // from; protected roots are dropped by the validator.
        let validator = PathValidator::new(self.rules.clone(), plan.approved_roots());
        let method = self.remover.method();
        let method_name = format!("{method:?}");
        let dry_run = plan.dry_run;
        tracing::info!(
            %session, dry_run, ?method, items = plan.items().len(), "cleanup started"
        );

        let mut results = Vec::with_capacity(plan.items().len());
        for item in plan.items() {
            if progress.is_cancelled() {
                results.push(ItemResult {
                    path: item.path.clone(),
                    size: item.size,
                    disk_usage: item.disk_usage,
                    outcome: ItemOutcome::NotAttempted,
                });
                continue;
            }
            let outcome = match validator.validate_for_removal(&item.path, Some(&item.fingerprint))
            {
                Err(e) => ItemOutcome::Skipped(e),
                Ok(_) if dry_run => ItemOutcome::WouldRemove,
                // Act on the resolved path the validator just checked, not
                // the path as recorded at scan time.
                Ok(real_path) => match self.remover.remove(&real_path) {
                    Ok(new_location) => ItemOutcome::Removed { new_location },
                    Err(e) => ItemOutcome::Failed(e.to_string()),
                },
            };
            progress.add(1, item.disk_usage);

            if let Some(log) = &self.log {
                let (name, detail, new_loc) = match &outcome {
                    ItemOutcome::Removed { new_location } => {
                        ("removed", None, new_location.as_deref())
                    }
                    ItemOutcome::WouldRemove => ("would_remove", None, None),
                    ItemOutcome::Skipped(e) => ("skipped", Some(e.to_string()), None),
                    ItemOutcome::Failed(e) => ("failed", Some(e.clone()), None),
                    ItemOutcome::NotAttempted => ("not_attempted", None, None),
                };
                log.record(
                    &session,
                    dry_run,
                    &method_name,
                    &item.path,
                    name,
                    detail.as_deref(),
                    new_loc,
                    item.size,
                );
            }
            results.push(ItemResult {
                path: item.path.clone(),
                size: item.size,
                disk_usage: item.disk_usage,
                outcome,
            });
        }

        let report = CleanupReport {
            session,
            dry_run,
            method,
            results,
            cancelled: progress.is_cancelled(),
        };
        tracing::info!(
            session = %report.session,
            removed = report.removed(),
            would_remove = report.would_remove(),
            skipped = report.skipped(),
            failed = report.failed(),
            "cleanup finished"
        );
        report
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::SafetyClass;
    use crate::cleanup_plan::CleanupPlan;
    use crate::scanner::{ScanTarget, Scanner};
    use rustclean_safety::QuarantineRemover;
    use std::fs;
    use std::path::Path;

    struct Env {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        root: PathBuf,
        rules: ProtectionRules,
    }

    fn env() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let base = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
        let root = base.join("cache");
        fs::create_dir_all(&root).unwrap();
        let rules = ProtectionRules::for_home(base.join("home"));
        Env {
            _tmp: tmp,
            base,
            root,
            rules,
        }
    }

    fn scan(e: &Env, class: SafetyClass) -> crate::ScanReport {
        Scanner::new(e.rules.clone()).scan(
            vec![ScanTarget::new("Cache", e.root.clone(), class)],
            None,
            &Progress::new(),
        )
    }

    fn quarantine_cleaner(e: &Env, log: Option<OperationLog>) -> Cleaner {
        let q = QuarantineRemover::open(e.base.join("q")).unwrap();
        Cleaner::new(e.rules.clone(), Box::new(q), log)
    }

    #[test]
    fn dry_run_removes_nothing() {
        let e = env();
        fs::write(e.root.join("a"), b"1").unwrap();
        let report = scan(&e, SafetyClass::Safe);
        let plan = CleanupPlan::from_selection(&report.candidates, RemovalMethod::Quarantine, true)
            .approve(false)
            .unwrap();
        let result = quarantine_cleaner(&e, None).execute(&plan, &Progress::new());
        assert_eq!(result.would_remove(), 1);
        assert_eq!(result.removed(), 0);
        assert!(e.root.join("a").exists());
    }

    #[test]
    fn real_run_quarantines_and_logs() {
        let e = env();
        fs::write(e.root.join("a"), b"1").unwrap();
        let report = scan(&e, SafetyClass::Safe);
        let plan =
            CleanupPlan::from_selection(&report.candidates, RemovalMethod::Quarantine, false)
                .approve(false)
                .unwrap();
        let log_path = e.base.join("logs/ops.jsonl");
        let log = OperationLog::open(log_path.clone()).unwrap();
        let result = quarantine_cleaner(&e, Some(log)).execute(&plan, &Progress::new());
        assert_eq!(result.removed(), 1);
        assert!(!e.root.join("a").exists());
        match &result.results[0].outcome {
            ItemOutcome::Removed {
                new_location: Some(p),
            } => assert!(p.exists()),
            other => panic!("unexpected outcome {other:?}"),
        }
        let log = fs::read_to_string(log_path).unwrap();
        assert!(log.contains("\"outcome\":\"removed\""));
    }

    #[test]
    fn file_changed_after_scan_is_skipped() {
        let e = env();
        fs::write(e.root.join("a"), b"1").unwrap();
        let report = scan(&e, SafetyClass::Safe);
        fs::write(e.root.join("a"), b"modified since scan").unwrap();
        let plan =
            CleanupPlan::from_selection(&report.candidates, RemovalMethod::Quarantine, false)
                .approve(false)
                .unwrap();
        let result = quarantine_cleaner(&e, None).execute(&plan, &Progress::new());
        assert_eq!(
            result.results[0].outcome,
            ItemOutcome::Skipped(ValidationError::ChangedSinceScan)
        );
        assert!(e.root.join("a").exists());
    }

    #[test]
    fn file_replaced_by_symlink_after_scan_is_skipped() {
        let e = env();
        let precious = e.base.join("precious");
        fs::write(&precious, b"keep").unwrap();
        fs::write(e.root.join("a"), b"1").unwrap();
        let report = scan(&e, SafetyClass::Safe);
        fs::remove_file(e.root.join("a")).unwrap();
        std::os::unix::fs::symlink(&precious, e.root.join("a")).unwrap();
        let plan =
            CleanupPlan::from_selection(&report.candidates, RemovalMethod::Quarantine, false)
                .approve(false)
                .unwrap();
        let result = quarantine_cleaner(&e, None).execute(&plan, &Progress::new());
        assert_eq!(
            result.results[0].outcome,
            ItemOutcome::Skipped(ValidationError::Symlink)
        );
        assert_eq!(fs::read(&precious).unwrap(), b"keep");
    }

    #[test]
    fn tampered_target_root_cannot_widen_scope() {
        // Even if a candidate claims an approved root of "/", the protection
        // rules drop it and validation fails.
        let e = env();
        let outside = e.base.join("outside");
        fs::write(&outside, b"x").unwrap();
        let mut report = scan(&e, SafetyClass::Safe);
        assert!(report.candidates.is_empty());
        let mut c =
            crate::cleanup_plan::tests::candidate(outside.to_str().unwrap(), SafetyClass::Safe);
        c.target_root = PathBuf::from("/");
        c.fingerprint = rustclean_safety::FileFingerprint::from_metadata(
            &fs::symlink_metadata(&outside).unwrap(),
        );
        report.candidates.push(c);
        let plan =
            CleanupPlan::from_selection(&report.candidates, RemovalMethod::Quarantine, false)
                .approve(false)
                .unwrap();
        let result = quarantine_cleaner(&e, None).execute(&plan, &Progress::new());
        assert_eq!(
            result.results[0].outcome,
            ItemOutcome::Skipped(ValidationError::OutsideApprovedRoot)
        );
        assert!(Path::new(&outside).exists());
    }

    #[test]
    fn cancelled_cleanup_attempts_nothing() {
        let e = env();
        fs::write(e.root.join("a"), b"1").unwrap();
        let report = scan(&e, SafetyClass::Safe);
        let plan =
            CleanupPlan::from_selection(&report.candidates, RemovalMethod::Quarantine, false)
                .approve(false)
                .unwrap();
        let progress = Progress::new();
        progress.cancel();
        let result = quarantine_cleaner(&e, None).execute(&plan, &progress);
        assert_eq!(result.not_attempted(), 1);
        assert!(e.root.join("a").exists());
    }
}
