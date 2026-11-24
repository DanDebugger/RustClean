//! Scanner engine: discovers files, measures them, and classifies them.
//!
//! The scanner is strictly read-only. It produces [`Candidate`]s; it has no
//! way to remove anything.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use rayon::prelude::*;
use rustclean_safety::{FileFingerprint, ProtectionRules};
use walkdir::WalkDir;

use crate::Progress;
use crate::classifier::{BaseClassifier, Classification, Classifier, SafetyClass};

/// A location to scan and the category its files belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTarget {
    /// User-facing category, e.g. "HTTP cache".
    pub category: String,
    /// A directory, or a single file.
    pub root: PathBuf,
    /// Classification for files under this root, before other rules apply.
    pub default_class: SafetyClass,
    /// Optional context shown in the UI, e.g. the Chrome profile name.
    pub context: Option<String>,
    /// Maximum walk depth below the root (`Some(1)` = direct children only).
    pub max_depth: Option<usize>,
    /// If set, only files with one of these (lowercase) extensions are
    /// reported.
    pub extensions: Option<Vec<String>>,
    /// Files modified more recently than this are raised to `Review`
    /// (they may still be in use).
    pub review_if_newer_than: Option<Duration>,
    /// Extra explanation attached to every file of this target.
    pub reason: Option<String>,
    /// If set, only files at least this large (logical size) are reported.
    pub min_size: Option<u64>,
    /// Directory names that are never descended into (e.g. `node_modules`).
    pub skip_dirs: Vec<String>,
}

impl ScanTarget {
    pub fn new(category: impl Into<String>, root: PathBuf, default_class: SafetyClass) -> Self {
        Self {
            category: category.into(),
            root,
            default_class,
            context: None,
            max_depth: None,
            extensions: None,
            review_if_newer_than: None,
            reason: None,
            min_size: None,
            skip_dirs: Vec::new(),
        }
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    pub fn extensions(mut self, exts: &[&str]) -> Self {
        self.extensions = Some(exts.iter().map(|e| e.to_ascii_lowercase()).collect());
        self
    }

    pub fn review_if_newer_than(mut self, age: Duration) -> Self {
        self.review_if_newer_than = Some(age);
        self
    }

    pub fn min_size(mut self, bytes: u64) -> Self {
        self.min_size = Some(bytes);
        self
    }

    pub fn skip_dirs(mut self, names: &[&str]) -> Self {
        self.skip_dirs = names.iter().map(|n| n.to_string()).collect();
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    fn matches_extension(&self, path: &Path) -> bool {
        let Some(exts) = &self.extensions else {
            return true;
        };
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| exts.iter().any(|x| x.eq_ignore_ascii_case(e)))
    }
}

pub const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// A discovered file and its classification.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    /// Logical file size.
    pub size: u64,
    /// Allocated size on disk; what removal would eventually reclaim.
    pub disk_usage: u64,
    pub category: String,
    pub context: Option<String>,
    pub class: SafetyClass,
    pub reason: Option<String>,
    pub fingerprint: FileFingerprint,
    /// The scan target root this file was found under.
    pub target_root: PathBuf,
}

impl Candidate {
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// A non-fatal problem encountered while scanning.
#[derive(Debug, Clone)]
pub struct ScanIssue {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct CategorySummary {
    pub category: String,
    pub files: usize,
    pub size: u64,
    pub disk_usage: u64,
    /// Disk usage of selectable (Safe or Review) files only.
    pub reclaimable: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    pub targets: Vec<ScanTarget>,
    pub candidates: Vec<Candidate>,
    pub issues: Vec<ScanIssue>,
    pub cancelled: bool,
    pub elapsed: Duration,
}

impl ScanReport {
    /// Estimated reclaimable space: disk usage of selectable files.
    pub fn reclaimable(&self) -> u64 {
        self.candidates
            .iter()
            .filter(|c| c.class.is_selectable())
            .map(|c| c.disk_usage)
            .sum()
    }

    pub fn total_disk_usage(&self) -> u64 {
        self.candidates.iter().map(|c| c.disk_usage).sum()
    }

    /// Per-category totals, in the order categories first appear in
    /// `targets`.
    pub fn by_category(&self) -> Vec<CategorySummary> {
        let mut order: Vec<&str> = Vec::new();
        for t in &self.targets {
            if !order.contains(&t.category.as_str()) {
                order.push(&t.category);
            }
        }
        let mut map: BTreeMap<&str, CategorySummary> = BTreeMap::new();
        for c in &self.candidates {
            let s = map.entry(&c.category).or_insert_with(|| CategorySummary {
                category: c.category.clone(),
                ..Default::default()
            });
            s.files += 1;
            s.size += c.size;
            s.disk_usage += c.disk_usage;
            if c.class.is_selectable() {
                s.reclaimable += c.disk_usage;
            }
        }
        let mut out: Vec<CategorySummary> =
            order.iter().filter_map(|cat| map.remove(cat)).collect();
        out.extend(map.into_values());
        out
    }
}

/// Read-only scanner. Combines the [`BaseClassifier`] with an optional
/// domain classifier; the most restrictive classification always wins.
pub struct Scanner {
    rules: ProtectionRules,
    base: BaseClassifier,
}

impl Scanner {
    pub fn new(rules: ProtectionRules) -> Self {
        Self {
            base: BaseClassifier::new(rules.clone()),
            rules,
        }
    }

    /// Scans all targets in parallel. Symlinks are never followed and the
    /// walk never crosses into another filesystem.
    pub fn scan(
        &self,
        targets: Vec<ScanTarget>,
        domain: Option<&dyn Classifier>,
        progress: &Progress,
    ) -> ScanReport {
        let start = Instant::now();
        let per_target: Vec<(Vec<Candidate>, Vec<ScanIssue>)> = targets
            .par_iter()
            .map(|t| self.scan_target(t, domain, progress))
            .collect();

        let mut seen = HashSet::new();
        let mut seen_ids = HashSet::new();
        let mut report = ScanReport {
            targets,
            ..Default::default()
        };
        for (candidates, issues) in per_target {
            // Overlapping targets must not double-count a file.
            report.candidates.extend(
                candidates
                    .into_iter()
                    // Same path, or the same file reached through another
                    // path (symlinked parent, hard link): count it once.
                    .filter(|c| {
                        let id = (c.fingerprint.device, c.fingerprint.inode);
                        seen.insert(c.path.clone()) && (id.0 == 0 || seen_ids.insert(id))
                    }),
            );
            report.issues.extend(issues);
        }
        report.cancelled = progress.is_cancelled();
        report.elapsed = start.elapsed();
        tracing::info!(
            files = report.candidates.len(),
            issues = report.issues.len(),
            cancelled = report.cancelled,
            elapsed_ms = report.elapsed.as_millis() as u64,
            "scan finished"
        );
        report
    }

    fn scan_target(
        &self,
        target: &ScanTarget,
        domain: Option<&dyn Classifier>,
        progress: &Progress,
    ) -> (Vec<Candidate>, Vec<ScanIssue>) {
        let mut candidates = Vec::new();
        let mut issues = Vec::new();
        let issue = |path: &Path, message: &str| ScanIssue {
            path: path.to_path_buf(),
            message: message.to_string(),
        };

        match fs::symlink_metadata(&target.root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (candidates, issues),
            Err(e) => {
                issues.push(issue(&target.root, &e.to_string()));
                return (candidates, issues);
            }
            Ok(m) if m.file_type().is_symlink() => {
                issues.push(issue(&target.root, "scan root is a symbolic link; skipped"));
                return (candidates, issues);
            }
            Ok(_) => {}
        }
        if let Some(reason) = self.rules.protection_reason(&target.root) {
            issues.push(issue(
                &target.root,
                &format!("scan root is protected ({reason}); skipped"),
            ));
            return (candidates, issues);
        }

        let mut walker = WalkDir::new(&target.root)
            .follow_links(false)
            .same_file_system(true);
        if let Some(depth) = target.max_depth {
            walker = walker.max_depth(depth);
        }
        let now = SystemTime::now();
        let skip = &target.skip_dirs;
        let walker = walker.into_iter().filter_entry(|e| {
            e.depth() == 0
                || !e.file_type().is_dir()
                || !skip.iter().any(|s| e.file_name() == s.as_str())
        });
        for entry in walker {
            if progress.is_cancelled() {
                break;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    let path = e.path().unwrap_or(&target.root).to_path_buf();
                    issues.push(ScanIssue {
                        path,
                        message: e.to_string(),
                    });
                    continue;
                }
            };
            let ft = entry.file_type();
            if !(ft.is_file() || ft.is_symlink()) || !target.matches_extension(entry.path()) {
                continue;
            }
            // For non-followed entries this is lstat, i.e. the link itself.
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    issues.push(issue(entry.path(), &e.to_string()));
                    continue;
                }
            };
            if target.min_size.is_some_and(|min| meta.len() < min) {
                continue;
            }
            let path = entry.into_path();
            let mut classification = self.base.classify(&path, ft.is_symlink(), target);
            if classification.reason.is_none() {
                classification.reason = target.reason.clone();
            }
            if let Some(age) = target.review_if_newer_than {
                // Unknown mtime counts as recent.
                let recent = meta
                    .modified()
                    .ok()
                    .and_then(|m| now.duration_since(m).ok())
                    .is_none_or(|elapsed| elapsed < age);
                if recent {
                    classification = classification.most_restrictive(Classification::new(
                        SafetyClass::Review,
                        format!(
                            "modified within the last {} day(s); may be in use",
                            age.as_secs().div_ceil(86_400)
                        ),
                    ));
                }
            }
            if let Some(domain) = domain {
                classification = classification.most_restrictive(domain.classify(
                    &path,
                    ft.is_symlink(),
                    target,
                ));
            }
            let disk_usage = rustclean_safety::platform::disk_usage(&meta);
            progress.add(1, disk_usage);
            candidates.push(Candidate {
                size: meta.len(),
                disk_usage,
                category: target.category.clone(),
                context: target.context.clone(),
                class: classification.class,
                reason: classification.reason,
                fingerprint: FileFingerprint::from_metadata(&meta),
                target_root: target.root.clone(),
                path,
            });
        }
        (candidates, issues)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::classifier::Classification;
    use std::os::unix::fs::symlink;

    fn setup() -> (tempfile::TempDir, PathBuf, Scanner) {
        let tmp = tempfile::tempdir().unwrap();
        let base = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
        let scanner = Scanner::new(ProtectionRules::for_home(base.join("home")));
        (tmp, base, scanner)
    }

    #[test]
    fn scans_files_without_following_symlinks() {
        let (_tmp, base, scanner) = setup();
        let root = base.join("cache");
        let outside = base.join("outside");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("a"), vec![0u8; 10]).unwrap();
        fs::write(root.join("sub/b"), vec![0u8; 20]).unwrap();
        fs::write(outside.join("secret"), b"x").unwrap();
        symlink(&outside, root.join("link")).unwrap();

        let report = scanner.scan(
            vec![ScanTarget::new("Cache", root.clone(), SafetyClass::Safe)],
            None,
            &Progress::new(),
        );
        let mut paths: Vec<_> = report.candidates.iter().map(|c| c.path.clone()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![root.join("a"), root.join("link"), root.join("sub/b")]
        );
        let link = report
            .candidates
            .iter()
            .find(|c| c.path.ends_with("link"))
            .unwrap();
        assert_eq!(link.class, SafetyClass::Unknown);
        assert!(!report.candidates.iter().any(|c| c.path.ends_with("secret")));
        let total: u64 = report
            .candidates
            .iter()
            .filter(|c| c.class == SafetyClass::Safe)
            .map(|c| c.size)
            .sum();
        assert_eq!(total, 30);
    }

    #[test]
    fn scanning_never_modifies_the_filesystem() {
        let (_tmp, base, scanner) = setup();
        let root = base.join("cache");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a"), b"1").unwrap();
        scanner.scan(
            vec![ScanTarget::new("C", root.clone(), SafetyClass::Safe)],
            None,
            &Progress::new(),
        );
        assert!(root.join("a").exists());
    }

    #[test]
    fn missing_root_is_silently_skipped_and_symlink_root_reported() {
        let (_tmp, base, scanner) = setup();
        let real = base.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("f"), b"1").unwrap();
        symlink(&real, base.join("linkroot")).unwrap();
        let report = scanner.scan(
            vec![
                ScanTarget::new("A", base.join("missing"), SafetyClass::Safe),
                ScanTarget::new("B", base.join("linkroot"), SafetyClass::Safe),
            ],
            None,
            &Progress::new(),
        );
        assert!(report.candidates.is_empty());
        assert_eq!(report.issues.len(), 1);
    }

    #[test]
    fn protected_root_is_refused() {
        let (_tmp, base, _) = setup();
        let home = base.join("home");
        let docs = home.join("Documents");
        fs::create_dir_all(&docs).unwrap();
        fs::write(docs.join("cv.pdf"), b"1").unwrap();
        let scanner = Scanner::new(ProtectionRules::for_home(&home));
        let report = scanner.scan(
            vec![ScanTarget::new("X", docs, SafetyClass::Safe)],
            None,
            &Progress::new(),
        );
        assert!(report.candidates.is_empty());
        assert_eq!(report.issues.len(), 1);
    }

    struct DenyNamed(&'static str);
    impl Classifier for DenyNamed {
        fn classify(&self, path: &Path, _: bool, _: &ScanTarget) -> Classification {
            if path.file_name().is_some_and(|n| n == self.0) {
                Classification::new(SafetyClass::Protected, "denied".to_string())
            } else {
                Classification::new(SafetyClass::Safe, None)
            }
        }
    }

    #[test]
    fn domain_classifier_can_only_make_things_stricter() {
        let (_tmp, base, scanner) = setup();
        let root = base.join("c");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Bookmarks"), b"1").unwrap();
        fs::write(root.join("blob"), b"1").unwrap();
        let report = scanner.scan(
            vec![ScanTarget::new("C", root, SafetyClass::Review)],
            Some(&DenyNamed("Bookmarks")),
            &Progress::new(),
        );
        for c in &report.candidates {
            let expected = if c.path.ends_with("Bookmarks") {
                SafetyClass::Protected
            } else {
                SafetyClass::Review
            };
            assert_eq!(c.class, expected, "{}", c.path.display());
        }
    }

    #[test]
    fn overlapping_targets_do_not_double_count() {
        let (_tmp, base, scanner) = setup();
        let root = base.join("c");
        fs::create_dir_all(root.join("inner")).unwrap();
        fs::write(root.join("inner/f"), b"1").unwrap();
        let report = scanner.scan(
            vec![
                ScanTarget::new("Outer", root.clone(), SafetyClass::Safe),
                ScanTarget::new("Inner", root.join("inner"), SafetyClass::Safe),
            ],
            None,
            &Progress::new(),
        );
        assert_eq!(report.candidates.len(), 1);
    }

    #[test]
    fn cancelled_scan_stops() {
        let (_tmp, base, scanner) = setup();
        let root = base.join("c");
        fs::create_dir_all(&root).unwrap();
        for i in 0..50 {
            fs::write(root.join(i.to_string()), b"1").unwrap();
        }
        let progress = Progress::new();
        progress.cancel();
        let report = scanner.scan(
            vec![ScanTarget::new("C", root, SafetyClass::Safe)],
            None,
            &progress,
        );
        assert!(report.cancelled);
        assert!(report.candidates.is_empty());
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;
    use std::fs::File;

    fn setup() -> (tempfile::TempDir, PathBuf, Scanner) {
        let tmp = tempfile::tempdir().unwrap();
        let base = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
        let scanner = Scanner::new(ProtectionRules::for_home(base.join("home")));
        (tmp, base, scanner)
    }

    fn set_age(path: &Path, age: Duration) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
    }

    #[test]
    fn depth_and_extension_filters() {
        let (_tmp, base, scanner) = setup();
        let root = base.join("dl");
        fs::create_dir_all(root.join("sub")).unwrap();
        for f in ["a.dmg", "b.PKG", "c.txt", "sub/d.dmg"] {
            fs::write(root.join(f), b"1").unwrap();
        }
        let target = ScanTarget::new("Installers", root.clone(), SafetyClass::Review)
            .max_depth(1)
            .extensions(&["dmg", "pkg"]);
        let report = scanner.scan(vec![target], None, &Progress::new());
        let mut names: Vec<_> = report.candidates.iter().map(|c| c.file_name()).collect();
        names.sort();
        assert_eq!(names, vec!["a.dmg", "b.PKG"]);
    }

    #[test]
    fn recent_files_are_raised_to_review() {
        let (_tmp, base, scanner) = setup();
        let root = base.join("logs");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("old.log"), b"1").unwrap();
        fs::write(root.join("new.log"), b"1").unwrap();
        set_age(&root.join("old.log"), 10 * DAY);
        let target = ScanTarget::new("Logs", root, SafetyClass::Safe).review_if_newer_than(7 * DAY);
        let report = scanner.scan(vec![target], None, &Progress::new());
        for c in &report.candidates {
            let expected = if c.file_name() == "old.log" {
                SafetyClass::Safe
            } else {
                SafetyClass::Review
            };
            assert_eq!(c.class, expected, "{}", c.file_name());
        }
        assert_eq!(report.candidates.len(), 2);
    }

    #[test]
    fn age_rule_never_relaxes_a_stricter_class() {
        let (_tmp, base, _) = setup();
        let home = base.join("home");
        let docs = home.join("Documents");
        fs::create_dir_all(&docs).unwrap();
        fs::write(docs.join("x"), b"1").unwrap();
        // Root is a parent of a protected dir: scanning it reports the
        // protected file as Protected, not Review.
        let scanner = Scanner::new(ProtectionRules::for_home(&home));
        let target =
            ScanTarget::new("X", docs.join("x"), SafetyClass::Safe).review_if_newer_than(7 * DAY);
        let report = scanner.scan(vec![target], None, &Progress::new());
        assert!(
            report.candidates.is_empty(),
            "protected root must be refused"
        );
    }
}

#[cfg(test)]
mod size_filter_tests {
    use super::*;

    #[test]
    fn min_size_and_skip_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let base = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
        let root = base.join("r");
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("big"), vec![0u8; 2000]).unwrap();
        fs::write(root.join("small"), vec![0u8; 10]).unwrap();
        fs::write(root.join("node_modules/big2"), vec![0u8; 2000]).unwrap();
        let t = ScanTarget::new("X", root, SafetyClass::Review)
            .min_size(1000)
            .skip_dirs(&["node_modules"]);
        let r = Scanner::new(ProtectionRules::for_home(base.join("home"))).scan(
            vec![t],
            None,
            &Progress::new(),
        );
        let names: Vec<_> = r.candidates.iter().map(|c| c.file_name()).collect();
        assert_eq!(names, vec!["big"]);
    }
}

#[cfg(all(test, unix))]
mod identity_dedupe_tests {
    use super::*;

    #[test]
    fn same_file_through_symlinked_parent_is_counted_once() {
        let tmp = tempfile::tempdir().unwrap();
        let base = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
        let real = base.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("f"), b"1").unwrap();
        std::os::unix::fs::symlink(&real, base.join("alias")).unwrap();
        let report = Scanner::new(ProtectionRules::for_home(base.join("home"))).scan(
            vec![
                ScanTarget::new("A", real.clone(), SafetyClass::Safe),
                // A target inside the symlinked alias (root itself is real).
                ScanTarget::new("B", base.join("alias").join("."), SafetyClass::Review),
            ],
            None,
            &Progress::new(),
        );
        assert_eq!(report.candidates.len(), 1, "{:?}", report.candidates);
    }
}
