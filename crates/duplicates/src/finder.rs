//! Duplicate detection: size → partial BLAKE3 hash → full BLAKE3 hash.
//!
//! Safety rules:
//! * One copy of every set is always kept: it is marked `Protected` ("kept
//!   copy") and cannot be selected. The kept copy is the oldest file
//!   (ties: shortest path).
//! * Every other copy is `Review`, so nothing is pre-selected and removal
//!   needs explicit confirmation. Duplicates are never deleted automatically.
//! * Hard links to the same file are not duplicates (removing one frees
//!   nothing) and are collapsed.
//! * Files are only read, never modified.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use rustclean_core::{
    Candidate, CleanupModule, Progress, SafetyClass, ScanReport, ScanSpec, ScanTarget, format_bytes,
};

pub const DEFAULT_MIN_SIZE: u64 = 1024 * 1024;
const PARTIAL: usize = 64 * 1024;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".Trash", "$RECYCLE.BIN"];

#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    pub hash: String,
    pub size: u64,
    /// Indices into the candidate list; the first one is the kept copy.
    pub members: Vec<usize>,
}

fn hash_file(path: &Path, limit: Option<usize>) -> io::Result<blake3::Hash> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    match limit {
        Some(n) => {
            let mut buf = vec![0u8; n];
            let mut read = 0;
            while read < n {
                let k = f.read(&mut buf[read..])?;
                if k == 0 {
                    break;
                }
                read += k;
            }
            hasher.update(&buf[..read]);
        }
        None => {
            io::copy(&mut f, &mut hasher)?;
        }
    }
    Ok(hasher.finalize())
}

/// Groups candidates whose contents are identical. Groups are sorted by
/// wasted space (size × extra copies), largest first.
pub fn find_duplicates(candidates: &[Candidate], progress: &Progress) -> Vec<DuplicateGroup> {
    // 1. Same size (and not a hard link of a file already seen).
    let mut by_size: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut seen_inodes = std::collections::HashSet::new();
    for (i, c) in candidates.iter().enumerate() {
        if c.class != SafetyClass::Review && c.class != SafetyClass::Safe {
            continue;
        }
        let id = (c.fingerprint.device, c.fingerprint.inode);
        if id != (0, 0) && !seen_inodes.insert(id) {
            continue;
        }
        if c.size > 0 {
            by_size.entry(c.size).or_default().push(i);
        }
    }
    let same_size: Vec<Vec<usize>> = by_size.into_values().filter(|v| v.len() > 1).collect();

    // 2. Partial then 3. full hash, in parallel.
    let refine =
        |groups: Vec<Vec<usize>>, limit: Option<usize>| -> Vec<(blake3::Hash, Vec<usize>)> {
            groups
                .into_par_iter()
                .flat_map_iter(|group| {
                    let mut by_hash: HashMap<blake3::Hash, Vec<usize>> = HashMap::new();
                    for i in group {
                        if progress.is_cancelled() {
                            break;
                        }
                        if let Ok(h) = hash_file(&candidates[i].path, limit) {
                            progress.add(1, 0);
                            by_hash.entry(h).or_default().push(i);
                        }
                    }
                    by_hash.into_iter().filter(|(_, v)| v.len() > 1)
                })
                .collect()
        };
    let partial: Vec<Vec<usize>> = refine(same_size, Some(PARTIAL))
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    let mut groups: Vec<DuplicateGroup> = refine(partial, None)
        .into_iter()
        .map(|(hash, mut members)| {
            // Keep the oldest copy (ties: shortest path, then path order).
            members.sort_by(|&a, &b| {
                let (ca, cb) = (&candidates[a], &candidates[b]);
                ca.fingerprint
                    .modified
                    .cmp(&cb.fingerprint.modified)
                    .then(ca.path.as_os_str().len().cmp(&cb.path.as_os_str().len()))
                    .then(ca.path.cmp(&cb.path))
            });
            DuplicateGroup {
                hash: hash.to_hex().to_string(),
                size: candidates[members[0]].size,
                members,
            }
        })
        .collect();
    groups.sort_by(|a, b| {
        let wa = a.size * (a.members.len() as u64 - 1);
        let wb = b.size * (b.members.len() as u64 - 1);
        wb.cmp(&wa)
    });
    groups
}

/// Replaces the report's candidates with duplicate copies only, labelled by
/// set, keeping one protected copy per set.
pub fn mark_duplicates(report: ScanReport, progress: &Progress) -> ScanReport {
    let groups = find_duplicates(&report.candidates, progress);
    let mut out = Vec::new();
    for (n, g) in groups.iter().enumerate() {
        let kept_path = report.candidates[g.members[0]].path.clone();
        let label = format!(
            "Set {} · {} copies · {}",
            n + 1,
            g.members.len(),
            format_bytes(g.size)
        );
        for (k, &i) in g.members.iter().enumerate() {
            let mut c = report.candidates[i].clone();
            c.category = "Duplicates".into();
            c.context = Some(label.clone());
            if k == 0 {
                c.class = SafetyClass::Protected;
                c.reason = Some("kept copy: one copy of every set is always kept".into());
            } else {
                c.class = SafetyClass::Review;
                c.reason = Some(format!("identical to {}", kept_path.display()));
            }
            out.push(c);
        }
    }
    ScanReport {
        candidates: out,
        ..report
    }
}

pub struct DuplicatesModule {
    home: PathBuf,
    pub min_size: u64,
    roots: Vec<PathBuf>,
}

impl DuplicatesModule {
    pub fn new(home: PathBuf) -> Self {
        let roots = rustclean_storage::personal_roots(&home);
        Self {
            home,
            min_size: DEFAULT_MIN_SIZE,
            roots,
        }
    }

    fn targets(&self) -> Vec<ScanTarget> {
        self.roots
            .iter()
            .map(|r| {
                ScanTarget::new("Duplicates", r.clone(), SafetyClass::Review)
                    .min_size(self.min_size)
                    .skip_dirs(SKIP_DIRS)
            })
            .collect()
    }
}

impl CleanupModule for DuplicatesModule {
    fn title(&self) -> &str {
        "Duplicate Finder"
    }

    fn refresh(&mut self) {
        self.roots = rustclean_storage::personal_roots(&self.home);
    }

    fn is_available(&self) -> bool {
        !self.roots.is_empty()
    }

    fn details(&self) -> Vec<(String, String)> {
        let names: Vec<String> = self
            .roots
            .iter()
            .filter_map(|r| r.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        vec![
            ("Looks in".into(), names.join(", ")),
            ("Compares files over".into(), format_bytes(self.min_size)),
        ]
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "Files are compared by content (BLAKE3), not by name.".into(),
            "One copy of every set is always kept, and nothing is selected for you.".into(),
            "Database, virtual-machine and Git files are never offered; mounted folders are skipped.".into(),
        ]
    }

    fn prepare_scan(&self) -> ScanSpec {
        let mut spec = ScanSpec::new(
            self.targets(),
            Some(Box::new(rustclean_storage::DataFileClassifier)),
        );
        spec.post_process = Some(Box::new(mark_duplicates));
        spec
    }

    fn active_warning(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustclean_core::Scanner;
    use rustclean_safety::ProtectionRules;
    use std::fs;
    use std::time::{Duration, SystemTime};

    #[test]
    fn finds_identical_content_and_keeps_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        let home = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
        let dl = home.join("Downloads");
        let pr = home.join("Projects");
        fs::create_dir_all(&dl).unwrap();
        fs::create_dir_all(&pr).unwrap();
        let a = vec![7u8; 200_000];
        let mut b = a.clone();
        *b.last_mut().unwrap() = 8; // same size and same first 64 KB, different
        fs::write(dl.join("copy1.bin"), &a).unwrap();
        fs::write(pr.join("copy2.bin"), &a).unwrap();
        fs::write(pr.join("near.bin"), &b).unwrap();
        fs::write(dl.join("unique.bin"), vec![1u8; 300_000]).unwrap();
        // Make copy2 the oldest.
        File::options()
            .write(true)
            .open(pr.join("copy2.bin"))
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(86_400))
            .unwrap();
        #[cfg(unix)]
        fs::hard_link(dl.join("copy1.bin"), dl.join("hardlink.bin")).unwrap();

        let mut m = DuplicatesModule::new(home.clone());
        m.min_size = 1000;
        let spec = m.prepare_scan();
        let report = Scanner::new(ProtectionRules::for_home(&home)).scan(
            spec.targets,
            None,
            &Progress::new(),
        );
        let report = (spec.post_process.unwrap())(report, &Progress::new());
        let mut found: Vec<(String, SafetyClass)> = report
            .candidates
            .iter()
            .map(|c| (c.file_name(), c.class))
            .collect();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        // copy1 and its hard link are one file: only one of them appears.
        assert_eq!(found.len(), 2, "{found:?}");
        let kept: Vec<_> = found
            .iter()
            .filter(|f| f.1 == SafetyClass::Protected)
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, "copy2.bin", "oldest copy is kept");
        assert!(
            found
                .iter()
                .all(|f| f.0 != "near.bin" && f.0 != "unique.bin")
        );
    }
}
