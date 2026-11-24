//! Large File finder.
//!
//! Large files are usually *your* files, so every result is `Review`:
//! nothing is pre-selected and removal needs explicit confirmation. Only
//! personal folders that are not protected are scanned (on macOS that is
//! e.g. `~/Downloads` and your own top-level folders; `~/Documents`,
//! `~/Desktop`, `~/Pictures`, `~/Movies` and `~/Music` are protected and
//! never offered).

use std::fs;
use std::path::{Path, PathBuf};

use rustclean_core::{Classification, Classifier};
use rustclean_core::{CleanupModule, SafetyClass, ScanReport, ScanSpec, ScanTarget, format_bytes};
use rustclean_safety::{ProtectionRules, platform};

pub const DEFAULT_THRESHOLD: u64 = 500 * 1024 * 1024;

/// Folders whose contents are tool-managed or rebuilt, not personal files.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".Trash", "$RECYCLE.BIN"];

/// Top-level folders of the home directory that hold personal files and
/// are not protected. Hidden folders and the system `Library`/`AppData`
/// folders are excluded.
pub fn personal_roots(home: &Path) -> Vec<PathBuf> {
    let rules = ProtectionRules::for_home(home);
    // Folders on another device (virtual mounts such as ~/OrbStack, network
    // shares) are not your local files: never scanned.
    let home_dev = fs::metadata(home)
        .ok()
        .map(|m| platform::file_identity(&m).1);
    let Ok(entries) = fs::read_dir(home) else {
        return Vec::new();
    };
    let mut roots: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .filter(|p| {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            !name.starts_with('.')
                && !matches!(
                    name.as_str(),
                    "Library" | "AppData" | "Applications" | "snap"
                )
                && !rules.is_protected(p)
                && fs::metadata(p).ok().map(|m| platform::file_identity(&m).1) == home_dev
        })
        .collect();
    roots.sort();
    roots
}

/// File extensions of live databases.
const DB_EXTENSIONS: &[&str] = &[
    "sqlite",
    "sqlite3",
    "sqlite-wal",
    "sqlite-shm",
    "db",
    "db-wal",
    "db-shm",
    "wt",
    "ldb",
    "mdb",
    "ibd",
    "frm",
    "myd",
    "myi",
    "realm",
    "lmdb",
    "rdb",
    "aof",
];

/// Virtual-machine disks (often in use by a running VM).
const VM_EXTENSIONS: &[&str] = &["vmdk", "vdi", "qcow2", "vhd", "vhdx", "hdd", "utm", "raw"];

/// Path components that indicate database or VCS internals.
const DATA_DIRS: &[&str] = &[
    ".git", ".hg", ".svn", "journal", "pg_wal", "base", "data/db",
];

/// Why a file must never be offered for removal, if it looks like part of a
/// database, a VM disk or version-control internals.
pub fn data_file_reason(path: &Path) -> Option<&'static str> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.starts_with("wiredtiger") || DB_EXTENSIONS.contains(&ext.as_str()) {
        return Some("database file: removing it can corrupt the database");
    }
    if VM_EXTENSIONS.contains(&ext.as_str()) {
        return Some("virtual machine disk: may be in use by a VM");
    }
    let s = path.to_string_lossy().replace('\\', "/").to_lowercase();
    if path.components().any(|c| {
        let c = c.as_os_str().to_string_lossy().to_lowercase();
        DATA_DIRS.contains(&c.as_str()) || c == "pg_version"
    }) || s.contains("/data/db/")
    {
        return Some("part of a database or version-control store");
    }
    None
}

/// Protects database, VM and version-control files in personal folders.
pub struct DataFileClassifier;

impl Classifier for DataFileClassifier {
    fn classify(&self, path: &Path, _: bool, _: &ScanTarget) -> Classification {
        match data_file_reason(path) {
            Some(r) => Classification::new(SafetyClass::Protected, r.to_string()),
            None => Classification::new(SafetyClass::Safe, None),
        }
    }
}

/// Friendly type for a file, from its extension.
pub fn file_kind(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "mp4" | "mov" | "mkv" | "avi" | "m4v" | "webm" | "wmv" => "Videos",
        "dmg" | "iso" | "img" | "pkg" | "exe" | "msi" | "deb" | "rpm" | "xip" | "appimage" => {
            "Disk images & installers"
        }
        "zip" | "tar" | "gz" | "tgz" | "7z" | "rar" | "xz" | "bz2" | "zst" => "Archives",
        "wav" | "flac" | "aiff" | "mp3" | "m4a" => "Audio",
        "psd" | "raw" | "cr2" | "nef" | "tif" | "tiff" | "heic" | "png" | "jpg" | "jpeg" => {
            "Images"
        }
        "vmdk" | "vdi" | "qcow2" | "vhd" | "vhdx" | "ova" | "hdd" | "utm" => "Virtual machines",
        _ => "Other files",
    }
}

/// Re-labels every candidate's category with its file type.
pub fn categorise_by_kind(mut report: ScanReport) -> ScanReport {
    for c in &mut report.candidates {
        c.category = file_kind(&c.path).to_string();
    }
    report
}

pub struct LargeFilesModule {
    home: PathBuf,
    pub threshold: u64,
    roots: Vec<PathBuf>,
}

impl LargeFilesModule {
    pub fn new(home: PathBuf) -> Self {
        let roots = personal_roots(&home);
        Self {
            home,
            threshold: DEFAULT_THRESHOLD,
            roots,
        }
    }

    pub fn targets(&self) -> Vec<ScanTarget> {
        self.roots
            .iter()
            .map(|r| {
                let name = r
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                ScanTarget::new("Large files", r.clone(), SafetyClass::Review)
                    .min_size(self.threshold)
                    .skip_dirs(SKIP_DIRS)
                    .with_context(format!("~/{name}"))
                    .with_reason("your file: check that you no longer need it")
            })
            .collect()
    }
}

impl CleanupModule for LargeFilesModule {
    fn title(&self) -> &str {
        "Large Files"
    }

    fn refresh(&mut self) {
        self.roots = personal_roots(&self.home);
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
            ("Shows files over".into(), format_bytes(self.threshold)),
        ]
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "These are your own files, so nothing is pre-selected and every removal needs confirmation.".into(),
            "Protected folders (Documents, Desktop, Pictures, Movies, Music) and mounted folders are never scanned.".into(),
            "Database, virtual-machine and Git files are shown but can never be removed.".into(),
        ]
    }

    fn prepare_scan(&self) -> ScanSpec {
        let mut spec = ScanSpec::new(self.targets(), Some(Box::new(DataFileClassifier)));
        spec.post_process = Some(Box::new(|r, _| categorise_by_kind(r)));
        spec
    }

    fn active_warning(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustclean_core::{Progress, Scanner};

    #[test]
    fn finds_only_large_personal_files_as_review() {
        let tmp = tempfile::tempdir().unwrap();
        let home = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
        for (rel, len) in [
            ("Downloads/movie.mp4", 3000),
            ("Downloads/note.txt", 10),
            ("Projects/app/node_modules/big.bin", 5000),
            ("Projects/disk.iso", 4000),
            ("Documents/thesis.pdf", 9000),
            (".hidden/big", 9000),
        ] {
            let p = home.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, vec![0u8; len]).unwrap();
        }
        let mut m = LargeFilesModule::new(home.clone());
        m.threshold = 1000;
        let spec = m.prepare_scan();
        let report = Scanner::new(ProtectionRules::for_home(&home)).scan(
            spec.targets,
            spec.classifier.as_deref(),
            &Progress::new(),
        );
        let report = (spec.post_process.unwrap())(report, &Progress::new());
        let mut found: Vec<(String, String)> = report
            .candidates
            .iter()
            .map(|c| (c.file_name(), c.category.clone()))
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                ("disk.iso".into(), "Disk images & installers".into()),
                ("movie.mp4".into(), "Videos".into()),
            ]
        );
        assert!(
            report
                .candidates
                .iter()
                .all(|c| c.class == SafetyClass::Review)
        );
    }
}

#[cfg(test)]
mod data_file_tests {
    use super::*;

    #[test]
    fn databases_vms_and_git_are_recognised() {
        for p in [
            "/h/OrbStack/docker/volumes/x/journal/WiredTigerPreplog.0000000001",
            "/h/app/data/db/collection-0.wt",
            "/h/app/dev.sqlite3",
            "/h/vm/disk.qcow2",
            "/h/proj/.git/objects/pack/pack-1.pack",
            "/h/pg/base/16384/1259",
        ] {
            assert!(data_file_reason(Path::new(p)).is_some(), "{p}");
        }
        for p in [
            "/h/Downloads/movie.mp4",
            "/h/proj/assets/logo.png",
            "/h/Downloads/setup.dmg",
        ] {
            assert!(data_file_reason(Path::new(p)).is_none(), "{p}");
        }
    }
}
