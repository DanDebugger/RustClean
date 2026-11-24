//! Junk Cleaner: application caches, updater caches, logs, crash reports,
//! temporary files and leftover installers.
//!
//! Rules:
//! * Apple-owned caches are not scanned (macOS manages them; some hold
//!   iCloud/CloudKit state).
//! * Caches owned by other modules (Chrome, developer tools) are excluded
//!   here so nothing is counted twice.
//! * Only third-party caches with a recognisable bundle-identifier name and
//!   updater caches are `Safe`; other names are `Review`.
//! * A cache whose app is running is raised to `Review`.
//! * Recent logs, crash reports and temporary files are `Review`.

use std::fs;
use std::path::{Path, PathBuf};

use rustclean_core::{
    Classification, Classifier, CleanupModule, DAY, SafetyClass, ScanSpec, ScanTarget,
};

use crate::developer::dev_owned_cache_names;
use crate::running_apps::RunningApps;
use rustclean_safety::{Os, platform};

pub const APP_CACHES: &str = "Application caches";
pub const UPDATER_CACHES: &str = "Updater caches";
pub const LOGS: &str = "Logs";
pub const CRASH_REPORTS: &str = "Crash reports";
pub const TEMP_FILES: &str = "Temporary files";
pub const INSTALLERS: &str = "Installers in Downloads";

/// Cache folders under `~/Library/Caches` that belong to macOS itself but
/// do not use a `com.apple.` prefix.
const APPLE_CACHE_NAMES: &[&str] = &[
    "CloudKit",
    "FamilyCircle",
    "familycircled",
    "GameKit",
    "GeoServices",
    "PassKit",
    "SiriTTS",
    "TrickPlay",
    "Animoji",
    "LSMImageCache",
    "SharedImageCache",
    "ARFileCache",
    "askpermissiond",
    "softwareupdate",
    "ssu",
    "tvapp_bag",
    "Metadata",
    "storeassetd",
    "Safari",
];

/// Cache-directory entries owned by other modules (whole names, or
/// `parent/child`).
pub(crate) fn other_module_caches() -> &'static [&'static str] {
    match platform::CURRENT {
        Os::MacOs => &["Google/Chrome"],
        Os::Linux => &["google-chrome", "mozilla", "chromium"],
        _ => &[],
    }
}

/// Cache folders that are always safe to clear on Linux.
pub(crate) const LINUX_SAFE_CACHES: &[&str] = &["thumbnails", "fontconfig", "mesa_shader_cache"];

/// Reverse-DNS prefixes that identify a bundle-identifier folder name.
const REVERSE_DNS_TLDS: &[&str] = &[
    "com", "org", "net", "io", "dev", "app", "ai", "co", "us", "xyz", "me", "de", "uk", "fr", "jp",
];

pub(crate) fn is_apple_cache(name: &str) -> bool {
    name.starts_with("com.apple.")
        || name.starts_with("AAProfilePicture")
        || APPLE_CACHE_NAMES
            .iter()
            .any(|a| a.eq_ignore_ascii_case(name))
}

pub(crate) fn is_updater_cache(name: &str) -> bool {
    let l = name.to_lowercase();
    l.ends_with(".shipit")
        || l.ends_with("-updater")
        || l.ends_with("_updater")
        || l.ends_with(".updater")
        || l.contains(".autoupdate")
        || l.contains("googleupdater")
}

pub(crate) fn is_reverse_dns(name: &str) -> bool {
    let mut parts = name.split('.');
    let (Some(tld), Some(second)) = (parts.next(), parts.next()) else {
        return false;
    };
    REVERSE_DNS_TLDS.contains(&tld.to_lowercase().as_str()) && !second.is_empty()
}

/// The per-user temporary directory: `$TMPDIR` under `/var/folders` on
/// macOS, `%TEMP%` on Windows. On Linux only a per-user `$TMPDIR` is used;
/// the shared `/tmp` is never scanned.
pub fn user_temp_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CStr;
        let mut buf = vec![0u8; 1024];
        // SAFETY: buf is valid for buf.len() bytes; confstr writes at most
        // that many bytes including the terminating NUL.
        let n = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n == 0 || n > buf.len() {
            return None;
        }
        let s = CStr::from_bytes_until_nul(&buf).ok()?.to_str().ok()?;
        let p = PathBuf::from(s);
        p.is_absolute().then_some(p)
    }
    #[cfg(windows)]
    {
        let p = std::env::temp_dir();
        p.is_absolute().then_some(p)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let p = PathBuf::from(std::env::var_os("TMPDIR")?);
        let shared = ["/tmp", "/var/tmp"].iter().any(|s| p == Path::new(s));
        (p.is_absolute() && !shared).then_some(p)
    }
}

fn installer_extensions() -> &'static [&'static str] {
    match platform::CURRENT {
        Os::MacOs => &["dmg", "pkg", "mpkg", "xip"],
        Os::Windows => &["exe", "msi", "msix", "msixbundle"],
        // AppImages are applications, not installers: not listed.
        _ => &["deb", "rpm"],
    }
}

pub struct JunkModule {
    home: PathBuf,
    temp_dir: Option<PathBuf>,
}

impl JunkModule {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            temp_dir: user_temp_dir(),
        }
    }

    /// For tests: explicit temp directory.
    pub fn with_temp_dir(home: PathBuf, temp_dir: Option<PathBuf>) -> Self {
        Self { home, temp_dir }
    }

    fn caches_dir(&self) -> PathBuf {
        platform::user_cache_dir(&self.home)
    }

    /// Builds the scan spec using the given running-app snapshot.
    pub fn prepare_scan_with(&self, running: RunningApps) -> ScanSpec {
        let mut targets = Vec::new();
        match platform::CURRENT {
            Os::MacOs => {
                self.app_cache_targets(&mut targets);
                self.log_targets(&mut targets);
            }
            Os::Linux => self.app_cache_targets(&mut targets),
            // %LOCALAPPDATA% holds application *data*, not just caches, so
            // only well-known cache folders are scanned on Windows.
            Os::Windows => self.windows_targets(&mut targets),
            Os::Other => {}
        }
        if let Some(tmp) = &self.temp_dir {
            temp_targets(tmp, &mut targets);
        }
        targets.push(
            ScanTarget::new(INSTALLERS, self.home.join("Downloads"), SafetyClass::Review)
                .max_depth(1)
                .extensions(installer_extensions())
                .with_reason("installer in Downloads; remove once the app is installed"),
        );
        ScanSpec::new(targets, Some(Box::new(JunkClassifier { running })))
    }

    fn app_cache_targets(&self, out: &mut Vec<ScanTarget>) {
        let caches = self.caches_dir();
        let Ok(entries) = fs::read_dir(&caches) else {
            return;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            if (platform::CURRENT == Os::MacOs && is_apple_cache(&name))
                || dev_owned_cache_names()
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(&name))
                || other_module_caches().contains(&name.as_str())
            {
                continue;
            }
            let path = caches.join(&name);
            // A folder that contains another module's cache: descend one
            // level and skip the owned child.
            let owned_children: Vec<&str> = other_module_caches()
                .iter()
                .filter_map(|o| o.strip_prefix(&format!("{name}/")))
                .collect();
            if !owned_children.is_empty() {
                if let Ok(children) = fs::read_dir(&path) {
                    for child in children.flatten() {
                        let cname = child.file_name().to_string_lossy().into_owned();
                        if owned_children.contains(&cname.as_str()) {
                            continue;
                        }
                        out.push(app_cache_target(
                            &format!("{name}/{cname}"),
                            child.path(),
                            &cname,
                        ));
                    }
                }
                continue;
            }
            out.push(app_cache_target(&name, path, &name));
        }
    }

    fn windows_targets(&self, out: &mut Vec<ScanTarget>) {
        let local = platform::local_app_data(&self.home);
        out.push(
            ScanTarget::new(CRASH_REPORTS, local.join("CrashDumps"), SafetyClass::Safe)
                .review_if_newer_than(7 * DAY),
        );
        out.push(
            ScanTarget::new(APP_CACHES, local.join("D3DSCache"), SafetyClass::Safe)
                .with_context("DirectX shader cache"),
        );
        out.push(
            ScanTarget::new(
                APP_CACHES,
                local.join(r"Microsoft\Windows\INetCache"),
                SafetyClass::Review,
            )
            .with_context("Windows internet cache")
            .with_reason("shared web cache used by Windows components"),
        );
    }

    fn log_targets(&self, out: &mut Vec<ScanTarget>) {
        let logs = self.home.join("Library/Logs");
        let crash_dirs = ["DiagnosticReports", "CrashReporter"];
        if let Ok(entries) = fs::read_dir(&logs) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if crash_dirs.contains(&name.as_str()) || name == "RustClean" {
                    continue;
                }
                out.push(
                    ScanTarget::new(LOGS, e.path(), SafetyClass::Safe)
                        .with_context(&name)
                        .review_if_newer_than(7 * DAY),
                );
            }
        }
        for dir in [
            logs.join("DiagnosticReports"),
            logs.join("CrashReporter"),
            self.home.join("Library/Application Support/CrashReporter"),
        ] {
            out.push(
                ScanTarget::new(CRASH_REPORTS, dir, SafetyClass::Safe)
                    .review_if_newer_than(7 * DAY),
            );
        }
    }
}

fn app_cache_target(label: &str, path: PathBuf, owner_name: &str) -> ScanTarget {
    let is_file = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
    let (category, class, reason) = if is_updater_cache(owner_name) {
        (UPDATER_CACHES, SafetyClass::Safe, None)
    } else if is_file {
        (
            APP_CACHES,
            SafetyClass::Review,
            Some("loose file in Caches; owner unknown"),
        )
    } else if is_reverse_dns(owner_name)
        || (platform::CURRENT == Os::Linux && LINUX_SAFE_CACHES.contains(&owner_name))
    {
        (APP_CACHES, SafetyClass::Safe, None)
    } else {
        (
            APP_CACHES,
            SafetyClass::Review,
            Some("cache folder name does not identify its app"),
        )
    };
    let t = ScanTarget::new(category, path, class).with_context(label);
    match reason {
        Some(r) => t.with_reason(r),
        None => t,
    }
}

fn temp_targets(tmp: &Path, out: &mut Vec<ScanTarget>) {
    let Ok(entries) = fs::read_dir(tmp) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // Apple services and Finder's in-flight copies.
        if name.starts_with("com.apple.") || name == "TemporaryItems" {
            continue;
        }
        out.push(
            ScanTarget::new(TEMP_FILES, e.path(), SafetyClass::Review)
                .with_context(&name)
                .review_if_newer_than(3 * DAY)
                .with_reason("temporary file; may belong to a running app"),
        );
    }
}

/// Raises caches of running apps to `Review`.
pub struct JunkClassifier {
    running: RunningApps,
}

impl Classifier for JunkClassifier {
    fn classify(&self, _path: &Path, _is_symlink: bool, target: &ScanTarget) -> Classification {
        if matches!(target.category.as_str(), APP_CACHES | UPDATER_CACHES) {
            let owner = target
                .context
                .as_deref()
                .and_then(|c| c.rsplit('/').next())
                .unwrap_or_default();
            if let Some(app) = self.running.owner_running(owner) {
                return Classification::new(
                    SafetyClass::Review,
                    format!("owning app appears to be running ({app})"),
                );
            }
        }
        Classification::new(SafetyClass::Safe, None)
    }
}

impl CleanupModule for JunkModule {
    fn title(&self) -> &str {
        "Junk Cleaner"
    }

    fn refresh(&mut self) {
        self.temp_dir = user_temp_dir();
    }

    fn is_available(&self) -> bool {
        true
    }

    fn details(&self) -> Vec<(String, String)> {
        let locations = match platform::CURRENT {
            Os::MacOs => {
                "~/Library/Caches, ~/Library/Logs, crash reports, ~/Downloads (installers)"
            }
            Os::Linux => "~/.cache, ~/Downloads (installers)",
            Os::Windows => {
                "Crash dumps, DirectX shader cache, internet cache, %TEMP%, Downloads (installers)"
            }
            Os::Other => "None on this platform",
        };
        let mut d = vec![("Locations".into(), locations.into())];
        if let Some(t) = &self.temp_dir {
            d.push(("Temporary folder".into(), t.display().to_string()));
        }
        d
    }

    fn notes(&self) -> Vec<String> {
        vec![
            match platform::CURRENT {
                Os::MacOs => "Apple system caches are managed by macOS and are not scanned.",
                Os::Windows => "Only known cache folders are scanned; application data in AppData is never touched.",
                _ => "Only your own cache folder is scanned; the shared /tmp is never touched.",
            }
            .into(),
            "Chrome and developer-tool caches appear in their own cleaners.".into(),
            "Caches of running apps, recent logs and temporary files are marked Review.".into(),
        ]
    }

    fn prepare_scan(&self) -> ScanSpec {
        self.prepare_scan_with(RunningApps::snapshot())
    }

    fn active_warning(&self) -> Option<String> {
        None
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use rustclean_core::{Progress, ScanReport, Scanner};
    use rustclean_safety::ProtectionRules;
    use std::fs::File;
    use std::time::SystemTime;

    fn write(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"data").unwrap();
    }

    fn age(path: &Path, days: u32) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - days * DAY)
            .unwrap();
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        home: PathBuf,
        temp: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let temp = base.join("T");
        let c = home.join("Library/Caches");
        write(&c.join("com.apple.Safari/x"));
        write(&c.join("CloudKit/x"));
        write(&c.join("Google/Chrome/Default/Cache/f"));
        write(&c.join("Google/GoogleUpdater/f"));
        write(&c.join("Homebrew/downloads/f.tar.gz"));
        write(&c.join("com.postmanlabs.mac/blob"));
        write(&c.join("com.microsoft.VSCode/blob"));
        write(&c.join("com.microsoft.VSCode.ShipIt/update.zip"));
        write(&c.join("JNA/lib"));
        write(&c.join("picture.png"));
        let l = home.join("Library/Logs");
        write(&l.join("App/old.log"));
        age(&l.join("App/old.log"), 30);
        write(&l.join("App/new.log"));
        write(&l.join("DiagnosticReports/a.ips"));
        age(&l.join("DiagnosticReports/a.ips"), 30);
        write(&l.join("RustClean/operations.jsonl"));
        write(&home.join("Downloads/Setup.dmg"));
        write(&home.join("Downloads/report.pdf"));
        write(&home.join("Downloads/nested/Other.pkg"));
        write(&temp.join("com.apple.foo/x"));
        write(&temp.join("work/x"));
        age(&temp.join("work/x"), 10);
        Fixture {
            _tmp: tmp,
            home,
            temp,
        }
    }

    fn scan(f: &Fixture, running: RunningApps) -> ScanReport {
        let m = JunkModule::with_temp_dir(f.home.clone(), Some(f.temp.clone()));
        let spec = m.prepare_scan_with(running);
        Scanner::new(ProtectionRules::for_home(&f.home)).scan(
            spec.targets,
            spec.classifier.as_deref(),
            &Progress::new(),
        )
    }

    fn class_of(r: &ScanReport, suffix: &str) -> Option<SafetyClass> {
        r.candidates
            .iter()
            .find(|c| c.path.ends_with(suffix))
            .map(|c| c.class)
    }

    #[test]
    fn classification_rules() {
        let f = fixture();
        let r = scan(&f, RunningApps::default());
        // Excluded entirely.
        for skipped in [
            "com.apple.Safari/x",
            "CloudKit/x",
            "Google/Chrome/Default/Cache/f",
            "Homebrew/downloads/f.tar.gz",
            "RustClean/operations.jsonl",
            "Downloads/report.pdf",
            "nested/Other.pkg",
            "com.apple.foo/x",
        ] {
            assert_eq!(
                class_of(&r, skipped),
                None,
                "{skipped} should not be offered"
            );
        }
        assert_eq!(
            class_of(&r, "com.postmanlabs.mac/blob"),
            Some(SafetyClass::Safe)
        );
        assert_eq!(
            class_of(&r, "com.microsoft.VSCode.ShipIt/update.zip"),
            Some(SafetyClass::Safe)
        );
        assert_eq!(
            class_of(&r, "Google/GoogleUpdater/f"),
            Some(SafetyClass::Safe)
        );
        assert_eq!(class_of(&r, "JNA/lib"), Some(SafetyClass::Review));
        assert_eq!(class_of(&r, "picture.png"), Some(SafetyClass::Review));
        assert_eq!(class_of(&r, "App/old.log"), Some(SafetyClass::Safe));
        assert_eq!(class_of(&r, "App/new.log"), Some(SafetyClass::Review));
        assert_eq!(
            class_of(&r, "DiagnosticReports/a.ips"),
            Some(SafetyClass::Safe)
        );
        assert_eq!(
            class_of(&r, "Downloads/Setup.dmg"),
            Some(SafetyClass::Review)
        );
        assert_eq!(class_of(&r, "work/x"), Some(SafetyClass::Review));
    }

    #[test]
    fn running_app_caches_need_review() {
        let f = fixture();
        let r = scan(&f, RunningApps::from_parts(&["com.microsoft.VSCode"], &[]));
        assert_eq!(
            class_of(&r, "com.microsoft.VSCode/blob"),
            Some(SafetyClass::Review)
        );
        assert_eq!(
            class_of(&r, "com.microsoft.VSCode.ShipIt/update.zip"),
            Some(SafetyClass::Review)
        );
        assert_eq!(
            class_of(&r, "com.postmanlabs.mac/blob"),
            Some(SafetyClass::Safe)
        );
    }

    #[test]
    fn name_helpers() {
        assert!(is_reverse_dns("com.postmanlabs.mac"));
        assert!(is_reverse_dns("dev.kdrag0n.MacVirt"));
        assert!(!is_reverse_dns("JNA"));
        assert!(!is_reverse_dns("node-gyp"));
        assert!(is_updater_cache("antigravity-updater"));
        assert!(is_updater_cache("com.mongodb.compass.ShipIt"));
        assert!(is_apple_cache("com.apple.bird"));
        assert!(is_apple_cache("geoservices"));
        assert!(!is_apple_cache("com.google.GoogleUpdater"));
    }

    #[test]
    fn user_temp_dir_is_under_var_folders() {
        let t = user_temp_dir().expect("confstr temp dir");
        assert!(
            t.to_string_lossy().contains("/var/folders/"),
            "{}",
            t.display()
        );
    }
}
