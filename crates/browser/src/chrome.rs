//! Google Chrome detection and cache analysis.
//!
//! Protection model, from outermost to innermost:
//!
//! 1. Only explicitly known cache locations become scan targets.
//! 2. Inside Chrome's user-data directory, [`ChromeClassifier`] allowlists
//!    those same cache locations; anything else is `Unknown`.
//! 3. A denylist of user-data names (bookmarks, passwords, history,
//!    cookies, extensions, preferences, ...) is always `Protected`, even if
//!    it somehow appears inside a cache location.
//! 4. Only regular files are ever removed, so profile directories and the
//!    user-data directory itself are never deleted.

use std::fs;
use std::path::{Path, PathBuf};

use rustclean_core::{Classification, Classifier, SafetyClass, ScanTarget};
use rustclean_safety::{Os, platform};

pub const HTTP_CACHE: &str = "HTTP cache";
pub const CODE_CACHE: &str = "Code cache";
pub const GPU_CACHE: &str = "GPU cache";
pub const SHADER_CACHE: &str = "Shader cache";
pub const SERVICE_WORKER_CACHE: &str = "Service worker cache";
pub const TEMPORARY: &str = "Temporary browser data";
pub const LOGS: &str = "Browser logs";

/// The main browser process name (helpers are "Google Chrome Helper ...").
pub const CHROME_PROCESS_NAME: &str = if cfg!(target_os = "macos") {
    "Google Chrome"
} else if cfg!(windows) {
    "chrome.exe"
} else {
    "chrome"
};

/// Chrome's user-data directory for this platform.
pub fn user_data_dir(home: &Path) -> PathBuf {
    match platform::CURRENT {
        Os::MacOs => home.join("Library/Application Support/Google/Chrome"),
        Os::Windows => platform::local_app_data(home).join(r"Google\Chrome\User Data"),
        _ => xdg_config(home).join("google-chrome"),
    }
}

/// Chrome's disk-cache directory. On Windows the caches live inside the
/// user-data directory, so this is the same path.
pub fn cache_dir(home: &Path) -> PathBuf {
    match platform::CURRENT {
        Os::MacOs => home.join("Library/Caches/Google/Chrome"),
        Os::Windows => user_data_dir(home),
        _ => platform::user_cache_dir(home).join("google-chrome"),
    }
}

fn xdg_config(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
}

/// Where the browser itself may be installed.
fn install_candidates(home: &Path) -> Vec<PathBuf> {
    match platform::CURRENT {
        Os::MacOs => vec![
            PathBuf::from("/Applications/Google Chrome.app"),
            home.join("Applications/Google Chrome.app"),
        ],
        Os::Windows => {
            let mut v: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)"]
                .iter()
                .filter_map(std::env::var_os)
                .map(|p| PathBuf::from(p).join(r"Google\Chrome\Application\chrome.exe"))
                .collect();
            v.push(platform::local_app_data(home).join(r"Google\Chrome\Application\chrome.exe"));
            v
        }
        _ => vec![
            PathBuf::from("/opt/google/chrome/chrome"),
            PathBuf::from("/usr/bin/google-chrome"),
            PathBuf::from("/usr/bin/google-chrome-stable"),
        ],
    }
}

/// Cache locations relative to a profile directory inside the user-data dir.
const PROFILE_CACHES: &[(&str, &str, SafetyClass)] = &[
    ("Cache", HTTP_CACHE, SafetyClass::Safe),
    ("Code Cache", CODE_CACHE, SafetyClass::Safe),
    ("GPUCache", GPU_CACHE, SafetyClass::Safe),
    ("DawnCache", GPU_CACHE, SafetyClass::Safe),
    ("DawnGraphiteCache", GPU_CACHE, SafetyClass::Safe),
    ("DawnWebGPUCache", GPU_CACHE, SafetyClass::Safe),
    // Offline data for web apps; removing it can break offline use until
    // the site is revisited, so it needs review.
    (
        "Service Worker/CacheStorage",
        SERVICE_WORKER_CACHE,
        SafetyClass::Review,
    ),
    (
        "Service Worker/ScriptCache",
        SERVICE_WORKER_CACHE,
        SafetyClass::Review,
    ),
];

/// Cache locations relative to the user-data directory root.
const ROOT_CACHES: &[(&str, &str, SafetyClass)] = &[
    ("ShaderCache", SHADER_CACHE, SafetyClass::Safe),
    ("GrShaderCache", SHADER_CACHE, SafetyClass::Safe),
    ("GraphiteDawnCache", SHADER_CACHE, SafetyClass::Safe),
    ("chrome_debug.log", LOGS, SafetyClass::Safe),
    // Crash reports may be useful for diagnosing problems.
    ("Crashpad/completed", LOGS, SafetyClass::Review),
];

/// Names inside Chrome's data that must never be removed. Matched
/// case-insensitively against every path component (SQLite `-journal` and
/// `-wal` siblings included).
const PROTECTED_NAMES: &[&str] = &[
    "Bookmarks",
    "Bookmarks.bak",
    "Login Data",
    "Login Data For Account",
    "History",
    "Archived History",
    "Cookies",
    "Extension Cookies",
    "Network",
    "Extensions",
    "Extension State",
    "Extension Rules",
    "Extension Scripts",
    "Local Extension Settings",
    "Sync Extension Settings",
    "Managed Extension Settings",
    "Preferences",
    "Secure Preferences",
    "Local State",
    "Web Data",
    "Sessions",
    "Current Session",
    "Last Session",
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "Sync Data",
    "Favicons",
    "Top Sites",
    "Shortcuts",
    "Visited Links",
    "Accounts",
    "Account Web Data",
];

fn is_protected_name(name: &str) -> bool {
    let base = name
        .strip_suffix("-journal")
        .or_else(|| name.strip_suffix("-wal"))
        .or_else(|| name.strip_suffix("-shm"))
        .unwrap_or(name);
    PROTECTED_NAMES.iter().any(|p| p.eq_ignore_ascii_case(base))
}

/// A Chrome profile ("Default", "Profile 1", ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromeProfile {
    /// Directory name, e.g. "Profile 1".
    pub dir_name: String,
    /// Name shown in Chrome, read from `Local State` if available.
    pub display_name: Option<String>,
    /// `<user data>/<dir_name>`
    pub data_dir: PathBuf,
    /// `~/Library/Caches/Google/Chrome/<dir_name>`
    pub cache_dir: PathBuf,
}

impl ChromeProfile {
    pub fn label(&self) -> String {
        match &self.display_name {
            Some(name) if name != &self.dir_name => format!("{name} ({})", self.dir_name),
            _ => self.dir_name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChromeInstallation {
    /// Location of `Google Chrome.app`, if found.
    pub app_bundle: Option<PathBuf>,
    pub user_data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub profiles: Vec<ChromeProfile>,
}

fn is_profile_dir_name(name: &str) -> bool {
    name == "Default"
        || name == "Guest Profile"
        || name == "System Profile"
        || name
            .strip_prefix("Profile ")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

impl ChromeInstallation {
    /// Detects Chrome for the user with the given home directory. Returns
    /// `None` when neither the app bundle nor any Chrome data exists.
    pub fn detect(home: &Path) -> Option<Self> {
        let app_bundle = install_candidates(home).into_iter().find(|p| p.exists());
        let user_data_dir = user_data_dir(home);
        let cache_dir = cache_dir(home);
        if app_bundle.is_none() && !user_data_dir.is_dir() && !cache_dir.is_dir() {
            return None;
        }
        let profiles = detect_profiles(&user_data_dir, &cache_dir);
        Some(Self {
            app_bundle,
            user_data_dir,
            cache_dir,
            profiles,
        })
    }

    /// Scan targets covering every known Chrome cache location. Only
    /// returns locations; existence is checked by the scanner.
    pub fn scan_targets(&self) -> Vec<ScanTarget> {
        let mut targets = Vec::new();
        for p in &self.profiles {
            let label = p.label();
            // HTTP and code caches live in the platform cache directory
            // (inside the profile on Windows).
            targets.push(
                ScanTarget::new(HTTP_CACHE, p.cache_dir.join("Cache"), SafetyClass::Safe)
                    .with_context(&label),
            );
            targets.push(
                ScanTarget::new(
                    CODE_CACHE,
                    p.cache_dir.join("Code Cache"),
                    SafetyClass::Safe,
                )
                .with_context(&label),
            );
            for (rel, category, class) in PROFILE_CACHES {
                targets.push(
                    ScanTarget::new(*category, p.data_dir.join(rel), *class).with_context(&label),
                );
            }
            // Anything else under the profile's cache directory is
            // temporary by convention, but unrecognised: review it. Not on
            // Windows, where that directory is the profile itself.
            let separate_cache_dir = self.cache_dir != self.user_data_dir;
            if let Some(entries) = separate_cache_dir
                .then(|| fs::read_dir(&p.cache_dir).ok())
                .flatten()
            {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if name == "Cache" || name == "Code Cache" {
                        continue;
                    }
                    targets.push(
                        ScanTarget::new(TEMPORARY, entry.path(), SafetyClass::Review)
                            .with_context(&label),
                    );
                }
            }
        }
        for (rel, category, class) in ROOT_CACHES {
            targets.push(ScanTarget::new(
                *category,
                self.user_data_dir.join(rel),
                *class,
            ));
        }
        targets
    }

    pub fn classifier(&self) -> ChromeClassifier {
        ChromeClassifier {
            user_data_dir: self.user_data_dir.clone(),
            cache_dir: self.cache_dir.clone(),
        }
    }
}

fn detect_profiles(user_data_dir: &Path, cache_dir: &Path) -> Vec<ChromeProfile> {
    let display_names = read_profile_names(user_data_dir);
    let mut names: Vec<String> = [user_data_dir, cache_dir]
        .iter()
        .filter_map(|d| fs::read_dir(d).ok())
        .flat_map(|it| it.flatten())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_profile_dir_name(n))
        .collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|dir_name| ChromeProfile {
            display_name: display_names.get(&dir_name).cloned(),
            data_dir: user_data_dir.join(&dir_name),
            cache_dir: cache_dir.join(&dir_name),
            dir_name,
        })
        .collect()
}

/// Reads profile display names from `Local State` (read-only, best effort).
fn read_profile_names(user_data_dir: &Path) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(text) = fs::read_to_string(user_data_dir.join("Local State")) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        tracing::debug!("could not parse Chrome Local State");
        return out;
    };
    if let Some(cache) = json
        .pointer("/profile/info_cache")
        .and_then(|v| v.as_object())
    {
        for (dir, info) in cache {
            if let Some(name) = info.get("name").and_then(|n| n.as_str()) {
                out.insert(dir.clone(), name.to_string());
            }
        }
    }
    out
}

/// Domain classifier enforcing Chrome's protection rules.
pub struct ChromeClassifier {
    user_data_dir: PathBuf,
    cache_dir: PathBuf,
}

impl ChromeClassifier {
    fn is_allowlisted_in_user_data(rel: &Path) -> bool {
        let mut comps = rel.components();
        let Some(first) = comps.next().and_then(|c| c.as_os_str().to_str()) else {
            return false;
        };
        if ROOT_CACHES.iter().any(|(p, _, _)| rel.starts_with(p)) {
            return true;
        }
        if is_profile_dir_name(first) {
            let inside = comps.as_path();
            return PROFILE_CACHES
                .iter()
                .any(|(p, _, _)| inside.starts_with(p) && inside != Path::new(p));
        }
        false
    }
}

impl Classifier for ChromeClassifier {
    fn classify(&self, path: &Path, _is_symlink: bool, target: &ScanTarget) -> Classification {
        let (base, in_user_data) = if let Ok(rel) = path.strip_prefix(&self.user_data_dir) {
            (rel, true)
        } else if let Ok(rel) = path.strip_prefix(&self.cache_dir) {
            (rel, false)
        } else {
            return Classification::new(
                SafetyClass::Unknown,
                "not inside a Chrome data location".to_string(),
            );
        };

        if let Some(name) = base
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .find(|n| is_protected_name(n))
        {
            return Classification::new(
                SafetyClass::Protected,
                format!("Chrome user data ({name}) is never removed"),
            );
        }
        if in_user_data && !Self::is_allowlisted_in_user_data(base) {
            return Classification::new(
                SafetyClass::Unknown,
                "not a recognised Chrome cache location".to_string(),
            );
        }
        Classification::new(target.default_class, None)
    }
}

/// Whether the main Google Chrome process is running for any user.
pub fn is_chrome_running() -> bool {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    sys.processes()
        .values()
        .any(|p| p.name() == CHROME_PROCESS_NAME)
}

// Fixtures model the macOS/Linux layout (separate cache directory).
#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use rustclean_core::{Progress, Scanner};
    use rustclean_safety::ProtectionRules;

    struct FakeHome {
        _tmp: tempfile::TempDir,
        home: PathBuf,
    }

    fn write(path: &Path, bytes: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![7u8; bytes]).unwrap();
    }

    /// A realistic Chrome layout with both cache and precious data.
    fn fake_home() -> FakeHome {
        let tmp = tempfile::tempdir().unwrap();
        let home = platform::canonicalize(tmp.path()).unwrap();
        let ud = user_data_dir(&home);
        let cd = cache_dir(&home);
        write_local_state(&ud);
        for profile in ["Default", "Profile 1"] {
            let p = ud.join(profile);
            for precious in [
                "Bookmarks",
                "Login Data",
                "Login Data-journal",
                "History",
                "Cookies",
                "Network/Cookies",
                "Preferences",
                "Extensions/abc/1.0/manifest.json",
                "Local Storage/leveldb/000003.log",
            ] {
                write(&p.join(precious), 10);
            }
            write(&p.join("GPUCache/data_0"), 100);
            write(&p.join("Service Worker/CacheStorage/abc/def"), 50);
            write(&p.join("Service Worker/Database/000001.log"), 5);
            write(&cd.join(profile).join("Cache/Cache_Data/f_000001"), 1000);
            write(&cd.join(profile).join("Code Cache/js/abc"), 200);
            write(&cd.join(profile).join("Other/tmp"), 1);
        }
        write(&ud.join("ShaderCache/data_1"), 300);
        write(&ud.join("chrome_debug.log"), 20);
        FakeHome { _tmp: tmp, home }
    }

    /// Writes a minimal `Local State` with profile display names.
    fn write_local_state(ud: &Path) {
        fs::create_dir_all(ud).unwrap();
        fs::write(
            ud.join("Local State"),
            r#"{"profile":{"info_cache":{"Default":{"name":"Personal"},"Profile 1":{"name":"Work"}}}}"#,
        )
        .unwrap();
    }

    fn scan(home: &Path) -> (ChromeInstallation, rustclean_core::ScanReport) {
        let chrome = ChromeInstallation::detect(home).expect("chrome data present");
        let scanner = Scanner::new(ProtectionRules::for_home(home));
        let classifier = chrome.classifier();
        let report = scanner.scan(chrome.scan_targets(), Some(&classifier), &Progress::new());
        (chrome, report)
    }

    #[test]
    fn detects_profiles_with_display_names() {
        let h = fake_home();
        let chrome = ChromeInstallation::detect(&h.home).unwrap();
        let labels: Vec<_> = chrome.profiles.iter().map(|p| p.label()).collect();
        assert_eq!(labels, vec!["Personal (Default)", "Work (Profile 1)"]);
    }

    #[test]
    fn detect_returns_none_without_chrome() {
        let tmp = tempfile::tempdir().unwrap();
        // /Applications may contain Chrome on the test machine; only assert
        // when it does not.
        if !install_candidates(tmp.path()).iter().any(|p| p.exists()) {
            assert!(ChromeInstallation::detect(tmp.path()).is_none());
        }
    }

    #[test]
    fn scan_finds_caches_and_never_offers_user_data() {
        let h = fake_home();
        let (_, report) = scan(&h.home);

        for c in &report.candidates {
            let s = c.path.to_string_lossy();
            for precious in [
                "Bookmarks",
                "Login Data",
                "History",
                "Cookies",
                "Preferences",
                "Extensions",
                "Local Storage",
            ] {
                assert!(!s.contains(precious), "user data offered for cleanup: {s}");
            }
            assert!(
                !s.contains("Service Worker/Database"),
                "SW database offered: {s}"
            );
        }

        let size_of = |cat: &str| -> u64 {
            report
                .candidates
                .iter()
                .filter(|c| c.category == cat)
                .map(|c| c.size)
                .sum()
        };
        assert_eq!(size_of(HTTP_CACHE), 2000);
        assert_eq!(size_of(CODE_CACHE), 400);
        assert_eq!(size_of(GPU_CACHE), 200);
        assert_eq!(size_of(SHADER_CACHE), 300);
        assert_eq!(size_of(SERVICE_WORKER_CACHE), 100);
        assert_eq!(size_of(LOGS), 20);
        assert_eq!(size_of(TEMPORARY), 2);

        for c in &report.candidates {
            let expected = match c.category.as_str() {
                SERVICE_WORKER_CACHE | TEMPORARY => SafetyClass::Review,
                _ => SafetyClass::Safe,
            };
            assert_eq!(c.class, expected, "{}", c.path.display());
        }
    }

    #[test]
    fn classifier_protects_user_data_even_inside_cache_targets() {
        let h = fake_home();
        let chrome = ChromeInstallation::detect(&h.home).unwrap();
        let c = chrome.classifier();
        let t = ScanTarget::new(
            GPU_CACHE,
            chrome.user_data_dir.join("Default/GPUCache"),
            SafetyClass::Safe,
        );
        for rel in [
            "Default/GPUCache/Bookmarks",
            "Default/GPUCache/History-journal",
            "Default/GPUCache/Cookies-wal",
        ] {
            assert_eq!(
                c.classify(&chrome.user_data_dir.join(rel), false, &t).class,
                SafetyClass::Protected,
                "{rel}"
            );
        }
    }

    #[test]
    fn classifier_rejects_unlisted_user_data_locations() {
        let h = fake_home();
        let chrome = ChromeInstallation::detect(&h.home).unwrap();
        let c = chrome.classifier();
        let t = ScanTarget::new(TEMPORARY, chrome.user_data_dir.clone(), SafetyClass::Safe);
        for rel in [
            "Default/Some New Feature/data",
            "Default/GPUCache",
            "Profile X/Cache/f",
            "random.txt",
        ] {
            assert_eq!(
                c.classify(&chrome.user_data_dir.join(rel), false, &t).class,
                SafetyClass::Unknown,
                "{rel}"
            );
        }
        assert_eq!(
            c.classify(
                &chrome.user_data_dir.join("Default/GPUCache/data_0"),
                false,
                &t
            )
            .class,
            SafetyClass::Safe
        );
    }

    #[test]
    fn profile_dir_names() {
        for ok in [
            "Default",
            "Profile 1",
            "Profile 23",
            "Guest Profile",
            "System Profile",
        ] {
            assert!(is_profile_dir_name(ok), "{ok}");
        }
        for bad in [
            "Profile ",
            "Profile X",
            "Crashpad",
            "ShaderCache",
            "default",
        ] {
            assert!(!is_profile_dir_name(bad), "{bad}");
        }
    }
}
