//! App Caches: every cache an application keeps, grouped **per app**, so the
//! user can see what each app stores and clear one app's cache (or several)
//! in one step.
//!
//! Sources (macOS):
//! * `~/Library/Caches/<bundle-id or name>` — the same folders the Junk
//!   Cleaner lists under "Application caches", shown here per app.
//! * `~/Library/Containers/<bundle-id>/Data/Library/Caches` — caches of
//!   sandboxed (App Store) apps. Not covered by any other module.
//! * `~/Library/Application Support/<App>/{Cache, Code Cache, GPUCache, …}`
//!   — Chromium disk caches of Electron apps (Slack, VS Code, Discord, …).
//!   Only used when the folder carries Chromium's `Local State` /
//!   `Preferences` marker, so arbitrary folders named "Cache" are ignored.
//!
//! On Linux `~/.cache/<app>` and `~/.config/<App>/<chromium cache>` are used.
//!
//! On Windows only the Electron/Chromium rule applies, to
//! `%APPDATA%\<App>\{Cache, Code Cache, GPUCache, …}` (Electron's default
//! user-data folder). `%LOCALAPPDATA%` is never scanned here, because it
//! mixes caches with app data and nothing there identifies a cache safely.
//!
//! Rules are those of the Junk Cleaner: Apple caches, developer-tool caches
//! and Chrome are excluded; only reverse-DNS, updater and Chromium caches
//! are `Safe`; anything whose owning app is running is raised to `Review`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rustclean_core::{
    Classification, Classifier, CleanupModule, Progress, SafetyClass, ScanReport, ScanSpec,
    ScanTarget,
};
use rustclean_safety::{Os, platform};

use crate::developer::dev_owned_cache_names;
use crate::junk::{
    LINUX_SAFE_CACHES, is_apple_cache, is_reverse_dns, is_updater_cache, other_module_caches,
};
use crate::running_apps::RunningApps;

/// Chromium/Electron cache folders directly under an app's data folder.
/// All are disk caches Chromium rebuilds on demand.
pub const CHROMIUM_CACHE_DIRS: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GrShaderCache",
    "ShaderCache",
];

/// Files Chromium writes into its user-data folder; their presence is what
/// identifies an Electron/Chromium app.
const CHROMIUM_MARKERS: &[&str] = &["Local State", "Preferences"];

/// Application-data folders never inspected here: browsers have their own
/// module (or are not supported yet) and RustClean never touches itself.
const SKIPPED_APP_DATA: &[&str] = &[
    "Google",
    "Chromium",
    "BraveSoftware",
    "Microsoft Edge",
    "Vivaldi",
    "Arc",
    "Firefox",
    "RustClean",
    "rustclean",
];

/// Extra Windows folders under `%APPDATA%`: browsers and vendor folders whose
/// caches belong to another module or are not ours to judge. (Chrome keeps
/// its data in `%LOCALAPPDATA%\Google\Chrome`, which is not scanned here;
/// the entry is defensive.)
const WINDOWS_SKIPPED_APP_DATA: &[&str] = &[
    "Microsoft",
    "Mozilla",
    "Opera Software",
    "Opera",
    "Brave-Browser",
];

/// Which cache sources apply on an OS. A pure function so the Windows
/// decision is testable on every platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sources {
    /// `platform::user_cache_dir` folders (`~/Library/Caches`, `~/.cache`).
    user_caches: bool,
    /// Sandboxed app containers (macOS only).
    containers: bool,
    /// Chromium disk caches inside the app-data folder.
    chromium: bool,
}

fn sources_for(os: Os) -> Sources {
    match os {
        Os::MacOs => Sources {
            user_caches: true,
            containers: true,
            chromium: true,
        },
        Os::Linux => Sources {
            user_caches: true,
            containers: false,
            chromium: true,
        },
        // `%LOCALAPPDATA%` (the Windows user cache dir) mixes caches with app
        // data, so only Electron/Chromium caches in `%APPDATA%` are offered.
        Os::Windows => Sources {
            user_caches: false,
            containers: false,
            chromium: true,
        },
        Os::Other => Sources {
            user_caches: false,
            containers: false,
            chromium: false,
        },
    }
}

fn is_skipped_app_data(os: Os, name: &str) -> bool {
    SKIPPED_APP_DATA
        .iter()
        .chain(if os == Os::Windows {
            WINDOWS_SKIPPED_APP_DATA
        } else {
            &[]
        })
        .any(|s| s.eq_ignore_ascii_case(name))
}

/// Where a cache folder was found; shown as the file's "Source".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    UserCaches,
    Container,
    Chromium,
}

/// Maps bundle identifiers and folder names to installed apps' names.
#[derive(Debug, Default, Clone)]
pub struct AppIndex {
    /// lowercase bundle id → (display name, bundle id)
    by_bundle: HashMap<String, (String, String)>,
    /// lowercase app name → (display name, bundle id)
    by_name: HashMap<String, (String, Option<String>)>,
}

impl AppIndex {
    /// Reads installed `.app` bundles (macOS). Read-only.
    pub fn installed(home: &Path) -> Self {
        let mut idx = Self::default();
        if platform::CURRENT == Os::MacOs {
            for app in rustclean_apps::installed_apps(home) {
                idx.add(&app.name, app.bundle_id.as_deref());
            }
        }
        idx
    }

    /// For tests: explicit (name, bundle id) pairs.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut idx = Self::default();
        for (name, id) in pairs {
            idx.add(name, Some(id));
        }
        idx
    }

    fn add(&mut self, name: &str, bundle_id: Option<&str>) {
        if let Some(id) = bundle_id {
            self.by_bundle
                .insert(id.to_lowercase(), (name.to_string(), id.to_string()));
        }
        self.by_name.insert(
            name.to_lowercase(),
            (name.to_string(), bundle_id.map(str::to_string)),
        );
    }

    /// Display name and bundle id of the app owning a cache folder `key`
    /// (a bundle id such as `com.foo.App.ShipIt`, or an app name).
    /// Unknown owners keep their folder name.
    pub fn resolve(&self, key: &str) -> (String, Option<String>) {
        let lower = key.to_lowercase();
        let mut base = lower.as_str();
        for suffix in [".shipit", "-updater", "_updater", ".updater"] {
            if let Some(s) = base.strip_suffix(suffix) {
                base = s;
            }
        }
        if let Some((name, id)) = self.by_bundle.get(base) {
            return (name.clone(), Some(id.clone()));
        }
        // A helper or sub-cache of an app: `com.foo.App.helper`. The longest
        // matching bundle id wins.
        if let Some((name, id)) = self
            .by_bundle
            .iter()
            .filter(|(id, _)| base.starts_with(&format!("{id}.")))
            .max_by_key(|(id, _)| id.len())
            .map(|(_, v)| v)
        {
            return (name.clone(), Some(id.clone()));
        }
        if let Some((name, id)) = self.by_name.get(base) {
            return (name.clone(), id.clone());
        }
        (pretty_name(key, base.len()), None)
    }
}

/// Bundle-id parts that say nothing about which app it is.
const GENERIC_PARTS: &[&str] = &[
    "mac", "macos", "osx", "app", "desktop", "helper", "client", "agent", "shipit", "updater",
];

/// Readable name for an app that is not installed (or not found):
/// `us.zoom.updater` → "Zoom", `com.postmanlabs.mac` → "Postmanlabs".
/// Other names are kept as they are. `base_len` is the length of `key`
/// without its updater suffix.
fn pretty_name(key: &str, base_len: usize) -> String {
    let base = &key[..base_len.min(key.len())];
    if !is_reverse_dns(base) {
        return key.to_string();
    }
    let part = base
        .split('.')
        .skip(1)
        .filter(|p| !p.is_empty() && !GENERIC_PARTS.contains(&p.to_lowercase().as_str()))
        .last();
    match part {
        Some(p) => {
            let mut c = p.chars();
            match c.next() {
                Some(f) if p.chars().all(|ch| !ch.is_uppercase()) => {
                    f.to_uppercase().chain(c).collect()
                }
                _ => p.to_string(),
            }
        }
        None => key.to_string(),
    }
}

/// One cache location attributed to an app.
#[derive(Debug, Clone)]
struct Found {
    app: String,
    /// Strings used to detect whether the owning app is running.
    owner_keys: Vec<String>,
    target: ScanTarget,
}

pub struct AppCachesModule {
    home: PathBuf,
    apps: AppIndex,
}

impl AppCachesModule {
    pub fn new(home: PathBuf) -> Self {
        // Installed apps are read on `refresh`, which runs before each scan,
        // so start-up stays fast.
        Self {
            home,
            apps: AppIndex::default(),
        }
    }

    /// For tests: explicit app index.
    pub fn with_apps(home: PathBuf, apps: AppIndex) -> Self {
        Self { home, apps }
    }

    /// Where apps keep their user data: `~/Library/Application Support`,
    /// `$XDG_CONFIG_HOME` or `%APPDATA%` (Electron's default `userData`).
    fn app_data_root(&self) -> Option<PathBuf> {
        sources_for(platform::CURRENT)
            .chromium
            .then(|| platform::roaming_app_data(&self.home))
    }

    /// Builds the scan spec using the given running-app snapshot.
    pub fn prepare_scan_with(&self, running: RunningApps) -> ScanSpec {
        let mut found = Vec::new();
        let sources = sources_for(platform::CURRENT);
        if sources.user_caches {
            self.user_cache_targets(&mut found);
        }
        if sources.containers {
            self.container_targets(&mut found);
        }
        if let Some(root) = self.app_data_root() {
            self.chromium_targets(&root, platform::CURRENT, &mut found);
        }
        found.sort_by(|a, b| {
            a.app
                .to_lowercase()
                .cmp(&b.app.to_lowercase())
                .then_with(|| a.target.root.cmp(&b.target.root))
        });
        let owners = found
            .iter()
            .map(|f| (f.target.root.clone(), f.owner_keys.clone()))
            .collect();
        let targets = found.into_iter().map(|f| f.target).collect();
        let mut spec = ScanSpec::new(
            targets,
            Some(Box::new(AppCacheClassifier { running, owners })),
        );
        spec.post_process = Some(Box::new(order_apps_by_size));
        spec
    }

    fn found(&self, key: &str, source: Source, root: PathBuf, label: &str) -> Found {
        let (app, bundle_id) = self.apps.resolve(key);
        let (class, reason) = match source {
            Source::Chromium => (SafetyClass::Safe, None),
            _ if is_updater_cache(key) || is_reverse_dns(key) => (SafetyClass::Safe, None),
            _ if platform::CURRENT == Os::Linux && LINUX_SAFE_CACHES.contains(&key) => {
                (SafetyClass::Safe, None)
            }
            _ => (
                SafetyClass::Review,
                Some("cache folder name does not identify its app"),
            ),
        };
        let context = match source {
            Source::UserCaches => format!("App cache folder · {label}"),
            Source::Container => format!("Sandboxed app container · {label}"),
            Source::Chromium => format!("Electron/Chromium cache · {label}"),
        };
        let mut target = ScanTarget::new(&app, root, class).with_context(context);
        if let Some(r) = reason {
            target = target.with_reason(r);
        }
        // Only facts are used to detect a running owner: the folder name and,
        // when the app was found installed, its name and bundle id. A guessed
        // display name ("Notes" from com.example.Notes) must not match an
        // unrelated running app (Apple Notes).
        let mut owner_keys = vec![key.to_string()];
        if let Some(id) = bundle_id {
            owner_keys.push(app.clone());
            owner_keys.push(id);
        }
        Found {
            app,
            owner_keys,
            target,
        }
    }

    fn user_cache_targets(&self, out: &mut Vec<Found>) {
        let caches = platform::user_cache_dir(&self.home);
        for name in dir_names(&caches) {
            if (platform::CURRENT == Os::MacOs && is_apple_cache(&name))
                || dev_owned_cache_names()
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(&name))
                || name.eq_ignore_ascii_case("RustClean")
            {
                continue;
            }
            let path = caches.join(&name);
            // Only folders: a loose file has no identifiable owner.
            if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            // A vendor folder holding another module's cache (Google/Chrome):
            // offer the other children individually.
            let owned: Vec<&str> = other_module_caches()
                .iter()
                .filter_map(|o| o.strip_prefix(&format!("{name}/")))
                .collect();
            if other_module_caches().contains(&name.as_str()) {
                continue;
            }
            if !owned.is_empty() {
                for child in dir_names(&path) {
                    if owned.contains(&child.as_str()) {
                        continue;
                    }
                    let label = format!("{name}/{child}");
                    out.push(self.found(&child, Source::UserCaches, path.join(&child), &label));
                }
                continue;
            }
            out.push(self.found(&name, Source::UserCaches, path, &name));
        }
    }

    fn container_targets(&self, out: &mut Vec<Found>) {
        let containers = self.home.join("Library/Containers");
        for id in dir_names(&containers) {
            if is_apple_cache(&id) || !is_reverse_dns(&id) {
                continue;
            }
            let caches = containers.join(&id).join("Data/Library/Caches");
            if fs::symlink_metadata(&caches).is_ok_and(|m| m.is_dir()) {
                out.push(self.found(&id, Source::Container, caches, &id));
            }
        }
    }

    /// Chromium disk caches of Electron apps under `root`.
    ///
    /// Partial-deletion rule: Chromium treats these folders purely as a
    /// disk cache and rebuilds the index and entries on demand, so removing
    /// any subset of their files is harmless (the same assumption already
    /// holds on macOS and Linux). Only the cache folders in
    /// `CHROMIUM_CACHE_DIRS` are listed, never cookies, IndexedDB or storage.
    fn chromium_targets(&self, root: &Path, os: Os, out: &mut Vec<Found>) {
        for name in dir_names(root) {
            if is_skipped_app_data(os, &name) || is_apple_cache(&name) {
                continue;
            }
            let app_dir = root.join(&name);
            // Windows: `Local State` only. `%APPDATA%` holds many non-Electron
            // apps, and a bare `Preferences` file is too generic to identify
            // Chromium there; Electron always writes `Local State`.
            let markers: &[&str] = if os == Os::Windows {
                &["Local State"]
            } else {
                CHROMIUM_MARKERS
            };
            let is_chromium = markers
                .iter()
                .any(|m| fs::symlink_metadata(app_dir.join(m)).is_ok_and(|md| md.is_file()));
            if !is_chromium {
                continue;
            }
            for dir in CHROMIUM_CACHE_DIRS {
                let p = app_dir.join(dir);
                if fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                    out.push(self.found(&name, Source::Chromium, p, &format!("{name}/{dir}")));
                }
            }
        }
    }
}

/// Sorted entry names of a directory; empty if it cannot be read.
fn dir_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// Lists apps (categories) largest first. Only reorders `targets`; files
/// and their classification are left untouched.
fn order_apps_by_size(mut report: ScanReport, _: &Progress) -> ScanReport {
    let mut size: HashMap<&str, u64> = HashMap::new();
    for c in &report.candidates {
        *size.entry(c.category.as_str()).or_default() += c.disk_usage;
    }
    let size: HashMap<String, u64> = size.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    report.targets.sort_by(|a, b| {
        let sa = size.get(&a.category).copied().unwrap_or(0);
        let sb = size.get(&b.category).copied().unwrap_or(0);
        sb.cmp(&sa).then_with(|| a.category.cmp(&b.category))
    });
    report
}

/// Raises caches of running apps to `Review`.
struct AppCacheClassifier {
    running: RunningApps,
    owners: HashMap<PathBuf, Vec<String>>,
}

impl Classifier for AppCacheClassifier {
    fn classify(&self, _path: &Path, _is_symlink: bool, target: &ScanTarget) -> Classification {
        let running = self
            .owners
            .get(&target.root)
            .into_iter()
            .flatten()
            .find_map(|k| self.running.owner_running(k));
        match running {
            Some(app) => Classification::new(
                SafetyClass::Review,
                format!("owning app appears to be running ({app}); quit it first"),
            ),
            None => Classification::new(SafetyClass::Safe, None),
        }
    }
}

impl CleanupModule for AppCachesModule {
    fn title(&self) -> &str {
        "App Caches"
    }

    fn refresh(&mut self) {
        self.apps = AppIndex::installed(&self.home);
    }

    fn is_available(&self) -> bool {
        let s = sources_for(platform::CURRENT);
        s.user_caches || s.chromium
    }

    fn details(&self) -> Vec<(String, String)> {
        let locations = match platform::CURRENT {
            Os::MacOs => {
                "~/Library/Caches, sandboxed app containers (~/Library/Containers/…/Caches), Electron app caches in ~/Library/Application Support"
            }
            Os::Linux => "~/.cache, Electron app caches in ~/.config",
            Os::Windows => "Electron app caches in %APPDATA%",
            _ => "Not supported on this platform",
        };
        vec![
            ("Locations".into(), locations.into()),
            ("Grouped by".into(), "Application (largest first)".into()),
        ]
    }

    fn notes(&self) -> Vec<String> {
        let mut notes = vec![
            "Tick an app in the list to clear its whole cache; apps rebuild caches when needed."
                .into(),
            "Caches of running apps are marked Review: quit the app first for a clean result."
                .into(),
            "Apple, browser and developer-tool caches are not listed here.".into(),
        ];
        if platform::CURRENT == Os::Windows {
            notes.push(
                "Only Electron/Chromium caches are listed. Other caches in %LOCALAPPDATA% are not, because that folder mixes caches with app data."
                    .into(),
            );
        } else {
            notes.push(
                "~/Library/Caches folders also appear in Junk Cleaner (grouped by type); cleaning in either place is the same."
                    .into(),
            );
        }
        if platform::CURRENT == Os::MacOs {
            notes.push(
                "macOS may ask once for permission to read other apps' containers; declining only hides those caches."
                    .into(),
            );
        }
        notes
    }

    fn prepare_scan(&self) -> ScanSpec {
        self.prepare_scan_with(RunningApps::snapshot())
    }

    fn active_warning(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_bundle_ids_helpers_updaters_and_names() {
        let idx = AppIndex::from_pairs(&[
            ("Slack", "com.tinyspeck.slackmacgap"),
            ("Visual Studio Code", "com.microsoft.VSCode"),
        ]);
        assert_eq!(idx.resolve("com.tinyspeck.slackmacgap").0, "Slack");
        assert_eq!(idx.resolve("com.tinyspeck.slackmacgap.ShipIt").0, "Slack");
        assert_eq!(
            idx.resolve("com.microsoft.VSCode.helper").0,
            "Visual Studio Code"
        );
        assert_eq!(idx.resolve("slack").0, "Slack");
        assert_eq!(
            idx.resolve("Slack").1.as_deref(),
            Some("com.tinyspeck.slackmacgap")
        );
        // Unknown owners get a readable name; a partial id is not a match.
        assert_eq!(idx.resolve("com.micro"), ("Micro".to_string(), None));
        assert_eq!(idx.resolve("us.zoom.updater").0, "Zoom");
        assert_eq!(idx.resolve("com.postmanlabs.mac").0, "Postmanlabs");
        assert_eq!(idx.resolve("com.example.NotesApp").0, "NotesApp");
        assert_eq!(idx.resolve("JNA").0, "JNA");
        assert_eq!(idx.resolve("GoogleUpdater").0, "GoogleUpdater");
    }

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
    }

    fn roots(found: &[Found]) -> Vec<PathBuf> {
        found.iter().map(|f| f.target.root.clone()).collect()
    }

    /// Fake `%APPDATA%`, canonicalised (macOS temp dirs are symlinked).
    fn roaming_fixture() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap().join("Roaming");
        touch(&root.join("Slack/Local State"));
        touch(&root.join("Slack/Cache/Cache_Data/f_0001"));
        touch(&root.join("Slack/Code Cache/js/a"));
        touch(&root.join("Slack/IndexedDB/x"));
        touch(&root.join("discord/Local State"));
        touch(&root.join("discord/GPUCache/data_0"));
        // Windows: a bare `Preferences` file does not identify Chromium.
        touch(&root.join("PrefsOnly/Preferences"));
        touch(&root.join("PrefsOnly/Cache/settings.dat"));
        touch(&root.join("Code/Local State"));
        touch(&root.join("Code/Cache/f"));
        // No marker: a folder called "Cache" is not enough.
        touch(&root.join("SomeTool/Cache/important.dat"));
        // Skipped vendor/browser folders, even with markers.
        for skipped in [
            "Microsoft",
            "Mozilla",
            "Opera Software",
            "Google",
            "RustClean",
        ] {
            touch(&root.join(skipped).join("Local State"));
            touch(&root.join(skipped).join("Cache/f"));
        }
        touch(&root.join("loose-file"));
        (tmp, root)
    }

    #[test]
    fn windows_finds_electron_caches_only() {
        let (_tmp, root) = roaming_fixture();
        let m = AppCachesModule::with_apps(root.clone(), AppIndex::default());
        let mut found = Vec::new();
        m.chromium_targets(&root, Os::Windows, &mut found);
        let mut got = roots(&found);
        got.sort();
        let mut want = vec![
            root.join("Slack/Cache"),
            root.join("Slack/Code Cache"),
            root.join("discord/GPUCache"),
            root.join("Code/Cache"),
        ];
        want.sort();
        assert_eq!(got, want);
        assert!(
            found
                .iter()
                .all(|f| f.target.default_class == SafetyClass::Safe)
        );
        let slack = found.iter().find(|f| f.app == "Slack").unwrap();
        assert_eq!(slack.owner_keys, vec!["Slack".to_string()]);
    }

    #[test]
    fn windows_skip_list_is_case_insensitive_and_windows_only() {
        assert!(is_skipped_app_data(Os::Windows, "microsoft"));
        assert!(is_skipped_app_data(Os::Windows, "Opera Software"));
        assert!(is_skipped_app_data(Os::Windows, "Google"));
        assert!(!is_skipped_app_data(Os::Windows, "Slack"));
        // macOS behaviour is unchanged: "Microsoft" is not skipped there.
        assert!(!is_skipped_app_data(Os::MacOs, "Microsoft"));
        assert!(is_skipped_app_data(Os::MacOs, "Google"));
    }

    #[test]
    fn windows_never_scans_the_user_cache_dir() {
        let w = sources_for(Os::Windows);
        assert!(!w.user_caches);
        assert!(!w.containers);
        assert!(w.chromium);
        assert!(sources_for(Os::MacOs).user_caches && sources_for(Os::MacOs).containers);
        assert!(sources_for(Os::Linux).user_caches && !sources_for(Os::Linux).containers);
        assert_eq!(
            sources_for(Os::Other),
            Sources {
                user_caches: false,
                containers: false,
                chromium: false
            }
        );
    }

    #[test]
    fn running_windows_app_raises_cache_to_review() {
        let (_tmp, root) = roaming_fixture();
        let m = AppCachesModule::with_apps(root.clone(), AppIndex::default());
        let mut found = Vec::new();
        m.chromium_targets(&root, Os::Windows, &mut found);
        let owners: HashMap<PathBuf, Vec<String>> = found
            .iter()
            .map(|f| (f.target.root.clone(), f.owner_keys.clone()))
            .collect();
        let c = AppCacheClassifier {
            running: RunningApps::from_parts(&[], &["Slack.exe", "Discord.exe"]),
            owners,
        };
        let class_of = |dir: &str| {
            let t = found
                .iter()
                .find(|f| f.target.root == root.join(dir))
                .unwrap();
            c.classify(&t.target.root, false, &t.target).class
        };
        assert_eq!(class_of("Slack/Cache"), SafetyClass::Review);
        assert_eq!(class_of("discord/GPUCache"), SafetyClass::Review);
        assert_eq!(class_of("Code/Cache"), SafetyClass::Safe);
    }

    #[test]
    fn reorders_categories_by_size() {
        let t = |c: &str| ScanTarget::new(c, PathBuf::from(format!("/x/{c}")), SafetyClass::Safe);
        let report = ScanReport {
            targets: vec![t("A"), t("B")],
            candidates: vec![rustclean_core::Candidate {
                path: PathBuf::from("/x/B/f"),
                size: 10,
                disk_usage: 10,
                category: "B".into(),
                context: None,
                class: SafetyClass::Safe,
                reason: None,
                fingerprint: rustclean_safety::FileFingerprint {
                    size: 10,
                    modified: None,
                    inode: 1,
                    device: 1,
                },
                target_root: PathBuf::from("/x/B"),
            }],
            ..Default::default()
        };
        let r = order_apps_by_size(report, &Progress::new());
        let order: Vec<_> = r.by_category().into_iter().map(|c| c.category).collect();
        assert_eq!(order, vec!["B"]);
        assert_eq!(r.targets[0].category, "B");
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use rustclean_core::Scanner;
    use rustclean_safety::ProtectionRules;

    fn write(path: &Path, bytes: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![1u8; bytes]).unwrap();
    }

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(tmp.path()).unwrap().join("home");
        let c = home.join("Library/Caches");
        write(&c.join("com.tinyspeck.slackmacgap/blob"), 100);
        write(&c.join("com.tinyspeck.slackmacgap.ShipIt/update.zip"), 50);
        write(&c.join("com.apple.Safari/x"), 10);
        write(&c.join("Google/Chrome/Default/Cache/f"), 10);
        write(&c.join("Google/GoogleUpdater/f"), 10);
        write(&c.join("Homebrew/downloads/x.tar.gz"), 10);
        write(&c.join("JNA/lib"), 10);
        write(&c.join("loose.png"), 10);
        let k = home.join("Library/Containers");
        write(
            &k.join("com.example.Notes/Data/Library/Caches/thumb.db"),
            30,
        );
        write(&k.join("com.example.Notes/Data/Documents/note.txt"), 30);
        write(&k.join("com.apple.mail/Data/Library/Caches/x"), 10);
        let s = home.join("Library/Application Support");
        write(&s.join("Slack/Local State"), 1);
        write(&s.join("Slack/Cache/Cache_Data/f_0001"), 400);
        write(&s.join("Slack/GPUCache/data_0"), 20);
        write(&s.join("Slack/IndexedDB/x"), 20);
        write(&s.join("Slack/Cookies"), 5);
        // Not Chromium: a folder called "Cache" is not enough.
        write(&s.join("SomeTool/Cache/important.dat"), 10);
        write(&s.join("Google/Chrome/Local State"), 1);
        write(&s.join("Google/Chrome/Default/Cache/f"), 10);
        (tmp, home)
    }

    fn scan(home: &Path, running: RunningApps) -> ScanReport {
        let m = AppCachesModule::with_apps(
            home.to_path_buf(),
            AppIndex::from_pairs(&[("Slack", "com.tinyspeck.slackmacgap")]),
        );
        let spec = m.prepare_scan_with(running);
        let r = Scanner::new(ProtectionRules::for_home(home)).scan(
            spec.targets,
            spec.classifier.as_deref(),
            &Progress::new(),
        );
        (spec.post_process.unwrap())(r, &Progress::new())
    }

    fn find<'a>(r: &'a ScanReport, suffix: &str) -> Option<&'a rustclean_core::Candidate> {
        r.candidates.iter().find(|c| c.path.ends_with(suffix))
    }

    #[test]
    fn groups_caches_per_app_and_skips_everything_else() {
        let (_tmp, home) = fixture();
        let r = scan(&home, RunningApps::default());
        for (suffix, app, class) in [
            ("com.tinyspeck.slackmacgap/blob", "Slack", SafetyClass::Safe),
            (
                "com.tinyspeck.slackmacgap.ShipIt/update.zip",
                "Slack",
                SafetyClass::Safe,
            ),
            ("Slack/Cache/Cache_Data/f_0001", "Slack", SafetyClass::Safe),
            ("Slack/GPUCache/data_0", "Slack", SafetyClass::Safe),
            ("Caches/thumb.db", "Notes", SafetyClass::Safe),
            ("JNA/lib", "JNA", SafetyClass::Review),
        ] {
            let c = find(&r, suffix).unwrap_or_else(|| panic!("{suffix} missing"));
            assert_eq!(c.category, app, "{suffix}");
            assert_eq!(c.class, class, "{suffix}");
        }
        for skipped in [
            "com.apple.Safari/x",
            "Google/Chrome/Default/Cache/f",
            "Homebrew/downloads/x.tar.gz",
            "loose.png",
            "Documents/note.txt",
            "com.apple.mail/Data/Library/Caches/x",
            "Slack/IndexedDB/x",
            "Slack/Cookies",
            "Slack/Local State",
            "SomeTool/Cache/important.dat",
        ] {
            assert!(find(&r, skipped).is_none(), "{skipped} must not be offered");
        }
        // Google's other caches (its updater) are still offered.
        assert!(find(&r, "Google/GoogleUpdater/f").is_some());
        // Largest app first.
        assert_eq!(r.by_category()[0].category, "Slack");
    }

    #[test]
    fn running_app_caches_need_review() {
        let (_tmp, home) = fixture();
        let r = scan(&home, RunningApps::from_parts(&[], &["slack"]));
        for suffix in [
            "com.tinyspeck.slackmacgap/blob",
            "Slack/Cache/Cache_Data/f_0001",
        ] {
            let c = find(&r, suffix).unwrap();
            assert_eq!(c.class, SafetyClass::Review, "{suffix}");
            assert!(c.reason.as_deref().unwrap().contains("running"));
        }
        assert_eq!(
            find(&r, "Caches/thumb.db").unwrap().class,
            SafetyClass::Safe
        ); // Regression: the guessed name "Notes" must not match a running
        // "Notes" process (Apple Notes).
        let r = scan(&home, RunningApps::from_parts(&[], &["notes"]));
        assert_eq!(
            find(&r, "Caches/thumb.db").unwrap().class,
            SafetyClass::Safe
        );
    }
}
