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
//! Windows is not supported: `%LOCALAPPDATA%` mixes caches with app data.
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
        (key.to_string(), None)
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

    fn app_data_root(&self) -> Option<PathBuf> {
        match platform::CURRENT {
            Os::MacOs => Some(self.home.join("Library/Application Support")),
            Os::Linux => Some(
                std::env::var_os("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
                    .unwrap_or_else(|| self.home.join(".config")),
            ),
            _ => None,
        }
    }

    /// Builds the scan spec using the given running-app snapshot.
    pub fn prepare_scan_with(&self, running: RunningApps) -> ScanSpec {
        let mut found = Vec::new();
        self.user_cache_targets(&mut found);
        if platform::CURRENT == Os::MacOs {
            self.container_targets(&mut found);
        }
        self.chromium_targets(&mut found);
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
        let mut owner_keys = vec![key.to_string(), app.clone()];
        owner_keys.extend(bundle_id);
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

    fn chromium_targets(&self, out: &mut Vec<Found>) {
        let Some(root) = self.app_data_root() else {
            return;
        };
        for name in dir_names(&root) {
            if SKIPPED_APP_DATA.contains(&name.as_str()) || is_apple_cache(&name) {
                continue;
            }
            let app_dir = root.join(&name);
            let is_chromium = CHROMIUM_MARKERS
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
        matches!(platform::CURRENT, Os::MacOs | Os::Linux)
    }

    fn details(&self) -> Vec<(String, String)> {
        let locations = match platform::CURRENT {
            Os::MacOs => {
                "~/Library/Caches, sandboxed app containers (~/Library/Containers/…/Caches), Electron app caches in ~/Library/Application Support"
            }
            Os::Linux => "~/.cache, Electron app caches in ~/.config",
            _ => "Not supported on this platform",
        };
        vec![
            ("Locations".into(), locations.into()),
            ("Grouped by".into(), "Application (largest first)".into()),
        ]
    }

    fn notes(&self) -> Vec<String> {
        let mut notes = vec![
            "Tick an app in the list to clear its whole cache; apps rebuild caches when needed.".into(),
            "Caches of running apps are marked Review: quit the app first for a clean result.".into(),
            "Apple, browser and developer-tool caches are not listed here.".into(),
            "~/Library/Caches folders also appear in Junk Cleaner (grouped by type); cleaning in either place is the same.".into(),
        ];
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
        // Unknown owner keeps its folder name; a partial id is not a match.
        assert_eq!(idx.resolve("com.micro"), ("com.micro".to_string(), None));
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
            ("Caches/thumb.db", "com.example.Notes", SafetyClass::Safe),
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
        );
    }
}
