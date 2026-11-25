//! Snapshot of running applications, used to avoid cleaning caches that an
//! app is actively using.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Lowercased bundle identifiers and names of running apps and processes.
#[derive(Debug, Default, Clone)]
pub struct RunningApps {
    bundle_ids: HashSet<String>,
    names: HashSet<String>,
}

impl RunningApps {
    /// Takes a snapshot of all processes visible to the current user. For
    /// processes inside an `.app` bundle, the bundle's `Info.plist` is read
    /// for its identifier and name.
    pub fn snapshot() -> Self {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
        );
        let mut apps = Self::default();
        let mut seen_bundles: HashSet<PathBuf> = HashSet::new();
        for p in sys.processes().values() {
            apps.add_name(&p.name().to_string_lossy());
            let Some(exe) = p.exe() else { continue };
            for bundle in app_bundles_of(exe) {
                if seen_bundles.insert(bundle.clone()) {
                    apps.add_bundle(&bundle);
                }
            }
        }
        apps
    }

    /// Cheap variant: process names only (no bundle metadata). Suitable for
    /// frequent polling.
    pub fn process_names() -> Self {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        let mut apps = Self::default();
        for p in sys.processes().values() {
            apps.add_name(&p.name().to_string_lossy());
        }
        apps
    }

    /// For tests: build from explicit identifiers and names.
    pub fn from_parts(bundle_ids: &[&str], names: &[&str]) -> Self {
        let mut apps = Self {
            bundle_ids: bundle_ids.iter().map(|s| s.to_lowercase()).collect(),
            names: HashSet::new(),
        };
        for n in names {
            apps.add_name(n);
        }
        apps
    }

    /// Records a process name, lowercased. A Windows `.exe` name such as
    /// `Slack.exe` is also recorded without the suffix, so it matches the
    /// owner folder `Slack`; the full name stays for `running_processes`.
    fn add_name(&mut self, name: &str) {
        let lower = name.to_lowercase();
        if let Some(stem) = lower.strip_suffix(".exe").filter(|s| !s.is_empty()) {
            self.names.insert(stem.to_string());
        }
        self.names.insert(lower);
    }

    fn add_bundle(&mut self, bundle: &Path) {
        let Ok(value) = plist::Value::from_file(bundle.join("Contents/Info.plist")) else {
            return;
        };
        let Some(dict) = value.as_dictionary() else {
            return;
        };
        let get = |k: &str| {
            dict.get(k)
                .and_then(|v| v.as_string())
                .map(str::to_lowercase)
        };
        if let Some(id) = get("CFBundleIdentifier") {
            self.bundle_ids.insert(id);
        }
        for key in ["CFBundleName", "CFBundleExecutable"] {
            if let Some(n) = get(key) {
                self.names.insert(n);
            }
        }
    }

    /// If the app that owns a cache folder named `dir_name` appears to be
    /// running, returns what matched. Matching is heuristic and errs on the
    /// side of reporting "running" (which only makes classification
    /// stricter).
    pub fn owner_running(&self, dir_name: &str) -> Option<String> {
        let n = normalize(dir_name);
        if n.is_empty() {
            return None;
        }
        let prefix = format!("{n}.");
        for id in &self.bundle_ids {
            if *id == n || n.starts_with(&format!("{id}.")) || id.starts_with(&prefix) {
                return Some(id.clone());
            }
        }
        self.names.contains(&n).then_some(n)
    }

    /// Which of the given process names are running (case-insensitive).
    pub fn running_processes(&self, names: &[&str]) -> Vec<String> {
        names
            .iter()
            .filter(|n| self.names.contains(&n.to_lowercase()))
            .map(|n| n.to_string())
            .collect()
    }
}

/// Strips updater suffixes so `com.foo.App.ShipIt` and `foo-updater` match
/// their apps.
fn normalize(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut s = lower.as_str();
    for suffix in [".shipit", "-updater", "_updater", ".updater"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped;
        }
    }
    s.to_string()
}

/// All `.app` bundles containing `exe` (outer app and nested helpers).
fn app_bundles_of(exe: &Path) -> Vec<PathBuf> {
    exe.ancestors()
        .filter(|a| a.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_bundle_ids_updaters_and_names() {
        let r = RunningApps::from_parts(
            &["com.microsoft.VSCode", "com.google.antigravity-ide.helper"],
            &["ollama", "Code"],
        );
        assert!(r.owner_running("com.microsoft.VSCode").is_some());
        assert!(r.owner_running("com.microsoft.VSCode.ShipIt").is_some());
        assert!(r.owner_running("com.google.antigravity-ide").is_some());
        assert!(r.owner_running("ollama").is_some());
        assert!(r.owner_running("Code").is_some());
        assert!(r.owner_running("com.postmanlabs.mac").is_none());
        // A vendor-level folder matches any running app of that vendor;
        // that only ever makes classification stricter.
        assert!(r.owner_running("com.microsoft").is_some());
        assert!(r.owner_running("com.micro").is_none());
    }

    #[test]
    fn matches_windows_exe_process_names() {
        let r = RunningApps::from_parts(&[], &["Slack.exe", "Discord.EXE", "Code.exe"]);
        for owner in ["Slack", "slack", "discord", "Code"] {
            assert!(r.owner_running(owner).is_some(), "{owner}");
        }
        assert!(r.owner_running("Teams").is_none());
        assert!(r.owner_running("exe").is_none());
        // The full process name is still queryable.
        assert_eq!(r.running_processes(&["slack.exe"]), vec!["slack.exe"]);
        // A bare ".exe" name does not produce an empty owner.
        let r = RunningApps::from_parts(&[], &[".exe"]);
        assert!(r.owner_running("").is_none());
    }

    #[test]
    fn finds_nested_bundles() {
        let b = app_bundles_of(Path::new(
            "/Applications/X.app/Contents/Frameworks/X Helper.app/Contents/MacOS/X Helper",
        ));
        assert_eq!(b.len(), 2);
    }
}
