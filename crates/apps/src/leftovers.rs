//! Application leftovers: support files left behind by apps that are no
//! longer installed (macOS).
//!
//! Conservative by design:
//! * Only reverse-DNS names (`com.vendor.App`) are considered; plain folder
//!   names are too ambiguous to attribute.
//! * Apple's own (`com.apple.*`) items are never considered.
//! * An item counts as a leftover only if **no** installed app and no
//!   running process from the same developer (`com.vendor`) exists. Shared
//!   helpers (e.g. a vendor's updater) are therefore not flagged while any
//!   app from that vendor remains.
//! * Every leftover is `Review`: nothing is pre-selected, and the full file
//!   list is shown before anything is moved to the Trash.
//! * Caches are left to the Junk Cleaner; sandbox containers are not read
//!   (they need Full Disk Access).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use rustclean_core::{
    Classification, Classifier, CleanupModule, SafetyClass, ScanSpec, ScanTarget,
};
use rustclean_safety::{Os, platform};

use crate::detector::installed_apps;

/// `~/Library` sub-folders where apps keep per-app data.
const LIBRARY_DIRS: &[&str] = &[
    "Application Support",
    "Preferences",
    "Logs",
    "Saved Application State",
    "HTTPStorages",
    "WebKit",
];

/// `com.vendor` part of a reverse-DNS identifier, lowercased.
pub fn vendor_of(id: &str) -> Option<String> {
    let mut parts = id.split('.');
    let (a, b) = (parts.next()?, parts.next()?);
    if a.is_empty() || b.is_empty() || parts.next().is_none() {
        return None;
    }
    Some(format!("{a}.{b}").to_lowercase())
}

/// Identifier from a Library entry name (`com.x.App.plist`,
/// `com.x.App.savedState`, `com.x.App.binarycookies`).
fn identifier_of(name: &str) -> &str {
    for suffix in [".plist", ".savedState", ".binarycookies"] {
        if let Some(s) = name.strip_suffix(suffix) {
            return s;
        }
    }
    name
}

/// Bundle-identifier prefixes that are reverse-DNS.
const TLDS: &[&str] = &[
    "com", "org", "net", "io", "dev", "app", "ai", "co", "us", "me", "de", "uk", "jp", "fr",
];

fn is_reverse_dns(id: &str) -> bool {
    id.split('.')
        .next()
        .is_some_and(|t| TLDS.contains(&t.to_lowercase().as_str()))
        && id.split('.').count() >= 3
}

/// Path fragments that suggest keys or credentials. Anything matching is
/// `Protected`, even inside a genuine leftover.
const SENSITIVE: &[&str] = &[
    "wallet",
    "identity",
    "identities",
    "keys",
    "keystore",
    "keychain",
    "credential",
    "secret",
    "seed",
    "mnemonic",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    "id_rsa",
    "id_ed25519",
];

/// Raises anything that looks like key material to `Protected`.
pub struct SensitiveClassifier;

impl Classifier for SensitiveClassifier {
    fn classify(&self, path: &Path, _: bool, _: &ScanTarget) -> Classification {
        let lower = path.to_string_lossy().to_lowercase();
        match SENSITIVE.iter().find(|s| lower.contains(*s)) {
            Some(s) => Classification::new(
                SafetyClass::Protected,
                format!("may contain keys or credentials (\"{s}\"); never removed"),
            ),
            None => Classification::new(SafetyClass::Safe, None),
        }
    }
}

/// Names of executables on `PATH` (lowercased), to recognise installed
/// command-line tools that keep data under reverse-DNS folders.
fn path_executables() -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(path) = std::env::var_os("PATH") else {
        return out;
    };
    for dir in std::env::split_paths(&path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                out.insert(e.file_name().to_string_lossy().to_lowercase());
            }
        }
    }
    out
}

/// Whether a folder looks like an installation (has `bin/` or executable
/// files) rather than leftover data.
fn looks_like_installation(dir: &Path) -> bool {
    if dir.join("bin").is_dir() {
        return true;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let Ok(m) = e.metadata() else { return false };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            m.is_file() && m.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            m.is_file() && e.path().extension().is_some_and(|x| x == "exe")
        }
    })
}

pub struct LeftoversModule {
    home: PathBuf,
    installed: usize,
    vendors: HashSet<String>,
    ids: HashSet<String>,
    tools: HashSet<String>,
}

impl LeftoversModule {
    pub fn new(home: PathBuf) -> Self {
        let mut m = Self {
            home,
            installed: 0,
            vendors: HashSet::new(),
            ids: HashSet::new(),
            tools: HashSet::new(),
        };
        m.refresh();
        m
    }

    /// For tests: explicit installed identifiers.
    pub fn with_installed(home: PathBuf, ids: &[&str], tools: &[&str]) -> Self {
        let mut m = Self {
            home,
            installed: ids.len(),
            vendors: HashSet::new(),
            ids: HashSet::new(),
            tools: tools.iter().map(|t| t.to_lowercase()).collect(),
        };
        for id in ids {
            m.add_id(id);
        }
        m
    }

    fn add_id(&mut self, id: &str) {
        self.ids.insert(id.to_lowercase());
        if let Some(v) = vendor_of(id) {
            self.vendors.insert(v);
        }
    }

    fn belongs_to_installed(&self, id: &str) -> bool {
        let l = id.to_lowercase();
        if self.ids.contains(&l) || vendor_of(&l).is_some_and(|v| self.vendors.contains(&v)) {
            return true;
        }
        // Command-line tools: any label (e.g. `dfx` in `org.dfinity.dfx`,
        // `stellar` in `org.stellar.stellar-cli`) naming a tool on PATH.
        l.split('.').skip(1).any(|label| {
            let base = label.strip_suffix("-cli").unwrap_or(label);
            self.tools.contains(label) || self.tools.contains(base)
        })
    }

    pub fn targets(&self) -> Vec<ScanTarget> {
        let mut out = Vec::new();
        for dir in LIBRARY_DIRS {
            let base = self.home.join("Library").join(dir);
            let Ok(entries) = fs::read_dir(&base) else {
                continue;
            };
            let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            paths.sort();
            for path in paths {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let id = identifier_of(&name);
                if id.to_lowercase().starts_with("com.apple.")
                    || !is_reverse_dns(id)
                    || self.belongs_to_installed(id)
                    || (path.is_dir() && looks_like_installation(&path))
                {
                    continue;
                }
                let vendor = vendor_of(id).unwrap_or_default();
                out.push(
                    ScanTarget::new("App leftovers", path.clone(), SafetyClass::Review)
                        .with_context(id.to_string())
                        .with_reason(format!(
                            "no installed app from this developer ({vendor}) was found; check before removing"
                        )),
                );
            }
        }
        out
    }
}

impl CleanupModule for LeftoversModule {
    fn title(&self) -> &str {
        "App Cleaner — leftovers"
    }

    fn refresh(&mut self) {
        if platform::CURRENT != Os::MacOs {
            return;
        }
        self.ids.clear();
        self.vendors.clear();
        self.tools = path_executables();
        let apps = installed_apps(&self.home);
        self.installed = apps.len();
        for a in apps {
            if let Some(id) = a.bundle_id {
                self.add_id(&id);
            }
        }
        // Running processes inside .app bundles count as installed too
        // (apps launched from other locations).
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
        );
        let bundles: HashSet<PathBuf> = sys
            .processes()
            .values()
            .filter_map(|p| p.exe())
            .filter_map(|exe| {
                exe.ancestors()
                    .find(|a| a.extension().is_some_and(|e| e == "app"))
                    .map(Path::to_path_buf)
            })
            .collect();
        for b in bundles {
            if let Ok(v) = plist::Value::from_file(b.join("Contents/Info.plist"))
                && let Some(id) = v
                    .as_dictionary()
                    .and_then(|d| d.get("CFBundleIdentifier"))
                    .and_then(|x| x.as_string())
            {
                self.add_id(id);
            }
        }
    }

    fn is_available(&self) -> bool {
        platform::CURRENT == Os::MacOs
    }

    fn details(&self) -> Vec<(String, String)> {
        if platform::CURRENT != Os::MacOs {
            return vec![("Status".into(), "Available on macOS only for now".into())];
        }
        vec![
            ("Installed apps".into(), self.installed.to_string()),
            (
                "Looks in".into(),
                "~/Library: Application Support, Preferences, Logs, Saved Application State, HTTPStorages, WebKit".into(),
            ),
        ]
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "An item is listed only when no installed app or command-line tool from the same developer exists.".into(),
            "Anything that looks like keys, wallets or credentials is never removed.".into(),
            "Everything here needs your review; app caches are handled by the Junk Cleaner.".into(),
        ]
    }

    fn prepare_scan(&self) -> ScanSpec {
        ScanSpec::new(self.targets(), Some(Box::new(SensitiveClassifier)))
    }

    fn active_warning(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_only_orphaned_reverse_dns_items() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let lib = home.join("Library");
        for rel in [
            "Application Support/com.gone.Editor/data.db",
            "Application Support/com.google.Keystone/x",
            "Application Support/Slack/x",
            "Application Support/com.apple.sharedfilelist/x",
            "Preferences/com.gone.Editor.plist",
            "Preferences/com.present.App.plist",
            "Application Support/org.dfinity.dfx/network/x",
            "Application Support/org.stellar.stellar-cli/spec",
            "Application Support/com.gone.Tool/bin/tool",
            "Saved Application State/com.gone.Editor.savedState/w",
        ] {
            let p = lib.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"x").unwrap();
        }
        let m = LeftoversModule::with_installed(
            home.clone(),
            &["com.google.Chrome", "com.present.App"],
            &["dfx", "stellar"],
        );
        let mut found: Vec<String> = m
            .targets()
            .iter()
            .map(|t| {
                t.root
                    .strip_prefix(&lib)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                "Application Support/com.gone.Editor",
                "Preferences/com.gone.Editor.plist",
                "Saved Application State/com.gone.Editor.savedState",
            ]
        );
        assert!(
            m.targets()
                .iter()
                .all(|t| t.default_class == SafetyClass::Review)
        );
    }

    #[test]
    fn vendor_and_identifier_parsing() {
        assert_eq!(
            vendor_of("com.Google.Chrome").as_deref(),
            Some("com.google")
        );
        assert_eq!(vendor_of("com.google"), None);
        assert_eq!(identifier_of("com.x.App.plist"), "com.x.App");
        assert!(is_reverse_dns("com.x.App"));
        assert!(!is_reverse_dns("Slack"));
    }
}

#[cfg(test)]
mod sensitive_tests {
    use super::*;

    #[test]
    fn key_material_is_protected() {
        let t = ScanTarget::new("App leftovers", PathBuf::from("/x"), SafetyClass::Review);
        for p in [
            "/x/wallets/main.json",
            "/x/identity/default.pem",
            "/x/Keys/a",
            "/x/id_ed25519",
        ] {
            assert_eq!(
                SensitiveClassifier.classify(Path::new(p), false, &t).class,
                SafetyClass::Protected,
                "{p}"
            );
        }
        assert_eq!(
            SensitiveClassifier
                .classify(Path::new("/x/cache.db"), false, &t)
                .class,
            SafetyClass::Safe
        );
    }
}
