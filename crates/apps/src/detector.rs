//! Installed application detection (macOS `.app` bundles).

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApp {
    pub name: String,
    pub bundle_id: Option<String>,
    pub path: PathBuf,
}

/// Folders searched for `.app` bundles (one level of sub-folders too, e.g.
/// `/Applications/Utilities`).
pub fn app_dirs(home: &Path) -> Vec<PathBuf> {
    vec![
        PathBuf::from("/Applications"),
        home.join("Applications"),
        PathBuf::from("/System/Applications"),
    ]
}

/// Lists installed apps. Read-only.
pub fn installed_apps(home: &Path) -> Vec<InstalledApp> {
    let mut out = Vec::new();
    for dir in app_dirs(home) {
        collect(&dir, 0, &mut out);
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<InstalledApp>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        if path.extension().is_some_and(|x| x == "app") {
            out.push(read_app(&path));
        } else if depth == 0 {
            collect(&path, 1, out);
        }
    }
}

fn read_app(path: &Path) -> InstalledApp {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let info = plist::Value::from_file(path.join("Contents/Info.plist")).ok();
    let dict = info.as_ref().and_then(|v| v.as_dictionary());
    let get = |k: &str| {
        dict.and_then(|d| d.get(k))
            .and_then(|v| v.as_string())
            .map(str::to_string)
    };
    InstalledApp {
        name: get("CFBundleName").unwrap_or(stem),
        bundle_id: get("CFBundleIdentifier"),
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bundles_including_one_subfolder_level() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (rel, id) in [
            ("A.app", "com.example.a"),
            ("Utilities/B.app", "org.example.b"),
        ] {
            let c = root.join(rel).join("Contents");
            fs::create_dir_all(&c).unwrap();
            fs::write(
                c.join("Info.plist"),
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>{id}</string></dict></plist>"#
                ),
            )
            .unwrap();
        }
        let mut out = Vec::new();
        collect(root, 0, &mut out);
        let mut ids: Vec<_> = out.iter().filter_map(|a| a.bundle_id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["com.example.a", "org.example.b"]);
        assert!(out.iter().any(|a| a.name == "A"));
    }
}
