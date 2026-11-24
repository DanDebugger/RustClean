//! Developer Cleaner: package-manager and build caches (macOS, Linux,
//! Windows).
//!
//! RustClean removes individual files, and a cleanup can stop part-way
//! (cancelled, or a file skipped by re-validation). A location is therefore
//! included only if **removing any subset of its files is harmless**: the
//! tool simply re-downloads or rebuilds what is missing.
//!
//! Deliberately excluded (need whole-directory or tool-driven removal):
//! * `~/.cargo/registry/src`, `~/.cargo/git/*` – a leftover `.cargo-ok`
//!   marker makes Cargo trust a partially deleted source tree.
//! * `~/go/pkg/mod` – read-only by design; use `go clean -modcache`.
//! * pnpm store – hard-linked into projects; use `pnpm store prune`.
//! * nvm/rustup installs – partial removal leaves a broken toolchain.
//! * Xcode Archives – contain release builds and debug symbols.

use std::path::{Path, PathBuf};

use rustclean_core::{CleanupModule, SafetyClass, ScanSpec, ScanTarget};
use rustclean_safety::{Os, platform};

use crate::running_apps::RunningApps;

/// Cache-directory entries owned by this module, excluded from the Junk
/// Cleaner (`~/Library/Caches` on macOS, `~/.cache` on Linux).
pub fn dev_owned_cache_names() -> &'static [&'static str] {
    match platform::CURRENT {
        Os::MacOs => &[
            "Homebrew",
            "go-build",
            "Yarn",
            "pnpm",
            "pip",
            "CocoaPods",
            "org.swift.swiftpm",
            "ms-playwright",
            "ms-playwright-go",
            "node-gyp",
            "typescript",
            "composer",
        ],
        Os::Linux => &[
            "Homebrew",
            "go-build",
            "yarn",
            "pnpm",
            "pip",
            "uv",
            "ms-playwright",
            "ms-playwright-go",
            "node-gyp",
            "typescript",
            "composer",
            "prisma",
            "JetBrains",
        ],
        _ => &[],
    }
}

/// Processes whose activity makes developer-cache cleanup risky.
const BUILD_TOOLS: &[&str] = &[
    "cargo",
    "rustc",
    "npm",
    "pnpm",
    "yarn",
    "go",
    "xcodebuild",
    "Xcode",
    "pod",
    "brew",
    "pip",
    "pip3",
    "uv",
    "swift-build",
    "gradle",
    "mvn",
    // Windows executable names.
    "cargo.exe",
    "rustc.exe",
    "node.exe",
    "go.exe",
    "msbuild.exe",
];

/// One cache location: home-relative path per platform (`None` = not
/// applicable there).
struct Loc {
    category: &'static str,
    mac: Option<&'static str>,
    linux: Option<&'static str>,
    windows: Option<&'static str>,
    class: SafetyClass,
    reason: Option<&'static str>,
}

const fn loc(
    category: &'static str,
    mac: Option<&'static str>,
    linux: Option<&'static str>,
    windows: Option<&'static str>,
) -> Loc {
    Loc {
        category,
        mac,
        linux,
        windows,
        class: SafetyClass::Safe,
        reason: None,
    }
}

const fn review(mut l: Loc, reason: &'static str) -> Loc {
    l.class = SafetyClass::Review;
    l.reason = Some(reason);
    l
}

const REBUILD: &str = "re-downloaded on next build; offline builds fail until then";

const LOCATIONS: &[Loc] = &[
    loc(
        "npm cache",
        Some(".npm/_cacache"),
        Some(".npm/_cacache"),
        Some("AppData/Local/npm-cache/_cacache"),
    ),
    loc(
        "npm cache",
        Some(".npm/_npx"),
        Some(".npm/_npx"),
        Some("AppData/Local/npm-cache/_npx"),
    ),
    loc(
        "npm cache",
        Some(".npm/_logs"),
        Some(".npm/_logs"),
        Some("AppData/Local/npm-cache/_logs"),
    ),
    loc(
        "Yarn cache",
        Some("Library/Caches/Yarn"),
        Some(".cache/yarn"),
        Some("AppData/Local/Yarn/Cache"),
    ),
    loc(
        "Yarn cache",
        Some(".yarn/berry/cache"),
        Some(".yarn/berry/cache"),
        Some(".yarn/berry/cache"),
    ),
    loc(
        "pnpm metadata cache",
        Some("Library/Caches/pnpm"),
        Some(".cache/pnpm"),
        Some("AppData/Local/pnpm-cache"),
    ),
    loc(
        "Cargo registry cache",
        Some(".cargo/registry/cache"),
        Some(".cargo/registry/cache"),
        Some(".cargo/registry/cache"),
    ),
    loc(
        "Go build cache",
        Some("Library/Caches/go-build"),
        Some(".cache/go-build"),
        Some("AppData/Local/go-build"),
    ),
    loc(
        "Xcode DerivedData",
        Some("Library/Developer/Xcode/DerivedData"),
        None,
        None,
    ),
    loc(
        "Simulator caches",
        Some("Library/Developer/CoreSimulator/Caches"),
        None,
        None,
    ),
    review(
        loc(
            "Xcode device support",
            Some("Library/Developer/Xcode/iOS DeviceSupport"),
            None,
            None,
        ),
        "re-copied from the device on next connection; slow",
    ),
    review(
        loc(
            "Gradle caches",
            Some(".gradle/caches"),
            Some(".gradle/caches"),
            Some(".gradle/caches"),
        ),
        REBUILD,
    ),
    review(
        loc(
            "Gradle wrappers",
            Some(".gradle/wrapper/dists"),
            Some(".gradle/wrapper/dists"),
            Some(".gradle/wrapper/dists"),
        ),
        "Gradle distributions; re-downloaded on next build",
    ),
    review(
        loc(
            "Maven repository",
            Some(".m2/repository"),
            Some(".m2/repository"),
            Some(".m2/repository"),
        ),
        REBUILD,
    ),
    loc(
        "pip cache",
        Some("Library/Caches/pip"),
        Some(".cache/pip"),
        Some("AppData/Local/pip/Cache"),
    ),
    loc("pip cache", Some(".cache/pip"), None, None),
    review(
        loc(
            "uv cache",
            Some(".cache/uv"),
            Some(".cache/uv"),
            Some("AppData/Local/uv/cache"),
        ),
        "virtual environments created with uv's symlink mode point into this cache",
    ),
    loc(
        "Homebrew downloads",
        Some("Library/Caches/Homebrew"),
        Some(".cache/Homebrew"),
        None,
    ),
    loc(
        "CocoaPods cache",
        Some("Library/Caches/CocoaPods"),
        None,
        None,
    ),
    loc(
        "Swift PM cache",
        Some("Library/Caches/org.swift.swiftpm"),
        None,
        None,
    ),
    review(
        loc(
            "Playwright browsers",
            Some("Library/Caches/ms-playwright"),
            Some(".cache/ms-playwright"),
            Some("AppData/Local/ms-playwright"),
        ),
        "reinstall with `playwright install`",
    ),
    review(
        loc(
            "Playwright browsers",
            Some("Library/Caches/ms-playwright-go"),
            Some(".cache/ms-playwright-go"),
            None,
        ),
        "reinstall with `playwright install`",
    ),
    loc(
        "node-gyp headers",
        Some("Library/Caches/node-gyp"),
        Some(".cache/node-gyp"),
        Some("AppData/Local/node-gyp/Cache"),
    ),
    loc(
        "TypeScript cache",
        Some("Library/Caches/typescript"),
        Some(".cache/typescript"),
        Some("AppData/Local/Microsoft/TypeScript"),
    ),
    loc(
        "Composer cache",
        Some("Library/Caches/composer"),
        Some(".cache/composer"),
        Some("AppData/Local/Composer"),
    ),
    review(
        loc(
            "Prisma engines",
            Some(".cache/prisma"),
            Some(".cache/prisma"),
            None,
        ),
        "re-downloaded by Prisma on next use",
    ),
    loc(
        "NuGet cache",
        None,
        Some(".nuget/packages"),
        Some(".nuget/packages"),
    ),
];

pub struct DeveloperModule {
    home: PathBuf,
}

impl DeveloperModule {
    pub fn new(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn targets(&self) -> Vec<ScanTarget> {
        targets_for(&self.home, platform::CURRENT)
    }
}

fn targets_for(home: &Path, os: Os) -> Vec<ScanTarget> {
    LOCATIONS
        .iter()
        .filter_map(|l| {
            let rel = match os {
                Os::MacOs => l.mac,
                Os::Linux => l.linux,
                Os::Windows => l.windows,
                Os::Other => None,
            }?;
            let t = ScanTarget::new(l.category, home.join(rel), l.class)
                .with_context(format!("~/{rel}"));
            Some(match l.reason {
                Some(r) => t.with_reason(r),
                None => t,
            })
        })
        .collect()
}

impl CleanupModule for DeveloperModule {
    fn title(&self) -> &str {
        "Developer Cleaner"
    }

    fn refresh(&mut self) {}

    fn is_available(&self) -> bool {
        true
    }

    fn details(&self) -> Vec<(String, String)> {
        let mut tools: Vec<String> = Vec::new();
        for t in self.targets() {
            let tool = t
                .category
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            if !tools.contains(&tool) {
                tools.push(tool);
            }
        }
        vec![("Covers".into(), tools.join(", "))]
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "Only caches that tools rebuild on demand are scanned; project source files are never scanned.".into(),
            "Not cleaned here (need tool commands): Cargo sources and git checkouts, Go module cache, pnpm store, nvm/rustup toolchains, Xcode Archives.".into(),
        ]
    }

    fn prepare_scan(&self) -> ScanSpec {
        ScanSpec::new(self.targets(), None)
    }

    fn active_warning(&self) -> Option<String> {
        let running = RunningApps::process_names().running_processes(BUILD_TOOLS);
        (!running.is_empty()).then(|| {
            format!(
                "Build tools are running ({}). Cleaning their caches during a build can make it fail.",
                running.join(", ")
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_os_has_targets_and_no_excluded_locations() {
        for os in [Os::MacOs, Os::Linux, Os::Windows] {
            let t = targets_for(Path::new("/h"), os);
            assert!(t.len() >= 10, "{os:?} has only {} targets", t.len());
            for target in &t {
                let p = target.root.to_string_lossy().replace('\\', "/");
                for banned in [
                    "registry/src",
                    ".cargo/git",
                    "go/pkg/mod",
                    "pnpm/store",
                    ".rustup",
                    ".nvm",
                    "Archives",
                ] {
                    assert!(
                        !p.contains(banned),
                        "{os:?}: {p} must not be cleaned file-by-file"
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn scans_only_listed_caches() {
        use rustclean_core::{Progress, Scanner};
        use rustclean_safety::ProtectionRules;
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let home = platform::canonicalize(tmp.path()).unwrap();
        for rel in [
            ".npm/_cacache/content-v2/sha512/ab/cd",
            ".cargo/registry/cache/index.crates.io-x/serde-1.0.0.crate",
            ".cargo/registry/src/index.crates.io-x/serde-1.0.0/.cargo-ok",
            ".cargo/git/checkouts/x/y/.cargo-ok",
            "go/pkg/mod/github.com/x/y.go",
            ".m2/repository/org/x/x.jar",
            "Library/pnpm/store/v3/files/00/abc",
            "projects/app/src/main.rs",
        ] {
            let p = home.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"x").unwrap();
        }
        let m = DeveloperModule::new(home.clone());
        let report = Scanner::new(ProtectionRules::for_home(&home)).scan(
            m.targets(),
            None,
            &Progress::new(),
        );
        let mut found: Vec<(String, SafetyClass)> = report
            .candidates
            .iter()
            .map(|c| {
                (
                    c.path.strip_prefix(&home).unwrap().display().to_string(),
                    c.class,
                )
            })
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                (
                    ".cargo/registry/cache/index.crates.io-x/serde-1.0.0.crate".into(),
                    SafetyClass::Safe
                ),
                (".m2/repository/org/x/x.jar".into(), SafetyClass::Review),
                (
                    ".npm/_cacache/content-v2/sha512/ab/cd".into(),
                    SafetyClass::Safe
                ),
            ]
        );
    }
}
