//! Locations that RustClean must never remove, regardless of what any
//! scanner or user selection says.

use std::path::{Path, PathBuf};

use crate::{platform, starts_with_ci};

/// The set of protected locations for one user.
#[derive(Debug, Clone)]
pub struct ProtectionRules {
    home: PathBuf,
    protected: Vec<PathBuf>,
}

impl ProtectionRules {
    /// Builds the default rule set for the given home directory. RustClean's
    /// own data directory is protected so scans never pick up quarantined
    /// files.
    pub fn for_home(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let mut protected = platform::system_protected();
        protected.extend(platform::user_protected().iter().map(|p| home.join(p)));
        protected.push(platform::app_data_dir(&home));
        // RustClean's own operation log must survive log cleanup.
        protected.push(platform::app_log_dir(&home));
        Self { home, protected }
    }

    /// Adds an extra protected location (e.g. from user settings).
    pub fn with_extra(mut self, path: impl Into<PathBuf>) -> Self {
        self.protected.push(path.into());
        self
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn protected_locations(&self) -> &[PathBuf] {
        &self.protected
    }

    /// Returns the reason a path is protected, or `None` if it is not.
    ///
    /// A path is protected if it is the filesystem root, the home directory,
    /// inside a protected location, or an *ancestor* of one (removing an
    /// ancestor would remove the protected location with it).
    pub fn protection_reason(&self, path: &Path) -> Option<String> {
        if path.parent().is_none() {
            return Some("filesystem root".into());
        }
        if starts_with_ci(&self.home, path) {
            return Some("home directory or one of its ancestors".into());
        }
        self.protected.iter().find_map(|p| {
            if starts_with_ci(path, p) {
                Some(format!("inside protected location {}", p.display()))
            } else if starts_with_ci(p, path) {
                Some(format!("contains protected location {}", p.display()))
            } else {
                None
            }
        })
    }

    pub fn is_protected(&self, path: &Path) -> bool {
        self.protection_reason(path).is_some()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn rules() -> ProtectionRules {
        ProtectionRules::for_home("/Users/alice")
    }

    #[test]
    fn system_locations_are_protected() {
        let r = rules();
        for p in [
            "/System/Library/x",
            "/usr/bin/ls",
            "/Library/Caches/x",
            "/private/var/db/x",
            "/bin",
        ] {
            assert!(r.is_protected(Path::new(p)), "{p} should be protected");
        }
    }

    #[test]
    fn user_locations_are_protected_case_insensitively() {
        let r = rules();
        for p in [
            "/Users/alice/Documents/report.pdf",
            "/Users/alice/documents/report.pdf",
            "/Users/alice/Library/Keychains/login.keychain-db",
            "/Users/alice/Library/Mail/V10",
            "/Users/alice/Desktop",
        ] {
            assert!(r.is_protected(Path::new(p)), "{p} should be protected");
        }
    }

    #[test]
    fn root_home_and_ancestors_are_protected() {
        let r = rules();
        for p in ["/", "/Users", "/Users/alice", "/Users/alice/Library"] {
            assert!(r.is_protected(Path::new(p)), "{p} should be protected");
        }
    }

    #[test]
    fn cache_files_are_not_protected() {
        let r = rules();
        assert!(!r.is_protected(Path::new(
            "/Users/alice/Library/Caches/Google/Chrome/Default/Cache/Cache_Data/f_000001"
        )));
        // Similar name, different component.
        assert!(!r.is_protected(Path::new("/Users/alice/DocumentsArchive/x")));
    }

    #[test]
    fn rustclean_data_dir_is_protected() {
        let r = rules();
        assert!(r.is_protected(Path::new(
            "/Users/alice/Library/Application Support/RustClean/Quarantine/s1/f"
        )));
    }
}
