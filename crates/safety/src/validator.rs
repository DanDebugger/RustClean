//! Re-validation of a path immediately before it is removed.
//!
//! The scanner's view of the filesystem is stale by the time the user
//! confirms a cleanup. Every path is therefore checked again here: it must
//! still be the same regular file, must not be (or resolve through) a
//! symlink out of an approved root, must not be protected, and must be
//! removable by the current user.

use std::fs::{self, Metadata};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ProtectionRules, platform, starts_with_fs};

/// Identity of a file at scan time, used to detect modification between
/// scan and cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFingerprint {
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub inode: u64,
    pub device: u64,
}

impl FileFingerprint {
    pub fn from_metadata(meta: &Metadata) -> Self {
        Self {
            size: meta.len(),
            modified: meta.modified().ok(),
            inode: platform::file_identity(meta).0,
            device: platform::file_identity(meta).1,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("path is not absolute")]
    NotAbsolute,
    #[error("path contains '.' or '..' components")]
    NotNormalized,
    #[error("protected: {0}")]
    Protected(String),
    #[error("outside every approved cleanup location")]
    OutsideApprovedRoot,
    #[error("is a symbolic link")]
    Symlink,
    #[error("no longer exists")]
    NotFound,
    #[error("not a regular file")]
    NotRegularFile,
    #[error("file changed since it was scanned")]
    ChangedSinceScan,
    #[error("file is locked (immutable, append-only, read-only or system flag set)")]
    Locked,
    #[error("permission denied")]
    PermissionDenied,
    #[error("I/O error: {0}")]
    Io(String),
}

/// Validates paths against the protection rules and a set of approved roots.
#[derive(Debug, Clone)]
pub struct PathValidator {
    rules: ProtectionRules,
    /// Approved roots, canonicalised (symlinks resolved) where possible.
    approved_roots: Vec<PathBuf>,
}

impl PathValidator {
    /// Approved roots that are themselves protected are dropped: no caller
    /// can widen the cleanup scope to cover a protected location.
    pub fn new(rules: ProtectionRules, approved_roots: impl IntoIterator<Item = PathBuf>) -> Self {
        let approved_roots = approved_roots
            .into_iter()
            .filter(|r| r.is_absolute())
            .map(|r| platform::canonicalize(&r).unwrap_or(r))
            .filter(|r| {
                let protected = rules.is_protected(r);
                if protected {
                    tracing::warn!(root = %r.display(), "ignoring protected approved root");
                }
                !protected
            })
            .collect();
        Self {
            rules,
            approved_roots,
        }
    }

    pub fn rules(&self) -> &ProtectionRules {
        &self.rules
    }

    /// Lexical checks that need no filesystem access.
    pub fn check_lexical(&self, path: &Path) -> Result<(), ValidationError> {
        if !path.is_absolute() {
            return Err(ValidationError::NotAbsolute);
        }
        if path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        {
            return Err(ValidationError::NotNormalized);
        }
        if let Some(reason) = self.rules.protection_reason(path) {
            return Err(ValidationError::Protected(reason));
        }
        Ok(())
    }

    /// Full validation of a file about to be removed. Returns the resolved
    /// (real) path on success.
    ///
    /// `expected` is the fingerprint recorded at scan time; if given, the
    /// file must be unchanged.
    pub fn validate_for_removal(
        &self,
        path: &Path,
        expected: Option<&FileFingerprint>,
    ) -> Result<PathBuf, ValidationError> {
        self.check_lexical(path)?;

        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ValidationError::NotFound);
            }
            Err(e) => return Err(io_err(e)),
        };
        if meta.file_type().is_symlink() {
            return Err(ValidationError::Symlink);
        }
        if !meta.file_type().is_file() {
            return Err(ValidationError::NotRegularFile);
        }

        // Resolve symlinked ancestors; the real location must also be
        // approved and unprotected.
        let parent = path.parent().ok_or(ValidationError::NotRegularFile)?;
        let file_name = path.file_name().ok_or(ValidationError::NotRegularFile)?;
        let real_parent = platform::canonicalize(parent).map_err(io_err)?;
        let real_path = real_parent.join(file_name);
        if let Some(reason) = self.rules.protection_reason(&real_path) {
            return Err(ValidationError::Protected(reason));
        }
        // Equality is allowed: a single file may itself be an approved root.
        // Directories never pass the regular-file check above.
        if !self
            .approved_roots
            .iter()
            .any(|root| starts_with_fs(&real_path, root))
        {
            return Err(ValidationError::OutsideApprovedRoot);
        }

        if let Some(expected) = expected
            && FileFingerprint::from_metadata(&meta) != *expected
        {
            return Err(ValidationError::ChangedSinceScan);
        }

        if platform::is_locked(&meta) {
            return Err(ValidationError::Locked);
        }

        // Removing a directory entry needs write+search permission on the
        // parent directory.
        if !platform::can_remove_from(&real_parent) {
            return Err(ValidationError::PermissionDenied);
        }

        Ok(real_path)
    }
}

fn io_err(e: std::io::Error) -> ValidationError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        ValidationError::PermissionDenied
    } else {
        ValidationError::Io(e.to_string())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        outside: PathBuf,
        validator: PathValidator,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = platform::canonicalize(tmp.path()).unwrap();
        let root = base.join("cache");
        let outside = base.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let rules = ProtectionRules::for_home(base.join("home"));
        let validator = PathValidator::new(rules, [root.clone()]);
        Fixture {
            _tmp: tmp,
            root,
            outside,
            validator,
        }
    }

    fn fingerprint(p: &Path) -> FileFingerprint {
        FileFingerprint::from_metadata(&fs::symlink_metadata(p).unwrap())
    }

    #[test]
    fn accepts_unchanged_file_in_approved_root() {
        let f = fixture();
        let file = f.root.join("a.bin");
        fs::write(&file, b"data").unwrap();
        let fp = fingerprint(&file);
        assert_eq!(f.validator.validate_for_removal(&file, Some(&fp)), Ok(file));
    }

    #[test]
    fn rejects_relative_and_dotdot_paths() {
        let f = fixture();
        assert_eq!(
            f.validator.validate_for_removal(Path::new("a.bin"), None),
            Err(ValidationError::NotAbsolute)
        );
        let sneaky = f.root.join("../outside/x");
        assert_eq!(
            f.validator.validate_for_removal(&sneaky, None),
            Err(ValidationError::NotNormalized)
        );
    }

    #[test]
    fn rejects_file_outside_approved_root() {
        let f = fixture();
        let file = f.outside.join("x");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            f.validator.validate_for_removal(&file, None),
            Err(ValidationError::OutsideApprovedRoot)
        );
    }

    #[test]
    fn rejects_symlink_file() {
        let f = fixture();
        let target = f.outside.join("precious");
        fs::write(&target, b"x").unwrap();
        let link = f.root.join("link");
        symlink(&target, &link).unwrap();
        assert_eq!(
            f.validator.validate_for_removal(&link, None),
            Err(ValidationError::Symlink)
        );
        assert!(target.exists());
    }

    #[test]
    fn rejects_file_reached_through_symlinked_directory_escaping_root() {
        let f = fixture();
        let target = f.outside.join("precious");
        fs::write(&target, b"x").unwrap();
        let dir_link = f.root.join("escape");
        symlink(&f.outside, &dir_link).unwrap();
        assert_eq!(
            f.validator
                .validate_for_removal(&dir_link.join("precious"), None),
            Err(ValidationError::OutsideApprovedRoot)
        );
    }

    #[test]
    fn rejects_changed_file() {
        let f = fixture();
        let file = f.root.join("a.bin");
        fs::write(&file, b"data").unwrap();
        let fp = fingerprint(&file);
        fs::write(&file, b"different length").unwrap();
        assert_eq!(
            f.validator.validate_for_removal(&file, Some(&fp)),
            Err(ValidationError::ChangedSinceScan)
        );
    }

    #[test]
    fn rejects_missing_file_and_directories() {
        let f = fixture();
        assert_eq!(
            f.validator
                .validate_for_removal(&f.root.join("missing"), None),
            Err(ValidationError::NotFound)
        );
        let dir = f.root.join("sub");
        fs::create_dir(&dir).unwrap();
        assert_eq!(
            f.validator.validate_for_removal(&dir, None),
            Err(ValidationError::NotRegularFile)
        );
    }

    #[test]
    fn rejects_protected_path_even_if_approved() {
        let tmp = tempfile::tempdir().unwrap();
        let home = platform::canonicalize(tmp.path()).unwrap();
        let docs = home.join("Documents");
        fs::create_dir_all(&docs).unwrap();
        let file = docs.join("thesis.docx");
        fs::write(&file, b"x").unwrap();
        // Attempt to approve a protected root: it must be ignored.
        let v = PathValidator::new(ProtectionRules::for_home(&home), [docs.clone()]);
        assert!(matches!(
            v.validate_for_removal(&file, None),
            Err(ValidationError::Protected(_))
        ));
    }

    #[test]
    fn rejects_read_only_parent() {
        use std::os::unix::fs::PermissionsExt;
        let f = fixture();
        let dir = f.root.join("ro");
        fs::create_dir(&dir).unwrap();
        let file = dir.join("a");
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let result = f.validator.validate_for_removal(&file, None);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        // Root bypasses permission bits; only assert when not running as root.
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } != 0 {
            assert_eq!(result, Err(ValidationError::PermissionDenied));
        }
    }
}
