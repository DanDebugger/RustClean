//! Reversible removal.
//!
//! RustClean never unlinks files directly. A removal either moves the file
//! to the user's Trash (via `NSFileManager`, so Finder's "Put Back" logic and
//! Trash emptying apply) or into a RustClean quarantine session that can be
//! restored with [`restore_quarantine`].

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ProtectionRules, platform};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RemovalMethod {
    /// Move to the user's Trash (recoverable from Finder).
    #[default]
    Trash,
    /// Move into RustClean's quarantine directory (recoverable via RustClean).
    Quarantine,
}

impl RemovalMethod {
    pub fn label(self) -> &'static str {
        match self {
            RemovalMethod::Trash => "Move to Trash",
            RemovalMethod::Quarantine => "Move to RustClean quarantine",
        }
    }
}

#[derive(Debug, Error)]
pub enum RemovalError {
    #[error("could not move to Trash: {0}")]
    Trash(String),
    #[error("destination already exists in quarantine: {0}")]
    QuarantineCollision(PathBuf),
    #[error("file is on a different volume than the quarantine directory")]
    CrossDevice,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Performs the actual (reversible) removal of a single, already validated
/// file. Implementations must not perform validation themselves; that is
/// the cleaner's job.
pub trait Remover: Send + Sync {
    fn method(&self) -> RemovalMethod;

    /// Removes `path`. Returns the new location if it is known.
    fn remove(&self, path: &Path) -> Result<Option<PathBuf>, RemovalError>;
}

/// Moves files to the user's Trash using `NSFileManager`.
pub struct TrashRemover {
    ctx: trash::TrashContext,
}

impl TrashRemover {
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut ctx = trash::TrashContext::default();
        #[cfg(target_os = "macos")]
        {
            use trash::macos::{DeleteMethod, TrashContextExtMacos};
            // NSFileManager does not need Finder automation permission.
            ctx.set_delete_method(DeleteMethod::NsFileManager);
        }
        // Linux: freedesktop.org Trash spec; Windows: Recycle Bin.
        Self { ctx }
    }
}

impl Default for TrashRemover {
    fn default() -> Self {
        Self::new()
    }
}

impl Remover for TrashRemover {
    fn method(&self) -> RemovalMethod {
        RemovalMethod::Trash
    }

    fn remove(&self, path: &Path) -> Result<Option<PathBuf>, RemovalError> {
        self.ctx
            .delete(path)
            .map(|()| None)
            .map_err(|e| RemovalError::Trash(e.to_string()))
    }
}

/// One quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub original: PathBuf,
    pub quarantined: PathBuf,
    pub size: u64,
    pub quarantined_at_unix: u64,
}

const MANIFEST: &str = "manifest.jsonl";

/// Moves files into a quarantine session directory, recording each move in
/// an append-only manifest.
pub struct QuarantineRemover {
    session_dir: PathBuf,
    manifest: Mutex<fs::File>,
}

impl QuarantineRemover {
    /// Creates a new session under `<base>/Quarantine/<timestamp>-<pid>`.
    pub fn new_session(base: &Path) -> std::io::Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let session_dir =
            base.join("Quarantine")
                .join(format!("{}-{}", now.as_secs(), std::process::id()));
        Self::open(session_dir)
    }

    /// Opens (or creates) a specific session directory.
    pub fn open(session_dir: PathBuf) -> std::io::Result<Self> {
        platform::create_private_dir(&session_dir)?;
        let manifest = platform::open_private_append(&session_dir.join(MANIFEST))?;
        Ok(Self {
            session_dir,
            manifest: Mutex::new(manifest),
        })
    }

    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    fn destination_for(&self, original: &Path) -> PathBuf {
        // Mirror the original absolute path beneath `files/`.
        let relative: PathBuf = original
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .collect();
        self.session_dir.join("files").join(relative)
    }
}

impl Remover for QuarantineRemover {
    fn method(&self) -> RemovalMethod {
        RemovalMethod::Quarantine
    }

    fn remove(&self, path: &Path) -> Result<Option<PathBuf>, RemovalError> {
        let dest = self.destination_for(path);
        if fs::symlink_metadata(&dest).is_ok() {
            return Err(RemovalError::QuarantineCollision(dest));
        }
        if let Some(parent) = dest.parent() {
            platform::create_private_dir(parent)?;
        }
        let size = fs::symlink_metadata(path).map(|m| m.len()).unwrap_or(0);

        // Hold the manifest lock across the move so the manifest never lags
        // behind what is actually in quarantine.
        let mut manifest = self.manifest.lock().unwrap_or_else(|p| p.into_inner());
        fs::rename(path, &dest).map_err(|e| {
            if e.kind() == std::io::ErrorKind::CrossesDevices {
                RemovalError::CrossDevice
            } else {
                RemovalError::Io(e)
            }
        })?;
        let entry = ManifestEntry {
            original: path.to_path_buf(),
            quarantined: dest.clone(),
            size,
            quarantined_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        let mut line = serde_json::to_string(&entry).map_err(std::io::Error::other)?;
        line.push('\n');
        if let Err(e) = manifest
            .write_all(line.as_bytes())
            .and_then(|()| manifest.sync_data())
        {
            // Without a manifest entry the file could not be restored by
            // RustClean; undo the move rather than orphan it.
            let _ = fs::rename(&dest, path);
            return Err(RemovalError::Io(e));
        }
        Ok(Some(dest))
    }
}

#[derive(Debug, Default)]
pub struct RestoreReport {
    pub restored: Vec<PathBuf>,
    /// Original location is occupied again; the quarantined copy was kept.
    pub conflicts: Vec<PathBuf>,
    pub missing: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
}

/// Restores every file recorded in a quarantine session's manifest to its
/// original location. Never overwrites an existing file.
///
/// The manifest is treated as untrusted: an entry is restored only if its
/// quarantined copy is a regular file genuinely inside this session (no
/// `..`), and its original location is absolute, normalised and not
/// protected. A tampered manifest therefore cannot be used to drop files
/// into protected places.
pub fn restore_quarantine(
    session_dir: &Path,
    rules: &ProtectionRules,
) -> std::io::Result<RestoreReport> {
    let file = fs::File::open(session_dir.join(MANIFEST))?;
    let mut report = RestoreReport::default();
    let no_dots = |p: &Path| {
        !p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    };
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: ManifestEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                report
                    .failed
                    .push((PathBuf::new(), format!("corrupt manifest line: {e}")));
                continue;
            }
        };
        if !(entry.quarantined.starts_with(session_dir) && no_dots(&entry.quarantined)) {
            report
                .failed
                .push((entry.original, "manifest entry outside session".into()));
            continue;
        }
        if !(entry.original.is_absolute() && no_dots(&entry.original)) {
            report.failed.push((
                entry.original,
                "original path is not absolute and normalised".into(),
            ));
            continue;
        }
        if let Some(reason) = rules.protection_reason(&entry.original) {
            report
                .failed
                .push((entry.original, format!("refused: protected ({reason})")));
            continue;
        }
        match fs::symlink_metadata(&entry.quarantined) {
            Err(_) => {
                report.missing.push(entry.original);
                continue;
            }
            Ok(m) if !m.file_type().is_file() => {
                report.failed.push((
                    entry.original,
                    "quarantined item is not a regular file".into(),
                ));
                continue;
            }
            Ok(_) => {}
        }
        if fs::symlink_metadata(&entry.original).is_ok() {
            report.conflicts.push(entry.original);
            continue;
        }
        let result = entry
            .original
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|()| fs::rename(&entry.quarantined, &entry.original));
        match result {
            Ok(()) => report.restored.push(entry.original),
            Err(e) => report.failed.push((entry.original, e.to_string())),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(base: &Path) -> ProtectionRules {
        ProtectionRules::for_home(base.join("home"))
    }

    #[test]
    fn tampered_manifest_cannot_restore_into_protected_or_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let base = platform::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let session = base.join("q");
        let q = QuarantineRemover::open(session.clone()).unwrap();
        let payload = session.join("files/payload");
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::write(&payload, b"x").unwrap();
        let evil = [
            ManifestEntry {
                original: home.join(".ssh/authorized_keys"),
                quarantined: payload.clone(),
                size: 1,
                quarantined_at_unix: 0,
            },
            ManifestEntry {
                original: base.join("anywhere"),
                quarantined: session.join("../outside"),
                size: 1,
                quarantined_at_unix: 0,
            },
            ManifestEntry {
                original: PathBuf::from("relative/path"),
                quarantined: payload.clone(),
                size: 1,
                quarantined_at_unix: 0,
            },
        ];
        {
            let mut f = q.manifest.lock().unwrap();
            for e in &evil {
                writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
            }
        }
        let report = restore_quarantine(&session, &ProtectionRules::for_home(&home)).unwrap();
        assert!(report.restored.is_empty(), "{report:?}");
        assert_eq!(report.failed.len(), 3, "{report:?}");
        assert!(!home.join(".ssh/authorized_keys").exists());
        assert!(payload.exists());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_and_session_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let session = tmp.path().join("q");
        let _q = QuarantineRemover::open(session.clone()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&session), 0o700);
        assert_eq!(mode(&session.join(MANIFEST)), 0o600);
    }

    #[test]
    fn quarantine_moves_and_restores() {
        let tmp = tempfile::tempdir().unwrap();
        let base = platform::canonicalize(tmp.path()).unwrap();
        let src_dir = base.join("cache/sub");
        fs::create_dir_all(&src_dir).unwrap();
        let file = src_dir.join("blob");
        fs::write(&file, b"hello").unwrap();

        let q = QuarantineRemover::open(base.join("q/session")).unwrap();
        let dest = q.remove(&file).unwrap().unwrap();
        assert!(!file.exists());
        assert_eq!(fs::read(&dest).unwrap(), b"hello");

        let report = restore_quarantine(q.session_dir(), &rules(&base)).unwrap();
        assert_eq!(report.restored, vec![file.clone()]);
        assert_eq!(fs::read(&file).unwrap(), b"hello");
        assert!(!dest.exists());
    }

    #[test]
    fn restore_never_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let base = platform::canonicalize(tmp.path()).unwrap();
        let file = base.join("blob");
        fs::write(&file, b"old").unwrap();
        let q = QuarantineRemover::open(base.join("q")).unwrap();
        let dest = q.remove(&file).unwrap().unwrap();
        fs::write(&file, b"new").unwrap();

        let report = restore_quarantine(q.session_dir(), &rules(&base)).unwrap();
        assert_eq!(report.conflicts, vec![file.clone()]);
        assert_eq!(fs::read(&file).unwrap(), b"new");
        assert_eq!(fs::read(&dest).unwrap(), b"old");
    }

    #[test]
    fn quarantine_refuses_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let base = platform::canonicalize(tmp.path()).unwrap();
        let file = base.join("blob");
        let q = QuarantineRemover::open(base.join("q")).unwrap();
        fs::write(&file, b"1").unwrap();
        q.remove(&file).unwrap();
        fs::write(&file, b"2").unwrap();
        assert!(matches!(
            q.remove(&file),
            Err(RemovalError::QuarantineCollision(_))
        ));
        assert!(file.exists());
    }
}

/// A quarantine session on disk.
#[derive(Debug, Clone)]
pub struct QuarantineSession {
    pub dir: PathBuf,
    /// Files still in quarantine (manifest entries whose copy exists).
    pub files: usize,
    pub bytes: u64,
    pub created_unix: u64,
}

/// The quarantine root for RustClean's data directory.
pub fn quarantine_root(app_data: &Path) -> PathBuf {
    app_data.join("Quarantine")
}

/// Lists quarantine sessions, newest first. Read-only.
pub fn list_quarantine_sessions(app_data: &Path) -> Vec<QuarantineSession> {
    let root = quarantine_root(app_data);
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out: Vec<QuarantineSession> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| {
            let dir = e.path();
            let created_unix = dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.split('-').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let (mut files, mut bytes) = (0, 0);
            if let Ok(f) = fs::File::open(dir.join(MANIFEST)) {
                for line in BufReader::new(f).lines().map_while(Result::ok) {
                    if let Ok(entry) = serde_json::from_str::<ManifestEntry>(&line)
                        && fs::symlink_metadata(&entry.quarantined).is_ok()
                    {
                        files += 1;
                        bytes += entry.size;
                    }
                }
            }
            QuarantineSession {
                dir,
                files,
                bytes,
                created_unix,
            }
        })
        .collect();
    out.sort_by(|a, b| b.created_unix.cmp(&a.created_unix));
    out
}

/// Permanently deletes a quarantine session. This is irreversible; callers
/// must confirm with the user. Refuses anything that is not a direct child
/// of the quarantine root.
pub fn purge_quarantine_session(app_data: &Path, session_dir: &Path) -> std::io::Result<()> {
    let root = platform::canonicalize(&quarantine_root(app_data))?;
    let meta = fs::symlink_metadata(session_dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(std::io::Error::other("not a quarantine session directory"));
    }
    let dir = platform::canonicalize(session_dir)?;
    if dir.parent() != Some(root.as_path()) {
        return Err(std::io::Error::other(
            "refusing to delete outside the quarantine folder",
        ));
    }
    fs::remove_dir_all(&dir)
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn lists_and_purges_only_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let data = platform::canonicalize(tmp.path()).unwrap();
        let src = data.join("cache");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a"), b"hello").unwrap();
        let q = QuarantineRemover::new_session(&data).unwrap();
        q.remove(&src.join("a")).unwrap();
        let sessions = list_quarantine_sessions(&data);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].files, 1);
        assert_eq!(sessions[0].bytes, 5);
        // Refuses paths outside the quarantine root.
        assert!(purge_quarantine_session(&data, &src).is_err());
        assert!(purge_quarantine_session(&data, &quarantine_root(&data)).is_err());
        purge_quarantine_session(&data, &sessions[0].dir).unwrap();
        assert!(list_quarantine_sessions(&data).is_empty());
        assert!(src.exists());
    }
}
