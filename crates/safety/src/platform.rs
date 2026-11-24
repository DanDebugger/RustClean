//! Platform layer: every OS-specific path and file-system check lives here
//! so the rest of RustClean stays portable.
//!
//! Supported: macOS (primary), Linux and Windows.

use std::fs::Metadata;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
    Windows,
    Other,
}

pub const CURRENT: Os = if cfg!(target_os = "macos") {
    Os::MacOs
} else if cfg!(target_os = "linux") {
    Os::Linux
} else if cfg!(windows) {
    Os::Windows
} else {
    Os::Other
};

impl Os {
    pub fn name(self) -> &'static str {
        match self {
            Os::MacOs => "macOS",
            Os::Linux => "Linux",
            Os::Windows => "Windows",
            Os::Other => "this platform",
        }
    }

    /// Whether the usual file system treats names case-insensitively.
    /// (APFS and NTFS by default; Linux file systems are case-sensitive.)
    pub fn case_insensitive_fs(self) -> bool {
        matches!(self, Os::MacOs | Os::Windows)
    }
}

/// The current user's home directory, if it is set and absolute.
pub fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = PathBuf::from(std::env::var_os(var)?);
    home.is_absolute().then_some(home)
}

/// Per-user local application data (`%LOCALAPPDATA%` on Windows).
pub fn local_app_data(home: &Path) -> PathBuf {
    match CURRENT {
        Os::Windows => std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join("AppData").join("Local")),
        Os::MacOs => home.join("Library/Application Support"),
        _ => xdg_dir("XDG_DATA_HOME", home, ".local/share"),
    }
}

/// Per-user cache directory (`~/Library/Caches`, `$XDG_CACHE_HOME`,
/// `%LOCALAPPDATA%`).
pub fn user_cache_dir(home: &Path) -> PathBuf {
    match CURRENT {
        Os::MacOs => home.join("Library/Caches"),
        Os::Windows => local_app_data(home),
        _ => xdg_dir("XDG_CACHE_HOME", home, ".cache"),
    }
}

fn xdg_dir(var: &str, home: &Path, default: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(default))
}

/// RustClean's own data directory (quarantine, manifests).
pub fn app_data_dir(home: &Path) -> PathBuf {
    match CURRENT {
        Os::MacOs => home.join("Library/Application Support/RustClean"),
        Os::Windows => local_app_data(home).join("RustClean"),
        _ => local_app_data(home).join("rustclean"),
    }
}

/// RustClean's operation log directory.
pub fn app_log_dir(home: &Path) -> PathBuf {
    match CURRENT {
        Os::MacOs => home.join("Library/Logs/RustClean"),
        Os::Windows => local_app_data(home).join("RustClean").join("Logs"),
        _ => xdg_dir("XDG_STATE_HOME", home, ".local/state").join("rustclean"),
    }
}

/// System locations that are never cleaned.
pub fn system_protected() -> Vec<PathBuf> {
    let list: &[&str] = match CURRENT {
        // `/etc`, `/var` and `/tmp` are symlinks into `/private`; both
        // spellings are listed so non-canonical input is covered too.
        Os::MacOs => &[
            "/System",
            "/Library",
            "/bin",
            "/sbin",
            "/usr",
            "/private/var/db",
            "/var/db",
            "/private/etc",
            "/etc",
            "/cores",
            "/Applications",
        ],
        Os::Linux => &[
            "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/opt", "/proc", "/root",
            "/run", "/sbin", "/snap", "/srv", "/sys", "/usr", "/var/lib", "/var/db",
        ],
        Os::Windows => &[
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
            r"C:\Recovery",
            r"C:\System Volume Information",
            r"C:\$Recycle.Bin",
        ],
        Os::Other => &["/"],
    };
    let mut out: Vec<PathBuf> = list.iter().map(PathBuf::from).collect();
    if CURRENT == Os::Windows {
        // Honour a non-C: system drive.
        for var in [
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramData",
        ] {
            if let Some(p) = std::env::var_os(var).map(PathBuf::from) {
                out.push(p);
            }
        }
    }
    out
}

/// Home-relative locations that are never cleaned.
pub fn user_protected() -> &'static [&'static str] {
    match CURRENT {
        Os::MacOs => &[
            "Documents",
            "Desktop",
            "Pictures",
            "Movies",
            "Music",
            "Library/Keychains",
            "Library/Mail",
            // iCloud Drive; deleting here deletes from the cloud.
            "Library/Mobile Documents",
            ".ssh",
            ".gnupg",
        ],
        Os::Linux => &[
            "Documents",
            "Desktop",
            "Pictures",
            "Videos",
            "Music",
            ".ssh",
            ".gnupg",
            ".local/share/keyrings",
            ".password-store",
            ".mozilla",
            ".thunderbird",
        ],
        Os::Windows => &[
            "Documents",
            "Desktop",
            "Pictures",
            "Videos",
            "Music",
            "OneDrive",
            ".ssh",
            ".gnupg",
            r"AppData\Roaming\Microsoft\Credentials",
            r"AppData\Local\Microsoft\Credentials",
            r"AppData\Roaming\Microsoft\Protect",
        ],
        Os::Other => &[],
    }
}

/// Inode and device identity, used to detect a file being replaced between
/// scan and cleanup. Windows has no stable equivalent in `std`; the
/// creation time stands in for the inode there.
pub fn file_identity(meta: &Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.ino(), meta.dev())
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        (meta.creation_time(), 0)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = meta;
        (0, 0)
    }
}

/// Bytes actually allocated on disk.
pub fn disk_usage(meta: &Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.blocks() * 512
    }
    #[cfg(not(unix))]
    {
        // Round up to the common 4 KiB cluster size.
        meta.len().div_ceil(4096) * 4096
    }
}

/// Whether the file is flagged so that it must not be removed (immutable /
/// append-only on macOS, read-only attribute on Windows).
pub fn is_locked(meta: &Metadata) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        // BSD flags from <sys/stat.h>: UF_IMMUTABLE, UF_APPEND,
        // SF_IMMUTABLE, SF_APPEND.
        const LOCK_FLAGS: u32 = 0x0000_0002 | 0x0000_0004 | 0x0002_0000 | 0x0004_0000;
        meta.st_flags() & LOCK_FLAGS != 0
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
        const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
        meta.file_attributes() & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM) != 0
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        // Linux immutable attributes need an ioctl; removal of such a file
        // fails safely with a permission error instead.
        let _ = meta;
        false
    }
}

/// Whether the current user may remove entries from `dir`.
pub fn can_remove_from(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = CString::new(dir.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `c_path` is a valid NUL-terminated string for the duration
        // of the call; `access` does not retain the pointer.
        unsafe { libc::access(c_path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        // Windows ACLs cannot be evaluated cheaply; a denied move fails
        // safely and is reported.
        let _ = dir;
        true
    }
}

/// `fs::canonicalize`, minus Windows' verbatim `\\?\C:\` prefix so results
/// compare equal to ordinary `C:\` paths (including the protection list).
pub fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    let p = std::fs::canonicalize(path)?;
    Ok(strip_verbatim(p))
}

fn strip_verbatim(p: PathBuf) -> PathBuf {
    if CURRENT != Os::Windows {
        return p;
    }
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        // Only plain drive paths; leave UNC and device paths untouched.
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => p,
    }
}

/// Creates a directory (and parents) readable only by the current user.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

/// Opens a file for appending, creating it readable only by the current user.
pub fn open_private_append(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}
