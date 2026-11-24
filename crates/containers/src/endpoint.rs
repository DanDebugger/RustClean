//! Discovery of local Docker engines. No network access: only Unix sockets
//! (macOS, Linux) or named pipes (Windows) on this machine are considered.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Runtime name, e.g. "OrbStack".
    pub name: String,
    /// Unix socket path, or a Windows named-pipe path.
    pub socket: PathBuf,
}

/// Candidate engines for this platform, most specific first.
fn candidates(home: &Path) -> Vec<(String, PathBuf)> {
    let mut c: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        let local = if cfg!(windows) { "npipe://" } else { "unix://" };
        if let Some(path) = host.strip_prefix(local) {
            c.push(("DOCKER_HOST".into(), PathBuf::from(path)));
        }
    }
    if cfg!(target_os = "macos") {
        c.extend([
            ("OrbStack".into(), home.join(".orbstack/run/docker.sock")),
            (
                "Docker Desktop".into(),
                home.join(".docker/run/docker.sock"),
            ),
            ("Colima".into(), home.join(".colima/default/docker.sock")),
            ("Rancher Desktop".into(), home.join(".rd/docker.sock")),
            ("Default".into(), PathBuf::from("/var/run/docker.sock")),
        ]);
    } else if cfg!(windows) {
        c.push((
            "Docker Desktop".into(),
            PathBuf::from(r"\\.\pipe\docker_engine"),
        ));
    } else {
        if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            c.push(("Docker (rootless)".into(), run.join("docker.sock")));
            c.push(("Podman".into(), run.join("podman/podman.sock")));
        }
        c.extend([
            (
                "Docker Desktop".into(),
                home.join(".docker/desktop/docker.sock"),
            ),
            ("Default".into(), PathBuf::from("/var/run/docker.sock")),
        ]);
    }
    c
}

fn is_engine_endpoint(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
    }
    #[cfg(windows)]
    {
        // Named pipes cannot be stat'ed reliably; the connection attempt
        // (ping) decides whether the engine is there.
        let _ = p;
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = p;
        false
    }
}

/// Returns available Docker engines, most specific runtime first.
/// Endpoints that resolve to the same file are listed once.
pub fn discover_endpoints(home: &Path) -> Vec<Endpoint> {
    let mut seen = HashSet::new();
    candidates(home)
        .into_iter()
        .filter(|(_, p)| is_engine_endpoint(p))
        .filter(|(_, p)| seen.insert(fs::canonicalize(p).unwrap_or_else(|_| p.clone())))
        .map(|(name, socket)| Endpoint { name, socket })
        .collect()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn finds_sockets_and_ignores_plain_files() {
        let tmp = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(home.join(".orbstack/run")).unwrap();
        fs::create_dir_all(home.join(".docker/run")).unwrap();
        let _l = UnixListener::bind(home.join(".orbstack/run/docker.sock")).unwrap();
        fs::write(home.join(".docker/run/docker.sock"), b"not a socket").unwrap();
        let eps: Vec<_> = discover_endpoints(&home)
            .into_iter()
            .filter(|e| e.socket.starts_with(&home))
            .collect();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].name, "OrbStack");
    }
}
