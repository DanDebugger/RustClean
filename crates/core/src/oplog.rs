//! Append-only JSON-lines log of every cleanup operation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Serialize)]
struct Record<'a> {
    ts_unix: u64,
    session: &'a str,
    dry_run: bool,
    method: &'a str,
    path: &'a Path,
    outcome: &'a str,
    detail: Option<&'a str>,
    new_location: Option<&'a Path>,
    size: u64,
}

pub struct OperationLog {
    path: PathBuf,
    file: Mutex<fs::File>,
}

impl OperationLog {
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Paths can be private; keep the log readable only by this user.
        let file = rustclean_safety::platform::open_private_append(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        session: &str,
        dry_run: bool,
        method: &str,
        path: &Path,
        outcome: &str,
        detail: Option<&str>,
        new_location: Option<&Path>,
        size: u64,
    ) {
        let rec = Record {
            ts_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            session,
            dry_run,
            method,
            path,
            outcome,
            detail,
            new_location,
            size,
        };
        let Ok(mut line) = serde_json::to_string(&rec) else {
            return;
        };
        line.push('\n');
        let mut f = self.file.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = f.write_all(line.as_bytes()) {
            tracing::error!(error = %e, log = %self.path.display(), "failed to write operation log");
        }
    }
}
