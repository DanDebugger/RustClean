//! Read-only security checks.
//!
//! The first check is a **persistence audit**: everything that starts
//! automatically (macOS LaunchAgents/LaunchDaemons, Linux XDG autostart and
//! systemd user units, the Windows Startup folder). Malware almost always
//! needs persistence, so this is where suspicious software shows up first.
//!
//! The audit reports *signals to review*, never verdicts: a signal such as
//! "runs an inline shell command" is common in malware but also in
//! legitimate tools. Nothing here modifies the system.

pub mod persistence;

pub use persistence::{
    Finding, PersistenceItem, PersistenceReport, Risk, Source, analyse_command, scan_persistence,
};
