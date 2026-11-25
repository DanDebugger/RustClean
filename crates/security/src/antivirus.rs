//! Built-in protection status (antivirus, Gatekeeper, Defender, ...).
//!
//! RustClean is not an antivirus engine. This only *reports* whether the
//! protection the operating system ships (or a registered third-party
//! antivirus) is switched on. Everything here is read-only: external tools are
//! run by absolute path with a hard timeout and their output is only parsed.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Whether a protection feature is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionStatus {
    On,
    Off,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProtectionCheck {
    /// e.g. "Gatekeeper", "Microsoft Defender Antivirus".
    pub name: String,
    pub status: ProtectionStatus,
    /// One plain-language sentence for the user.
    pub detail: String,
    /// Off is common and not a problem by itself (e.g. the macOS firewall,
    /// off by default). Not counted as a problem in summaries.
    pub informational: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProtectionReport {
    pub checks: Vec<ProtectionCheck>,
    pub notes: Vec<String>,
}

impl ProtectionReport {
    pub fn count(&self, s: ProtectionStatus) -> usize {
        self.checks.iter().filter(|c| c.status == s).count()
    }

    /// Checks that are off and not merely informational: real problems.
    pub fn problems(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == ProtectionStatus::Off && !c.informational)
            .count()
    }
}

/// How long an external command may run before it is killed. PowerShell's
/// cold start alone can take several seconds on Windows.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(if cfg!(windows) { 15 } else { 5 });

const NOT_AN_ANTIVIRUS_NOTE: &str =
    "RustClean does not scan files for viruses; it reports what your system already provides.";

fn check(name: &str, status: ProtectionStatus, detail: impl Into<String>) -> ProtectionCheck {
    ProtectionCheck {
        name: name.to_string(),
        status,
        detail: detail.into(),
        informational: false,
    }
}

/// Checks the built-in protection of this machine. Blocking; never panics.
pub fn scan_protection() -> ProtectionReport {
    let mut report = ProtectionReport::default();
    if cfg!(target_os = "macos") {
        report.checks = macos_checks();
    } else if cfg!(target_os = "windows") {
        report.checks = windows_checks();
    } else if cfg!(target_os = "linux") {
        report.checks = linux_checks();
    } else {
        report
            .notes
            .push("Protection status is not available on this platform.".to_string());
    }
    report.notes.push(NOT_AN_ANTIVIRUS_NOTE.to_string());
    report
}

// ---------------------------------------------------------------- commands

/// Runs `program` (absolute path only) and returns `(exit_success, stdout)`.
/// Errors on spawn failure, timeout (the child is killed) or non-UTF-8 output.
fn run_command(program: &str, args: &[&str]) -> Result<(bool, String), String> {
    debug_assert!(Path::new(program).is_absolute());
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| format!("cannot start: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("no output pipe")?;
    // Drain on a thread so a chatty child can never block on a full pipe.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let r = stdout.read_to_end(&mut buf).map(|_| buf);
        let _ = tx.send(r);
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() >= COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timed out".to_string());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("wait failed: {e}"));
            }
        }
    };
    let remaining = COMMAND_TIMEOUT.saturating_sub(start.elapsed());
    let bytes = rx
        .recv_timeout(remaining.max(Duration::from_millis(500)))
        .map_err(|_| "timed out reading output".to_string())?
        .map_err(|e| format!("cannot read output: {e}"))?;
    // Lossy: Windows consoles use OEM code pages, so a product name with an
    // accent must not turn the whole check into "unknown".
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok((status.success(), text))
}

fn run_ok(program: &str, args: &[&str]) -> Result<String, String> {
    match run_command(program, args)? {
        (true, out) => Ok(out),
        (false, _) => Err("command failed".to_string()),
    }
}

fn could_not_check(what: &str) -> String {
    format!("{what} could not be checked.")
}

// ------------------------------------------------------------------- macOS

const XPROTECT_PLIST: &str =
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";

fn macos_checks() -> Vec<ProtectionCheck> {
    let mut checks = Vec::new();

    let gatekeeper = run_ok("/usr/sbin/spctl", &["--status"]).map(|o| parse_spctl(&o));
    checks.push(match gatekeeper {
        Ok(ProtectionStatus::On) => check(
            "Gatekeeper",
            ProtectionStatus::On,
            "Gatekeeper is on, so macOS checks apps before they first open.",
        ),
        Ok(ProtectionStatus::Off) => check(
            "Gatekeeper",
            ProtectionStatus::Off,
            "Gatekeeper is off, so apps from anywhere can open without a check.",
        ),
        _ => check(
            "Gatekeeper",
            ProtectionStatus::Unknown,
            could_not_check("Gatekeeper"),
        ),
    });

    let sip = run_ok("/usr/bin/csrutil", &["status"]).map(|o| parse_csrutil(&o));
    checks.push(match sip {
        Ok(ProtectionStatus::On) => check(
            "System Integrity Protection",
            ProtectionStatus::On,
            "System Integrity Protection is on and guards core system files.",
        ),
        Ok(ProtectionStatus::Off) => check(
            "System Integrity Protection",
            ProtectionStatus::Off,
            "System Integrity Protection is off, so core system files are not guarded.",
        ),
        _ => check(
            "System Integrity Protection",
            ProtectionStatus::Unknown,
            could_not_check("System Integrity Protection"),
        ),
    });

    checks.push(match xprotect_version(Path::new(XPROTECT_PLIST)) {
        Some(v) => check(
            "XProtect",
            ProtectionStatus::On,
            format!("Apple's built-in malware definitions are present (version {v})."),
        ),
        None => check(
            "XProtect",
            ProtectionStatus::Unknown,
            "Apple's built-in malware definitions could not be found or read.",
        ),
    });

    let firewall = run_ok(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    )
    .map(|o| parse_firewall(&o));
    let mut firewall_check = match firewall {
        Ok(ProtectionStatus::On) => check(
            "Application Firewall",
            ProtectionStatus::On,
            "The firewall is on and controls incoming connections to apps.",
        ),
        Ok(ProtectionStatus::Off) => check(
            "Application Firewall",
            ProtectionStatus::Off,
            "The firewall is off. This is common and informational, not a problem by itself.",
        ),
        _ => check(
            "Application Firewall",
            ProtectionStatus::Unknown,
            could_not_check("The firewall"),
        ),
    };
    // macOS ships with the firewall off; that alone is not a problem.
    firewall_check.informational = true;
    checks.push(firewall_check);
    checks
}

/// Maps "enabled"/"disabled" wording to a status. "disabled" is tested first
/// so that any text mentioning both is treated conservatively as Off.
fn parse_enabled_disabled(text: &str) -> ProtectionStatus {
    let t = text.to_ascii_lowercase();
    if t.contains("disabled") {
        ProtectionStatus::Off
    } else if t.contains("enabled") {
        ProtectionStatus::On
    } else {
        ProtectionStatus::Unknown
    }
}

/// `spctl --status`: "assessments enabled" / "assessments disabled".
pub fn parse_spctl(output: &str) -> ProtectionStatus {
    if output.to_ascii_lowercase().contains("assessments") {
        parse_enabled_disabled(output)
    } else {
        ProtectionStatus::Unknown
    }
}

/// `csrutil status`: only the first line is used, because a custom
/// configuration ("unknown (Custom Configuration)") lists per-feature
/// enabled/disabled lines that must not be mistaken for the overall state.
pub fn parse_csrutil(output: &str) -> ProtectionStatus {
    let first = output.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first
        .to_ascii_lowercase()
        .contains("system integrity protection")
    {
        parse_enabled_disabled(first)
    } else {
        ProtectionStatus::Unknown
    }
}

/// `socketfilterfw --getglobalstate`: "Firewall is enabled. (State = 1)".
pub fn parse_firewall(output: &str) -> ProtectionStatus {
    if output.to_ascii_lowercase().contains("firewall") {
        parse_enabled_disabled(output)
    } else {
        ProtectionStatus::Unknown
    }
}

/// Reads `CFBundleShortVersionString` from an XProtect `Info.plist`.
pub fn xprotect_version(plist_path: &Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let v = value
        .as_dictionary()?
        .get("CFBundleShortVersionString")?
        .as_string()?
        .trim()
        .to_string();
    (!v.is_empty()).then_some(v)
}

// ----------------------------------------------------------------- Windows

const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const SECURITY_CENTER_QUERY: &str = "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { \"$($_.displayName)|$($_.productState)\" }";

fn windows_checks() -> Vec<ProtectionCheck> {
    // Honour a relocated Windows folder, but never resolve through PATH.
    let powershell = std::env::var_os("SystemRoot")
        .map(|root| {
            Path::new(&root)
                .join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
                .to_string_lossy()
                .into_owned()
        })
        .filter(|p| Path::new(p).is_absolute())
        .unwrap_or_else(|| POWERSHELL.to_string());
    let output = run_ok(
        &powershell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SECURITY_CENTER_QUERY,
        ],
    );
    match output {
        Ok(out) => windows_checks_from_output(&out),
        Err(_) => vec![check(
            "Antivirus",
            ProtectionStatus::Unknown,
            "Registered antivirus products could not be checked (Windows Server has no Security Center).",
        )],
    }
}

/// Turns the PowerShell output into checks, handling "nothing registered".
pub fn windows_checks_from_output(output: &str) -> Vec<ProtectionCheck> {
    if output.trim().is_empty() {
        return vec![check(
            "Antivirus",
            ProtectionStatus::Off,
            "No antivirus product is registered with Windows.",
        )];
    }
    let parsed = parse_windows_av(output);
    if parsed.is_empty() {
        return vec![check(
            "Antivirus",
            ProtectionStatus::Unknown,
            could_not_check("Antivirus status"),
        )];
    }
    parsed
}

/// Parses lines of `displayName|productState`. Malformed lines are skipped.
pub fn parse_windows_av(output: &str) -> Vec<ProtectionCheck> {
    output
        .lines()
        .filter_map(|line| {
            let (name, state) = line.trim().rsplit_once('|')?;
            let name = name.trim();
            let state: u32 = state.trim().parse().ok()?;
            if name.is_empty() {
                return None;
            }
            let (enabled, outdated) = decode_product_state(state);
            let (status, detail) = match (enabled, outdated) {
                (true, false) => (
                    ProtectionStatus::On,
                    "Real-time protection is on and its definitions are up to date.",
                ),
                (true, true) => (
                    ProtectionStatus::On,
                    "Real-time protection is on, but its definitions are out of date.",
                ),
                (false, false) => (ProtectionStatus::Off, "Real-time protection is turned off."),
                (false, true) => (
                    ProtectionStatus::Off,
                    "Real-time protection is turned off and its definitions are out of date.",
                ),
            };
            Some(check(name, status, detail))
        })
        .collect()
}

/// Decodes a SecurityCenter2 `productState` into
/// `(real_time_protection_enabled, definitions_out_of_date)`.
pub fn decode_product_state(state: u32) -> (bool, bool) {
    (state & 0x1000 != 0, (state >> 4) & 0xF != 0)
}

// ------------------------------------------------------------------- Linux

const LINUX_BIN_DIRS: [&str; 3] = ["/usr/bin", "/usr/sbin", "/usr/local/bin"];

fn linux_checks() -> Vec<ProtectionCheck> {
    let dirs: Vec<&Path> = LINUX_BIN_DIRS.iter().map(Path::new).collect();
    vec![clamav_check(&dirs)]
}

/// Looks for `clamscan`/`clamd` in exactly the given directories.
pub fn clamav_check(dirs: &[&Path]) -> ProtectionCheck {
    let found = dirs
        .iter()
        .flat_map(|d| ["clamscan", "clamd"].map(|n| d.join(n)))
        .any(|p| p.is_file());
    if found {
        check(
            "ClamAV",
            ProtectionStatus::On,
            "ClamAV is installed (this does not show whether it is running or up to date).",
        )
    } else {
        check(
            "Antivirus",
            ProtectionStatus::Unknown,
            "No antivirus found; Linux desktops usually do not ship one.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn informational_checks_are_not_problems() {
        let mut fw = check("Firewall", ProtectionStatus::Off, "");
        fw.informational = true;
        let r = ProtectionReport {
            checks: vec![
                fw,
                check("Gatekeeper", ProtectionStatus::Off, ""),
                check("XProtect", ProtectionStatus::On, ""),
            ],
            notes: Vec::new(),
        };
        assert_eq!(r.count(ProtectionStatus::Off), 2);
        assert_eq!(r.problems(), 1);
    }
    use ProtectionStatus::*;

    #[test]
    fn spctl() {
        assert_eq!(parse_spctl("assessments enabled\n"), On);
        assert_eq!(parse_spctl("assessments disabled\n"), Off);
        assert_eq!(parse_spctl(""), Unknown);
        assert_eq!(parse_spctl("\u{0}\u{1}garbage enabled"), Unknown);
    }

    #[test]
    fn csrutil() {
        assert_eq!(
            parse_csrutil("System Integrity Protection status: enabled.\n"),
            On
        );
        assert_eq!(
            parse_csrutil("System Integrity Protection status: disabled.\n"),
            Off
        );
        let custom = "System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tDebugging Restrictions: disabled\n";
        assert_eq!(parse_csrutil(custom), Unknown);
        assert_eq!(parse_csrutil(""), Unknown);
        assert_eq!(parse_csrutil("nonsense"), Unknown);
    }

    #[test]
    fn firewall() {
        assert_eq!(parse_firewall("Firewall is enabled. (State = 1)"), On);
        assert_eq!(parse_firewall("Firewall is disabled. (State = 0)"), Off);
        assert_eq!(parse_firewall(""), Unknown);
        assert_eq!(parse_firewall("enabled"), Unknown);
    }

    #[test]
    fn product_state() {
        assert_eq!(decode_product_state(266_240), (true, false)); // 0x41000
        assert_eq!(decode_product_state(266_256), (true, true)); // 0x41010
        assert_eq!(decode_product_state(262_144), (false, false)); // 0x40000
        assert_eq!(decode_product_state(393_216), (false, false)); // 0x60000
        assert_eq!(decode_product_state(0), (false, false));
        assert_eq!(decode_product_state(u32::MAX), (true, true));
    }

    #[test]
    fn windows_av_parsing() {
        let out = "Windows Defender|397568\r\nOther AV|266256\r\nOff AV|262144\r\n";
        let checks = parse_windows_av(out);
        assert_eq!(checks.len(), 3);
        assert_eq!(checks[0].name, "Windows Defender");
        assert_eq!(checks[0].status, On); // 397568 = 0x61100
        assert_eq!(checks[1].status, On);
        assert!(checks[1].detail.contains("out of date"));
        assert_eq!(checks[2].status, Off);
    }

    #[test]
    fn windows_av_garbage_and_empty() {
        assert!(parse_windows_av("").is_empty());
        assert!(parse_windows_av("no pipe here\n|123\nName|notanumber\n").is_empty());
        let none = windows_checks_from_output("  \r\n");
        assert_eq!(none.len(), 1);
        assert_eq!(none[0].name, "Antivirus");
        assert_eq!(none[0].status, Off);
        let bad = windows_checks_from_output("garbage");
        assert_eq!(bad[0].status, Unknown);
        let name_with_pipe = parse_windows_av("A|B AV|266240");
        assert_eq!(name_with_pipe[0].name, "A|B AV");
    }

    #[test]
    fn clamav_detection() {
        let dir = tempfile::tempdir().unwrap();
        let empty = clamav_check(&[dir.path()]);
        assert_eq!(empty.status, Unknown);
        std::fs::write(dir.path().join("clamscan"), b"").unwrap();
        assert_eq!(clamav_check(&[dir.path()]).status, On);
        assert_eq!(
            clamav_check(&[Path::new("/nonexistent-dir")]).status,
            Unknown
        );
    }

    #[test]
    fn xprotect_plist() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Info.plist");
        assert_eq!(xprotect_version(&p), None);
        std::fs::write(&p, "not a plist").unwrap();
        assert_eq!(xprotect_version(&p), None);
        std::fs::write(
            &p,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>5301</string></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(xprotect_version(&p).as_deref(), Some("5301"));
    }

    #[cfg(unix)]
    #[test]
    fn command_timeout_and_failure() {
        let start = Instant::now();
        assert!(run_command("/nonexistent/program", &[]).is_err());
        assert_eq!(
            run_command("/bin/echo", &["hi"]).unwrap(),
            (true, "hi\n".to_string())
        );
        assert!(!run_command("/usr/bin/false", &[]).unwrap().0);
        assert!(start.elapsed() < COMMAND_TIMEOUT);
    }

    #[test]
    fn report_counts_and_never_panics() {
        let r = scan_protection();
        assert!(r.notes.iter().any(|n| n.contains("does not scan")));
        let total = r.count(On) + r.count(Off) + r.count(Unknown);
        assert_eq!(total, r.checks.len());
    }
}
