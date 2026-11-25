# RustClean

A native macOS system cleaner written entirely in Rust (egui/eframe).
Safety first: scanning never deletes, every removal is confirmed, re-validated
and reversible (Trash or quarantine), and RustClean makes no network
connections.

## Status — v0.1.0

| Module | What it cleans | Removal |
|---|---|---|
| **Junk Cleaner** | Third-party app caches, updater caches (ShipIt, `*-updater`), logs, crash reports, per-user temp files, `.dmg`/`.pkg`/`.xip` installers in `~/Downloads` | Trash / quarantine |
| **App Caches** | Caches grouped **per app** (largest first): `~/Library/Caches`, sandboxed app containers (`~/Library/Containers/*/Data/Library/Caches`) and Electron app caches (Slack, VS Code, Discord… — `Cache`, `Code Cache`, `GPUCache`). On Windows: only Electron app caches in `%APPDATA%` (folders with Chromium's `Local State`); `%LOCALAPPDATA%` is not scanned because it mixes caches with app data. Tick an app to clear its whole cache; running apps → Review | Trash / quarantine |
| **Browser Cleaner** | Google Chrome HTTP, code, GPU, shader and service-worker caches, temporary data, logs | Trash / quarantine |
| **Developer Cleaner** | npm, Yarn, pnpm metadata, Cargo registry cache, Go build cache, Xcode DerivedData / device support, simulator caches, Gradle, Maven, pip, uv, Homebrew downloads, CocoaPods, Swift PM, Playwright browsers, node-gyp, TypeScript, Composer, Prisma | Trash / quarantine |
| **Docker** | Stopped containers, unused images, unused build cache (only records neither in use nor shared, matching Docker's own estimate), and (opt-in) unused volumes — via the Docker Engine API (OrbStack, Docker Desktop, Colima, Rancher Desktop, `/var/run/docker.sock`, `DOCKER_HOST`) | Docker API, **irreversible** |

| **Large Files** | Files over 500 MB in your own non-protected folders (Downloads, project folders…), grouped by type | Trash / quarantine (all Review) |
| **Duplicate Finder** | Identical files ≥ 1 MB (size → partial → full BLAKE3); one copy per set is always kept | Trash / quarantine (all Review) |
| **App Leftovers** (macOS) | Support files of apps no longer installed (`~/Library/Application Support`, Preferences, Logs, Saved State, HTTPStorages, WebKit) | Trash / quarantine (all Review) |
| **Storage Analyzer** | Drill-down folder sizes and disk usage | Read-only |
| **Antivirus** | Status of the protection the system already has: Gatekeeper, SIP, XProtect, firewall (macOS); registered antivirus products such as Microsoft Defender (Windows); ClamAV (Linux), with a ring diagram, why each protection matters and *Open settings* buttons that hand over to the system's own settings. Your choices: check at start-up, sidebar warning, treat informational items (e.g. a firewall off by default) as problems. RustClean does not scan files for viruses or change protection settings | Read-only |
| **Backup & Sync** | Placeholder (shown as *soon*); design not decided yet | — |
| **Quarantine** | Earlier "Quarantine" cleanups | Restore, or delete permanently (confirmed) |

**Cleaning flow:** select files (per file, per app/category, or *Select
shown* for the current filter, or *Select for cleanup* in a file's details
dialog) → the action bar appears → *Clean N selected…* → one confirmation
dialog with a summary and a per-file review list (untick any file to keep
it) → **Move N files to Trash**
(or Quarantine). *Simulate first* is optional; after a simulation, *Clean
now…* continues without reselecting. Review items, a live warning (e.g.
Chrome running) and Docker's irreversibility each need an explicit tick.

**Guards for personal files** (Large Files, Duplicates, App Leftovers):
mounted folders (e.g. `~/OrbStack`, network shares) are never scanned;
database, VM-disk and Git files are always Protected; app leftovers are
listed only when no installed app *or command-line tool on PATH* from the
same developer exists, folders that look like installations are skipped,
and anything resembling keys, wallets or credentials is Protected.

### Interface

Modern light/dark theme (rust accent, Phosphor icons, the system UI font
when available: SF on macOS, Segoe UI on Windows). The layout is responsive
down to phone width (min window 360 px):

| Width | Layout |
|---|---|
| ≥ 960 px content | Sidebar; categories list beside a full-width file table |
| 640–960 px | Sidebar; category and safety dropdowns, file table fills the rest of the window |
| < 640 px | Top page picker; dropdowns, stacked file cards, wrapping action bar |
| < 860 px window | Sidebar replaced by the page picker |

Clicking a file opens its details ("why" it has its class, dates, select /
reveal / copy, previous / next) in a dialog in every layout. The action bar
appears only while files are selected. Windows shorter than 640 px get
one-line banners so the file list keeps its space.

Rendered screenshots of the real app (fake home folder, Docker fixture data;
nothing is removed) at 1280, 900 and 390 px, plus 1093×614 (a 1366×768
Windows laptop at 125 % scaling):

```sh
cargo test -p rustclean -- --ignored ui_snapshots   # → design/screenshots/*.png (git-ignored)
```

## Build and run

Requires Rust 1.92+ (see `rust-version`; tested with 1.94.1).

```sh
cargo run --release -p rustclean        # desktop app
cargo test --workspace                  # unit tests

# Headless, read-only checks against this machine (dry runs; nothing removed)
cargo run -p rustclean-browser --example chrome_dry_run
cargo run --release -p rustclean-junk --example junk_dry_run
cargo run -p rustclean-containers --example docker_dry_run
```

## Architecture

```
crates/
  safety/      protected_paths.rs  validator.rs  quarantine.rs
  core/        scanner.rs  classifier.rs  recommend.rs  cleanup_plan.rs  cleaner.rs  module.rs  oplog.rs
  browser/     chrome.rs  module.rs
  junk/        junk.rs  developer.rs  app_caches.rs  running_apps.rs
  containers/  endpoint.rs  classify.rs  lib.rs (scan / plan / execute)
  app/         main.rs  app.rs  navigation.rs  scan_page.rs  docker_page.rs  dashboard.rs
```

File-based modules implement `core::CleanupModule` (targets, classifier,
live warning) and share one UI flow (`scan_page.rs`). Scan targets support a
depth limit, an extension filter, and an age rule that raises recently
modified files to Review.

Docker is separate because its data lives inside a VM disk image: it has its
own read-only scan, `DockerPlan` → `ApprovedDockerPlan`, and executor. Tokio
(for `bollard`) is confined to `crates/containers`.

The **scanner** (`core::scanner`) is read-only: it walks scan targets in
parallel (Rayon), never follows symlinks or crosses filesystems, and
classifies each file. The **cleaner** (`core::cleaner`) accepts only an
`ApprovedPlan`, which can be created solely by `CleanupPlan::approve` (the
user's confirmation). It re-validates every path and removes through a
`Remover` (Trash or quarantine); it has no code path that unlinks files.

**File details panel:** category/app, source, kind, size on disk vs.
logical size, modified/created/last-opened dates, the scan root, where the
file goes when removed, why it has its safety label, and a live check
(changed since scan, no longer exists).

**Smart recommendations:** each scan highlights the files that are safe to
delete (Safe class and unchanged for at least a day) with *Select
recommended*, a *Recommended* filter and a reason per file. Recommendations
only pre-select; you still confirm, and removal stays reversible.

**Appearance:** System / Light / Dark switch in the sidebar (a single
cycling button on narrow windows); the choice is remembered.

Design notes: [docs/SYSTEM_DESIGN.md](docs/SYSTEM_DESIGN.md).

## Safety model

| Class     | Meaning                                    | Selectable              |
|-----------|--------------------------------------------|-------------------------|
| Safe      | Known cache data                           | Yes                     |
| Review    | Cache data with side effects (e.g. offline web-app data, crash reports) | Yes, with extra confirmation |
| Unknown   | Unrecognised, or a symlink                 | No                      |
| Protected | Protected location or Chrome user data     | No                      |

Classifications combine to the most restrictive. Defence in depth:

1. **Protected locations** (`safety::protected_paths`): `/System`, `/Library`,
   `/bin`, `/sbin`, `/usr`, `/private/var/db`, `~/Documents`, `~/Desktop`,
   `~/Pictures`, `~/Movies`, `~/Music`, `~/Library/Keychains`,
   `~/Library/Mail`, iCloud Drive, RustClean's own data, plus `/`, `~` and any
   ancestor of these. Matching is case-insensitive (APFS default).
2. **Chrome rules** (`browser::chrome`): only allowlisted cache paths inside
   Chrome's user data are cleanable; bookmarks, passwords, history, cookies,
   extensions, preferences, sessions, local storage etc. are always Protected.
   Only files are removed, never profile or user-data directories.
3. **Re-validation before removal** (`safety::validator`): absolute and
   normalised path; not a symlink; regular file; real path (symlinked parents
   resolved) inside an approved scan root and not protected; unchanged since the
   scan (size, mtime, inode, device); not immutable/append-only; parent
   writable. Failures are skipped, never forced.
4. **Live warnings**: Chrome running, or build tools (cargo, npm, xcodebuild,
   …) running, are shown live; a real cleanup then needs an extra
   acknowledgement, re-checked at the moment of confirmation.
5. **Junk rules**: Apple caches (`com.apple.*` and known Apple names) are not
   scanned. Only reverse-DNS app caches and updater caches are Safe; other
   names are Review. Caches whose app is running (matched via `Info.plist`
   bundle IDs of running processes) are Review. Logs and crash reports newer
   than 7 days and temp files are Review.
6. **Developer rules**: a location is included only if removing *any subset*
   of its files is harmless, because a cleanup can stop part-way. Excluded for
   that reason: `~/.cargo/registry/src` and `~/.cargo/git` (a leftover
   `.cargo-ok` marker makes Cargo trust a partial tree), `~/go/pkg/mod`
   (read-only), the pnpm store (hard links), nvm/rustup installs, Xcode
   Archives.
7. **Docker rules**: nothing in Docker's disk image is touched. Every API
   removal uses `force=false`, so the daemon refuses running containers,
   images used by any container and volumes in use; RustClean also re-inspects
   each item first. Running containers and in-use images/volumes are
   Protected; unused volumes are Protected unless volume cleanup is enabled.
   Containers are removed before images; anonymous volumes are kept. Build
   cache is one aggregate "unused build cache" item (BuildKit prunes only
   records not in use). A real run requires an irreversibility
   acknowledgement.

Files: quarantine sessions live in
`~/Library/Application Support/RustClean/Quarantine/<session>/` with a
`manifest.jsonl` (`safety::restore_quarantine` restores without overwriting).
Every cleanup item, including dry runs, is logged to
`~/Library/Logs/RustClean/operations.jsonl`.

## Smart Scan and Security Center

- **Smart Scan** runs every module's read-only scan plus the security audit
  and summarises reclaimable space, Safe space and security signals, with a
  link into each module for review and confirmation.
- **Security Center** (read-only) — first check: *login items and background
  agents* (macOS LaunchAgents/LaunchDaemons, Linux XDG autostart and systemd
  user units, Windows Startup folder). It reports signals, not verdicts:
  missing programs (leftovers), programs in temporary/download/shared
  folders, hidden files, inline interpreter code (`sh -c`, `osascript -e`,
  `powershell -enc`, …) and download-and-execute patterns. Planned checks:
  app signatures/notarization, browser extension permissions, privacy
  permissions, opt-in YARA-X signature scanning.

```sh
cargo run -p rustclean-security --example persistence_audit   # read-only
cargo run -p rustclean-security --example protection_status   # read-only
```

## Platform support

All OS-specific code lives in `crates/safety/src/platform.rs` (paths,
protected locations, file identity, lock flags, permissions, private file
creation, Windows path canonicalisation).

| | macOS | Linux | Windows |
|---|---|---|---|
| Builds (`cargo clippy`, 0 warnings) | ✅ tested + run | ✅ type-checked | ✅ type-checked (`x86_64-pc-windows-gnu`) |
| Trash | `NSFileManager` | freedesktop Trash | Recycle Bin |
| Junk | `~/Library/Caches`, Logs, crash reports, `$TMPDIR` | `~/.cache` (never shared `/tmp`) | crash dumps, DirectX shader cache, INetCache, `%TEMP%` |
| Chrome | ✅ | `~/.config/google-chrome`, `~/.cache/google-chrome` | `%LOCALAPPDATA%\Google\Chrome\User Data` |
| Developer caches | ✅ | ✅ (XDG paths) | ✅ (`%LOCALAPPDATA%` paths, NuGet) |
| Docker | OrbStack, Docker Desktop, Colima, Rancher | rootless, Podman, Docker Desktop, `/var/run/docker.sock` | named pipe `\\.\pipe\docker_engine` |
| Persistence audit | LaunchAgents/Daemons | XDG autostart, systemd user units | Startup folder (Run keys planned) |
| App Caches | ✅ | ✅ | Electron caches in `%APPDATA%` only |
| Antivirus status | Gatekeeper, SIP, XProtect, firewall | ClamAV installed? | Security Center (`AntiVirusProduct`) via PowerShell |
| Wording | "Trash", "Reveal in Finder" | "Trash" | "Recycle Bin", "Show in Explorer"; local dates via Win32 |

Linux and Windows builds are type-checked only; they have not been run on
those systems yet. Path protection matching is case- and
Unicode-normalisation-insensitive everywhere; matching of *approved* cleanup
roots follows the platform (case-sensitive on Linux).

## Known limitations

- Space is only reclaimed after the Trash is emptied (or quarantine purged);
  the UI says so. Disk figures refresh every 3 s, so emptying the Trash
  outside RustClean shows up without a restart. No quarantine restore/purge UI yet (API only).
- Moving a very large number of files to the Trash is sequential and can take
  minutes; progress and cancel are shown.
- A small time-of-check/time-of-use window remains between validation and
  the move; mitigated by validating the resolved path immediately before it.
- Generic "file in use" detection is not implemented; Chrome-running detection
  covers the Chrome cleaner.
- Path matching is ASCII case-insensitive; Unicode normalisation differences
  are not folded.
- Dependencies are pinned to versions supporting Rust 1.92–1.94 (eframe 0.35,
  sysinfo 0.38); newer releases require Rust 1.95.
- Not yet implemented: tool-driven cleanup (`brew cleanup`, `pnpm store
  prune`, `go clean -modcache`, `rustup toolchain uninstall`, `xcrun simctl
  delete unavailable`), emptying the Trash and Docker Desktop leftover
  detection (both need Full Disk Access onboarding), root-owned system
  caches/logs (need a privileged helper), and `/var/folders/…/C` caches.
- "Running app" matching for caches is heuristic (bundle ID / name); it errs
  towards Review.
- Docker "selectable" totals include images freed only if their stopped
  containers are removed too; Docker's own reclaimable estimate is shown
  alongside.
