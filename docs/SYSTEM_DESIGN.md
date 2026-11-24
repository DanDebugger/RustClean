# RustClean — System Design

Scope: how a cleanup works end to end, and the design of the **App Caches**
module, **file details**, and **selective deletion** added in v0.1.x.
For the full safety rules, see the README's *Safety model*.

## 1. Goals and non-goals

| Goals | Non-goals |
|---|---|
| Show the user *exactly* what will be removed, and why it is safe | Automatic / scheduled cleaning |
| Let the user choose per app, per category, per file | Deleting anything outright (`unlink`) |
| Every removal reversible (Trash or quarantine) | Root-owned system caches (needs a privileged helper) |
| No network access; nothing leaves the machine | Windows app caches (`%LOCALAPPDATA%` mixes caches and data) |

## 2. Architecture

```
┌──────────────────────────── crates/app (egui UI, main thread) ───────────────────────────┐
│ Sidebar/Navigation → ScanPage (one per module) ─ Dashboard ─ Smart Scan ─ Docker ─ …     │
│   ScanPage: filters · selection · detail panel · confirm dialog · result dialog          │
└──────────────┬───────────────────────────────────────────────────────┬───────────────────┘
               │ Job::spawn (worker thread, Progress + cancel)          │
┌──────────────▼──────────────┐                         ┌──────────────▼──────────────┐
│ core::Scanner  (read-only)  │                         │ core::Cleaner               │
│  ScanTarget[] → Candidate[] │                         │  ApprovedPlan only          │
│  BaseClassifier + domain    │                         │  re-validate → Remover      │
└──────────────▲──────────────┘                         └──────────────┬──────────────┘
               │ ScanSpec (targets, classifier, post_process)          │
┌──────────────┴──────────────────────────────┐         ┌──────────────▼──────────────┐
│ CleanupModule implementations               │         │ safety: PathValidator,      │
│  junk::{JunkModule, DeveloperModule,        │         │  TrashRemover,              │
│         AppCachesModule ← new}              │         │  QuarantineRemover,         │
│  browser::ChromeModule  apps::Leftovers     │         │  ProtectionRules            │
│  storage::LargeFiles    duplicates::…       │         └─────────────────────────────┘
└─────────────────────────────────────────────┘
```

Module boundaries are unchanged: modules only *describe* what to scan and
how to classify it. They cannot remove anything. Only `core::Cleaner`
removes, and it accepts only an `ApprovedPlan`.

## 3. Cleanup lifecycle (all file modules)

```
 detect ─► scan (read-only, parallel) ─► review & select ─► confirm ─► re-validate ─► move ─► report
            │                              │                  │          │              │
            Candidate{path, size,          filters, per-app,  plan built  size/mtime/   Trash or
            disk_usage, class, reason,     select shown,      from        inode/device  quarantine;
            fingerprint, target_root}      detail panel       selection;  unchanged,    op log
                                                              untick to   inside root,  (JSONL)
                                                              exclude;    not protected
                                                              Review ack
```

Invariants:

1. **Scanning never writes.** The scanner does not follow symlinks and does
   not cross filesystems.
2. **The most restrictive classification wins:** Safe < Review < Unknown < Protected.
   Unknown and Protected files can never be selected, and
   `CleanupPlan::from_selection` drops them even if the UI were wrong.
3. **Explicit approval.** `CleanupPlan::approve(review_ack)` is the only way
   to get an `ApprovedPlan`. Review files need the extra acknowledgement.
4. **Time-of-check re-validation.** Before each move, the file must match its
   scan fingerprint and sit under its approved scan root. Otherwise it is
   *skipped*, never forced.
5. **Partial failure is safe.** Modules include a location only if removing
   *any subset* of its files is harmless. A cancelled or failed run leaves a
   consistent state, and the result dialog plus the operation log say what
   happened.

## 4. Feature: App Caches (per-app cache clearing)

**Problem.** Junk Cleaner groups `~/Library/Caches` by *type*. Users think in
*apps* ("clear Slack's cache"). The largest app caches often live elsewhere:
in sandbox containers and in Electron apps' Chromium caches.

**Sources** (`crates/junk/src/app_caches.rs`):

| Source | Path | Default class |
|---|---|---|
| App cache folder | `~/Library/Caches/<bundle-id or name>/` | Safe if reverse-DNS or updater, else Review |
| Sandbox container | `~/Library/Containers/<bundle-id>/Data/Library/Caches/` | Safe (reverse-DNS, non-Apple only) |
| Electron/Chromium | `~/Library/Application Support/<App>/{Cache, Code Cache, GPUCache, Dawn*, GrShaderCache, ShaderCache}/` | Safe, only if `<App>` has a `Local State` or `Preferences` file |
| Linux | `~/.cache/<app>/`, `~/.config/<App>/<chromium cache>/` | as above |

**Exclusions** are the same as Junk: Apple caches (`com.apple.*` and known
names), developer-tool caches, Chrome (and other browsers' data folders),
and RustClean itself. Loose files in `Caches` have no identifiable owner,
so they are not offered here. Data next to a Chromium cache (`IndexedDB`,
`Local Storage`, `Cookies`, …) is never a scan target.

**Grouping.** `AppIndex` reads installed `.app` bundles (`CFBundleIdentifier`
→ `CFBundleName`) on every `refresh()`, i.e. before each scan. Owners are
resolved in this order: exact bundle id; then updater suffix stripped
(`.ShipIt`, `-updater`); then longest bundle-id prefix (helpers); then app
name. If nothing matches, the folder name is kept. The resolved name becomes
the `Candidate.category`, so the existing category list *is* the per-app list,
with a tri-state checkbox: tick an app to clear its whole cache. A
`post_process` step only reorders targets so apps are listed largest first.
It never adds files or relaxes a classification.

**Running apps.** `AppCacheClassifier` checks each target's owner keys
(folder name, app name, bundle id) against a `RunningApps` snapshot. A match
raises the file to **Review**, with the reason "quit it first".

**Overlap with Junk.** `~/Library/Caches/*` appears in both modules: Junk
groups it by type, App Caches by app. To avoid double counting, App Caches is
**not** part of Smart Scan or the dashboard's total. Cleaning in one module
leaves the other's results stale but safe: the validator skips missing files,
and the result dialog reports them.

**Permissions.** On macOS 14+, reading other apps' containers can trigger
the system's "access data from other apps" prompt. If the user declines,
those folders become scan issues and are hidden. Nothing else changes.

## 5. Feature: file details ("what exactly am I deleting?")

The detail panel shows, per file:

* **Scan data:** category (app), source, kind (from the extension), size on
  disk vs. logical size, modified time, and the scan root it was found in.
* **Live data:** a single `lstat` when the panel opens or ↻ is pressed. It
  shows created and last-opened times, plus state: *unchanged*,
  *changed since the scan* (will be skipped), *no longer exists*, or
  *unreadable*. This is informational only. The cleaner still re-validates
  every file itself.
* **Decision support:** why the file has its safety label, what removing it
  will do, and where it goes (Trash or quarantine), plus Reveal in Finder and
  Copy path.

## 6. Feature: selective deletion

| Level | How |
|---|---|
| App / category | Tick the app in the categories list (wide layout), or filter with a chip and press **Select shown** (all layouts) |
| Filter result | Safety chip + name/path search → **Select shown / Unselect shown** (Safe + Review; never Unknown/Protected) |
| File | Row checkbox |
| At confirmation | **Review every file** list (open by default for ≤ 50 files): untick a file to keep it. The plan is rebuilt from the remaining selection, and the dialog closes if the plan becomes empty |

Guards:

* The action bar shows how many selected files the current filter hides,
  so nothing is removed unseen.
* After you untick a file in the confirm dialog, the same frame's button
  click is ignored. The user always sees the updated plan before confirming.
* Acknowledgements survive a smaller plan, because removing files only makes
  the plan safer.

## 7. Feature: smart recommendations

`core::recommend` (pure function, unit-tested) decides per file:

| Recommended | Not recommended |
|---|---|
| Class **Safe** *and* last modified ≥ 24 h ago | Review ("needs your review first"), Unknown/Protected ("cannot be removed"), modified in the last 24 h or in the future ("may be in use"), unknown mtime |

* Computed **once per scan** into `ScanPage.recommended`, a vector parallel
  to `candidates` and `selected`. The page redraws often and scans can have
  100k+ files, so it is not recomputed every frame. `forget_removed` keeps
  the three vectors aligned.
* UI: a green banner ("Recommended: N files (X) are safe to delete") with
  **Select recommended** and **Show only these**, a **Recommended** filter
  chip, and a *Recommendation* row in the details panel giving the reason.
* A recommendation only *adds to the selection*. It never removes anything
  itself, never relaxes a classification, and still goes through the same
  confirmation, re-validation and reversible move.

## 8. Feature: appearance (light / dark)

* Both palettes (`theme::LIGHT`, `theme::DARK`) are applied to egui's light
  and dark visuals. `ctx.set_theme(ThemePreference)` picks one, or
  **System** follows macOS.
* Switch: three buttons (System / Light / Dark) under the logo in the sidebar.
  At narrow widths, a single button in the top bar cycles through them.
* The choice is saved best-effort to
  `~/Library/Application Support/RustClean/appearance`: a private folder
  (0700) that is protected from cleanup. It is loaded at start-up, and
  missing or invalid content falls back to System.

## 9. Fixed defects

| Defect | Cause | Fix |
|---|---|---|
| After a cleanup with skipped files, the detail panel showed a **different file** | `forget_removed` shifted indices; `detail` kept the old index | Detail is re-resolved by path; it closes if that file was removed |
| Whole-category selection impossible below 960 px | Only the wide category list had checkboxes; chips only filter | **Select shown** works on any filter, at every width |
| Long app names overlapped sizes in the category list | Label laid out before the right-aligned value | Value laid out first; the label truncates, with the full name on hover |
| "1 files" in the confirmation summary | No pluralisation | Fixed |

## 10. Failure modes

| Failure | Behaviour |
|---|---|
| Scan root unreadable / permission denied | Recorded as a scan issue ("N locations could not be read"); the scan continues |
| File changes between scan and cleanup | Skipped by the validator; listed in the result dialog |
| App starts while the confirm dialog is open | Its caches stay Review (snapshot from scan time). Chromium tolerates a partly removed cache; rescan for a fresh state |
| Cancel during cleanup | Remaining items reported as *not attempted*; what was moved stays restorable |
| Trash unavailable | The per-item failure is reported; nothing is deleted outright |
| Crash of a worker thread | The job reports a crash; the UI asks for a rescan; the operation log has what was processed |

## 11. Testing

* `crates/junk/src/app_caches.rs`: owner resolution (bundle id, updater,
  helper prefix, name); size ordering; a macOS fixture home covering every
  source and every exclusion (Apple, Chrome, Homebrew, loose files,
  container `Documents`, Chromium `IndexedDB`/`Cookies`, a non-Chromium
  `Cache`); running app → Review.
* `crates/app/src/scan_page.rs`: Select shown respects filters and never
  selects locked files; hidden-selection count; detail survives cleanup;
  unticking in the confirmation shrinks the plan and closes it when empty.
* `crates/app/src/widgets.rs`: date conversion, local time formatting, file
  kinds, `~` paths.
* `crates/core/src/recommend.rs`: only old Safe files are recommended
  (recent, future, unknown mtime, Review/Unknown/Protected are not).
* `theme.rs`: appearance preference round trip and invalid-value fallback.
* Visual: `cargo test -p rustclean -- --ignored ui_snapshots` renders App
  Caches, its confirmation and dark mode at 1280, 900 and 390 px.

## 12. Future work

* Per-app "Clear cache" from the Storage Analyzer and App Leftovers pages.
* Re-check running apps at confirmation time (as Chrome already does) and
  require an acknowledgement.
* Firefox, Safari (with Full Disk Access) and Chromium-based browser profiles.
* Tool-driven cleanup (`brew cleanup`, `xcrun simctl delete unavailable`).
