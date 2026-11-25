# Contributing to RustClean

Guide for anyone changing this codebase, human or AI coding agent. Read it
before your first change; update it when you change how things work
(see [Keeping docs current](#keeping-docs-current)).

RustClean is a desktop disk cleaner written entirely in Rust (egui/eframe).
It runs on macOS (primary), Linux and Windows. **Its main job is to never
remove something the user needs**; finding reclaimable space comes second.

Related docs:

- [`README.md`](../README.md): features, safety model, platform support,
  known limitations.
- [`docs/SYSTEM_DESIGN.md`](SYSTEM_DESIGN.md): architecture diagram, cleanup
  lifecycle, invariants, failure modes, feature designs.

## Safety rules (never break these)

These are enforced by the type system and by tests. A change that weakens
any of them needs explicit sign-off from the maintainer, not just a passing
build.

1. **Nothing is ever deleted outright.** Files go to the Trash or RustClean
   quarantine through a `safety::Remover`. Do not call `fs::remove_file`,
   `remove_dir_all` or `unlink` on user data. The only exceptions are
   RustClean's own quarantine purge (`purge_quarantine_session`, confirmed by
   the user) and Docker removals through the Docker API.
2. **Only `core::Cleaner` removes files, and only from an `ApprovedPlan`.**
   Modules and scanners describe; they never act. `CleanupPlan::approve` is
   the only way to build an `ApprovedPlan`. Do not add another constructor.
3. **Re-validate right before acting.** `PathValidator::validate_for_removal`
   runs per file at cleanup time: unchanged fingerprint, inside an approved
   scan root, not protected, not a symlink, not locked. Skip on failure;
   never force.
4. **Classifications only get stricter.** The order is
   Safe < Review < Unknown < Protected, and the most restrictive one wins.
   Domain classifiers and `post_process` steps may drop candidates or raise
   their class; they must never lower one.
5. **The partial-deletion rule.** Add a location only if removing *any
   subset* of its files is harmless, because a cleanup can stop part-way
   (cancelled, or a file skipped). Example: `~/.cargo/registry/src` is
   excluded because a leftover `.cargo-ok` marker makes Cargo trust a
   half-deleted tree.
6. **Protected stays protected.** Never shrink `ProtectionRules` or the
   per-OS lists in `safety/src/platform.rs`. Database, VM-disk and Git files
   (`storage::DataFileClassifier`) and key/credential-like paths
   (`apps::SensitiveClassifier`) are Protected wherever they appear.
7. **Scans are read-only.** Never follow symlinks; never cross into another
   file system (mounted folders such as `~/OrbStack` are skipped).
8. **No network.** The only connection allowed is the local Docker socket or
   named pipe. No telemetry, no update checks, no downloads.
9. **Docker:** API only, always `force = false`; never touch Docker's disk
   image. Real removals need the irreversibility acknowledgement.
10. **Irreversible or risky actions need explicit confirmation in the UI**
    (Review files, live warnings such as "Chrome is running", Docker,
    quarantine purge).

**Check new rules against a real machine before you trust them.** On the
first real run, three rules that looked fine in fixtures turned out to be
dangerous:

- App Leftovers flagged `org.dfinity.dfx`, but the `dfx` tool is *installed
  inside* that folder.
- Duplicate Finder offered live MongoDB journal files under `~/OrbStack`.
- The same file reached through a symlinked folder was counted twice.

Before shipping a new location or rule, run the matching read-only example
(below) on a real machine and read the output.

## Repository map

| Crate | Responsibility |
|---|---|
| `crates/safety` | `platform.rs` (**all** OS-specific code), protected paths, `PathValidator`, Trash and quarantine (restore, purge) |
| `crates/core` | `Scanner` (read-only), classifiers, `CleanupPlan` → `ApprovedPlan`, `Cleaner`, operation log, the `CleanupModule` trait |
| `crates/browser` | Chrome detection, cache targets, protected-data classifier |
| `crates/junk` | Junk Cleaner, App Caches, Developer Cleaner, running-app detection |
| `crates/storage` | Storage Analyzer, Large Files, `DataFileClassifier`, personal-folder roots |
| `crates/duplicates` | Duplicate Finder (size → partial → full BLAKE3) |
| `crates/apps` | Installed-app detection, App Leftovers (+ `SensitiveClassifier`) |
| `crates/containers` | Docker via `bollard`; Tokio stays inside this crate |
| `crates/security` | Read-only persistence audit (LaunchAgents, autostart, Startup folder) and protection status (Gatekeeper, Defender, ClamAV) |
| `crates/app` | The `rustclean` binary: egui UI, pages, theme, widgets, screenshot tests |
| `scripts/release.sh` | Builds `dist/` packages (macOS `.dmg`, Windows `.zip`) |

Dependencies flow one way: `app` → feature crates → `core` → `safety`.
Feature crates never depend on `app`.

## Commands

```sh
cargo run --release -p rustclean                  # run the app
cargo test --workspace                            # all unit tests
cargo fmt --all
cargo clippy --workspace --all-targets            # must report 0 warnings

# Type-check other platforms (one-time: rustup target add …)
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu

# Screenshots of the real UI at 1280 / 900 / 390 px → design/screenshots/
cargo test -p rustclean -- --ignored ui_snapshots

# Read-only checks against THIS machine (dry runs; nothing is removed)
cargo run -p rustclean-browser --example chrome_dry_run
cargo run --release -p rustclean-junk --example junk_dry_run
cargo run -p rustclean-apps --example leftovers
cargo run --release -p rustclean-duplicates --example find_dupes
cargo run -p rustclean-containers --example docker_dry_run
cargo run -p rustclean-security --example persistence_audit
cargo run -p rustclean-security --example protection_status

# Real end-to-end Trash check: moves ONE file it creates itself to your Trash
cargo run -p rustclean-core --example trash_e2e

scripts/release.sh [all|macos|windows]           # packages into dist/
```

Toolchain: `rust-version = 1.92`. `eframe`/`egui` are pinned to 0.35 and
`sysinfo` to 0.38, because newer releases need Rust 1.95. Bump them together,
and only after raising `rust-version`. Windows release builds need
`brew install mingw-w64`; macOS signing is optional (`SIGN_IDENTITY`).

## Adding a cleanup module

1. Implement `core::CleanupModule` in the right feature crate: `title`,
   `refresh`, `is_available`, `details`, `notes`, `prepare_scan`,
   `active_warning`.
2. `prepare_scan` returns a `ScanSpec`: targets (with `min_size`,
   `skip_dirs`, `extensions`, `max_depth` and `review_if_newer_than` as
   needed), an optional domain classifier, and an optional `post_process`.
   Remember rule 4: they may only make things stricter.
3. Get paths from `safety::platform` (`user_cache_dir`, `local_app_data`,
   …), not hard-coded `~/Library`. Mark a location `None` on platforms where
   it doesn't apply.
4. Default to **Review** unless the files are provably rebuilt on demand.
   Put the "why" in `with_reason`, because the UI shows it to the user.
5. Add a `ScanPage` in `crates/app/src/app.rs` (`Loaded`), a `Page` entry and
   icon in `navigation.rs`, and a badge if useful. Decide whether it belongs
   in Smart Scan (avoid double counting with another module).
6. Write tests against a `tempfile` fixture home (below), add a read-only
   example, and run it on a real machine.
7. Update the README's module table and safety rules.

## UI conventions

- **Colours and sizes come from `theme.rs`** (`palette(ui)`, `card`,
  `primary_button`, `INK`). Don't hard-code colours; the theme has light
  and dark palettes.
- **Use the shared widgets** (`widgets.rs`): `pill`/`class_pill` (always
  colour *and* text), `banner`, `callout`, `chip`, `card_grid`,
  `header_with_action`, `action_bar`, `toast`, `short_path`, `trash_name`
  / `method_label`, `reveal_label`.
- **Responsive layout is required.** Breakpoints on *content* width:
  - ≥ 960 px: categories list + file table
  - 640–960 px: category/safety dropdowns, table fills the remaining height
  - < 640 px: dropdowns, stacked cards

  File details are a dialog (`Modal`) in every layout, never a panel that
  takes list space. Height matters too: the file list gets what is left of
  the window (min `MIN_LIST_H`), and windows under 640 px tall get one-line
  banners. Below an 860 px window the sidebar becomes a page picker. Use
  `card_grid` for card rows; `ui.columns` misbehaved at one column (a card
  disappeared). Wrap long text (`Label::wrap`), truncate single-line labels
  next to a value, and use `horizontal_wrapped` for button rows.
- **Name things the way the OS does.** Never hard-code "Trash" or "Finder":
  use `widgets::trash_name()` ("Recycle Bin" on Windows), `method_label`
  and `reveal_label`.
- **Plain language.** Say what will happen ("Move 12 files to Trash"), say
  that it's reversible, and explain every Review/Protected label.
- **Any visible UI change:** re-render the screenshots and look at all four
  sizes (1280, 900, 390 and 1093×614, a 1366×768 Windows laptop at 125 %)
  before calling it done. Test-only hooks live behind `#[cfg(test)]`
  (e.g. `select_for_test`, `detail_for_test`, `set_report_for_test`).

## Testing

- **Fixtures:** build a fake home in `tempfile::tempdir()` and canonicalise
  it with `safety::platform::canonicalize` (macOS temp paths go through the
  `/var` → `/private/var` symlink). Tests must never read or change the real
  home folder. The `ui_snapshots` test is the one exception: it may *scan*
  the real temp folder, read-only.
- **Gate platform-specific tests:** `#[cfg(unix)]` for symlinks and
  permissions, `#[cfg(target_os = "macos")]` for macOS layouts.
- **Cover failure paths**, not only happy paths: changed-after-scan,
  symlink swaps, protected roots, cancellation, tampered quarantine
  manifests.
- **Don't weaken a failing safety test to get a green build.** Fix the code,
  or raise it with the maintainer.

## Definition of done

- [ ] `cargo fmt`, `cargo clippy` (0 warnings) on macOS, Linux and Windows targets
- [ ] `cargo test --workspace` passes; new behaviour has tests, including failure cases
- [ ] New locations/rules checked with a read-only example on a real machine
- [ ] UI changes: screenshots reviewed at 1280, 900 and 390 px
- [ ] README / SYSTEM_DESIGN / this file updated where behaviour changed
- [ ] No secrets, personal paths or real user file names committed (`design/` and `dist/` are git-ignored for this reason)

## Keeping docs current

| You changed… | Update |
|---|---|
| A safety rule, protected path, or what a module cleans | README *Safety model* / module table, and rules above if it's an invariant |
| Architecture, lifecycle, or a feature's design | `docs/SYSTEM_DESIGN.md` |
| Commands, toolchain, conventions, contributor workflow | This file |
| Platform support | README *Platform support* |

Keep this file short and factual. If a section grows into a design
discussion, move it to `SYSTEM_DESIGN.md` and link it.
