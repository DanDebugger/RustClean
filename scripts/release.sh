#!/usr/bin/env bash
# Build release packages of RustClean (run on macOS).
#
#   scripts/release.sh            # macOS .dmg + Windows .zip
#   scripts/release.sh macos      # macOS only
#   scripts/release.sh windows    # Windows only
#
# Output: dist/RustClean-<version>-macos.dmg
#         dist/RustClean-<version>-windows-x64.zip
#
# Optional environment variables:
#   BUNDLE_ID        macOS bundle identifier (default: com.rustclean.app)
#   SIGN_IDENTITY    "Developer ID Application: ..." to code-sign the .app/.dmg
#                    (unset = unsigned; users must right-click → Open once)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

WHAT="${1:-all}"
case "$WHAT" in
  all|macos|windows) ;;
  *) echo "usage: $0 [all|macos|windows]" >&2; exit 2 ;;
esac

[[ "$(uname -s)" == "Darwin" ]] || { echo "error: run this script on macOS" >&2; exit 1; }

# Version from [workspace.package] in Cargo.toml.
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
[[ -n "$VERSION" ]] || { echo "error: could not read version from Cargo.toml" >&2; exit 1; }

BUNDLE_ID="${BUNDLE_ID:-com.rustclean.app}"
DIST="$ROOT/dist"
mkdir -p "$DIST"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found. $2" >&2; exit 1; }; }

ensure_target() {
  rustup target list --installed | grep -qx "$1" || rustup target add "$1"
}

build_macos() {
  echo "==> macOS $VERSION (universal: Apple Silicon + Intel)"
  need lipo "Install Xcode Command Line Tools: xcode-select --install"
  need hdiutil ""

  for t in aarch64-apple-darwin x86_64-apple-darwin; do
    ensure_target "$t"
    cargo build --release --locked -p rustclean --target "$t"
  done

  local stage="$DIST/macos-stage"
  local app="$stage/RustClean.app"
  rm -rf "$stage"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

  lipo -create \
    target/aarch64-apple-darwin/release/rustclean \
    target/x86_64-apple-darwin/release/rustclean \
    -output "$app/Contents/MacOS/rustclean"

  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>               <string>RustClean</string>
  <key>CFBundleDisplayName</key>        <string>RustClean</string>
  <key>CFBundleExecutable</key>         <string>rustclean</string>
  <key>CFBundleIdentifier</key>         <string>${BUNDLE_ID}</string>
  <key>CFBundleVersion</key>            <string>${VERSION}</string>
  <key>CFBundleShortVersionString</key> <string>${VERSION}</string>
  <key>CFBundlePackageType</key>        <string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key>     <string>11.0</string>
  <key>NSHighResolutionCapable</key>    <true/>
</dict>
</plist>
PLIST

  # Optional app icon: put a macOS icon at assets/RustClean.icns.
  if [[ -f assets/RustClean.icns ]]; then
    cp assets/RustClean.icns "$app/Contents/Resources/RustClean.icns"
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string RustClean" "$app/Contents/Info.plist"
  fi

  if [[ -n "${SIGN_IDENTITY:-}" ]]; then
    echo "==> Signing with: $SIGN_IDENTITY"
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$app"
  else
    # Ad-hoc signature: required for Apple Silicon to launch it at all.
    codesign --force --sign - "$app"
  fi

  ln -s /Applications "$stage/Applications"

  local dmg="$DIST/RustClean-$VERSION-macos.dmg"
  rm -f "$dmg"
  hdiutil create -volname "RustClean" -srcfolder "$stage" -ov -format UDZO "$dmg" >/dev/null
  [[ -n "${SIGN_IDENTITY:-}" ]] && codesign --force --timestamp --sign "$SIGN_IDENTITY" "$dmg"

  rm -rf "$stage"
  echo "    -> $dmg"
}

build_windows() {
  echo "==> Windows $VERSION (x86_64)"
  need x86_64-w64-mingw32-gcc "Install the Windows linker: brew install mingw-w64"
  need zip ""

  local t=x86_64-pc-windows-gnu
  ensure_target "$t"
  cargo build --release --locked -p rustclean --target "$t"

  local stage="$DIST/windows-stage/RustClean"
  rm -rf "$DIST/windows-stage"
  mkdir -p "$stage"
  cp "target/$t/release/rustclean.exe" "$stage/RustClean.exe"
  cp README.md "$stage/README.md"
  [[ -f LICENSE ]] && cp LICENSE "$stage/LICENSE.txt"

  local zipf="$DIST/RustClean-$VERSION-windows-x64.zip"
  rm -f "$zipf"
  (cd "$DIST/windows-stage" && zip -qr "$zipf" RustClean)
  rm -rf "$DIST/windows-stage"
  echo "    -> $zipf"
}

[[ "$WHAT" == all || "$WHAT" == macos ]] && build_macos
[[ "$WHAT" == all || "$WHAT" == windows ]] && build_windows

echo "==> Done. Packages are in dist/"
(cd "$DIST" && shasum -a 256 RustClean-"$VERSION"-* 2>/dev/null) || true
