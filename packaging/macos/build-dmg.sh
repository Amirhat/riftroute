#!/usr/bin/env bash
# Package RiftRoute.app into a distributable .dmg.
#
# Code signing + notarization are OPTIONAL and gated on environment variables —
# without them the script still produces an ad-hoc .dmg (Gatekeeper will warn).
# Set these (typically from CI secrets) to produce a signed, notarized build:
#   MAC_SIGN_IDENTITY   "Developer ID Application: Name (TEAMID)"
#   AC_NOTARY_PROFILE   notarytool keychain profile name, OR
#   AC_APPLE_ID / AC_TEAM_ID / AC_PASSWORD  (app-specific password)
#
# Usage: VERSION=1.2.3 packaging/macos/build-dmg.sh
# Requires the app already built at desktop/build/bin/RiftRoute.app (make desktop).
set -euo pipefail

VERSION="${VERSION:-0.0.1}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="${ROOT}/desktop/build/bin/RiftRoute.app"
OUT="${ROOT}/dist"
DMG="${OUT}/RiftRoute_${VERSION}.dmg"

[ -d "$APP" ] || { echo "missing ${APP} — run 'make desktop' first" >&2; exit 1; }
mkdir -p "$OUT"

# Bundle the CLI + daemon inside the app so the GUI can install/manage the
# service (it escalates `riftroute daemon …` via the admin prompt). They go under
# Contents/Resources/bin — NOT next to the GUI in MacOS/, because the filesystem
# is case-insensitive and "riftroute" would collide with "RiftRoute".
echo "bundling riftroute + riftrouted into the app…"
BINDIR="${APP}/Contents/Resources/bin"
mkdir -p "$BINDIR"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "${BINDIR}/riftroute" "${ROOT}/cmd/riftroute"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "${BINDIR}/riftrouted" "${ROOT}/cmd/riftrouted"

# Re-sign AFTER bundling — adding files under Contents/ invalidates the signature
# Wails applied at build time. A VALID signature is REQUIRED even without a
# Developer ID: an app with a broken signature is reported by macOS as "damaged
# and can't be opened". So we always re-sign — Developer ID when available, else
# ad-hoc (users then just clear quarantine on first launch; see README).
if [ -n "${MAC_SIGN_IDENTITY:-}" ]; then
  echo "signing app with Developer ID…"
  codesign --force --options runtime --timestamp --sign "${MAC_SIGN_IDENTITY}" \
    "${BINDIR}/riftrouted" "${BINDIR}/riftroute"
  codesign --force --options runtime --timestamp --deep --sign "${MAC_SIGN_IDENTITY}" "$APP"
else
  echo "no Developer ID — ad-hoc signing (valid signature so macOS won't call it 'damaged')"
  codesign --force --deep --sign - "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP" || {
  echo "code signature verification failed" >&2; exit 1; }

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "RiftRoute" -srcfolder "$STAGE" -ov -format UDZO "$DMG"

if [ -n "${MAC_SIGN_IDENTITY:-}" ]; then
  codesign --force --sign "${MAC_SIGN_IDENTITY}" --timestamp "$DMG"
  if [ -n "${AC_NOTARY_PROFILE:-}" ]; then
    echo "notarizing with stored profile…"
    xcrun notarytool submit "$DMG" --keychain-profile "${AC_NOTARY_PROFILE}" --wait
    xcrun stapler staple "$DMG"
  elif [ -n "${AC_APPLE_ID:-}" ]; then
    echo "notarizing with Apple ID…"
    xcrun notarytool submit "$DMG" --apple-id "${AC_APPLE_ID}" \
      --team-id "${AC_TEAM_ID}" --password "${AC_PASSWORD}" --wait
    xcrun stapler staple "$DMG"
  else
    echo "no notarization creds — skipping (DMG is signed but not notarized)"
  fi
fi

echo "built ${DMG}"
