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
# Tunnels' openvpn (scripts/build-openvpn.sh universal) is bundled from
# OPENVPN_BIN (default build/openvpn/universal/openvpn), with the licenses/
# folder beside it — never one without the other (it is GPL-2.0: the
# licenses and SOURCES.txt go wherever it goes). Without them the .dmg still
# builds, without openvpn, and macOS tunnels say what's missing;
# REQUIRE_OPENVPN=1 (release builds) makes that an error.
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
echo "bundling riftroute + riftrouted into the app (universal arm64 + x86_64)…"
BINDIR="${APP}/Contents/Resources/bin"
mkdir -p "$BINDIR"
LD="-s -w -X main.version=${VERSION}"

# Build each CLI for both Mac architectures and lipo them into one universal
# binary, so the bundled tools run on Apple Silicon AND Intel regardless of which
# runner built the DMG (matches the universal GUI — see `make desktop-universal`).
build_universal() {
  local pkg="$1" out="$2" tmp
  tmp="$(mktemp -d)"
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "${tmp}/arm64" "$pkg"
  GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "${tmp}/amd64" "$pkg"
  lipo -create -output "$out" "${tmp}/arm64" "${tmp}/amd64"
  rm -rf "$tmp"
}
build_universal "${ROOT}/cmd/riftroute"  "${BINDIR}/riftroute"
build_universal "${ROOT}/cmd/riftrouted" "${BINDIR}/riftrouted"

# Tunnels' openvpn goes next to riftrouted: the app's Install button runs
# `riftroute daemon install` from here, which installs it root-owned beside the
# daemon. The daemon never runs any other openvpn (never Homebrew's).
OPENVPN_BIN="${OPENVPN_BIN:-${ROOT}/build/openvpn/universal/openvpn}"
OPENVPN_LICENSES="$(dirname "$OPENVPN_BIN")/licenses"
rm -f "${BINDIR}/openvpn"
rm -rf "${APP}/Contents/Resources/licenses"
# The licenses build-openvpn.sh writes: every component's, and the sources.
have_licenses() {
  local l="$1" f
  for f in SOURCES.txt openvpn/COPYING openssl/LICENSE.txt lzo/COPYING lz4/LICENSE; do
    [ -f "${l}/${f}" ] || return 1
  done
}
if [ -f "$OPENVPN_BIN" ] && have_licenses "$OPENVPN_LICENSES"; then
  echo "bundling openvpn from ${OPENVPN_BIN}, with ${OPENVPN_LICENSES}"
  lipo "$OPENVPN_BIN" -verify_arch arm64 x86_64 || {
    echo "${OPENVPN_BIN} must be universal (arm64 + x86_64)" >&2; exit 1; }
  cp "$OPENVPN_BIN" "${BINDIR}/openvpn"
  chmod 755 "${BINDIR}/openvpn"
  cp -R "$OPENVPN_LICENSES" "${APP}/Contents/Resources/licenses"
elif [ -n "${REQUIRE_OPENVPN:-}" ]; then
  echo "missing ${OPENVPN_BIN} or its licenses (${OPENVPN_LICENSES}/) — build both with" \
    "scripts/build-openvpn.sh universal" >&2
  exit 1
elif [ -f "$OPENVPN_BIN" ]; then
  echo "${OPENVPN_BIN} has no complete ${OPENVPN_LICENSES}/ beside it: openvpn is never bundled" \
    "without its licenses, so the app ships without it; tunnels won't be available on macOS" >&2
else
  echo "no openvpn at ${OPENVPN_BIN}: the app ships without it; tunnels won't be available on macOS" >&2
fi

# The bundle says which release it is (Finder's Get Info; Wails' template
# leaves 1.0.0).
plutil -replace CFBundleShortVersionString -string "${VERSION}" "${APP}/Contents/Info.plist"
plutil -replace CFBundleVersion -string "${VERSION}" "${APP}/Contents/Info.plist"

# Re-sign AFTER bundling — adding files under Contents/ invalidates the signature
# Wails applied at build time. A VALID signature is REQUIRED even without a
# Developer ID: an app with a broken signature is reported by macOS as "damaged
# and can't be opened". So we always re-sign — Developer ID when available, else
# ad-hoc (users then just clear quarantine on first launch; see README).
if [ -n "${MAC_SIGN_IDENTITY:-}" ]; then
  echo "signing app with Developer ID…"
  codesign --force --options runtime --timestamp --sign "${MAC_SIGN_IDENTITY}" \
    "${BINDIR}/riftrouted" "${BINDIR}/riftroute"
  if [ -f "${BINDIR}/openvpn" ]; then
    codesign --force --options runtime --timestamp --identifier com.riftroute.openvpn \
      --sign "${MAC_SIGN_IDENTITY}" "${BINDIR}/openvpn"
  fi
  codesign --force --options runtime --timestamp --deep --sign "${MAC_SIGN_IDENTITY}" "$APP"
else
  echo "no Developer ID — ad-hoc signing (valid signature so macOS won't call it 'damaged')"
  if [ -f "${BINDIR}/openvpn" ]; then
    codesign --force --identifier com.riftroute.openvpn --sign - "${BINDIR}/openvpn"
  fi
  codesign --force --deep --sign - "$APP"
fi
if [ -f "${BINDIR}/openvpn" ]; then
  codesign --verify --strict --verbose=2 "${BINDIR}/openvpn" || {
    echo "openvpn signature verification failed" >&2; exit 1; }
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
