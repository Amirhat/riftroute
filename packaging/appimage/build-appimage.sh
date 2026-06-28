#!/usr/bin/env bash
# Build a portable AppImage of the RiftRoute GUI for Linux.
# Requires the GUI already built (make desktop) at desktop/build/bin/RiftRoute,
# plus linuxdeploy (auto-downloaded if absent).
#
# Usage: VERSION=1.2.3 ARCH=x86_64 packaging/appimage/build-appimage.sh
# Output: dist/RiftRoute-<version>-<arch>.AppImage
set -euo pipefail

VERSION="${VERSION:-0.0.1}"
ARCH="${ARCH:-x86_64}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${ROOT}/desktop/build/bin/RiftRoute"
OUT="${ROOT}/dist"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

[ -f "$BIN" ] || { echo "missing ${BIN} — run 'make desktop' first" >&2; exit 1; }
mkdir -p "$OUT"

APPDIR="${WORK}/RiftRoute.AppDir"
install -D -m 0755 "$BIN" "${APPDIR}/usr/bin/RiftRoute"

cat > "${APPDIR}/riftroute.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=RiftRoute
Exec=RiftRoute
Icon=riftroute
Categories=Network;
EOF

ICON_SRC="${ROOT}/desktop/build/appicon.png"
[ -f "$ICON_SRC" ] || ICON_SRC="${ROOT}/desktop/frontend/src/assets/appicon.png"
if [ -f "$ICON_SRC" ]; then
  install -D -m 0644 "$ICON_SRC" "${APPDIR}/riftroute.png"
else
  # 1x1 transparent PNG fallback so linuxdeploy is happy.
  printf '\x89PNG\r\n\x1a\n' > "${APPDIR}/riftroute.png"
fi

LD="${WORK}/linuxdeploy-${ARCH}.AppImage"
if ! command -v linuxdeploy >/dev/null 2>&1; then
  echo "fetching linuxdeploy…"
  curl -fsSL -o "$LD" \
    "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-${ARCH}.AppImage"
  chmod +x "$LD"
else
  LD="$(command -v linuxdeploy)"
fi

OUTPUT="${OUT}/RiftRoute-${VERSION}-${ARCH}.AppImage"
( cd "$WORK" && OUTPUT="$OUTPUT" "$LD" --appdir "$APPDIR" --output appimage )
echo "built ${OUTPUT}"
