#!/usr/bin/env bash
# Build a .deb containing the RiftRoute CLI + daemon and the systemd unit.
# Pure-Go binaries (cgo off) — no runtime deps. The GUI is NOT packaged here.
#
# Usage: VERSION=1.2.3 ARCH=amd64 packaging/deb/build-deb.sh
# Output: dist/riftroute_<version>_<arch>.deb
set -euo pipefail

VERSION="${VERSION:-0.0.1}"
ARCH="${ARCH:-amd64}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${ROOT}/dist"
PKG="$(mktemp -d)"
trap 'rm -rf "$PKG"' EXIT

echo "building riftroute binaries (linux/${ARCH})…"
GOOS=linux GOARCH="${ARCH}" CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${PKG}/usr/bin/riftrouted" "${ROOT}/cmd/riftrouted"
GOOS=linux GOARCH="${ARCH}" CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${PKG}/usr/bin/riftroute" "${ROOT}/cmd/riftroute"

install -D -m 0644 "${ROOT}/packaging/systemd/riftroute.service" \
  "${PKG}/lib/systemd/system/riftroute.service"

mkdir -p "${PKG}/DEBIAN"
cat > "${PKG}/DEBIAN/control" <<EOF
Package: riftroute
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: AmirHat <a.h.amani.t@gmail.com>
Depends: iproute2, nftables
Description: Cross-platform split-tunneling / policy-based routing controller
 RiftRoute steers traffic by policy with a safety-first Apply Protocol
 (snapshot, watchdog, commit-confirm, atomic rollback). This package ships the
 privileged daemon (riftrouted) and the CLI (riftroute).
EOF

cat > "${PKG}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
echo "RiftRoute installed. Enable the daemon with: sudo systemctl enable --now riftroute"
EOF
chmod 0755 "${PKG}/DEBIAN/postinst"

cat > "${PKG}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
systemctl disable --now riftroute >/dev/null 2>&1 || true
EOF
chmod 0755 "${PKG}/DEBIAN/prerm"

mkdir -p "${OUT}"
DEB="${OUT}/riftroute_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "${PKG}" "${DEB}"
echo "built ${DEB}"
