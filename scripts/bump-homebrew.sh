#!/usr/bin/env bash
# Rewrite packaging/homebrew/riftroute.rb for a release: set the version and the
# per-platform sha256 values from a checksums.txt (sha256sum format).
#
# Usage: VERSION=1.2.3 scripts/bump-homebrew.sh dist/checksums.txt
set -euo pipefail

VERSION="${VERSION:?set VERSION}"
CHECKSUMS="${1:?usage: bump-homebrew.sh <checksums.txt>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORMULA="${ROOT}/packaging/homebrew/riftroute.rb"

sum_for() { awk -v f="riftroute_${VERSION}_$1.tar.gz" '$2==f || $2=="*"f {print $1}' "$CHECKSUMS"; }

DA="$(sum_for darwin_arm64)"; DI="$(sum_for darwin_amd64)"
LA="$(sum_for linux_arm64)";  LI="$(sum_for linux_amd64)"

tmp="$(mktemp)"
sed \
  -e "s/^  version \".*\"/  version \"${VERSION}\"/" \
  -e "s/REPLACE_DARWIN_ARM64/${DA}/" \
  -e "s/REPLACE_DARWIN_AMD64/${DI}/" \
  -e "s/REPLACE_LINUX_ARM64/${LA}/" \
  -e "s/REPLACE_LINUX_AMD64/${LI}/" \
  "$FORMULA" > "$tmp"
mv "$tmp" "$FORMULA"
echo "updated ${FORMULA} → v${VERSION}"
