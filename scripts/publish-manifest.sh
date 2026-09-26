#!/bin/bash
# Publish a signed release manifest to the update server. Run on the
# maintainer's machine after `riftroute-release sign <tag>`:
#
#   RR_SERVER_HOST=root@<server> [RR_SERVER_KEY=<ssh key>] scripts/publish-manifest.sh v0.2.6 [channel] [rollout%]
#
# rollout% defaults to 100 for a new version; re-publishing the same version
# keeps its current rollout and halt unless you pass one.
#
# The files go to a temporary directory on the server; the server's own
# `riftroute-server publish` (run as its service account) verifies the
# signature against the release keys compiled into it, refuses anything older
# than what's published, and moves them into place. The temporary copy is
# always removed.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=${1:?usage: publish-manifest.sh <tag> [channel] [rollout%]}
CHANNEL=${2:-stable}
ROLLOUT=${3:--1}
HOST=${RR_SERVER_HOST:?set RR_SERVER_HOST=root@<server>}
OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
[[ -n "${RR_SERVER_KEY:-}" ]] && OPTS+=(-i "$RR_SERVER_KEY")
DIR=dist/release/$TAG
[[ -f $DIR/manifest.json && -f $DIR/manifest.json.sig ]] || { echo "no signed manifest in $DIR (run: riftroute-release sign $TAG)"; exit 1; }
[[ $CHANNEL =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "bad channel"; exit 1; }
[[ $ROLLOUT == -1 || ( $ROLLOUT =~ ^[0-9]{1,3}$ && ROLLOUT -le 100 ) ]] || { echo "rollout must be 0–100"; exit 1; }

TMP=$(ssh "${OPTS[@]}" "$HOST" 'd=$(mktemp -d /tmp/rr-publish-XXXXXX) && chmod 755 "$d" && echo "$d"')
trap 'ssh "${OPTS[@]}" "$HOST" "rm -rf -- $TMP"' EXIT
scp -q "${OPTS[@]}" "$DIR/manifest.json" "$DIR/manifest.json.sig" "$HOST:$TMP/"
ssh "${OPTS[@]}" "$HOST" "chmod 644 $TMP/manifest.json $TMP/manifest.json.sig && sudo -u riftroute-server /opt/riftroute-server/bin/riftroute-server publish -data /var/lib/riftroute-server -channel $CHANNEL -rollout $ROLLOUT -manifest $TMP/manifest.json -sig $TMP/manifest.json.sig"
