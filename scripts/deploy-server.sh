#!/bin/bash
# Deploy riftroute-server to the shared host. It touches ONLY riftroute-server's
# own files (Clew lives on the same machine and is never touched):
#   /opt/riftroute-server/bin/riftroute-server{,.new,.prev}  and a service restart.
#
#   scripts/deploy-server.sh              build from a CLEAN tree, upload, switch, health-check
#   scripts/deploy-server.sh --rollback   switch back to the previous binary
#
# The host is never written into this repository; it comes from the
# environment:
#   RR_SERVER_HOST=root@<server>   (required)
#   RR_SERVER_KEY=<ssh key path>   (optional; ssh's own config otherwise)
#
# The new binary is uploaded as .new and checksummed on the server before it
# replaces anything; the old one is kept as .prev. The deploy counts only when
# the NEW commit answers the health check; otherwise the previous binary is
# put back automatically.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${RR_SERVER_HOST:?set RR_SERVER_HOST=root@<server>}
PORT=7780
BIN=/opt/riftroute-server/bin
OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
[[ -n "${RR_SERVER_KEY:-}" ]] && OPTS+=(-i "$RR_SERVER_KEY")
SSH=(ssh "${OPTS[@]}" "$HOST")

remote_switch() { # $1 = "deploy" | "rollback"
  "${SSH[@]}" "MODE=$1 BIN=$BIN PORT=$PORT SUM=${SUM:-} EXPECT=${EXPECT:-} bash -s" <<'REMOTE'
set -euo pipefail
cd "$BIN"
# Healthy = answering, and (when EXPECT is set) answering as that commit.
health() {
  local out
  for i in $(seq 1 20); do
    if out=$(curl -fsS "http://127.0.0.1:$PORT/healthz" 2>/dev/null); then
      if [ -z "$EXPECT" ] || [[ "$out" == *"\"commit\":\"$EXPECT\""* ]]; then echo "$out"; return 0; fi
    fi
    sleep 0.5
  done
  echo "last answer: ${out:-none}"
  return 1
}
restart() { systemctl reset-failed riftroute-server 2>/dev/null || true; systemctl restart riftroute-server; }
if [ "$MODE" = rollback ]; then
  [ -f riftroute-server.prev ] || { echo "no previous binary to roll back to"; exit 1; }
  mv -f riftroute-server.prev riftroute-server
  restart
  health && echo "rolled back" && exit 0
  echo "rollback health check failed"; exit 1
fi
echo "$SUM  riftroute-server.new" | sha256sum -c -
chmod 0755 riftroute-server.new
[ -f riftroute-server ] && cp -p riftroute-server riftroute-server.prev
mv -f riftroute-server.new riftroute-server
restart
if health; then echo "deployed"; exit 0; fi
echo "health check failed — restoring the previous binary"
if [ -f riftroute-server.prev ]; then
  mv -f riftroute-server.prev riftroute-server
  EXPECT=""
  restart
  health && echo "previous binary restored"
fi
exit 1
REMOTE
}

if [[ "${1:-}" == "--rollback" ]]; then
  remote_switch rollback
  exit
fi

[[ -z "$(git status --porcelain)" ]] || { echo "refusing to deploy from a dirty tree (commit or stash first)"; exit 1; }
VERSION=$(git describe --tags --always)
OUT=dist/server/riftroute-server
mkdir -p "$(dirname "$OUT")"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT" ./cmd/riftroute-server
SUM=$(shasum -a 256 "$OUT" | cut -d' ' -f1)
EXPECT=$(git rev-parse HEAD | cut -c1-7)
echo "built riftroute-server $VERSION ($EXPECT, $SUM)"
scp -q "${OPTS[@]}" "$OUT" "$HOST:$BIN/riftroute-server.new"
SUM=$SUM EXPECT=$EXPECT remote_switch deploy
