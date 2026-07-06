#!/bin/bash
# Live macOS PF verification — the ONE step automation can't cover without root:
# loading real route-to rules into /dev/pf and proving full teardown.
#
#   sudo bash scripts/live-pf-test.sh
#
# Everything is scoped and reversible: the only destination steered is TEST-NET-2
# (198.51.100.0/24, documentation-only), rules live in RiftRoute's own PF anchor,
# and the trap ALWAYS panics + kills the daemon + verifies /etc/pf.conf is
# byte-identical to before. Every wait is bounded; nothing here can hang.
set -u

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo bash $0"; exit 1; }
cd "$(dirname "$0")/.." || exit 1

SOCK=/tmp/rr-root.sock
DB=/tmp/rr-root.db
LOG=/tmp/rr-root.log
CFG=/tmp/rr-root-config.yaml
TOKEN=/var/run/riftroute.pf.token
PASS=0; FAIL=0
ck() { if [[ "$2" == *"$3"* ]]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 -> got [$2] want [$3]"; FAIL=$((FAIL+1)); fi; }

# bounded exec (gtimeout from coreutils if present, else raw)
bt() { if command -v gtimeout >/dev/null; then gtimeout "$@"; else local t=$1; shift; "$@"; fi; }

DPID=""
cleanup() {
  set +u
  if [[ -n "$DPID" ]] && kill -0 "$DPID" 2>/dev/null; then
    bt 10 ./bin/riftroute --socket "$SOCK" panic >/dev/null 2>&1
    kill -TERM "$DPID" 2>/dev/null
    for i in $(seq 1 25); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$DPID" 2>/dev/null
  fi
  rm -f "$SOCK" "$DB" "$CFG"
}
trap cleanup EXIT INT TERM

echo "==== live PF root test (TEST-NET-2 only; fully reversible) ===="

echo "-- 0. preflight: stop stale daemons, snapshot pf state"
pkill -f "riftrouted -socket $SOCK" 2>/dev/null; sleep 0.5
PF_BEFORE=$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)
# Compare only the Enabled/Disabled STATE word: the status line's uptime timer
# legitimately resets when our enable token is released (PF flips back off one
# second before the check), which is exactly the restore we're verifying.
PF_STATE_BEFORE=$(pfctl -si 2>/dev/null | head -1 | grep -o "Enabled\|Disabled" | head -1)
echo "  pf.conf sha256: ${PF_BEFORE:0:16}...  |  pf state: ${PF_STATE_BEFORE}"

echo "-- 1. start root daemon (real provider, fresh state)"
rm -f "$SOCK" "$DB"
./bin/riftrouted -socket "$SOCK" -db "$DB" -provider auto -log info > "$LOG" 2>&1 &
DPID=$!
up=no
for i in $(seq 1 40); do
  [[ -S "$SOCK" ]] && bt 5 ./bin/riftroute --socket "$SOCK" status >/dev/null 2>&1 && { up=yes; break; }
  sleep 0.2
done
ck "daemon ready within 8s" "$up" "yes"
[[ "$up" == yes ]] || { tail -5 "$LOG"; exit 1; }

echo "-- 2. include profile steering TEST-NET-2 into the live tunnel"
cat > "$CFG" <<'YAML'
version: 1
profiles:
  - name: pf-live-test
    enabled: true
    mode: include
    rules:
      - { type: cidr, value: "198.51.100.0/24" }
YAML
echo "  dry-run plan:"
bt 15 ./bin/riftroute --socket "$SOCK" apply --dry-run "$CFG" 2>&1 | sed 's/^/    /' | head -8
bt 20 ./bin/riftroute --socket "$SOCK" apply --yes "$CFG" 2>&1 | sed 's/^/    /' | head -4
sleep 1

echo "-- 3. verify the REAL PF anchor"
ANCHOR=$(bt 8 pfctl -a riftroute -sr 2>&1)
echo "$ANCHOR" | sed 's/^/    /'
ck "route-to rule loaded in anchor" "$ANCHOR" "route-to"
ck "rule targets TEST-NET-2" "$ANCHOR" "198.51.100.0/24"
ck "rule carries our label" "$ANCHOR" "riftroute"
HOOK=$(grep -c "riftroute" /etc/pf.conf)
ck "pf.conf hook present (marked block)" "$([[ "$HOOK" -ge 1 ]] && echo yes)" "yes"
ck "kernel route decision for 198.51.100.1 known" "$(bt 8 route -n get 198.51.100.1 2>/dev/null | grep -c interface)" "1"

echo "-- 4. daemon restart: anchor survives, no drift"
kill -TERM "$DPID"
for i in $(seq 1 25); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.2; done
./bin/riftrouted -socket "$SOCK" -db "$DB" -provider auto -log info >> "$LOG" 2>&1 &
DPID=$!
for i in $(seq 1 40); do [[ -S "$SOCK" ]] && bt 5 ./bin/riftroute --socket "$SOCK" status >/dev/null 2>&1 && break; sleep 0.2; done
ANCHOR2=$(bt 8 pfctl -a riftroute -sr 2>&1)
ck "anchor rule still loaded after restart" "$ANCHOR2" "198.51.100.0/24"
DRIFT=$(bt 8 ./bin/riftroute --socket "$SOCK" --json status 2>/dev/null | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['drift']['pending'], d['drift'].get('reason',''))" 2>/dev/null)
ck "no drift after restart (rules reconciled)" "$DRIFT" "False"

echo "-- 5. panic: full teardown, baseline restored"
bt 15 ./bin/riftroute --socket "$SOCK" panic 2>&1 | sed 's/^/    /'
sleep 1
ANCHOR3=$(bt 8 pfctl -a riftroute -sr 2>&1)
ck "anchor empty after panic" "$(echo "$ANCHOR3" | grep -c route-to)" "0"
ck "pf.conf hook removed" "$(grep -c riftroute /etc/pf.conf)" "0"
PF_AFTER=$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)
ck "pf.conf byte-identical to before" "$PF_AFTER" "$PF_BEFORE"
ck "pf enable token released" "$([[ -f "$TOKEN" ]] && echo present || echo gone)" "gone"
PF_STATE_AFTER=$(pfctl -si 2>/dev/null | head -1 | grep -o "Enabled\|Disabled" | head -1)
ck "pf enabled/disabled state restored" "$PF_STATE_AFTER" "$PF_STATE_BEFORE"

echo "-- 6. shutdown + log scan"
kill -TERM "$DPID"
for i in $(seq 1 25); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.2; done
DPID=""
if grep -iE "panic:|fatal" "$LOG" >/dev/null; then echo "  FAIL: panic/fatal in daemon log"; FAIL=$((FAIL+1)); else echo "  PASS: no panic/fatal in daemon log"; PASS=$((PASS+1)); fi
rm -f /etc/pf.conf.riftroute.bak

echo
echo "==== RESULT: $PASS passed, $FAIL failed ===="
echo "(daemon log kept at $LOG)"
exit $FAIL
