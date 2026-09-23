#!/bin/bash
# Live macOS kill-switch verification — needs root (real pf), so it's yours to
# run; automation only checks the generated rules parse. It proves that:
#   1. turning the kill switch on hooks its anchor into pf.conf, loads the
#      user-scoped block and turns pf on — i.e. it is actually ENFORCED
#      (before this fix the anchor was never referenced: "on", enforcing nothing);
#   2. root traffic — where VPN clients' helpers run — still gets out, so a VPN
#      can always reconnect;
#   3. your apps' traffic gets out only through a tunnel;
#   4. turning it off restores pf.conf byte-identical and pf's previous state.
#
#   sudo bash scripts/live-killswitch-test.sh
#
# Clearest with the VPN DISCONNECTED: then (3) shows your apps being refused.
# It runs its own daemon on a scratch socket and database; the trap always
# turns the kill switch off and stops that daemon. Every wait is bounded.
set -u

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo bash $0"; exit 1; }
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] || { echo "run via sudo from your normal account (SUDO_USER is needed)"; exit 1; }
cd "$(dirname "$0")/.." || exit 1
[[ -x ./bin/riftrouted && -x ./bin/riftroute ]] || { echo "build first: make build"; exit 1; }

SOCK=/tmp/rr-ks.sock
DB=/tmp/rr-ks.db
LOG=/tmp/rr-ks.log
TARGET=https://1.1.1.1
PASS=0; FAIL=0
ck() { if [[ "$2" == *"$3"* ]]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 -> got [$2] want [$3]"; FAIL=$((FAIL+1)); fi; }
rr() { ./bin/riftroute --socket "$SOCK" "$@"; }
# HTTP status of one bounded request (000 = refused / no connection).
probe() { curl -s -o /dev/null -m 6 -w '%{http_code}' "$TARGET" 2>/dev/null; }
probe_as_user() { sudo -u "$SUDO_USER" curl -s -o /dev/null -m 6 -w '%{http_code}' "$TARGET" 2>/dev/null; }

DPID=""
cleanup() {
  set +u
  if [[ -n "$DPID" ]] && kill -0 "$DPID" 2>/dev/null; then
    rr killswitch off >/dev/null 2>&1
    kill -TERM "$DPID" 2>/dev/null
    for i in $(seq 1 25); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$DPID" 2>/dev/null
  fi
  rm -f "$SOCK" "$DB" "$DB-wal" "$DB-shm"
}
trap cleanup EXIT INT TERM

echo "==== live kill-switch test (fully reversible) ===="

echo "-- 0. preflight: snapshot pf.conf and pf state"
PF_BEFORE=$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)
PF_STATE_BEFORE=$(pfctl -si 2>/dev/null | head -1 | grep -o "Enabled\|Disabled" | head -1)
ROUTE_IF=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')
echo "  pf.conf sha256: ${PF_BEFORE:0:16}...  |  pf: ${PF_STATE_BEFORE}  |  1.1.1.1 routes via: ${ROUTE_IF:-none}"
BASE_ROOT=$(probe); BASE_USER=$(probe_as_user)
echo "  before: root reaches $TARGET -> $BASE_ROOT, $SUDO_USER -> $BASE_USER"
[[ "$BASE_ROOT" != "000" ]] || echo "  NOTE: no internet even before the test — steps 2/3 can't prove anything"

echo "-- 1. start a test daemon (real provider, empty database)"
rm -f "$SOCK" "$DB"
./bin/riftrouted -socket "$SOCK" -db "$DB" -provider auto -log info > "$LOG" 2>&1 &
DPID=$!
up=no
for i in $(seq 1 40); do
  [[ -S "$SOCK" ]] && rr status >/dev/null 2>&1 && { up=yes; break; }
  sleep 0.2
done
ck "daemon ready within 8s" "$up" "yes"
[[ "$up" == yes ]] || { tail -20 "$LOG"; exit 1; }

echo "-- 2. turn the kill switch on — is it really enforced?"
ck "kill switch reports on" "$(rr killswitch on 2>&1)" "ON"
ck "pf.conf's loaded ruleset references the anchor" "$(pfctl -sr 2>/dev/null)" 'anchor "riftroute_ks"'
ck "anchor holds the user-scoped block" "$(pfctl -a riftroute_ks -sr 2>/dev/null)" "user 499 >< 60001"
ck "pf is running" "$(pfctl -si 2>/dev/null | head -1)" "Enabled"

echo "-- 3. who can still get out?"
ON_ROOT=$(probe); ON_USER=$(probe_as_user)
echo "  root -> $ON_ROOT   |   $SUDO_USER -> $ON_USER   (1.1.1.1 via ${ROUTE_IF:-none})"
if [[ "$BASE_ROOT" != "000" ]]; then
  [[ "$ON_ROOT" != "000" ]] && r=reachable || r=blocked
  ck "root (VPN helpers) still reaches the internet" "$r" "reachable"
  case "$ROUTE_IF" in
    utun*|ipsec*|ppp*|tun*|wg*)
      [[ "$ON_USER" != "000" ]] && r=reachable || r=blocked
      ck "your apps get out through the tunnel ($ROUTE_IF)" "$r" "reachable" ;;
    *)
      [[ "$ON_USER" == "000" ]] && r=blocked || r=reachable
      ck "your apps are blocked outside the tunnel ($ROUTE_IF)" "$r" "blocked" ;;
  esac
fi

echo "-- 4. turn it off — back exactly as before?"
ck "kill switch reports off" "$(rr killswitch off 2>&1)" "off"
ck "anchor emptied" "[$(pfctl -a riftroute_ks -sr 2>/dev/null)]" "[]"
if pfctl -sr 2>/dev/null | grep -q 'anchor "riftroute_ks"'; then r=present; else r=gone; fi
ck "anchor reference gone from the loaded ruleset" "$r" "gone"
ck "pf.conf byte-identical" "$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)" "$PF_BEFORE"
ck "pf back to its previous state" "$(pfctl -si 2>/dev/null | head -1)" "$PF_STATE_BEFORE"
OFF_USER=$(probe_as_user)
[[ "$BASE_USER" == "000" || "$OFF_USER" != "000" ]] && r=restored || r=still-blocked
ck "your apps' connectivity restored" "$r" "restored"

echo
echo "==== $PASS passed, $FAIL failed ===="
[[ $FAIL -eq 0 ]]
