#!/bin/bash
# Live macOS L2TP/IPsec test: a real L2TP/IPsec tunnel to your server, as a
# split tunnel to one address inside your VPN, beside your main VPN. It
# needs root (a real utun, charon with the kernel's IPsec, routes), so it's
# yours to run:
#
#   make build
#   sudo bash scripts/live-l2tp-test.sh <l2tp.conf | profile.mobileconfig> <an address inside the VPN>
#
# The configuration is RiftRoute's [L2TP] file or a .mobileconfig with an L2TP
# VPN. The login is asked for (hidden) when it doesn't carry one.
#
# It proves on this Mac that:
#   1. RiftRoute's own charon (built here: build/strongswan-l2tp, copied
#      next to bin/riftrouted, installed with the daemon) brings IPsec up in
#      transport mode, and L2TP and PPP come up on a utun;
#   2. the address goes into the tunnel, and answers;
#   3. no L2TP leaves this Mac unencrypted: none on UDP 1701, ESP in UDP 4500;
#   4. a disconnect leaves no IPsec policy or SA for the server, and stops
#      charon;
#   5. the daemon killed while it's connected: the next one stops the charon
#      it left, and its policies go.
#
# It installs this build as the system daemon for the test. The EXIT trap
# removes the test tunnel and reinstalls the app's daemon (KEEP_DEV=1 keeps
# this build). Nothing prints the configuration's secrets or the password.
# The report is also written to /tmp/rr-l2tp-test.log.
set -u
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo bash $0 <config> <address>"; exit 1; }
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] || { echo "run via sudo from your normal account (SUDO_USER is needed)"; exit 1; }
cd "$(dirname "$0")/.." || exit 1
CONF=${1:-}
TARGET=${2:-}
[[ -n "$CONF" && -r "$CONF" && -n "$TARGET" ]] || { echo "usage: sudo bash $0 <l2tp.conf | profile.mobileconfig> <an address inside the VPN>"; exit 1; }
[[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "the address must be an IPv4 address"; exit 1; }
for t in jq tcpdump setkey launchctl perl; do
  command -v "$t" >/dev/null || { echo "missing $t"; exit 1; }
done
[[ -x ./bin/riftroute && -x ./bin/riftrouted ]] || { echo "build first: make build"; exit 1; }
HEAD=$(sudo -u "$SUDO_USER" git rev-parse --short=7 HEAD 2>/dev/null)
[[ -n "$HEAD" && "$(./bin/riftroute version 2>/dev/null | awk '/^riftroute /')" == *"$HEAD"* ]] ||
  { echo "./bin isn't this checkout's HEAD (${HEAD:-?}): run make build"; exit 1; }
# charon goes with the daemon: from beside it.
if [[ ! -x ./bin/charon ]]; then
  [[ -x ./build/strongswan-l2tp/charon ]] || { echo "no charon: build it with scripts/build-strongswan.sh $(uname -m) build/strongswan-l2tp"; exit 1; }
  cp ./build/strongswan-l2tp/charon ./bin/charon && chown "$SUDO_USER" ./bin/charon
fi

NAME=rr-l2tptest
LABEL=system/com.riftroute.daemon
BUNDLE_CLI=${BUNDLE_CLI:-/Applications/RiftRoute.app/Contents/Resources/bin/riftroute}
CHARON=/Library/PrivilegedHelperTools/riftroute-charon
DLOG=/var/log/riftroute/riftrouted.err.log
REPORT=/tmp/rr-l2tp-test.log
TMPD=$(mktemp -d /tmp/rr-l2tptest.XXXXXX) && chmod 700 "$TMPD" || exit 1
: > "$REPORT" && chown "$SUDO_USER" "$REPORT" && chmod 600 "$REPORT"

# The login, before the report starts (nothing of it is printed).
CONF_TEXT=$(cat "$CONF")
has_user=0; has_pass=0
if grep -qi '^\[l2tp\]' <<<"$CONF_TEXT"; then
  grep -qiE '^[[:space:]]*username[[:space:]]*=' <<<"$CONF_TEXT" && has_user=1
  grep -qiE '^[[:space:]]*password[[:space:]]*=' <<<"$CONF_TEXT" && has_pass=1
else
  grep -q '<key>AuthName</key>' <<<"$CONF_TEXT" && has_user=1
  grep -q '<key>AuthPassword</key>' <<<"$CONF_TEXT" && has_pass=1
fi
L2TP_USER=""; L2TP_PASS=""
[[ $has_user == 1 ]] || read -r -p "L2TP username: " L2TP_USER
[[ $has_pass == 1 ]] || { read -r -s -p "L2TP password: " L2TP_PASS; echo; }

exec > >(tee -a "$REPORT") 2>&1
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
ck()   { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 -> got [${2:0:200}] want [$3]"; fi; }
ckeq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 -> got [${2:0:200}] want [$3]"; fi; }
note() { echo "  NOTE: $*"; }
to()   { perl -e 'alarm shift @ARGV; exec @ARGV' "$@"; }
rr()   { to 90 ./bin/riftroute --socket /var/run/riftroute.sock "$@"; }
until_ok() { local n=$1 i; shift; for ((i = 0; i < n; i++)); do "$@" && return 0; sleep 1; done; return 1; }
via()  { route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'; }
tj()   { rr --json tunnel list 2>/dev/null | jq -r --arg n "$NAME" ".[] | select(.name == \$n) | $1" 2>/dev/null; }
up_now() { [[ "$(tj .state)" == connected ]]; }
failed_now() { [[ "$(tj .state)" == failed ]]; }
daemon_ok() { rr status >/dev/null 2>&1; }
charons() { pgrep -f "^$CHARON( |$)" | wc -l | tr -d ' '; }
# The kernel's IPsec state for the server: policies and SAs that name it.
policies() { setkey -DP 2>/dev/null | grep -c "$1"; }
sas() { setkey -D 2>/dev/null | grep -c "$1"; }
no_policies() { [[ "$(policies "$1")" == 0 && "$(sas "$1")" == 0 ]]; }
# seen <filter> <seconds>: packets tcpdump sees on the physical interface
# while the target is pinged.
seen() {
  local f=$1 s=$2
  to $((s + 2)) tcpdump -ni "$PHYSIF" -l "$f" >"$TMPD/cap" 2>/dev/null &
  local p=$!
  sleep 1
  ping -c 4 -i 0.5 -t 2 "$TARGET" >/dev/null 2>&1
  sleep "$s"
  kill "$p" 2>/dev/null; wait "$p" 2>/dev/null
  grep -c . "$TMPD/cap"
}

ADDED=0; INSTALLED=0; DONE=0
finish() {
  [[ $DONE == 1 ]] && return
  DONE=1
  set +u
  rm -rf "$TMPD"
  echo "-- cleanup: the test tunnel goes, and the app's daemon comes back"
  if [[ $ADDED == 1 ]]; then
    rr tunnel rm "$NAME" 2>&1 | sed 's/^/    /'
    [[ -n "${SERVER:-}" ]] && { until_ok 15 no_policies "$SERVER"; ckeq "no IPsec policy or SA for the server" "$(policies "$SERVER")/$(sas "$SERVER")" "0/0"; }
    until_ok 10 test "$(charons)" = 0
    ckeq "charon stopped" "$(charons)" "0"
  fi
  if [[ $INSTALLED == 1 && -z "${KEEP_DEV:-}" ]]; then
    if [[ -x "$BUNDLE_CLI" ]]; then
      "$BUNDLE_CLI" daemon install --allow-downgrade 2>&1 | sed 's/^/    /'
      ck "the app's daemon is back ($BASE_VER)" "$(rr version 2>/dev/null | awk '/^riftrouted /')" "$BASE_VER"
    else
      note "no app bundle at $BUNDLE_CLI: this build stays installed; reinstall your release's daemon"
    fi
  fi
  if [[ -n "${DLOG_LINES:-}" && -r "$DLOG" ]]; then
    NEW=$(tail -n +"$((DLOG_LINES + 1))" "$DLOG")
    if echo "$NEW" | grep -qiE "panic:|fatal"; then fail "a panic or fatal error in the daemon's log"; else pass "no panic or fatal error in the daemon's log"; fi
    echo "-- the daemon's L2TP and IPsec lines during the test"
    echo "$NEW" | grep -iE "l2tp|ipsec|charon" | grep -viE "secret|password|psk" | tail -40 | sed 's/^/    /'
  fi
  echo
  echo "==== RESULT: $PASS passed, $FAIL failed ===="
  echo "(report: $REPORT)"
  exit $FAIL
}
trap finish EXIT
trap 'echo "  interrupted"; exit 130' INT TERM

echo "==== live L2TP/IPsec test (reversible; the trap cleans up) ===="
echo "  if anything looks wrong, press Ctrl-C: the tunnel goes and the app's daemon comes back"
echo "  if this is killed hard: sudo ./bin/riftroute tunnel rm $NAME, then"
echo "  sudo $BUNDLE_CLI daemon install --allow-downgrade"

echo "-- 0. preflight and the baseline"
BASE_VER=$(rr version 2>/dev/null | awk '/^riftrouted /{print $2}')
echo "  installed daemon: ${BASE_VER:-none}"
daemon_ok || { fail "the installed daemon isn't answering"; exit 1; }
rr --json tunnel list 2>/dev/null | jq -r '.[].name' | grep -qx "$NAME" && { fail "a tunnel named $NAME already exists"; exit 1; }
read -r PHYSGW PHYSIF < <(netstat -rn -f inet | awk '$1 == "default" && $2 ~ /^[0-9]+\./ {print $2, $4; exit}')
B_TARGET=$(via "$TARGET")
echo "  physical: ${PHYSIF:-none} via ${PHYSGW:-none} | $TARGET goes by ${B_TARGET:-none} | charon running: $(charons)"
[[ -n "$PHYSIF" ]] || { fail "no physical default route"; exit 1; }
DLOG_LINES=$(wc -l < "$DLOG" 2>/dev/null | tr -d ' ')

echo "-- 1. install this build ($HEAD) as the system daemon, with its charon"
INSTALLED=1
./bin/riftroute daemon install 2>&1 | sed 's/^/    /'
until_ok 30 daemon_ok
ck "the daemon is this build" "$(rr version 2>/dev/null | awk '/^riftrouted /')" "$HEAD"
[[ -x "$CHARON" && "$(stat -f %Su "$CHARON")" == root ]] && pass "charon installed, root-owned ($CHARON)" || { fail "no root-owned $CHARON"; exit 1; }
: > "$TMPD/empty.conf"
ck "charon runs here" "$(env -i PATH=/usr/bin:/bin OPENSSL_CONF=/dev/null STRONGSWAN_CONF="$TMPD/empty.conf" "$CHARON" --version 2>&1)" "strongSwan 6."
sleep 2

echo "-- 2. add the tunnel and connect"
ADDED=1
args=(tunnel add "$NAME" "$CONF" --route "$TARGET/32")
[[ -n "$L2TP_USER" ]] && args+=(--username "$L2TP_USER")
if [[ -n "$L2TP_PASS" ]]; then
  printf '%s\n' "$L2TP_PASS" | rr "${args[@]}" --password-stdin 2>&1 | sed 's/^/    /'
else
  rr "${args[@]}" 2>&1 | sed 's/^/    /'
fi
L2TP_PASS=""
rr tunnel up "$NAME" --no-wait 2>&1 | sed 's/^/    /'
for _ in $(seq 1 60); do up_now && break; failed_now && break; sleep 1; done
st=$(tj .state)
ckeq "connected" "$st" "connected"
if [[ "$st" != connected ]]; then
  echo "  why: $(tj '.last_error // ""')"
  rr tunnel log "$NAME" 2>&1 | grep -viE "secret|password|psk" | tail -25 | sed 's/^/    /'
  exit 1
fi
T=$(tj .iface)
SERVER=$(tj '.server // ""' | sed -E 's/:[0-9]+$//')
echo "  interface: ${T:-none} | server: ${SERVER:-none} | address: $(tj '.local_ip // ""')"
[[ "$T" == utun* ]] && pass "on its own utun ($T)" || fail "interface: $T"

echo "-- 3. the address goes into it, and nothing leaves unencrypted"
ckeq "$TARGET goes into the tunnel" "$(via "$TARGET")" "$T"
ck "route explain agrees" "$(rr route explain "$TARGET" 2>&1)" "via tunnel $NAME"
if until_ok 5 ping -c 1 -t 2 "$TARGET" >/dev/null 2>&1; then pass "$TARGET answers through it"; else note "$TARGET doesn't answer ping (it may not): the wire checks still tell"; fi
ckeq "charon running (one)" "$(charons)" "1"
np=$(policies "$SERVER")
[[ "$np" -gt 0 ]] && pass "the kernel holds IPsec policies for the server ($np lines)" || fail "no IPsec policy names $SERVER"
n=$(seen "udp port 1701 and host $SERVER" 4)
ckeq "no L2TP on the wire unencrypted (UDP 1701 to $SERVER)" "$n" "0"
n=$(seen "udp port 4500 and host $SERVER" 4)
[[ "$n" -gt 0 ]] && pass "ESP in UDP 4500 to the server ($n packets)" || fail "no ESP in UDP 4500 seen"

echo "-- 4. disconnect: IPsec goes with it"
rr tunnel down "$NAME" 2>&1 | sed 's/^/    /'
until_ok 15 no_policies "$SERVER"
ckeq "no IPsec policy or SA for the server" "$(policies "$SERVER")/$(sas "$SERVER")" "0/0"
until_ok 10 test "$(charons)" = 0
ckeq "charon stopped with the last tunnel" "$(charons)" "0"
ckeq "$TARGET takes its usual path again" "$(via "$TARGET")" "$B_TARGET"

echo "-- 5. the daemon killed while it's connected"
rr tunnel up "$NAME" --no-wait 2>&1 | sed 's/^/    /'
until_ok 60 up_now
ckeq "connected again" "$(tj .state)" "connected"
OLD=$(pgrep -f "^$CHARON( |$)" | head -1)
kill -9 "$(launchctl print "$LABEL" 2>/dev/null | awk '/pid =/{print $3; exit}')" 2>/dev/null
until_ok 30 daemon_ok
pass "launchd started the daemon again"
until_ok 15 test -z "$(pgrep -f "^$CHARON( |$)" | grep -x "${OLD:-none}")"
[[ -z "$(pgrep -f "^$CHARON( |$)" | grep -x "${OLD:-none}")" ]] && pass "the new daemon stopped the charon the old one left" || fail "the old charon ($OLD) is still running"
until_ok 15 no_policies "$SERVER"
ckeq "its policies and SAs went with it" "$(policies "$SERVER")/$(sas "$SERVER")" "0/0"
ckeq "the tunnel isn't brought back (it wasn't set to)" "$(tj .state)" "disconnected"

finish
