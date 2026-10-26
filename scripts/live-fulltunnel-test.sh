#!/bin/bash
# Live macOS full-tunnel test: a real WireGuard tunnel carrying all traffic,
# beside your main VPN and your profiles. It needs root (a real utun, real
# routes, the system's DNS), so it's yours to run:
#
#   make build
#   sudo bash scripts/live-fulltunnel-test.sh ~/wg.conf
#
# It proves on this Mac that:
#   1. the tunnel takes everything: the four /2 quarters go into its
#      interface, and the exit address is the tunnel's;
#   2. what's routed elsewhere on purpose keeps its path: exclude profiles,
#      the LAN, the main VPN's network and DNS server, the tunnel's server
#      (direct), 1.1.1.1 (the watchdog's anchor), link-local, multicast,
#      broadcast;
#   3. IPv6 the tunnel can't carry is refused, while IPv6 link-local and
#      multicast (AirDrop, Bonjour) keep their scoped routes;
#   4. DNS goes to the tunnel's server, through it, and no query leaves by
#      another interface; the swap holds when the service's owner rewrites it;
#   5. after a disconnect, a daemon crash (kill -9) and a block-when-down
#      outage, routes and DNS are as they were.
#
# It installs this build as the system daemon for the test. The EXIT trap
# always removes the test tunnel, and reinstalls the app's daemon (KEEP_DEV=1
# keeps this build). Two optional steps ask you to do something (AirDrop;
# the main VPN off and on): Enter when done, s to skip. Nothing prints the
# configuration's keys. The report is also written to /tmp/rr-fulltunnel-test.log.
set -u
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo bash $0 <wireguard.conf>"; exit 1; }
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] || { echo "run via sudo from your normal account (SUDO_USER is needed)"; exit 1; }
cd "$(dirname "$0")/.." || exit 1
CONF=${1:-}
[[ -n "$CONF" && -r "$CONF" ]] || { echo "usage: sudo bash $0 <wireguard.conf>"; exit 1; }
for t in jq tcpdump dig dscacheutil scutil dns-sd curl launchctl; do
  command -v "$t" >/dev/null || { echo "missing $t"; exit 1; }
done
[[ -x ./bin/riftroute && -x ./bin/riftrouted ]] || { echo "build first: make build"; exit 1; }
HEAD=$(sudo -u "$SUDO_USER" git rev-parse --short=7 HEAD 2>/dev/null)
[[ -n "$HEAD" && "$(./bin/riftroute version 2>/dev/null | awk '/^riftroute /')" == *"$HEAD"* ]] ||
  { echo "./bin isn't this checkout's HEAD (${HEAD:-?}): run make build"; exit 1; }

NAME=rr-fulltest
LABEL=system/com.riftroute.daemon
BUNDLE_CLI=${BUNDLE_CLI:-/Applications/RiftRoute.app/Contents/Resources/bin/riftroute}
DLOG=/var/log/riftroute/riftrouted.err.log # slog writes to stderr
REPORT=/tmp/rr-fulltunnel-test.log
TMPD=$(mktemp -d /tmp/rr-fulltest.XXXXXX) && chmod 700 "$TMPD" || exit 1
: > "$REPORT" && chown "$SUDO_USER" "$REPORT" && chmod 600 "$REPORT"
exec > >(tee -a "$REPORT") 2>&1

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
ck()   { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 -> got [${2:0:200}] want [$3]"; fi; }
ckeq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 -> got [${2:0:200}] want [$3]"; fi; }
ckne() { if [[ "$2" != "$3" ]]; then pass "$1"; else fail "$1 -> [$3] unexpectedly"; fi; }
note() { echo "  NOTE: $*"; }
rr()   { ./bin/riftroute --socket /var/run/riftroute.sock "$@"; }
# until_ok N cmd…: runs cmd once a second until it succeeds, N times at most.
until_ok() { local n=$1 i; shift; for ((i = 0; i < n; i++)); do "$@" && return 0; sleep 1; done; return 1; }
# ask: an optional step for you; false when skipped, timed out or not on a terminal.
ask() { [[ -t 0 ]] || return 1; local a; read -r -t 300 -p "  >> $1 [Enter: done, s: skip] " a || return 1; [[ "$a" != s* ]]; }

# Where the kernel sends an address: its interface, gateway, flags.
via()  { route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'; }
gwof() { route -n get "$1" 2>/dev/null | awk '/gateway:/{print $2}'; }
flg()  { route -n get "$1" 2>/dev/null | awk '/flags:/{print $2}'; }
via6() { route -n get -inet6 "$1" 2>/dev/null | awk '/interface:/{i=$2} /flags:/{f=$2} END{print (i == "" ? "none" : i " " f)}'; }
defif() { route -n get default 2>/dev/null | awk '/interface:/{print $2}'; }
# The system's DNS: the first resolver, the primary service and its servers,
# and RiftRoute's keys in the dynamic store (a backup and the applied record).
ns1() { scutil --dns 2>/dev/null | awk '/^resolver #1$/{f=1; next} f && /nameserver\[0\]/{print $3; exit} f && /^resolver #/{exit}'; }
primary() { echo "show State:/Network/Global/IPv4" | scutil 2>/dev/null | awk '$1 == "PrimaryService" {print $3}'; }
servers_of() { echo "show $1" | scutil 2>/dev/null | awk '/ServerAddresses : <array>/{f=1; next} f && /}/{exit} f {print $3}' | paste -sd, -; }
svcdns() { servers_of "State:/Network/Service/$1/DNS"; }
rrkeys() { echo "list State:/Network/RiftRoute/.*" | scutil 2>/dev/null | grep -c "subKey"; }
resolves() { dscacheutil -q host -a name "$1" 2>/dev/null | awk '/^ip_address/{print $2; exit}'; }
exitip() { curl -s -m 8 "$1" 2>/dev/null | awk -F= '$1 == "ip" {print $2}'; }
reach() { curl -s -o /dev/null -m 6 "$1" && echo ok || echo blocked; }
dns_is()  { [[ "$(ns1)" == "$1" ]]; }
no_keys() { [[ "$(rrkeys)" == 0 ]]; }
up_now()  { [[ "$(tj .state)" == connected ]]; }
daemon_ok() { rr status >/dev/null 2>&1; }
# tj <jq>: a field of the test tunnel's status.
tj() { rr --json tunnel list 2>/dev/null | jq -r --arg n "$NAME" ".[] | select(.name == \$n) | $1" 2>/dev/null; }
# probe_of 95.38.170/24 → 95.38.170.1: an address inside a route netstat prints.
probe_of() {
  local IFS=.
  set -- ${1%/*}
  case $# in 1) echo "$1.0.0.1" ;; 2) echo "$1.$2.0.1" ;; 3) echo "$1.$2.$3.1" ;; *) echo "$1.$2.$3.$(($4 + 1))" ;; esac
}

# Addresses in each quarter (a Google, Verisign and Quad9 resolver, TEST-NET-1)
# and in each IPv6 quarter (none of it reachable here without a v6 tunnel).
Q4="8.8.4.4 64.6.64.6 149.112.112.112 192.0.2.1"
Q6="2001:db8::1 4000::1 8000::1 c000::1"
LINK6="fe80::1%awdl0 ff02::fb%awdl0 fe80::1%lo0 ff02::1%lo0"

BGPIDS=""
ADDED=0; INSTALLED=0; DONE=0
finish() {
  [[ $DONE == 1 ]] && return
  DONE=1
  set +u
  for p in $BGPIDS; do kill "$p" 2>/dev/null; done
  rm -rf "$TMPD"
  echo "-- cleanup: the test tunnel goes, and the app's daemon comes back"
  if [[ $ADDED == 1 ]]; then
    rr tunnel rm "$NAME" 2>&1 | sed 's/^/    /'
    until_ok 10 no_keys
    if ! no_keys; then
      note "RiftRoute's DNS keys are still there: restarting this build, whose start-up puts them back"
      launchctl kickstart -k "$LABEL" >/dev/null 2>&1
      until_ok 30 daemon_ok; until_ok 15 no_keys
    fi
    ckeq "no RiftRoute keys left in the dynamic store" "$(rrkeys)" "0"
    ckeq "the first resolver is the one from before" "$(ns1)" "$BASE_NS"
    [[ -n "$PSVC" && "$(primary)" == "$PSVC" ]] && ckeq "the primary service's DNS is as before" "$(svcdns "$PSVC")" "$BASE_SERVERS"
    ckeq "nothing goes into a tunnel any more (8.8.4.4)" "$(via 8.8.4.4)" "$MAINIF"
    ckeq "IPv6 is as before" "$(via6 2001:db8::1)" "$B6"
  fi
  if [[ $INSTALLED == 1 && -z "${KEEP_DEV:-}" ]]; then
    if ! no_keys; then
      fail "not reinstalling the app's daemon: it can't put the DNS back. Run: sudo ./bin/riftroute daemon install, then sudo ./bin/riftroute panic"
    elif [[ -x "$BUNDLE_CLI" ]]; then
      "$BUNDLE_CLI" daemon install --allow-downgrade 2>&1 | sed 's/^/    /'
      ck "the app's daemon is back ($BASE_VER)" "$(rr version 2>/dev/null | awk '/^riftrouted /')" "$BASE_VER"
    else
      note "no app bundle at $BUNDLE_CLI: this build stays installed; reinstall your release's daemon"
    fi
  fi
  if [[ -n "${DLOG_LINES:-}" && -r "$DLOG" ]]; then
    NEW=$(tail -n +"$((DLOG_LINES + 1))" "$DLOG")
    if echo "$NEW" | grep -qiE "panic:|fatal"; then fail "a panic or fatal error in the daemon's log"; else pass "no panic or fatal error in the daemon's log"; fi
    echo "-- the daemon's DNS lines during the test"
    echo "$NEW" | grep -iE "dns|resolv" | tail -40 | sed 's/^/    /'
  fi
  echo
  echo "==== RESULT: $PASS passed, $FAIL failed ===="
  echo "(report: $REPORT)"
  exit $FAIL
}
trap finish EXIT
trap 'echo "  interrupted"; exit 130' INT TERM

echo "==== live full-tunnel test (reversible; the trap cleans up) ===="
echo "  if this is killed hard: sudo ./bin/riftroute tunnel rm $NAME, then"
echo "  sudo $BUNDLE_CLI daemon install --allow-downgrade"

echo "-- 0. preflight and the baseline"
BASE_VER=$(rr version 2>/dev/null | awk '/^riftrouted /{print $2}')
echo "  installed daemon: ${BASE_VER:-none}"
daemon_ok || { fail "the installed daemon isn't answering"; exit 1; }
rr --json tunnel list 2>/dev/null | jq -r '.[].name' | grep -qx "$NAME" && { fail "a tunnel named $NAME already exists"; exit 1; }
[[ "$(rr killswitch status 2>&1)" == *off* ]] || note "the kill switch is on: the checks still hold, but block-when-down overlaps it"
read -r PHYSGW PHYSIF < <(netstat -rn -f inet | awk '$1 == "default" && $2 ~ /^[0-9]+\./ {print $2, $4; exit}')
MAINIF=$(via 8.8.4.4)
PSVC=$(primary)
BASE_NS=$(ns1)
BASE_SERVERS=$(svcdns "$PSVC")
BASE_EXIT=$(exitip https://www.cloudflare.com/cdn-cgi/trace)
BASE_EXIT1=$(exitip https://1.1.1.1/cdn-cgi/trace)
BASE_REACH=$(reach https://1.0.0.1)
EXNET=$(netstat -rn -f inet | awk -v gw="$PHYSGW" '$2 == gw && $1 != "default" && $3 ~ /S/ && $3 !~ /[HW]/ {print $1; exit}')
EXPROBE=""; [[ -n "$EXNET" ]] && EXPROBE=$(probe_of "$EXNET")
CLONE=$(netstat -rn -f inet | awk -v i="$MAINIF" '$4 == i && $3 ~ /W/ && $3 ~ /H/ && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $1 != "1.1.1.1" {print $1; exit}')
B6=$(via6 2001:db8::1)
SERVER=$(awk -F= 'tolower($1) ~ /^[[:space:]]*endpoint[[:space:]]*$/ {print $2; exit}' "$CONF" | tr -d ' ' | sed -E 's#^\[##; s#\]?:[0-9]+$##')
B_SRV=$(gwof "$SERVER")
BASE_KEEP=""
for a in "$PHYSGW" "$EXPROBE" "$BASE_NS" 169.254.1.1 224.0.0.251 255.255.255.255; do
  [[ -n "$a" ]] && BASE_KEEP="$BASE_KEEP $a=$(via "$a")"
done
BASE_LINK6="" # one "address=route" a line: a route holds a space
for a in $LINK6; do BASE_LINK6="$BASE_LINK6$a=$(via6 "$a")"$'\n'; done
browse() { dns-sd -B _services._dns-sd._udp local. > "$TMPD/browse" 2>&1 & local p=$!; sleep 4; kill $p 2>/dev/null; wait $p 2>/dev/null; grep -c " Add " "$TMPD/browse"; }
BASE_BROWSE=$(browse)
DLOG_LINES=$(wc -l < "$DLOG" 2>/dev/null | tr -d ' ')
echo "  physical: $PHYSIF via $PHYSGW | everything else: $MAINIF | primary service: ${PSVC:-none}"
echo "  first resolver: ${BASE_NS:-none} | the primary service's DNS: ${BASE_SERVERS:-none}"
echo "  exit address: ${BASE_EXIT:-none} (1.1.1.1: ${BASE_EXIT1:-none}) | https://1.0.0.1: $BASE_REACH"
echo "  an excluded network: ${EXNET:-none} | a route cloned before: ${CLONE:-none} | Bonjour services: $BASE_BROWSE"
[[ -n "$PHYSGW" && -n "$MAINIF" && -n "$BASE_NS" ]] || { fail "couldn't read the baseline"; exit 1; }
[[ "$MAINIF" == "$PHYSIF" ]] && note "no main VPN up: what goes to the main VPN goes to $PHYSIF instead"
[[ "$(rrkeys)" == 0 ]] || { fail "RiftRoute's DNS keys are already in the dynamic store: a run that didn't end cleanly"; exit 1; }

echo "-- 1. install this build ($HEAD) as the system daemon"
INSTALLED=1
./bin/riftroute daemon install 2>&1 | sed 's/^/    /'
until_ok 30 daemon_ok
ck "the daemon is this build" "$(rr version 2>/dev/null | awk '/^riftrouted /')" "$HEAD"
[[ "$(rr version 2>/dev/null | awk '/^riftrouted /')" == *"$HEAD"* ]] || exit 1
sleep 3

echo "-- 2. add the tunnel, carrying all traffic, and connect"
ADDED=1
rr tunnel add "$NAME" "$CONF" --all-traffic --connect 2>&1 | sed 's/^/    /'
until_ok 30 up_now
ckeq "connected" "$(tj .state)" "connected"
T=$(tj .iface)
echo "  interface: ${T:-none} | server: $(tj '.server // .servers[0] // ""') (its configuration's: ${SERVER:-none})"
[[ -n "$T" ]] || { fail "no interface: nothing more to test"; rr tunnel log "$NAME" 2>&1 | tail -20 | sed 's/^/    /'; exit 1; }
rr tunnel list 2>&1 | sed 's/^/    /'
ck "tunnel list says all traffic" "$(rr tunnel list 2>&1)" "all traffic"

echo "-- 3. routes: everything into the tunnel, except what's routed elsewhere on purpose"
on_t() { [[ "$(via 8.8.4.4)" == "$T" ]]; }
until_ok 10 on_t
for a in $Q4; do ckeq "$a goes into the tunnel" "$(via "$a")" "$T"; done
ck "route explain agrees (8.8.4.4)" "$(rr route explain 8.8.4.4 2>&1)" "via tunnel $NAME"
EX=$(rr route explain 8.8.4.4 2>&1)
[[ "$EX" != *DRIFT* ]] && pass "no drift between the kernel and the plan" || fail "drift: $EX"
for pair in $BASE_KEEP; do
  a=${pair%%=*}; want=${pair#*=}
  ckeq "$a keeps its path (${want:-none})" "$(via "$a")" "$want"
done
ckeq "the tunnel's server goes direct ($SERVER via $PHYSGW)" "$(gwof "$SERVER")" "$PHYSGW"
ckeq "1.1.1.1 (the watchdog's anchor) stays on $MAINIF" "$(via 1.1.1.1)" "$MAINIF"
[[ -n "$CLONE" ]] && ckeq "$CLONE, cloned onto $MAINIF before, now goes into the tunnel" "$(via "$CLONE")" "$T"
ck "the LAN answers ($PHYSGW)" "$(ping -c 1 -t 2 "$PHYSGW" 2>&1)" "1 packets received"
E_T=$(exitip https://www.cloudflare.com/cdn-cgi/trace)
echo "  exit address now: ${E_T:-none} (before: ${BASE_EXIT:-none})"
[[ -n "$E_T" ]] && ckne "the exit address is the tunnel's" "$E_T" "$BASE_EXIT" || fail "no exit address through the tunnel"
[[ -n "$BASE_EXIT1" ]] && ckeq "1.1.1.1 still exits by $MAINIF" "$(exitip https://1.1.1.1/cdn-cgi/trace)" "$BASE_EXIT1"
for a in 8.8.4.4 1.1.1.1 "$SERVER" $EXPROBE; do
  echo "  explain $a:"; rr route explain "$a" 2>&1 | sed 's/^/    /'
done

echo "-- 4. IPv6: refused, but link-local and multicast keep their scoped routes"
if grep -qiE '^[[:space:]]*Address[[:space:]]*=.*:' "$CONF"; then
  note "the configuration has an IPv6 address: IPv6 goes through the tunnel"
  ck "2001:db8::1 goes into the tunnel" "$(via6 2001:db8::1)" "$T"
else
  for a in $Q6; do ck "$a is refused" "$(via6 "$a")" "REJECT"; done
  ck "tunnel list says IPv6 is blocked" "$(rr tunnel list 2>&1)" "IPv6"
fi
while IFS= read -r pair; do
  [[ -n "$pair" ]] || continue
  a=${pair%%=*}; want=${pair#*=}
  ckeq "$a keeps its route ($want)" "$(via6 "$a")" "$want"
done <<< "$BASE_LINK6"
NOW_BROWSE=$(browse)
if [[ "$BASE_BROWSE" -gt 0 ]]; then
  [[ "$NOW_BROWSE" -gt 0 ]] && pass "Bonjour still finds services ($NOW_BROWSE)" || fail "Bonjour finds nothing now (before: $BASE_BROWSE)"
else note "Bonjour found nothing before either"; fi
if ask "Optional: try AirDrop to a nearby device now"; then
  ask "Did AirDrop find and reach it? Enter for yes, s for no" && pass "AirDrop works (you)" || fail "AirDrop didn't work (you)"
fi

echo "-- 5. DNS: the tunnel's, through it, and nowhere else"
TDNS=$(tj '(.dns // [])[0] // ""')
CONF_DNS=$(awk -F= 'tolower($1) ~ /^[[:space:]]*dns[[:space:]]*$/ {print $2; exit}' "$CONF" | tr -d ' ' | cut -d, -f1)
ckeq "the tunnel's DNS is its configuration's" "$TDNS" "$CONF_DNS"
until_ok 10 dns_is "$TDNS"
ckeq "the system's first resolver is the tunnel's" "$(ns1)" "$TDNS"
R1=$(scutil --dns | sed -n '/^resolver #1$/,/^$/p')
ck "and macOS takes it as reachable" "$R1" "(Reachable"
ckne "not a supplemental resolver scoped to another interface" "$(echo "$R1" | grep -c Supplemental)" "1"
SVC=$(primary)
ck "the primary service ($SVC) has it" "$(svcdns "$SVC")" "$TDNS"
ckeq "a backup and the applied record are in the dynamic store" "$(rrkeys)" "2"
ckeq "$TDNS is reached through the tunnel" "$(via "$TDNS")" "$T"
ck "tunnel list says so" "$(rr tunnel list 2>&1)" "DNS goes through it, to $TDNS"
ckne "names resolve (example.com)" "$(resolves example.com)" ""
ckne "the tunnel's DNS server answers" "$(dig +short +time=3 +tries=1 @"$TDNS" example.com A 2>/dev/null | head -1)" ""
# The leak test: a name never asked before, watched on every interface.
QN="rr-$RANDOM$RANDOM.example.com"
for i in $(echo "$T $PHYSIF $MAINIF" | tr ' ' '\n' | sort -u); do
  tcpdump -l -n -i "$i" port 53 > "$TMPD/cap.$i" 2>/dev/null &
  BGPIDS="$BGPIDS $!"
done
sleep 2
dscacheutil -q host -a name "$QN" >/dev/null 2>&1
sleep 3
# (each by its pid: a bare wait would also wait for the report's tee)
for p in $BGPIDS; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
BGPIDS=""
[[ "$(grep -c "$QN" "$TMPD/cap.$T")" -ge 1 ]] && pass "the query for $QN went into the tunnel" || fail "the query for $QN wasn't seen on $T"
for i in $PHYSIF $MAINIF; do
  [[ "$i" == "$T" ]] && continue
  ckeq "no query left by $i" "$(grep -c "$QN" "$TMPD/cap.$i")" "0"
done
HELD=0
for n in 1 2 3 4 5 6 7 8 9 10; do dns_is "$TDNS" && HELD=$((HELD + 1)); sleep 2; done
ckeq "the swap held for 20 s" "$HELD/10" "10/10"
# The service's owner (DHCP, the main VPN's app) writing its DNS back: taken as
# the backup, and swapped again within the 5 s recheck.
if [[ "$(primary)" == "$SVC" && -n "$BASE_SERVERS" ]]; then
  printf 'open\nget State:/Network/Service/%s/DNS\nd.add ServerAddresses * %s\nset State:/Network/Service/%s/DNS\nclose\n' \
    "$SVC" "${BASE_SERVERS//,/ }" "$SVC" | scutil
  echo "  rewrote $SVC's servers to $BASE_SERVERS: now $(svcdns "$SVC")"
  until_ok 12 dns_is "$TDNS"
  ckeq "swapped again after the owner's rewrite" "$(ns1)" "$TDNS"
  ckeq "the owner's value is the backup now" "$(servers_of "State:/Network/RiftRoute/DNSBackup/$SVC")" "$BASE_SERVERS"
fi

if [[ "$MAINIF" != "$PHYSIF" ]] && ask "Optional: turn your main VPN OFF now, in its app"; then
  echo "-- 5b. the main VPN off, then on again"
  off_now() { [[ "$(defif)" == "$PHYSIF" ]]; }
  until_ok 20 off_now; sleep 6
  OFFSVC=$(primary)
  echo "  primary service now: ${OFFSVC:-none} | default: $(defif)"
  ckeq "the tunnel stays connected" "$(tj .state)" "connected"
  until_ok 12 dns_is "$TDNS"
  ckeq "DNS is still the tunnel's" "$(ns1)" "$TDNS"
  ckeq "1.1.1.1 moved to $PHYSIF" "$(via 1.1.1.1)" "$PHYSIF"
  [[ -n "$E_T" ]] && ckeq "the exit address is still the tunnel's" "$(exitip https://www.cloudflare.com/cdn-cgi/trace)" "$E_T"
  ck "WireGuard still sends to its server" "$(tj .server)" "$SERVER"
  OFFBACKUP=$(servers_of "State:/Network/RiftRoute/DNSBackup/$OFFSVC")
  if ask "Now turn your main VPN back ON"; then
    back_now() { [[ -n "$(defif)" && "$(defif)" != "$PHYSIF" ]]; }
    until_ok 40 back_now; sleep 6
    NEWMAIN=$(defif)
    echo "  main VPN on $NEWMAIN | primary service: $(primary)"
    until_ok 12 dns_is "$TDNS"
    ckeq "DNS is still the tunnel's" "$(ns1)" "$TDNS"
    [[ -n "$OFFSVC" && "$OFFSVC" != "$(primary)" ]] && ckeq "$OFFSVC got its DNS back" "$(svcdns "$OFFSVC")" "$OFFBACKUP"
    ckeq "1.1.1.1 is back on the main VPN" "$(via 1.1.1.1)" "$NEWMAIN"
    ck "WireGuard still sends to its server" "$(tj .server)" "$SERVER"
    if [[ "$NEWMAIN" != "$MAINIF" ]]; then
      BASE_KEEP=${BASE_KEEP//=$MAINIF/=$NEWMAIN}; MAINIF=$NEWMAIN
    fi
  else
    note "the main VPN stays off: later checks against the baseline may fail"
  fi
fi

echo "-- 6. disconnect: routes and DNS as before"
rr tunnel down "$NAME" 2>&1 | sed 's/^/    /'
until_ok 10 dns_is "$BASE_NS"
ckeq "the first resolver is the one from before" "$(ns1)" "$BASE_NS"
ckeq "no RiftRoute keys left" "$(rrkeys)" "0"
[[ "$(primary)" == "$PSVC" ]] && ckeq "the primary service's DNS is as before" "$(svcdns "$PSVC")" "$BASE_SERVERS"
for a in $Q4; do ckeq "$a takes its usual path again" "$(via "$a")" "$MAINIF"; done
ckeq "IPv6 is as before" "$(via6 2001:db8::1)" "$B6"
ckeq "the server's pin is gone" "$(gwof "$SERVER")" "$B_SRV"
ckne "names resolve" "$(resolves example.com)" ""
[[ -n "$BASE_EXIT" ]] && ckeq "the exit address is the one from before" "$(exitip https://www.cloudflare.com/cdn-cgi/trace)" "$BASE_EXIT"

echo "-- 7. a daemon crash with the swap in place: its successor puts it all back"
rr tunnel up "$NAME" 2>&1 | sed 's/^/    /'
until_ok 30 up_now; until_ok 10 dns_is "$TDNS"
ckeq "up again, with its DNS" "$(ns1)" "$TDNS"
OLDPID=$(pgrep -f /Library/PrivilegedHelperTools/riftrouted | head -1)
launchctl kill 9 "$LABEL" >/dev/null 2>&1 || kill -9 "$OLDPID"
new_daemon() { local p; p=$(pgrep -f /Library/PrivilegedHelperTools/riftrouted | head -1); [[ -n "$p" && "$p" != "$OLDPID" ]] && daemon_ok; }
until_ok 40 new_daemon
ckne "launchd started it again" "$(pgrep -f /Library/PrivilegedHelperTools/riftrouted | head -1)" "$OLDPID"
until_ok 15 dns_is "$BASE_NS"
ckeq "the first resolver is the one from before" "$(ns1)" "$BASE_NS"
ckeq "no RiftRoute keys left" "$(rrkeys)" "0"
[[ "$(primary)" == "$PSVC" ]] && ckeq "the primary service's DNS is as before" "$(svcdns "$PSVC")" "$BASE_SERVERS"
sleep 2
ckeq "8.8.4.4 takes its usual path" "$(via 8.8.4.4)" "$MAINIF"
ckeq "IPv6's reject routes are gone" "$(via6 2001:db8::1)" "$B6"
ckeq "the server's pin is gone" "$(gwof "$SERVER")" "$B_SRV"
ckeq "the tunnel isn't brought back (it wasn't set to)" "$(tj .state)" "disconnected"

echo "-- 8. block when down: a server that never answers"
sed -E 's/^([[:space:]]*Endpoint[[:space:]]*=.*):[0-9]+[[:space:]]*$/\1:9/' "$CONF" > "$TMPD/dead.conf"
chmod 600 "$TMPD/dead.conf"
rr tunnel edit "$NAME" --profile "$TMPD/dead.conf" --when-down block 2>&1 | sed 's/^/    /'
rr tunnel up "$NAME" --no-wait 2>&1 | sed 's/^/    /'
blocking() { [[ "$(tj .blocking)" == true ]]; }
until_ok 15 blocking
ckne "not connected" "$(tj .state)" "connected"
ckeq "blocking" "$(tj .blocking)" "true"
ck "8.8.4.4 is refused" "$(flg 8.8.4.4)" "REJECT"
ck "route explain says why" "$(rr route explain 8.8.4.4 2>&1)" "blocked"
[[ "$BASE_REACH" == ok ]] && ckeq "https://1.0.0.1 can't be reached" "$(reach https://1.0.0.1)" "blocked"
ck "the LAN still answers" "$(ping -c 1 -t 2 "$PHYSGW" 2>&1)" "1 packets received"
[[ -n "$EXPROBE" ]] && ckeq "the excluded network still goes direct" "$(via "$EXPROBE")" "$PHYSIF"
ckeq "1.1.1.1 still goes by $MAINIF" "$(via 1.1.1.1)" "$MAINIF"
ckeq "DNS isn't the tunnel's while it's down" "$(ns1)" "$BASE_NS"
ckne "names still resolve, so it can connect again" "$(resolves example.com)" ""
rr tunnel down "$NAME" 2>&1 | sed 's/^/    /'
sleep 2
ckeq "8.8.4.4 takes its usual path again" "$(via 8.8.4.4)" "$MAINIF"
[[ "$BASE_REACH" == ok ]] && ckeq "https://1.0.0.1 is reachable again" "$(reach https://1.0.0.1)" "ok"

finish
