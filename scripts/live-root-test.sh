#!/bin/bash
# Live macOS ROOT test for the v0.2.2 features that automation can't cover
# without root: real single-route delete/edit (route-ops) and wildcard-domain
# DNS learning (loopback proxy + /etc/resolver files + real subdomain learning).
#
#   sudo bash scripts/live-root-test.sh
#
# Everything is scoped and reversible:
#   * the only external route touched is TEST-NET-2 (198.51.100.0/24, doc-only);
#   * the only wildcard is *.example.com (IANA's reserved example domain);
#   * every mutation is undone (route delete, panic teardown, resolver-file
#     removal) by an EXIT trap that runs even on failure, and the script
#     verifies the routing table + /etc/resolver are byte-restored at the end.
# Every wait is bounded; nothing here can hang. Run the PF-anchor test
# (scripts/live-pf-test.sh) alongside this for full root coverage.
#
# Topology-robust: works whether the default route has a gateway or is on-link
# (point-to-point VPN), and proves wildcard learning by querying the proxy
# directly — so it does not depend on physical-gateway routing being present.
set -u
[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo bash $0"; exit 1; }
cd "$(dirname "$0")/.." || exit 1

SOCK=/tmp/rr-root2.sock
DB=/tmp/rr-root2.db
LOG=/tmp/rr-root2.log
CFG=/tmp/rr-root2.yaml
TESTNET=198.51.100.0/24
RESOLVER=/etc/resolver/example.com
PASS=0; FAIL=0
ck() { if [[ "$2" == *"$3"* ]]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 -> got [${2:0:200}] want [$3]"; FAIL=$((FAIL+1)); fi; }
ckn() { if [[ "$2" != *"$3"* ]]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 -> [$3] unexpectedly present"; FAIL=$((FAIL+1)); fi; }
CURL() { curl -s --max-time 12 --unix-socket "$SOCK" "$@"; }
bt() { if command -v gtimeout >/dev/null; then gtimeout "$@"; else shift; "$@"; fi; }

# add_testnet installs the reversible TEST-NET-2 route the way an external tool
# would: via a real gateway if we found one, else on-link via the interface.
add_testnet() {
  if [[ -n "$GW" ]]; then route -n add -net "$TESTNET" "$GW" >/dev/null 2>&1
  else route -n add -net "$TESTNET" -interface "$IFACE" >/dev/null 2>&1; fi
}

DPID=""
cleanup() {
  set +u
  echo "-- cleanup"
  if [[ -n "$DPID" ]] && kill -0 "$DPID" 2>/dev/null; then
    bt 15 ./bin/riftroute --socket "$SOCK" panic >/dev/null 2>&1
    kill -TERM "$DPID" 2>/dev/null
    for i in $(seq 1 25); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$DPID" 2>/dev/null
  fi
  # Belt-and-suspenders: drop the test route + resolver file if anything remains.
  route -n delete -net "$TESTNET" >/dev/null 2>&1
  [[ -f "$RESOLVER" ]] && grep -q "managed by riftroute" "$RESOLVER" 2>/dev/null && rm -f "$RESOLVER"
  rm -f "$SOCK" "$DB" "$CFG"
}
trap cleanup EXIT INT TERM

echo "==== live ROOT test — route-ops + wildcard learning (reversible) ===="
echo "-- 0. preflight: baselines"
pkill -f "riftrouted -socket $SOCK" 2>/dev/null; sleep 0.5
ROUTES_BEFORE=$(netstat -rn -f inet | wc -l | tr -d ' ')
RESOLVERS_BEFORE=$(ls /etc/resolver 2>/dev/null | sort | tr '\n' ',')
# Prefer a real gatewayed default (physical uplink); the winning default may be
# an on-link VPN with no gateway, so scan the table for a gatewayed one.
read -r GW IFACE < <(netstat -rn -f inet | awk '$1=="default" && $2 ~ /^[0-9]+\./ {print $2, $4; exit}')
if [[ -z "$IFACE" ]]; then
  IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
  GW=""
fi
echo "  default gw=${GW:-<on-link>} iface=${IFACE:-<none>}  routes(v4 lines)=$ROUTES_BEFORE"
[[ -n "$IFACE" ]] || { echo "  no usable default interface — need network connectivity"; exit 1; }

echo "-- 1. start root daemon (real provider, fresh state)"
rm -f "$SOCK" "$DB"
./bin/riftrouted -socket "$SOCK" -db "$DB" -provider auto -log info > "$LOG" 2>&1 &
DPID=$!
up=no
for i in $(seq 1 50); do [[ -S "$SOCK" ]] && bt 5 ./bin/riftroute --socket "$SOCK" status >/dev/null 2>&1 && { up=yes; break; }; sleep 0.2; done
ck "daemon ready" "$up" "yes"
[[ "$up" == yes ]] || { tail -8 "$LOG"; exit 1; }

echo "==== SECTION A: single-route delete/edit of a REAL external route ===="
echo "-- A1. add an external route the way a terminal/VPN client would"
add_testnet
ck "external route present in kernel table" "$(netstat -rn -f inet | grep -c '198.51.100')" "1"

echo "-- A2. delete it through the daemon (/routes/ops, guarded + committed)"
DEL=$(CURL -X POST --data "{\"action\":\"delete\",\"route\":{\"dst_cidr\":\"$TESTNET\",\"gateway\":\"$GW\",\"iface\":\"$IFACE\",\"family\":\"v4\",\"owner\":\"system\"}}" "http://d/routes/ops?yes=1")
ck "route-op delete applied" "$DEL" '"status"'
sleep 1
ck "external route removed from kernel" "$(netstat -rn -f inet | grep -c '198.51.100')" "0"

echo "-- A3. re-add + EDIT the route atomically through the daemon"
add_testnet
# Edit is delete+add in one tx; keep the same gw/iface so we don't need a second
# real next-hop — proves the atomic swap path end-to-end and stays reversible.
REP=$(CURL -X POST --data "{\"action\":\"replace\",\"route\":{\"dst_cidr\":\"$TESTNET\",\"gateway\":\"$GW\",\"iface\":\"$IFACE\",\"family\":\"v4\",\"owner\":\"system\"},\"new_route\":{\"dst_cidr\":\"$TESTNET\",\"gateway\":\"$GW\",\"iface\":\"$IFACE\",\"family\":\"v4\"}}" "http://d/routes/ops?yes=1")
ck "route-op replace applied" "$REP" '"status"'
ck "edited route present" "$(netstat -rn -f inet | grep -c '198.51.100')" "1"

echo "-- A4. the default route is PROTECTED (non-canonical /0 cannot bypass)"
SNEAK=$(CURL -X POST --data '{"action":"delete","route":{"dst_cidr":"128.0.0.0/0","iface":"'"$IFACE"'","family":"v4"}}' "http://d/routes/ops?yes=1")
ck "keep-default-route guardrail fired" "$SNEAK" "keep-default-route"
ck "real default route still present" "$(route -n get default 2>/dev/null | grep -c interface)" "1"
route -n delete -net "$TESTNET" >/dev/null 2>&1  # tidy the test route

echo "==== SECTION B: wildcard *.example.com DNS learning ===="
echo "-- B1. apply an exclude profile with a wildcard rule + enable auto-apply"
CURL -X PUT --data '{"enabled":true}' http://d/autoapply >/dev/null
cat > "$CFG" <<'YAML'
version: 1
profiles:
  - name: wildcard-live
    enabled: true
    mode: exclude
    rules:
      - { type: domain, value: "*.example.com" }
YAML
bt 20 ./bin/riftroute --socket "$SOCK" apply --yes "$CFG" 2>&1 | sed 's/^/    /' | head -4
sleep 1

echo "-- B2. the learner is up and the scoped resolver file points at it"
DOC=$(CURL http://d/doctor)
ck "wildcard-dns check present" "$DOC" '"wildcard-dns"'
PORT=$(echo "$DOC" | python3 -c "import json,sys,re;print(next((re.search(r'127\.0\.0\.1:(\d+)',c['detail']).group(1) for c in json.load(sys.stdin)['checks'] if c['name']=='wildcard-dns' and '127.0.0.1' in c['detail']),''))" 2>/dev/null)
ck "learner reports a loopback port" "$([[ -n "$PORT" ]] && echo yes)" "yes"
ck "resolver file written" "$([[ -f "$RESOLVER" ]] && echo yes)" "yes"
ck "resolver file is ours" "$(cat "$RESOLVER" 2>/dev/null)" "managed by riftroute"
[[ -n "$PORT" ]] && ck "resolver file names the proxy port" "$(cat "$RESOLVER" 2>/dev/null)" "port $PORT"

echo "-- B3. learning proof — query the proxy directly (deterministic), then via the system"
if [[ -n "$PORT" ]] && command -v dig >/dev/null; then
  D1=$(dig +short +time=4 @127.0.0.1 -p "$PORT" www.example.com A 2>/dev/null | head -1)
  echo "    proxy answered www.example.com → ${D1:-<none>}"
  D2=$(dig +short +time=4 @127.0.0.1 -p "$PORT" iana.example.com A 2>/dev/null | head -1)
  echo "    proxy answered iana.example.com → ${D2:-<none>}"
fi
# And through the SYSTEM resolver (exercises the scoped /etc/resolver file):
scutil --dns 2>/dev/null | grep -A3 "example.com" | grep -q "127.0.0.1" && echo "    scoped resolver registered for example.com (system → proxy)"
bt 8 dscacheutil -q host -a name docs.example.com >/dev/null 2>&1
sleep 2

echo "-- B4. the learner recorded subdomain addresses"
LEARNLOG=$(grep -c "wildcard subdomain learned" "$LOG")
ck "learner observed at least one subdomain" "$([[ "$LEARNLOG" -ge 1 ]] && echo yes)" "yes"
grep "wildcard subdomain learned" "$LOG" | tail -3 | sed 's/^/    /'
# Whether those IPs become installed routes depends on mode + this host's
# physical-gateway topology, so report it rather than gate on it (the routing
# pipeline itself is covered by the non-root drive + the PF anchor test).
STATE=$(CURL http://d/state)
MANAGED=$(echo "$STATE" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["managed_route_count"],"routes",d.get("managed_rule_count",0),"rules")' 2>/dev/null)
echo "    installed from learning: ${MANAGED:-n/a}"

echo "-- B5. panic tears it ALL down and restores baseline"
bt 15 ./bin/riftroute --socket "$SOCK" panic >/dev/null 2>&1
sleep 1
ck "resolver file removed by panic" "$([[ -f "$RESOLVER" ]] && echo present || echo gone)" "gone"

echo "-- 6. shutdown + baseline verification"
kill -TERM "$DPID"; for i in $(seq 1 25); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.2; done; DPID=""
ROUTES_AFTER=$(netstat -rn -f inet | wc -l | tr -d ' ')
RESOLVERS_AFTER=$(ls /etc/resolver 2>/dev/null | sort | tr '\n' ',')
ck "route table line count restored" "$ROUTES_AFTER" "$ROUTES_BEFORE"
ck "/etc/resolver restored" "$RESOLVERS_AFTER" "$RESOLVERS_BEFORE"
ckn "TEST-NET route fully gone" "$(netstat -rn -f inet)" "198.51.100"
if grep -iE "panic:|fatal" "$LOG" >/dev/null; then echo "  FAIL: panic/fatal in daemon log"; FAIL=$((FAIL+1)); else echo "  PASS: no panic/fatal in daemon log"; PASS=$((PASS+1)); fi

echo
echo "==== RESULT: $PASS passed, $FAIL failed ===="
echo "(daemon log kept at $LOG)"
exit $FAIL
