#!/bin/bash
# Real Linux check of RiftRoute's L2TP engine (internal/l2tp), in Docker:
# an xl2tpd + pppd server (the usual Linux L2TP server) and the engine as
# its client, over a Linux TUN, with each login the server can ask for.
# No IPsec yet (docs/tunnels-l2tp.md, step 2).
#
#   rr-l2tp-client (10.88.9.10) ---- rr-l2tp-server (10.88.9.20)
#                  PPP: 10.88.0.1x <-> 10.88.0.1
#
# It loads the ppp and l2tp kernel modules in Docker's VM (or the CI
# runner's kernel). KEEP=1 leaves the containers up.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
IMG=riftroute-l2tp-e2e
WORK=$(mktemp -d)
FAILED=0
pass() { printf '  PASS %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILED=1; }
cx() { docker exec rr-l2tp-client "$@"; }
sx() { docker exec rr-l2tp-server "$@"; }
cleanup() {
  docker rm -f rr-l2tp-client rr-l2tp-server >/dev/null 2>&1 || true
  docker network rm rr-l2tp-net >/dev/null 2>&1 || true
}
cleanup
trap 'rm -rf "$WORK"' EXIT
[ "${KEEP:-}" = 1 ] || trap 'cleanup; rm -rf "$WORK"' EXIT

echo "== kernel modules (ppp, l2tp)"
docker run --rm --privileged --pid=host alpine nsenter -t 1 -m -- \
  sh -c 'for m in ppp_generic ppp_async ppp_synctty l2tp_ppp; do modprobe $m || true; done' >/dev/null 2>&1 || true

arch=$(docker version -f '{{.Server.Arch}}')
echo "== build (linux/$arch)"
(cd "$ROOT" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$WORK/probe" ./test/l2tp-linux/probe)
docker build -t "$IMG" "$HERE" >"$WORK/build.log" 2>&1 || { tail -30 "$WORK/build.log"; exit 1; }

docker network create --subnet 10.88.9.0/24 rr-l2tp-net >/dev/null
docker run -d --name rr-l2tp-server --network rr-l2tp-net --ip 10.88.9.20 --privileged "$IMG" sleep infinity >/dev/null
docker run -d --name rr-l2tp-client --network rr-l2tp-net --ip 10.88.9.10 --privileged "$IMG" sleep infinity >/dev/null
docker cp "$WORK/probe" rr-l2tp-client:/probe
for c in rr-l2tp-server rr-l2tp-client; do docker exec $c sh -c '[ -e /dev/ppp ] || mknod /dev/ppp c 108 0'; done

# server <login options…>: (re)starts xl2tpd with these pppd options.
server() {
  sx pkill xl2tpd 2>/dev/null || true
  sx pkill pppd 2>/dev/null || true
  sleep 1
  printf '%s\n' "$@" ms-dns 10.88.0.53 ms-dns 10.88.0.54 auth mtu 1400 mru 1400 \
    lcp-echo-interval 5 lcp-echo-failure 4 nodefaultroute noccp nodeflate nobsdcomp \
    debug logfile /var/log/ppp.log | docker exec -i rr-l2tp-server sh -c 'cat > /etc/ppp/options.xl2tpd'
  sx sh -c 'rm -f /var/run/xl2tpd/l2tp-control; xl2tpd -D >/var/log/xl2tpd.log 2>&1 &'
  sleep 1
}
# probe <args…>: starts the client; waits for UP or FAIL; prints its log.
probe() {
  cx sh -c 'pkill -TERM -f /probe; sleep 0.5; rm -f /tmp/probe.log'
  docker exec -d rr-l2tp-client sh -c "/probe -server 10.88.9.20 $* >/tmp/probe.log 2>&1"
  for _ in $(seq 1 40); do
    if cx grep -qE '^(UP|FAIL)' /tmp/probe.log 2>/dev/null; then break; fi
    sleep 0.5
  done
  cx cat /tmp/probe.log 2>/dev/null || true
}
stop_probe() {
  cx sh -c 'pkill -TERM -f /probe' || true
  for _ in $(seq 1 20); do cx grep -q '^COUNTERS' /tmp/probe.log 2>/dev/null && break; sleep 0.25; done
}
server_ppp_gone() { for _ in $(seq 1 20); do sx ip link show ppp0 >/dev/null 2>&1 || return 0; sleep 0.5; done; return 1; }

# Each login the server may ask for.
for login in "require-mschap-v2 refuse-pap refuse-chap refuse-mschap:MS-CHAPv2" "require-chap refuse-pap refuse-mschap refuse-mschap-v2:CHAP-MD5"; do
  opts=${login%%:*}; name=${login##*:}
  echo "== $name"
  # shellcheck disable=SC2086
  server $opts
  out=$(probe -user alice -pass s3cret)
  if [[ "$out" == UP* ]]; then pass "up: ${out%%$'\n'*}"; else fail "not up: $out"; sx tail -20 /var/log/ppp.log || true; continue; fi
  [[ "$out" == *"dns=[10.88.0.53 10.88.0.54]"* ]] && pass "the server's DNS servers" || fail "dns: $out"
  local_ip=$(sed -n 's/^UP local=\([0-9.]*\).*/\1/p' <<<"$out")
  if cx ping -c 3 -W 2 -I l2tp0 10.88.0.1 >/dev/null 2>&1; then pass "ping through it (10.88.0.1)"; else fail "no ping through it"; fi
  if sx ip -4 addr show ppp0 2>/dev/null | grep -q "peer $local_ip"; then pass "the server's ppp0 has the client's $local_ip"; else fail "server ppp0: $(sx ip -4 addr show ppp0 2>&1)"; fi
  if sx ping -c 2 -W 2 "$local_ip" >/dev/null 2>&1; then pass "the server reaches the client ($local_ip)"; else fail "the server can't reach $local_ip"; fi
  big=$(cx ping -c 1 -W 2 -s 1300 -I l2tp0 10.88.0.1 2>&1 | grep -c ' 0% packet loss' || true)
  [ "$big" = 1 ] && pass "a 1328-byte packet" || fail "a large packet didn't get through"
  stop_probe
  log=$(cx cat /tmp/probe.log)
  [[ "$log" == *CLOSED* ]] && pass "closed" || fail "close: $log"
  [[ "$(sed -n 's/^COUNTERS rx=\([0-9]*\).*/\1/p' <<<"$log")" -gt 0 ]] && pass "counted: $(grep COUNTERS <<<"$log")" || fail "counters: $log"
  if server_ppp_gone; then pass "the server's ppp0 is gone (it was told)"; else fail "the server's session stayed"; fi
done

echo "== a wrong password"
server require-mschap-v2 refuse-pap refuse-chap refuse-mschap
out=$(probe -user alice -pass wrong)
[[ "$out" == *"FAIL the server rejected the username or password"* ]] && pass "rejected: ${out%%$'\n'*}" || fail "wrong password: $out"

echo "== PAP"
server require-pap refuse-chap refuse-mschap refuse-mschap-v2
out=$(probe -user alice -pass s3cret)
[[ "$out" == *"sends the password unencrypted"* ]] && pass "refused without IPsec: ${out%%$'\n'*}" || fail "PAP in the clear: $out"
stop_probe
out=$(probe -user alice -pass s3cret -encrypted)
[[ "$out" == UP* ]] && pass "accepted under IPsec: ${out%%$'\n'*}" || fail "PAP: $out"
stop_probe

echo "== the server goes away"
server require-mschap-v2 refuse-pap refuse-chap refuse-mschap
out=$(probe -user alice -pass s3cret)
[[ "$out" == UP* ]] || fail "not up: $out"
sx pkill -TERM xl2tpd || true
for _ in $(seq 1 40); do cx grep -q '^ENDED' /tmp/probe.log && break; sleep 0.5; done
log=$(cx cat /tmp/probe.log)
[[ "$log" == *ENDED* ]] && pass "noticed: $(grep ENDED <<<"$log")" || fail "didn't notice: $log"

if [ "$FAILED" = 0 ]; then echo "ALL PASSED"; else echo "SOME FAILED"; exit 1; fi
