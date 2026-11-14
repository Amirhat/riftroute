#!/bin/bash
# Real Linux check of RiftRoute's L2TP engine (internal/l2tp) and its IPsec
# (internal/ipsec), in Docker: an xl2tpd + pppd server with strongSwan in
# transport mode (the usual Linux L2TP/IPsec server), and the engine as its
# client over a Linux TUN, with each login the server can ask for, and IPsec
# by a pre-shared key (IKEv1) or certificates (IKEv1, IKEv2) through the
# distribution's charon-systemd.
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
  sh -c 'for m in ppp_generic ppp_async ppp_synctty l2tp_ppp xfrm_user xfrm_algo esp4; do modprobe $m || true; done' >/dev/null 2>&1 || true

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
# plain_l2tp_seen: L2TP that crossed the wire unencrypted while pinging.
plain_l2tp_seen() {
  sx sh -c 'rm -f /tmp/plain.txt; (timeout 6 tcpdump -ni eth0 -l "udp port 1701" > /tmp/plain.txt 2>/dev/null &) ; sleep 0.5'
  cx ping -c 4 -i 0.5 -W 2 -I l2tp0 10.88.0.1 >/dev/null 2>&1 || true
  sleep 6
  sx grep . /tmp/plain.txt >>"$WORK/plain.txt" || true
  sx sh -c 'grep -c . /tmp/plain.txt || true'  # tcpdump ends with an empty line
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
  if [ "$name" = MS-CHAPv2 ]; then # the IPsec checks below can see unencrypted L2TP
    n=$(plain_l2tp_seen); : >"$WORK/plain.txt"
    [ "$n" -gt 0 ] && pass "without IPsec, L2TP is seen on the wire ($n packets)" || fail "the capture saw nothing without IPsec"
  fi
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

echo "== IPsec: the server's strongSwan"
sx sh -c 'exec 2>/dev/null; cd /etc/swanctl && pki --gen --type ecdsa --size 256 --outform pem > private/ca.key \
  && pki --self --ca --lifetime 30 --in private/ca.key --dn "CN=rr test ca" --outform pem > x509ca/ca.pem \
  && pki --gen --type rsa --size 2048 --outform pem > private/server.key \
  && pki --pub --in private/server.key | pki --issue --lifetime 30 --cacert x509ca/ca.pem --cakey private/ca.key \
       --dn "CN=10.88.9.20" --san 10.88.9.20 --outform pem > x509/server.pem \
  && pki --gen --type rsa --size 2048 --outform pem > /tmp/alice.key \
  && pki --pub --in /tmp/alice.key | pki --issue --lifetime 30 --cacert x509ca/ca.pem --cakey private/ca.key \
       --dn "CN=alice" --san alice --outform pem > /tmp/alice.pem'
for f in alice.key alice.pem; do docker cp "rr-l2tp-server:/tmp/$f" "$WORK/$f"; docker cp "$WORK/$f" "rr-l2tp-client:/tmp/$f"; done
docker cp rr-l2tp-server:/etc/swanctl/x509ca/ca.pem "$WORK/ca.pem"; docker cp "$WORK/ca.pem" rr-l2tp-client:/tmp/ca.pem
sx sh -c '/usr/sbin/charon-systemd >/var/log/charon.log 2>&1 &'
for _ in $(seq 1 30); do sx swanctl --stats >/dev/null 2>&1 && break; sleep 0.5; done
# ipsec_conf <version> <psk|cert>: the server's one connection.
ipsec_conf() {
  local auth=$2 local_auth remote_auth secrets
  if [ "$auth" = psk ]; then
    local_auth='auth = psk
      id = 10.88.9.20'
    remote_auth='auth = psk'
    secrets='ike-psk { secret = "rr-l2tp-psk" }'
  else
    local_auth='auth = pubkey
      certs = server.pem
      id = 10.88.9.20'
    remote_auth='auth = pubkey
      cacerts = ca.pem'
    secrets='rsa-srv { file = server.key }'
  fi
  docker exec -i rr-l2tp-server sh -c 'cat > /etc/swanctl/conf.d/rr.conf' <<CONF
connections {
  l2tp {
    version = $1
    proposals = aes256-sha256-modp2048,aes128-sha1-modp2048,3des-sha1-modp1024
    local { $local_auth }
    remote { $remote_auth }
    children {
      l2tp {
        mode = transport
        local_ts = dynamic[17/1701]
        remote_ts = dynamic[17]
        esp_proposals = aes256-sha1,aes128-sha1,3des-sha1
      }
    }
  }
}
secrets { $secrets }
CONF
  sx swanctl --load-all --clear >/dev/null 2>&1
}
server require-mschap-v2 refuse-pap refuse-chap refuse-mschap
for scenario in "1 psk" "1 cert" "2 cert"; do
  set -- $scenario
  echo "== IPsec: IKEv$1, $2"
  ipsec_conf "$1" "$2"
  if [ "$2" = psk ]; then creds="-psk rr-l2tp-psk"; else creds="-cert /tmp/alice.pem -key /tmp/alice.key -ca /tmp/ca.pem"; fi
  out=$(probe -user alice -pass s3cret -ikev "$1" $creds)
  if [[ "$out" == *"IPSEC up"* && "$out" == *$'\n'UP* ]]; then pass "up through IPsec: $(grep ^UP <<<"$out")"; else fail "not up: $out"; sx tail -15 /var/log/charon.log || true; continue; fi
  sas=$(sx swanctl --list-sas 2>/dev/null)
  [[ "$sas" == *TRANSPORT* && "$sas" == *"INSTALLED"* ]] && pass "the server's SA is in transport mode" || fail "server SAs: $sas"
  if cx ping -c 3 -W 2 -I l2tp0 10.88.0.1 >/dev/null 2>&1; then pass "ping through it"; else fail "no ping through it"; fi
  n=$(plain_l2tp_seen)
  [ "$n" = 0 ] && pass "no L2TP crossed the wire unencrypted" || fail "$n plain L2TP packets on the wire"
  if [ "$2" = psk ]; then
    sx swanctl --terminate --ike l2tp >/dev/null 2>&1 || true
    n=$(plain_l2tp_seen)
    [ "$n" = 0 ] && pass "the SA cut by the server: still nothing in the clear (trap)" || fail "$n plain L2TP packets after the SA was cut"
    ok=0; for _ in $(seq 1 10); do cx ping -c 1 -W 2 -I l2tp0 10.88.0.1 >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
    [ "$ok" = 1 ] && pass "and it came back by itself" || fail "it didn't come back after the SA was cut"
  fi
  stop_probe
  left=x; for _ in $(seq 1 20); do left=$(cx sh -c 'ip xfrm policy; ip xfrm state' 2>/dev/null); [ -z "$left" ] && break; sleep 0.5; done
  [ -z "$left" ] && pass "no IPsec policies or SAs left on the client" || fail "left on the client: $left"
done

echo "== IPsec: a wrong pre-shared key"
ipsec_conf 1 psk
out=$(probe -user alice -pass s3cret -psk not-the-key)
[[ "$out" == *"FAIL IPsec: the server rejected the shared secret"* ]] && pass "rejected: ${out##*FAIL }" || fail "wrong PSK: $out"
stop_probe

[ -s "$WORK/plain.txt" ] && { echo "-- unencrypted L2TP seen:"; cat "$WORK/plain.txt"; }
if [ "$FAILED" = 0 ]; then echo "ALL PASSED"; else echo "SOME FAILED"; exit 1; fi
