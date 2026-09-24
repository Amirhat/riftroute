#!/bin/bash
# Real Linux end-to-end check of RiftRoute tunnels, in Docker:
#
#   rr-client (10.77.1.10) --lan-- rr-router --wan-- rr-server (10.77.2.20)
#
# The client runs the real Linux riftrouted. Its "main VPN" is a dummy wg0
# holding 0/1 + 128/1, which swallows everything (including the path to the
# OpenVPN server) unless RiftRoute pins it. The server is an old-style
# OpenVPN: AES-256-CBC only, username/password, pushes redirect-gateway, DNS
# and a route. Behind it is 10.99.9.0/24 (a dummy interface, 10.99.9.1).
#
# Run it with `make test-tunnels-linux` (needs Docker). KEEP=1 leaves the
# containers up for poking around afterwards.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
IMG=riftroute-tunnels-e2e
WORK=$(mktemp -d)
pass() { printf '  PASS %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILED=1; }
FAILED=0
cx() { docker exec -e RIFTROUTE_SOCKET=/run/rr.sock rr-client "$@"; }
sx() { docker exec rr-server "$@"; }

cleanup() {
  docker rm -f rr-client rr-server rr-router >/dev/null 2>&1 || true
  docker network rm rr-lan rr-wan >/dev/null 2>&1 || true
}
cleanup
trap 'rm -rf "$WORK"' EXIT
[ "${KEEP:-}" = 1 ] || trap 'cleanup; rm -rf "$WORK"' EXIT

arch=$(docker version -f '{{.Server.Arch}}')
echo "== build (linux/$arch)"
for b in riftrouted riftroute; do
  (cd "$ROOT" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$WORK/$b" "./cmd/$b")
done
docker build -t "$IMG" "$HERE" >"$WORK/build.log" 2>&1 || { cat "$WORK/build.log"; exit 1; }

docker network create --subnet 10.77.1.0/24 rr-lan >/dev/null
docker network create --subnet 10.77.2.0/24 rr-wan >/dev/null

echo "== router"
docker run -d --name rr-router --network rr-lan --ip 10.77.1.254 --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 $IMG sleep infinity >/dev/null
docker network connect --ip 10.77.2.254 rr-wan rr-router

echo "== OpenVPN server"
docker run -d --name rr-server --network rr-wan --ip 10.77.2.20 --cap-add NET_ADMIN \
  --device /dev/net/tun $IMG sleep infinity >/dev/null
sx sh -euc '
  ip route replace default via 10.77.2.254
  ip link add infra0 type dummy && ip addr add 10.99.9.1/24 dev infra0 && ip link set infra0 up
  mkdir -p /etc/ovpn && cd /etc/ovpn
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=rr-test-ca 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj /CN=server 2>/dev/null
  printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 -extfile ext 2>/dev/null
  printf "#!/bin/sh\n[ \"\$(sed -n 1p \"\$1\")\" = alice ] && [ \"\$(sed -n 2p \"\$1\")\" = s3cret ]\n" > check.sh
  chmod 755 check.sh
  cat > server.conf <<EOF
port 1194
proto tcp-server
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ca /etc/ovpn/ca.crt
cert /etc/ovpn/server.crt
key /etc/ovpn/server.key
dh none
data-ciphers AES-256-CBC
auth SHA512
verify-client-cert none
username-as-common-name
script-security 2
auth-user-pass-verify /etc/ovpn/check.sh via-file
push "redirect-gateway def1"
push "dhcp-option DNS 8.8.8.8"
push "route 10.99.9.0 255.255.255.0"
keepalive 10 60
verb 3
EOF
  openvpn --config server.conf --daemon --log /var/log/ovpn.log
'

echo "== client (RiftRoute)"
docker run -d --name rr-client --network rr-lan --ip 10.77.1.10 --cap-add NET_ADMIN \
  --device /dev/net/tun $IMG sleep infinity >/dev/null
docker cp "$WORK/riftrouted" rr-client:/usr/local/bin/riftrouted
docker cp "$WORK/riftroute" rr-client:/usr/local/bin/riftroute
cx sh -euc '
  ip route replace default via 10.77.1.254 dev eth0
  ip link add wg0 type dummy && ip addr add 10.66.0.2/32 dev wg0 && ip link set wg0 up
  ip route add 0.0.0.0/1 dev wg0 && ip route add 128.0.0.0/1 dev wg0
  mkdir -p /var/lib/riftroute
  cp /etc/resolv.conf /tmp/resolv.before
'
if cx ping -c1 -W1 10.77.2.20 >/dev/null 2>&1; then
  fail "the main VPN should swallow the server path before RiftRoute pins it"
else
  pass "main VPN (wg0) swallows everything, including the OpenVPN server"
fi
start_daemon() {
  cx sh -c 'riftrouted -provider auto -socket /run/rr.sock -db /var/lib/riftroute/rr.db -log debug >>/var/log/rrd.log 2>&1 & echo $! > /run/rrd.pid'
  for _ in $(seq 1 50); do cx test -S /run/rr.sock && return; sleep 0.2; done
  cx tail -20 /var/log/rrd.log; exit 1
}
start_daemon

echo "== openvpn missing → install help for this distro, picked up without restart"
cx mv /usr/sbin/openvpn /usr/sbin/openvpn.off
out=$(cx riftroute tunnel list 2>&1)
if grep -q "On Debian GNU/Linux 12 (bookworm), run:" <<<"$out" && grep -q "sudo apt install openvpn" <<<"$out"; then
  pass "tunnel list shows: $(grep -m1 'sudo apt' <<<"$out" | xargs)"
else
  fail "no Debian install help in: $out"
fi
cx mv /usr/sbin/openvpn.off /usr/sbin/openvpn
out=$(cx riftroute tunnel list 2>&1)
if grep -q "isn't installed" <<<"$out"; then fail "still reported missing after install"; else pass "openvpn found again without restarting the daemon"; fi

# The version probe runs on read-only requests, so a root daemon must run it
# unprivileged: wrap openvpn to record who ran it.
cx sh -euc '
  mv /usr/sbin/openvpn /usr/sbin/openvpn.real
  printf "#!/bin/sh\nid -u > /tmp/probe-uid\nexec /usr/sbin/openvpn.real \"\$@\"\n" > /usr/sbin/openvpn
  chmod 755 /usr/sbin/openvpn
'
cx riftroute tunnel list >/dev/null 2>&1 || true
probe_uid=$(cx cat /tmp/probe-uid 2>/dev/null || echo none)
cx sh -c 'mv /usr/sbin/openvpn.real /usr/sbin/openvpn'
[ "$probe_uid" = 65534 ] && pass "the root daemon probed openvpn's version as nobody" || fail "version probe ran as uid $probe_uid"

echo "== add + connect"
docker cp rr-server:/etc/ovpn/ca.crt "$WORK/ca.crt"
{ printf 'client\ndev tun\nproto tcp\nremote 10.77.2.20 1194\nnobind\npersist-key\npersist-tun\n'
  printf 'remote-cert-tls server\ncipher AES-256-CBC\nauth SHA512\nauth-user-pass\nverb 3\n<ca>\n'
  cat "$WORK/ca.crt"; printf '</ca>\n'; } > "$WORK/infra.ovpn"
docker cp "$WORK/infra.ovpn" rr-client:/tmp/infra.ovpn
if cx sh -c 'printf "s3cret\n" | riftroute tunnel add infra /tmp/infra.ovpn --route 10.99.9.0/24 --username alice --password-stdin --connect'; then
  pass "connected"
else
  fail "connect"; cx riftroute tunnel log infra | tail -30 || true
fi

echo "== routing"
routes=$(cx ip route show proto riftroute)
echo "$routes" | sed 's/^/    /'
grep -q "^10.99.9.0/24 dev tun" <<<"$routes" && pass "infra network goes into the tunnel" || fail "no tunnel route"
grep -q "^10.77.2.20 via 10.77.1.254 dev eth0" <<<"$routes" && pass "server pinned to the physical gateway" || fail "no server pin"
cx ping -c2 -W2 10.99.9.1 >/dev/null && pass "10.99.9.1 (behind the server) answers through the tunnel" || fail "ping through tunnel"
get=$(cx ip route get 1.1.1.1 | head -1)
grep -q "dev wg0" <<<"$get" && pass "everything else still goes to the main VPN: $get" || fail "main VPN lost: $get"
cx ip route show 0.0.0.0/1 | grep -q "dev wg0" && pass "server's redirect-gateway ignored" || fail "redirect-gateway applied"
if cx ip route | grep -q "via 10.8.0.1"; then fail "pushed route applied by openvpn"; else pass "server's pushed route ignored (only RiftRoute's)"; fi
cx cmp -s /etc/resolv.conf /tmp/resolv.before && pass "DNS untouched" || fail "resolv.conf changed"
cx riftroute doctor 2>&1 | grep -E "tunnel" | sed 's/^/    /' || true

echo "== daemon crash: the orphaned openvpn is reaped on restart"
ovpn_pids() { cx sh -c 'for p in /proc/[0-9]*; do tr "\0" " " < $p/cmdline 2>/dev/null | grep -q "^/usr/sbin/openvpn --config" && basename $p; done; true'; }
before=$(ovpn_pids)
cx sh -c 'kill -9 $(cat /run/rrd.pid)'
sleep 1
[ -n "$(ovpn_pids)" ] && pass "openvpn outlived the killed daemon (pid $before)" || fail "openvpn died with the daemon"
cx rm -f /run/rr.sock
start_daemon
sleep 3
[ -z "$(ovpn_pids)" ] && pass "restarted daemon reaped it (via /proc, no ps)" || fail "orphan still running: $(ovpn_pids)"
left=$(cx ip route show proto riftroute)
[ -z "$left" ] && pass "and withdrew the dead session's routes" || fail "stale routes after restart: $left"

echo "== up/down"
cx riftroute tunnel up infra >/dev/null && pass "reconnected" || fail "reconnect"
cx riftroute tunnel down infra >/dev/null
sleep 1
[ -z "$(cx ip route show proto riftroute)" ] && pass "down removes every tunnel route" || fail "routes left: $(cx ip route show proto riftroute)"
[ -z "$(ovpn_pids)" ] && pass "down stops openvpn" || fail "openvpn still running"

echo
[ "$FAILED" = 0 ] && echo "ALL PASSED" || { echo "FAILURES"; exit 1; }
