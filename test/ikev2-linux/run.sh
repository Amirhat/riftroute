#!/bin/bash
# Real Linux end-to-end check of RiftRoute's IKEv2 tunnels, in Docker:
#
#   rr-ike-client (10.78.1.10) --lan-- rr-ike-router --wan-- rr-ike-server (10.78.2.20)
#
# The server is strongSwan (charon + swanctl), set up the way road-warrior
# servers usually are: a full tunnel (0.0.0.0/0), a pool of virtual IPs,
# certificates on both sides (ECDSA P-384, AES-256-GCM). Behind it is
# 10.99.9.0/24 (a dummy interface, 10.99.9.1).
#
# The client runs the real Linux riftrouted with the distribution's
# charon-cmd, from a .mobileconfig built here the way Apple Configurator
# writes one. Its "main VPN" is a dummy wg0 holding 0/1 + 128/1, which
# swallows everything (the path to the server included) unless RiftRoute
# pins it — and which charon's own routes for the full tunnel would take over
# if they weren't kept out of the way.
#
# Run it with `make test-ikev2-linux` (needs Docker). KEEP=1 leaves the
# containers up for poking around afterwards. SWAN=6 gives the client the
# charon-cmd RiftRoute builds for macOS instead (strongSwan 6.1 with its
# patch, built here from the same pinned source: Dockerfile.swan6).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
IMG=riftroute-ikev2-e2e
DOCKERFILE=Dockerfile
if [ "${SWAN:-}" = 6 ]; then IMG=riftroute-ikev2-e2e-swan6 DOCKERFILE=Dockerfile.swan6; fi
WORK=$(mktemp -d)
pass() { printf '  PASS %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILED=1; }
FAILED=0
cx() { docker exec -e RIFTROUTE_SOCKET=/run/rr.sock rr-ike-client "$@"; }
sx() { docker exec rr-ike-server "$@"; }

cleanup() {
  docker rm -f rr-ike-client rr-ike-server rr-ike-router >/dev/null 2>&1 || true
  docker network rm rr-ike-lan rr-ike-wan >/dev/null 2>&1 || true
}
cleanup
trap 'rm -rf "$WORK"' EXIT
[ "${KEEP:-}" = 1 ] || trap 'cleanup; rm -rf "$WORK"' EXIT

arch=$(docker version -f '{{.Server.Arch}}')
echo "== build (linux/$arch)"
for b in riftrouted riftroute; do
  (cd "$ROOT" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$WORK/$b" "./cmd/$b")
done
mkdir "$WORK/ctx" && cp "$HERE"/Dockerfile* "$ROOT"/packaging/strongswan/*.patch "$WORK/ctx/"
docker build -t "$IMG" -f "$WORK/ctx/$DOCKERFILE" "$WORK/ctx" >"$WORK/build.log" 2>&1 || { tail -40 "$WORK/build.log"; exit 1; }
echo "   client: $(docker run --rm "$IMG" charon-cmd --version)"

docker network create --subnet 10.78.1.0/24 rr-ike-lan >/dev/null
docker network create --subnet 10.78.2.0/24 rr-ike-wan >/dev/null

echo "== router"
docker run -d --name rr-ike-router --network rr-ike-lan --ip 10.78.1.254 --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 $IMG sleep infinity >/dev/null
docker network connect --ip 10.78.2.254 rr-ike-wan rr-ike-router

echo "== strongSwan server"
docker run -d --name rr-ike-server --network rr-ike-wan --ip 10.78.2.20 --cap-add NET_ADMIN \
  $IMG sleep infinity >/dev/null
sx sh -euc '
  ip route replace default via 10.78.2.254
  ip link add infra0 type dummy && ip addr add 10.99.9.1/24 dev infra0 && ip link set infra0 up
  mkdir -p /pki && cd /pki
  key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" 2>/dev/null; }
  key ca.key
  openssl req -x509 -new -key ca.key -out ca.crt -days 2 -subj /CN=rr-test-ca \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
  issue() { # name subject san
    key "$1.key"
    openssl req -new -key "$1.key" -out "$1.csr" -subj "$2" 2>/dev/null
    printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nsubjectAltName=%s\n" "$3" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 2 -extfile "$1.ext" 2>/dev/null
  }
  issue server /CN=vpn.test DNS:vpn.test
  issue client /CN=alice@test email:alice@test
  openssl pkcs12 -export -inkey client.key -in client.crt -certfile ca.crt -passout pass:pw -out client.p12
  openssl x509 -in ca.crt -outform der -out ca.der
  cp ca.crt /etc/swanctl/x509ca/ && cp server.crt /etc/swanctl/x509/ && cp server.key /etc/swanctl/private/
  cat > /etc/swanctl/conf.d/rw.conf <<EOF
connections {
  rw {
    local_addrs = 10.78.2.20
    pools = rw4
    proposals = aes256gcm16-prfsha256-ecp384
    local {
      auth = pubkey
      certs = server.crt
      id = vpn.test
    }
    remote {
      auth = pubkey
      cacerts = ca.crt
    }
    children {
      rw {
        local_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16-ecp384
      }
    }
  }
}
pools {
  rw4 {
    addrs = 10.9.0.0/24
  }
}
EOF
  /usr/lib/ipsec/charon >/var/log/charon.log 2>&1 &
  for i in $(seq 1 50); do [ -S /var/run/charon.vici ] && break; sleep 0.1; done
  swanctl --load-all >/var/log/swanctl.log 2>&1
'
sx swanctl --list-conns | grep -q "rw:" && pass "server up, with its full-tunnel connection" || { fail "server"; sx cat /var/log/charon.log | tail -20; }

echo "== the profile (.mobileconfig, as Apple Configurator writes one)"
docker cp rr-ike-server:/pki/client.p12 "$WORK/client.p12"
docker cp rr-ike-server:/pki/ca.der "$WORK/ca.der"
b64() { base64 < "$1" | tr -d '\n'; }
params() {
  printf '<dict><key>EncryptionAlgorithm</key><string>AES-256-GCM</string><key>IntegrityAlgorithm</key><string>SHA2-256</string>'
  printf '<key>DiffieHellmanGroup</key><integer>20</integer><key>LifeTimeInMinutes</key><integer>%s</integer></dict>' "$1"
}
cat > "$WORK/office.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>test.riftroute.office</string>
  <key>PayloadUUID</key><string>7C3E2E58-0001-4000-8000-000000000001</string>
  <key>PayloadDisplayName</key><string>Office VPN</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.pkcs12</string>
      <key>PayloadUUID</key><string>7C3E2E58-0001-4000-8000-000000000002</string>
      <key>PayloadDisplayName</key><string>alice@test</string>
      <key>Password</key><string>pw</string>
      <key>PayloadContent</key><data>$(b64 "$WORK/client.p12")</data>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>7C3E2E58-0001-4000-8000-000000000003</string>
      <key>PayloadDisplayName</key><string>rr-test-ca</string>
      <key>PayloadContent</key><data>$(b64 "$WORK/ca.der")</data>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key><string>7C3E2E58-0001-4000-8000-000000000004</string>
      <key>UserDefinedName</key><string>Office</string>
      <key>VPNType</key><string>IKEv2</string>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key><string>10.78.2.20</string>
        <key>RemoteIdentifier</key><string>vpn.test</string>
        <key>LocalIdentifier</key><string>alice@test</string>
        <key>AuthenticationMethod</key><string>Certificate</string>
        <key>PayloadCertificateUUID</key><string>7C3E2E58-0001-4000-8000-000000000002</string>
        <key>ServerCertificateCommonName</key><string>vpn.test</string>
        <key>ExtendedAuthEnabled</key><integer>0</integer>
        <key>EnablePFS</key><integer>1</integer>
        <key>DeadPeerDetectionRate</key><string>Medium</string>
        <key>IKESecurityAssociationParameters</key>$(params 480)
        <key>ChildSecurityAssociationParameters</key>$(params 60)
      </dict>
      <key>IPv4</key><dict><key>OverridePrimary</key><integer>1</integer></dict>
      <key>DNS</key><dict><key>ServerAddresses</key><array><string>10.99.9.53</string></array></dict>
    </dict>
  </array>
</dict>
</plist>
EOF
pass "built (PKCS#12 + root CA + IKEv2 payload)"

echo "== client (RiftRoute)"
docker run -d --name rr-ike-client --network rr-ike-lan --ip 10.78.1.10 --cap-add NET_ADMIN \
  --device /dev/net/tun $IMG sleep infinity >/dev/null
docker cp "$WORK/riftrouted" rr-ike-client:/usr/local/bin/riftrouted
docker cp "$WORK/riftroute" rr-ike-client:/usr/local/bin/riftroute
docker cp "$WORK/office.mobileconfig" rr-ike-client:/tmp/office.mobileconfig
cx sh -euc '
  ip route replace default via 10.78.1.254 dev eth0
  ip link add wg0 type dummy && ip addr add 10.66.0.2/32 dev wg0 && ip link set wg0 up
  ip route add 0.0.0.0/1 dev wg0 && ip route add 128.0.0.0/1 dev wg0
  mkdir -p /var/lib/riftroute
  cp /etc/resolv.conf /tmp/resolv.before
'
if cx ping -c1 -W1 10.78.2.20 >/dev/null 2>&1; then
  fail "the main VPN should swallow the server path before RiftRoute pins it"
else
  pass "main VPN (wg0) swallows everything, including the IKEv2 server"
fi
start_daemon() {
  cx sh -c 'riftrouted -provider auto -socket /run/rr.sock -db /var/lib/riftroute/rr.db -log debug >>/var/log/rrd.log 2>&1 & echo $! > /run/rrd.pid'
  for _ in $(seq 1 50); do cx test -S /run/rr.sock && return; sleep 0.2; done
  cx tail -20 /var/log/rrd.log; exit 1
}
start_daemon

echo "== add; charon-cmd missing → install help for this distro, picked up without restart"
if cx riftroute tunnel add office /tmp/office.mobileconfig --route 10.99.9.0/24 >"$WORK/add.out" 2>&1; then
  pass "added: $(head -1 "$WORK/add.out")"
else
  fail "add: $(cat "$WORK/add.out")"
fi
cx mv /usr/sbin/charon-cmd /usr/sbin/charon-cmd.off
out=$(cx riftroute tunnel list 2>&1 || true)
if grep -q "strongSwan's charon-cmd isn't installed" <<<"$out" && grep -q "sudo apt install --no-install-recommends charon-cmd" <<<"$out"; then
  pass "tunnel list shows: $(grep -m1 'sudo apt' <<<"$out" | xargs)"
else
  fail "no Debian install help in: $out"
fi
cx mv /usr/sbin/charon-cmd.off /usr/sbin/charon-cmd
out=$(cx riftroute tunnel list 2>&1 || true)
if grep -q "isn't installed" <<<"$out"; then fail "still reported missing after install"; else pass "charon-cmd found again without restarting the daemon"; fi

echo "== connect"
if cx riftroute tunnel up office >"$WORK/up.out" 2>&1; then
  pass "$(tail -1 "$WORK/up.out")"
else
  fail "connect: $(tail -3 "$WORK/up.out")"; cx riftroute tunnel log office | tail -40 || true
fi
iface=$(cx riftroute --json tunnel list | sed -n 's/.*"iface": *"\([^"]*\)".*/\1/p' | head -1)
vip=$(cx riftroute --json tunnel list | sed -n 's/.*"local_ip": *"\([^"]*\)".*/\1/p' | head -1)
[ -n "$iface" ] && pass "on $iface with $vip from the server's pool" || fail "no interface"
case "$vip" in 10.9.0.*) pass "the address is the server's virtual IP" ;; *) fail "unexpected address $vip" ;; esac

echo "== routing"
routes=$(cx ip route show proto riftroute)
echo "$routes" | sed 's/^/    /'
grep -q "^10.99.9.0/24 dev $iface" <<<"$routes" && pass "infra network goes into the tunnel" || fail "no tunnel route"
grep -q "^10.78.2.20 via 10.78.1.254 dev eth0" <<<"$routes" && pass "server pinned to the physical gateway" || fail "no server pin"
cx ping -c2 -W2 10.99.9.1 >/dev/null && pass "10.99.9.1 (behind the server) answers through IPsec" || fail "ping through tunnel"
get=$(cx ip route get 1.1.1.1 | head -1)
grep -q "dev wg0" <<<"$get" && pass "everything else still goes to the main VPN: $get" || fail "main VPN lost: $get"
own=$(cx ip route show table main | grep " dev ${iface:-none}\b" | grep -v "proto riftroute" || true)
[ -n "$iface" ] && [ -z "$own" ] && pass "charon installed no route of its own in main" || fail "charon's own routes in main: $own"
table=$(cx ip route show table 52520 2>/dev/null || true)
[ -n "$table" ] && sed 's/^/    table 52520: /' <<<"$table"
rules=$(cx ip rule | grep 52520 || true)
[ -n "$rules" ] && sed 's/^/    rule: /' <<<"$rules"
if [ -z "$rules" ] || ! grep -qv "fwmark 0x7f52ea21" <<<"$rules"; then
  pass "charon's rule (if any) only matches a mark nothing sets"
else
  fail "charon's rule matches unmarked packets: $rules"
fi
# What main can't answer must not fall into charon's table: take main's
# routes away (the main VPN's halves and the default) and look again.
cx sh -c 'ip route del 0.0.0.0/1 dev wg0; ip route del 128.0.0.0/1 dev wg0; ip route del default'
get=$(cx ip route get 8.8.8.8 2>&1 | head -1 || true)
cx sh -c 'ip route add default via 10.78.1.254 dev eth0; ip route add 0.0.0.0/1 dev wg0; ip route add 128.0.0.0/1 dev wg0'
grep -q "ipsec0" <<<"$get" && fail "with main empty, traffic falls into the tunnel: $get" ||
  pass "with main empty, nothing falls into the tunnel ($get)"
if [ "${SWAN:-}" = 6 ]; then
  # RiftRoute's patch: kernel-libipsec installs no route at all.
  [ -z "$table" ] && pass "the patched charon-cmd installed no route anywhere" || fail "routes despite the patch: $table"
fi
cx cmp -s /etc/resolv.conf /tmp/resolv.before && pass "DNS untouched (the profile's DNS ignored)" || fail "resolv.conf changed"
# strongSwan 6 takes the key as PEM, 5.x (Debian's) as a PKCS#12.
keyfile=$(cx sh -c 'ls /var/lib/riftroute/tunnels/office.key.pem /var/lib/riftroute/tunnels/office.p12 2>/dev/null | head -1')
cx stat -c "%a" "${keyfile:-none}" 2>/dev/null | grep -q "^600$" && pass "the key ($(basename "$keyfile")) is 0600 while connected" || fail "key file mode: ${keyfile:-none}"
cx stat -c "%a" /var/lib/riftroute/tunnels | grep -q "^700$" && pass "in a 0700 directory" || fail "tunnels dir mode"

echo "== the server drops the connection: charon-cmd is restarted, and the tunnel comes back"
sx swanctl --terminate --ike rw >/dev/null 2>&1 || true
back=0
for _ in $(seq 1 60); do
  st=$(cx riftroute tunnel list 2>/dev/null | awk '$1=="office"{print $3}')
  [ "$st" = reconnecting ] && seen_down=1
  if [ "$st" = connected ] && [ "${seen_down:-0}" = 1 ]; then back=1; break; fi
  sleep 1
done
[ "${seen_down:-0}" = 1 ] && pass "noticed the drop (reconnecting)" || fail "never saw the drop"
[ $back = 1 ] && pass "connected again" || fail "didn't come back: $(cx riftroute tunnel list 2>&1)"
cx ping -c2 -W2 10.99.9.1 >/dev/null && pass "and 10.99.9.1 answers again" || fail "ping after reconnect"

echo "== daemon crash: charon-cmd goes with it (Linux: the parent-death signal) and ends the connection"
charon_pids() { cx sh -c 'for p in /proc/[0-9]*; do tr "\0" " " < $p/cmdline 2>/dev/null | grep -q "^/usr/sbin/charon-cmd " && basename $p; done; true'; }
[ -n "$(charon_pids)" ] || fail "no charon-cmd running before the crash"
cx sh -c 'kill -9 $(cat /run/rrd.pid)'
sleep 2
[ -z "$(charon_pids)" ] && pass "charon-cmd ended with the killed daemon" || fail "charon-cmd outlived the daemon: $(charon_pids)"
sx swanctl --list-sas 2>/dev/null | grep -q "rw:" && fail "the server still holds the SA" || pass "and deleted the connection with the server"
cx rm -f /run/rr.sock
start_daemon
sleep 3
[ -z "$(charon_pids)" ] && pass "nothing to reap after the restart" || fail "charon-cmd running after restart: $(charon_pids)"
left=$(cx ip route show proto riftroute)
[ -z "$left" ] && pass "and withdrew the dead session's routes" || fail "stale routes after restart: $left"
files=$(cx ls /var/lib/riftroute/tunnels | grep -v '\.json$' | tr '\n' ' ' || true)
[ -z "$files" ] && pass "and removed its key and config files" || fail "files left: $files"

echo "== up/down"
cx riftroute tunnel up office >/dev/null && pass "reconnected" || fail "reconnect"
cx riftroute tunnel down office >/dev/null
sleep 1
[ -z "$(cx ip route show proto riftroute)" ] && pass "down removes every tunnel route" || fail "routes left: $(cx ip route show proto riftroute)"
[ -z "$(charon_pids)" ] && pass "down stops charon-cmd" || fail "charon-cmd still running"
files=$(cx ls /var/lib/riftroute/tunnels | grep -v '\.json$' | tr '\n' ' ' || true)
[ -z "$files" ] && pass "and leaves no key or config behind" || fail "files left: $files"
sx swanctl --list-sas 2>/dev/null | grep -q "rw:" && fail "the server still holds an SA after down" || pass "the connection was deleted with the server"

echo
[ "$FAILED" = 0 ] && echo "ALL PASSED" || { echo "FAILURES"; exit 1; }
