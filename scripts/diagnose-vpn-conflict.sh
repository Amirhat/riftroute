#!/bin/bash
# READ-ONLY diagnostics for "my VPN won't connect while RiftRoute is active".
# Changes NOTHING — it only reads state so the cause can be identified.
#
#   sudo bash scripts/diagnose-vpn-conflict.sh > /tmp/rr-vpn-diag.txt 2>&1
#
# Best run in the BROKEN state: profiles enabled + VPN failing to connect.
# (Run it a second time after a panic, to diff what changed.)
set -u
[[ $(id -u) -eq 0 ]] || { echo "run with sudo (pfctl needs root): sudo bash $0"; exit 1; }
cd "$(dirname "$0")/.." 2>/dev/null || true

RR=./bin/riftroute
[[ -x "$RR" ]] || RR=$(command -v riftroute || echo "")

echo "======== RiftRoute VPN-conflict diagnostics — $(date) ========"

echo; echo "######## 1. RiftRoute state (profiles, mode, kill switch, drift) ########"
if [[ -n "$RR" ]]; then
  $RR status 2>&1 | sed 's/^/  /'
  echo "  --- profiles (name / enabled / MODE) ---"
  $RR --json profile list 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
for p in (d if isinstance(d,list) else d.get("profiles",[])):
    print("   %-24s enabled=%-5s mode=%s rules=%d" % (p.get("name"),p.get("enabled"),p.get("mode"),len(p.get("rules") or [])))
' 2>/dev/null || echo "   (could not list profiles)"
else
  echo "  riftroute CLI not found — run from the repo, or install it"
fi

echo; echo "######## 2. PF state — THE most likely conflict (both apps use pf) ########"
echo "  --- is pf enabled? ---"
pfctl -si 2>/dev/null | head -3 | sed 's/^/  /'
echo "  --- MAIN ruleset currently loaded (whose rules are active?) ---"
pfctl -sr 2>/dev/null | sed 's/^/  /' | head -30
echo "  --- anchors present (windscribe/other VPNs load their own) ---"
pfctl -s Anchors 2>/dev/null | sed 's/^/  /'
echo "  --- RiftRoute's own anchor ---"
pfctl -a riftroute -sr 2>/dev/null | sed 's/^/  /'
echo "  --- does /etc/pf.conf carry RiftRoute's hook block? ---"
grep -n "riftroute" /etc/pf.conf 2>/dev/null | sed 's/^/  /' || echo "  (no riftroute hook in pf.conf)"
echo "  --- RiftRoute's pf enable-token (present = we force-enabled pf) ---"
[[ -f /var/run/riftroute.pf.token ]] && echo "  token present: $(cat /var/run/riftroute.pf.token)" || echo "  no token (we did not force-enable pf)"

echo; echo "######## 3. Routing table — is anything shadowing the VPN endpoint? ########"
echo "  --- default routes ---"
netstat -rn -f inet 2>/dev/null | awk 'NR<=2 || $1=="default"' | sed 's/^/  /'
echo "  --- RiftRoute-managed routes ---"
if [[ -n "$RR" ]]; then $RR table show --managed 2>&1 | sed 's/^/  /' | head -25; fi
echo "  --- tunnel interfaces present ---"
ifconfig 2>/dev/null | grep -E "^(utun|ipsec|ppp)" | sed 's/^/  /'

echo; echo "######## 4. DNS — scoped resolvers could break the VPN's own lookups ########"
echo "  --- /etc/resolver entries (RiftRoute writes these for wildcard rules) ---"
ls -1 /etc/resolver 2>/dev/null | sed 's/^/  /' || echo "  (no /etc/resolver dir)"
for f in /etc/resolver/*; do
  [[ -f "$f" ]] && { echo "  === $f ==="; sed 's/^/    /' "$f"; }
done 2>/dev/null
echo "  --- system resolvers ---"
scutil --dns 2>/dev/null | grep -E "nameserver|domain " | head -12 | sed 's/^/  /'

echo; echo "######## 5. THE DECISIVE CHECK — where does the VPN's own traffic go? ########"
echo "  (run this WHILE the VPN is failing to connect)"
echo "  --- VPN client sockets (which endpoint is it dialing?) ---"
VPNSOCKS=$(lsof -nP -iTCP -iUDP 2>/dev/null \
  | grep -iE "windscribe|openvpn|wireguard|nym|cisco|anyconnect|tunnelblick")
echo "$VPNSOCKS" | sed 's/^/    /'
# BSD awk (macOS) — extract the remote address from "local->remote:port".
VPNIPS=$(echo "$VPNSOCKS" | awk '{for(i=1;i<=NF;i++) if($i ~ /->/){split($i,a,"->"); n=split(a[2],b,":"); if(n>1){p=""; for(j=1;j<n;j++) p=p (j>1?":":"") b[j]; print p}}}' | sort -u | head -8)
echo "$VPNIPS" | sed 's/^/    endpoint: /'
echo "  --- half-open (SYN_SENT) connections = handshakes that are failing ---"
netstat -an 2>/dev/null | grep -i "syn_sent" | head -10 | sed 's/^/    /'
echo "  --- FOR EACH endpoint: which interface does the kernel use? ---"
echo "      (if this shows a utun/ipsec instead of en0, the VPN is being"
echo "       routed into a tunnel and can never establish — that's the bug)"
for ip in $VPNIPS; do
  [[ -z "$ip" ]] && continue
  echo "    === route to $ip ==="
  route -n get "$ip" 2>/dev/null | grep -E "gateway|interface|destination" | sed 's/^/      /'
  if [[ -n "$RR" ]]; then
    echo "      riftroute explain:"
    $RR route explain "$ip" 2>/dev/null | sed 's/^/        /' | head -6
  fi
done

echo; echo "######## 6. Daemon log ########"
for L in /var/log/riftroute/riftrouted.log /var/log/riftroute/riftrouted.err.log /tmp/rr-root.log; do
  [[ -f "$L" ]] && { echo "  === $L (last 30) ==="; tail -30 "$L" | sed 's/^/    /'; }
done

echo; echo "======== end ========"
