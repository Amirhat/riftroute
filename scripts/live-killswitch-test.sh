#!/bin/bash
# Live macOS kill-switch verification — needs root (real pf), so it's yours to
# run; automation only checks that the generated rules parse. It proves that:
#   1. turning the kill switch on hooks its anchor into pf.conf, loads the
#      user-scoped block and turns pf on — it is actually ENFORCED (before
#      this fix the anchor was never referenced: "on", enforcing nothing);
#   2. root traffic — where VPN clients' helpers run — still gets out, so a VPN
#      can always reconnect;
#   3. your apps get out only through a tunnel (TCP, UDP, and IPv6 if present);
#   4. turning it off restores pf.conf byte-identical and pf's previous state.
#
#   make build && sudo ./bin/riftroute daemon install     (this build, first)
#   sudo bash scripts/live-killswitch-test.sh
#
# Clearest with the VPN DISCONNECTED: then (3) shows your apps being refused.
# It drives the INSTALLED daemon (no second daemon, no temp files) and needs
# the kill switch OFF to start; the trap always turns it off again.
set -u

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo bash $0"; exit 1; }
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] || { echo "run via sudo from your normal account (SUDO_USER is needed)"; exit 1; }
cd "$(dirname "$0")/.." || exit 1
[[ -x ./bin/riftroute ]] || { echo "build first: make build"; exit 1; }

PASS=0; FAIL=0
ck() { if [[ "$2" == *"$3"* ]]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 -> got [$2] want [$3]"; FAIL=$((FAIL+1)); fi; }
rr() { ./bin/riftroute --socket /var/run/riftroute.sock "$@"; }
# Each probe prints "ok" or "blocked"; every one is bounded.
tcp4() { curl -s -o /dev/null -m 6 https://1.1.1.1 && echo ok || echo blocked; }
udp4() { [[ -n "$(dig +time=3 +tries=1 +short @1.1.1.1 one.one.one.one A 2>/dev/null | grep -E '^[0-9.]+$' | head -1)" ]] && echo ok || echo blocked; }
tcp6() { curl -s -o /dev/null -m 6 'https://[2606:4700:4700::1111]' && echo ok || echo blocked; }
as_user() { sudo -u "$SUDO_USER" bash -c "$(declare -f "$1"); $1"; }

echo "==== live kill-switch test (fully reversible) ===="

echo "-- 0. preflight"
VER=$(rr version 2>&1)
echo "$VER" | sed 's/^/  /'
cli=$(echo "$VER" | awk '/^riftroute /{print $3}'); dmn=$(echo "$VER" | awk '/^riftrouted /{print $3}')
[[ -n "$dmn" && "$cli" == "$dmn" ]] && ! echo "$VER" | grep -q '^!' || { echo "  the installed daemon isn't this build — run: sudo ./bin/riftroute daemon install"; exit 1; }
[[ "$(rr killswitch status 2>&1)" == *off* ]] || { echo "  turn the kill switch off first (riftroute killswitch off)"; exit 1; }
trap 'rr killswitch off >/dev/null 2>&1' EXIT
trap 'echo "  interrupted"; exit 130' INT TERM
PF_BEFORE=$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)
PF_STATE_BEFORE=$(pfctl -si 2>/dev/null | head -1 | grep -o "Enabled\|Disabled" | head -1)
[[ -n "$PF_STATE_BEFORE" ]] || { echo "  could not read pf state (pfctl -si)"; exit 1; }
VIA=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')
VIA6=$(route -n get -inet6 2606:4700:4700::1111 2>/dev/null | awk '/interface:/{print $2}')
echo "  pf.conf ${PF_BEFORE:0:16}…  |  pf: $PF_STATE_BEFORE  |  1.1.1.1 routes via: ${VIA:-none}"
B_T=$(as_user tcp4); B_U=$(as_user udp4); B_6=$(as_user tcp6); R_T=$(tcp4)
echo "  baseline — $SUDO_USER: tcp4=$B_T udp4=$B_U tcp6=$B_6 | root: tcp4=$R_T"
[[ "$B_T" == ok && "$R_T" == ok ]] || echo "  NOTE: no internet at baseline — step 2 can't prove anything"

echo "-- 1. turn it on"
ON_OUT=$(rr killswitch on 2>&1); ON_RC=$?
echo "$ON_OUT" | sed 's/^/  > /'
if [[ $ON_RC -ne 0 && "$ON_OUT" == *"own connection"* ]]; then
  # Safe mode: with a VPN whose own connection runs as your account (e.g.
  # Windscribe in WireGuard mode), the kill switch refuses rather than cut it.
  echo "  PASS: refused — it would have cut your VPN's own connection (safe mode)"; PASS=$((PASS+1))
  ck "nothing left enforced" "[$(pfctl -a riftroute_ks -sr 2>/dev/null)]" "[]"
  [[ "$R_T" == ok ]] && ck "the VPN still works (root)" "$(tcp4)" "ok"
  [[ "$B_T" == ok ]] && ck "the VPN still works (your apps)" "$(as_user tcp4)" "ok"
  echo; echo "==== $PASS passed, $FAIL failed ===="
  [[ $FAIL -eq 0 ]]; exit
fi
ck "kill switch reports on" "$ON_OUT" "ON"
ck "loaded ruleset references the anchor" "$(pfctl -sr 2>/dev/null)" 'anchor "riftroute_ks"'
ck "anchor holds the user-scoped block" "$(pfctl -a riftroute_ks -sr 2>/dev/null)" "user 499 >< 65534"
ck "pf is running" "$(pfctl -si 2>/dev/null | head -1)" "Enabled"

echo "-- 2. who can still get out?"
O_T=$(as_user tcp4); O_U=$(as_user udp4); O_6=$(as_user tcp6); O_R=$(tcp4)
echo "  $SUDO_USER: tcp4=$O_T udp4=$O_U tcp6=$O_6 | root: tcp4=$O_R"
[[ "$R_T" == ok ]] && ck "root (VPN helpers) still reaches the internet" "$O_R" "ok"
case "$VIA" in
  utun*|ipsec*|ppp*|tun*|wg*) expect=ok;   what="through the tunnel ($VIA)" ;;
  *)                          expect=blocked; what="refused outside the tunnel ($VIA)" ;;
esac
[[ "$B_T" == ok ]] && ck "your apps (TCP) $what" "$O_T" "$expect"
[[ "$B_U" == ok ]] && ck "your apps (UDP) $what" "$O_U" "$expect"
case "$VIA6" in
  utun*|ipsec*|ppp*|tun*|wg*) e6=ok ;;
  *)                          e6=blocked ;;
esac
[[ "$B_6" == ok ]] && ck "your apps (IPv6) via ${VIA6:-none}" "$O_6" "$e6"
echo "  (waiting 8s: the daemon must not start cutting the VPN)"; sleep 8
case "$VIA" in
  utun*|ipsec*|ppp*|tun*|wg*) [[ "$R_T" == ok ]] && ck "the VPN still works after 8s" "$(tcp4)" "ok" ;;
esac

echo "-- 3. turn it off — back exactly as before?"
ck "kill switch reports off" "$(rr killswitch off 2>&1)" "off"
ck "anchor emptied" "[$(pfctl -a riftroute_ks -sr 2>/dev/null)]" "[]"
if pfctl -sr 2>/dev/null | grep -q 'anchor "riftroute_ks"'; then r=present; else r=gone; fi
ck "anchor reference gone from the loaded ruleset" "$r" "gone"
ck "pf.conf byte-identical" "$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)" "$PF_BEFORE"
ck "pf back to its previous state" "$(pfctl -si 2>/dev/null | head -1)" "$PF_STATE_BEFORE"
[[ "$B_T" == ok ]] && ck "your apps' connectivity restored" "$(as_user tcp4)" "ok"

echo
echo "==== $PASS passed, $FAIL failed ===="
[[ $FAIL -eq 0 ]]
