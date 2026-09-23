#!/bin/bash
# Which packet-filter rules are loaded on this Mac — and which ones fire?
#
#   sudo bash scripts/diagnose-pf.sh --live > /tmp/rr-pf-diag.txt 2>&1
#
# Always read-only part: pf status, who holds pf enable references, the main
# ruleset, and every anchor (recursively) with its rules — including rules
# other software (VPN clients' firewalls) left loaded while pf was off, which
# take effect the moment anything enables pf.
#
# With --live it also turns the RiftRoute kill switch on for a few seconds,
# makes one probe as root, dumps every rule's hit counters, and turns it off
# again (the trap always turns it off). Needs the installed daemon.
set -u
[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo bash $0 [--live]"; exit 1; }
cd "$(dirname "$0")/.." || exit 1
LIVE=no; [[ "${1:-}" == "--live" ]] && LIVE=yes

# Every anchor path, depth-first (pfctl -sA lists one level at a time).
anchors() {
  local parent="${1:-}" a
  if [[ -z "$parent" ]]; then set -- $(pfctl -sA 2>/dev/null); else set -- $(pfctl -a "$parent" -sA 2>/dev/null); fi
  for a in "$@"; do echo "$a"; anchors "$a"; done
}

dump() { # $1 = extra pfctl flags (e.g. -v for counters)
  echo "---- main ruleset ----"
  pfctl $1 -sr 2>/dev/null | sed 's/^/  /'
  local a
  for a in $(anchors); do
    local rules; rules=$(pfctl -a "$a" $1 -sr 2>/dev/null)
    [[ -z "$rules" ]] && { echo "---- anchor $a: (empty)"; continue; }
    echo "---- anchor $a ----"
    echo "$rules" | sed 's/^/  /'
  done
}

echo "======== pf diagnostics — $(date) ========"
echo; echo "## status"; pfctl -si 2>/dev/null | head -3
echo; echo "## enable references (who turned pf on)"; pfctl -s References 2>/dev/null
echo; echo "## anchors"; anchors | sed 's/^/  /'
echo; echo "## BLOCK rules anywhere (these fire as soon as pf is on)"
{ pfctl -sr 2>/dev/null | sed 's/^/[main] /'; for a in $(anchors); do pfctl -a "$a" -sr 2>/dev/null | sed "s|^|[$a] |"; done; } | grep -i " block\|^\[[^]]*\] block" | sed 's/^/  /'
echo; echo "## all loaded rules"; dump ""

if [[ "$LIVE" == yes ]]; then
  rr() { ./bin/riftroute --socket /var/run/riftroute.sock "$@"; }
  trap 'rr killswitch off >/dev/null 2>&1' EXIT
  trap 'exit 130' INT TERM
  echo; echo "######## live: kill switch on, one probe, rule hit counters ########"
  pfctl -z >/dev/null 2>&1   # zero the counters (rules and states untouched)
  rr killswitch on
  echo "route to 1.1.1.1: $(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')"
  curl -s -o /dev/null -m 6 https://1.1.1.1 && echo "root probe: ok" || echo "root probe: blocked"
  echo; echo "## rules that matched packets (Packets > 0)"
  { pfctl -v -sr 2>/dev/null | sed 's/^/[main] /'; for a in $(anchors); do pfctl -a "$a" -v -sr 2>/dev/null | sed "s|^|[$a] |"; done; } \
    | awk '/^\[[^]]*\] [a-z]/{rule=$0; next} /Packets: [1-9]/{print rule; print "      " $0}' | sed 's/^/  /'
  echo; echo "## status while on"; pfctl -si 2>/dev/null | head -3
  echo; echo "## enable references while on"; pfctl -s References 2>/dev/null
  rr killswitch off
fi
echo; echo "======== end ========"
