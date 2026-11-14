#!/usr/bin/env bash
# Check the charon-cmd and charon builds scripts/build-strongswan.sh made, independently
# of it (CI runs this on cached builds too):
#
#   scripts/check-strongswan.sh <dir>   # <dir>/{arm64,x86_64,universal}
#
# Each links only macOS's own libraries, has no LC_RPATH, is signed, carries
# RiftRoute's kernel-libipsec patch (without it charon would install routes
# for the whole server's traffic selectors — a full tunnel), and ships its
# licenses; the universal one holds both architectures; the native one says
# its version.
set -euo pipefail
DIR=${1:?usage: scripts/check-strongswan.sh <dir>}
fail() { echo "::error::$*" >&2; exit 1; }

for a in arm64 x86_64 universal; do
  for bin in charon-cmd charon; do
    f="${DIR}/${a}/${bin}"
    [ -f "$f" ] || fail "no ${f}"
    otool -L "$f"
    if otool -L "$f" | awk '/^\t/ {print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)'; then
      fail "$f links a library outside /usr/lib and /System"
    fi
    [ "$(otool -l "$f" | grep -c LC_RPATH || true)" = 0 ] || fail "$f has an LC_RPATH"
    codesign --verify --strict "$f"
  done
  f="${DIR}/${a}/charon-cmd"
  # The patches: kernel-libipsec's own message when it skips a route (the
  # setting's name alone is also kernel-pfkey's), and charon-cmd's
  # send_cert_always.
  grep -q 'kernel-libipsec: install_routes = no' "$f" || fail "$f was built without the kernel-libipsec patch"
  grep -q '%s.send_cert_always' "$f" || fail "$f was built without the charon-cmd send-cert patch"
  # charon (L2TP/IPsec) keeps its PID file in RiftRoute's run directory.
  grep -q '/var/run/riftroute-ipsec/charon.pid' "${DIR}/${a}/charon" || fail "${DIR}/${a}/charon has another PID directory"
  l="${DIR}/${a}/licenses"
  for x in SOURCES.txt strongswan/COPYING strongswan/LICENSE openssl/LICENSE.txt; do
    [ -f "${l}/${x}" ] || fail "${l}/${x} is missing"
  done
  ls "${l}"/strongswan/*.patch >/dev/null 2>&1 || fail "${l}/strongswan has no patch"
done
lipo "${DIR}/universal/charon-cmd" -verify_arch arm64 x86_64
lipo "${DIR}/universal/charon" -verify_arch arm64 x86_64
native=$(uname -m)
out=$(env -i PATH=/usr/bin:/bin OPENSSL_CONF=/dev/null STRONGSWAN_CONF=/dev/null "${DIR}/${native}/charon-cmd" --version 2>&1 || true)
echo "$out"
grep -q '^charon-cmd, strongSwan 6\.' <<<"$out" || fail "charon-cmd --version didn't identify itself"
# charon reads its strongswan.conf first, and takes /dev/null for an invalid one.
conf=$(mktemp)
out=$(env -i PATH=/usr/bin:/bin OPENSSL_CONF=/dev/null STRONGSWAN_CONF="$conf" "${DIR}/${native}/charon" --version 2>&1 || true)
rm -f "$conf"
echo "$out"
grep -q '^strongSwan 6\.' <<<"$out" || fail "charon --version didn't identify itself"
