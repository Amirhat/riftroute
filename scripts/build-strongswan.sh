#!/usr/bin/env bash
# Build the strongSwan client that ships with RiftRoute on macOS for IKEv2
# tunnels (docs/tunnels-ikev2.md). The daemon runs it as root, so, like the
# openvpn it ships (scripts/build-openvpn.sh), it must not come from a
# user-writable prefix like Homebrew's, nor load anything from one.
#
#   scripts/build-strongswan.sh <arm64|x86_64|universal> <outdir>
#
# Produces <outdir>/charon-cmd — strongSwan's single-connection IKE client,
# one process per tunnel — over a static OpenSSL, linking only macOS's own
# libraries, with every plugin it needs compiled in (monolithic) and nothing
# loadable: IKEv2, userspace ESP over a utun (kernel-libipsec), macOS routing
# (kernel-pfroute), the VICI control socket, X.509/PKCS#1/PKCS#8/PEM keys,
# and EAP-MSCHAPv2 (with its own MD4/DES, which OpenSSL 3 keeps in its legacy
# provider). No DNS (osx-attr), no updown scripts, no revocation fetching.
# Two changes to strongSwan (packaging/strongswan/*.patch): kernel-libipsec
# honours install_routes = no, as the kernel backends do — RiftRoute routes
# the networks it sends into a tunnel itself, and charon's own routes for a
# 0.0.0.0/0 traffic selector would take every connection instead; and
# charon-cmd sends its certificate unasked (send_cert_always, on by default),
# as Apple's client does — some servers never ask for it, and wait.
# Plus <outdir>/licenses/. "universal" builds (or reuses) both architectures
# and joins them with lipo, for the app bundle; the release tarballs carry
# the thin ones.
#
# Every source tarball is pinned by version AND SHA-256 and checked before it
# is unpacked. Downloads come only from the projects' own sites / GitHub
# releases. Nothing is installed outside the work dir; no sudo, no Homebrew.
#
# Environment:
#   RR_STRONGSWAN_WORK     work dir (default: build/strongswan-work) — kept
#                          between runs; an arch whose output is already there
#                          and whose pins match is not rebuilt
#                          (RR_STRONGSWAN_REBUILD=1 forces)
#   RR_STRONGSWAN_SOURCES  a directory of pre-downloaded tarballs to use
#                          instead of downloading (still checked against the
#                          pinned hashes)
#   JOBS                   parallel make jobs (default: the CPU count)
#
# Host requirements: macOS with the Xcode command line tools (clang, make, lipo,
# otool, codesign, strip) and perl (the system's is fine). Building x86_64 on an
# Apple Silicon Mac is a cross build; its --version check needs Rosetta and is
# skipped without it.
set -euo pipefail

# ---------------------------------------------------------------- pins
# Hashes: OpenSSL — as in build-openvpn.sh (the same 3.x LTS build);
# strongSwan — of the official download whose GPG signature
# (strongswan-6.1.0.tar.bz2.sig) verifies against the strongSwan release key
# 948F158A4E76A27BF3D07532DF42C170B34DBA77 (Andreas Steffen), and whose MD5
# matches the site's (c789d4f7389057b6c99860bf1e52ed1e).
OPENSSL_VERSION=3.5.8
OPENSSL_SHA256=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2
OPENSSL_URL=https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz

STRONGSWAN_VERSION=6.1.0
STRONGSWAN_SHA256=fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4
STRONGSWAN_URL=https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2

# Compiled-in paths. They sit inside a root-owned directory and are never
# created: the daemon always names charon-cmd's config (STRONGSWAN_CONF), so
# a default one can't be planted by a user; OpenSSL's openssl.cnf likewise
# (and the daemon runs it with OPENSSL_CONF=/dev/null).
HELPERDIR=/Library/PrivilegedHelperTools/riftroute-strongswan.d
OPENSSLDIR=${HELPERDIR}/ssl
# Go 1.25 (the daemon) needs macOS 12, so nothing older is supported anyway.
MACOS_MIN=12.0

# The plugins compiled in (monolithic; nothing is loaded from disk).
PLUGINS=(
  --enable-cmd --enable-ikev2 --enable-vici
  --enable-kernel-libipsec --enable-kernel-pfroute --enable-socket-default
  --enable-openssl --enable-nonce --enable-kdf
  --enable-x509 --enable-pubkey --enable-pkcs1 --enable-pkcs8 --enable-pem --enable-constraints
  --enable-eap-identity --enable-eap-mschapv2 --enable-md4 --enable-des
)

# ---------------------------------------------------------------- args
usage() { echo "usage: $0 <arm64|x86_64|universal> <outdir>" >&2; exit 2; }
[ $# -eq 2 ] || usage
ARCH=$1
OUT=$2
case "$ARCH" in arm64|x86_64|universal) ;; *) usage ;; esac
[ "$(uname -s)" = Darwin ] || { echo "build-strongswan.sh builds the macOS charon-cmd; run it on a Mac" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# What an existing build must match to be reused: the pins, this script and
# the patches.
PATCHES=("${ROOT}"/packaging/strongswan/*.patch)
PINS="$(cat "$0" "${PATCHES[@]}" | shasum -a 256 | awk '{print $1}')"
WORK="${RR_STRONGSWAN_WORK:-${ROOT}/build/strongswan-work}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"
mkdir -p "$WORK" "$OUT"
WORK="$(cd "$WORK" && pwd)"
OUT="$(cd "$OUT" && pwd)"

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'build-strongswan: %s\n' "$*" >&2; exit 1; }

# The system's tools only: nothing from a user-writable directory early on
# PATH may take part in a build that runs as root.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
for tool in clang make perl lipo otool codesign strip strings shasum curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "missing build tool: $tool (install the Xcode command line tools: xcode-select --install)"
done

# ---------------------------------------------------------------- sources
SRC="${WORK}/sources"
mkdir -p "$SRC"

# fetch <url> <sha256>: put the tarball in $SRC (from RR_STRONGSWAN_SOURCES
# or the network) and refuse it unless the hash matches the pin.
fetch() {
  local url=$1 want=$2 name got
  name=$(basename "$url")
  if [ ! -f "${SRC}/${name}" ] && [ -n "${RR_STRONGSWAN_SOURCES:-}" ] && [ -f "${RR_STRONGSWAN_SOURCES}/${name}" ]; then
    cp "${RR_STRONGSWAN_SOURCES}/${name}" "${SRC}/${name}.part"
    mv "${SRC}/${name}.part" "${SRC}/${name}"
  fi
  if [ ! -f "${SRC}/${name}" ]; then
    log "downloading ${url}"
    curl -fL --retry 3 --proto '=https' --tlsv1.2 -o "${SRC}/${name}.part" "$url"
    mv "${SRC}/${name}.part" "${SRC}/${name}"
  fi
  got=$(shasum -a 256 "${SRC}/${name}" | awk '{print $1}')
  if [ "$got" != "$want" ]; then
    rm -f "${SRC}/${name}"
    die "${name}: SHA-256 is ${got}, the pinned hash is ${want} — refusing to build from it"
  fi
}

# unpack <tarball> <dir>: a fresh copy of the (already verified) source.
unpack() {
  rm -rf "$2"
  mkdir -p "$2"
  tar -xf "${SRC}/$1" -C "$2" --strip-components 1
}

# ---------------------------------------------------------------- checks
# check_links <binary>: it may link only the OS's own libraries — never a
# library from Homebrew, MacPorts, /usr/local or anywhere a user can write.
check_links() {
  local bin=$1 bad
  log "otool -L ${bin}"
  otool -L "$bin" >&2
  bad=$(otool -L "$bin" | awk '/^\t/ {print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)' || true)
  [ -z "$bad" ] || die "$(basename "$bin") links libraries outside /usr/lib and /System: ${bad}"
  # Not `otool | grep -q`: under pipefail, grep exiting early makes the
  # pipeline fail and the check pass.
  if otool -l "$bin" | grep -c LC_RPATH >/dev/null; then
    die "$(basename "$bin") has an LC_RPATH; it must not look for libraries anywhere"
  fi
  # OpenSSL is linked in, never macOS's own libcrypto (a private one apps
  # mustn't load).
  if otool -L "$bin" | grep -Ec 'lib(crypto|ssl)' >/dev/null; then
    die "$(basename "$bin") links a libcrypto/libssl dylib; OpenSSL must be static"
  fi
}

# check_version <binary> <arch>: run it (as this user, with the daemon's
# environment) and make sure it is the build we meant.
check_version() {
  local bin=$1 arch=$2 out
  if [ "$arch" != "$(uname -m)" ] && ! arch -"$arch" /usr/bin/true 2>/dev/null; then
    log "can't run ${arch} code on this Mac (no Rosetta) — skipping the --version check"
    return 0
  fi
  out=$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin OPENSSL_CONF=/dev/null STRONGSWAN_CONF=/dev/null arch -"$arch" "$bin" --version 2>&1 || true)
  printf '%s\n' "$out" >&2
  case "$out" in *"charon-cmd, strongSwan ${STRONGSWAN_VERSION}"*) ;; *) die "charon-cmd --version doesn't show strongSwan ${STRONGSWAN_VERSION}" ;; esac
}

# ---------------------------------------------------------------- build
# build_arch <arch> <dest>: the whole chain for one architecture.
build_arch() {
  local arch=$1 dest=$2 host build ossl_target b prefix cflags
  case "$arch" in
    arm64) host=aarch64-apple-darwin; ossl_target=darwin64-arm64-cc ;;
    x86_64) host=x86_64-apple-darwin; ossl_target=darwin64-x86_64-cc ;;
  esac
  case "$(uname -m)" in
    arm64) build=aarch64-apple-darwin ;;
    *) build=x86_64-apple-darwin ;;
  esac

  if [ -z "${RR_STRONGSWAN_REBUILD:-}" ] && [ -x "${dest}/charon-cmd" ] && [ "$(cat "${dest}/.pins" 2>/dev/null)" = "$PINS" ]; then
    log "${arch}: up to date in ${dest}"
    check_links "${dest}/charon-cmd"
    return 0
  fi

  b="${WORK}/build-${arch}"
  prefix="${b}/prefix"
  rm -rf "$b"
  mkdir -p "$prefix/lib" "$prefix/include"

  # A clean environment: nothing from Homebrew (or the caller) may reach the
  # compiler, the linker or pkg-config.
  unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH CPPFLAGS LDFLAGS LIBS \
        PKG_CONFIG_PATH DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH OPENSSL_CONF OPENSSL_MODULES STRONGSWAN_CONF
  export PKG_CONFIG_LIBDIR="${prefix}/lib/pkgconfig" PKG_CONFIG_PATH=""
  export MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN"
  # strongSwan's configure insists on a pkg-config; macOS has none, and the
  # build must not use Homebrew's. Everything it needs is named explicitly
  # below, so this one knows no packages.
  mkdir -p "${b}/bin"
  cat >"${b}/bin/pkg-config" <<'PKGCONFIG'
#!/bin/sh
case "$1" in
  --version) echo 0.29.2 ;;
  --atleast-pkgconfig-version) exit 0 ;;
  *) exit 1 ;;
esac
PKGCONFIG
  chmod +x "${b}/bin/pkg-config"
  export PKG_CONFIG="${b}/bin/pkg-config"
  cflags="-O2 -arch ${arch} -mmacosx-version-min=${MACOS_MIN}"

  log "${arch}: OpenSSL ${OPENSSL_VERSION}"
  unpack "openssl-${OPENSSL_VERSION}.tar.gz" "${b}/openssl"
  (
    cd "${b}/openssl"
    # Static libraries, nothing loadable, no config read on its own (see
    # build-openvpn.sh).
    CC=clang ./Configure "$ossl_target" no-shared no-module no-engine no-dso no-autoload-config \
      no-tests no-docs no-apps \
      --prefix="$prefix" --libdir=lib --openssldir="$OPENSSLDIR" \
      -mmacosx-version-min="$MACOS_MIN" >"${b}/openssl-configure.log"
    make -j"$JOBS" build_libs >"${b}/openssl-build.log" 2>&1 || { tail -40 "${b}/openssl-build.log" >&2; exit 1; }
    make install_dev >"${b}/openssl-install.log" 2>&1 || { tail -40 "${b}/openssl-install.log" >&2; exit 1; }
  )

  log "${arch}: strongSwan ${STRONGSWAN_VERSION}"
  unpack "strongswan-${STRONGSWAN_VERSION}.tar.bz2" "${b}/strongswan"
  (
    cd "${b}/strongswan"
    for p in "${PATCHES[@]}"; do
      patch -p1 -N -s <"$p" || die "$(basename "$p") doesn't apply to strongSwan ${STRONGSWAN_VERSION}"
    done
    # --disable-defaults, then only the plugins above, all compiled in
    # (--enable-monolithic, static, no shared libraries): nothing is looked
    # up on disk at run time. Our lib dir, searched first, holds only the
    # static libcrypto, so -lcrypto can't be a dylib (check_links makes sure).
    ./configure --host="$host" --build="$build" \
      --prefix="$HELPERDIR" --sysconfdir="${HELPERDIR}/etc" \
      --disable-defaults "${PLUGINS[@]}" \
      --enable-monolithic --enable-static --disable-shared \
      CC=clang CFLAGS="$cflags" CPPFLAGS="-I${prefix}/include" LDFLAGS="-L${prefix}/lib" \
      >"${b}/strongswan-configure.log" 2>&1 || { tail -40 "${b}/strongswan-configure.log" >&2; exit 1; }
    grep -A3 'strongSwan will be built with the following plugins' "${b}/strongswan-configure.log" >&2 || true
    make -j"$JOBS" >"${b}/strongswan-build.log" 2>&1 || { tail -60 "${b}/strongswan-build.log" >&2; exit 1; }
  )

  mkdir -p "$dest"
  rm -f "${dest}/charon-cmd" "${dest}/.pins"
  cp "${b}/strongswan/src/charon-cmd/charon-cmd" "${dest}/charon-cmd"
  strip "${dest}/charon-cmd"
  check_links "${dest}/charon-cmd"
  codesign --force --sign - --identifier com.riftroute.charon-cmd "${dest}/charon-cmd"
  check_version "${dest}/charon-cmd" "$arch"
  licenses "$dest"
  printf '%s' "$PINS" >"${dest}/.pins"
  rm -rf "$b" # the sources stay; the build tree is large and not reused
}

# licenses <dest>: the license of every component in the binary, taken from
# the exact sources it was built from, and where to get those sources.
licenses() {
  local d="$1/licenses" t
  rm -rf "$d"
  mkdir -p "$d/strongswan" "$d/openssl"
  t=$(mktemp -d)
  tar -xf "${SRC}/strongswan-${STRONGSWAN_VERSION}.tar.bz2" -C "$t" "strongswan-${STRONGSWAN_VERSION}/COPYING" "strongswan-${STRONGSWAN_VERSION}/LICENSE"
  cp "$t/strongswan-${STRONGSWAN_VERSION}/COPYING" "$t/strongswan-${STRONGSWAN_VERSION}/LICENSE" "$d/strongswan/"
  cp "${PATCHES[@]}" "$d/strongswan/"
  tar -xzf "${SRC}/openssl-${OPENSSL_VERSION}.tar.gz" -C "$t" "openssl-${OPENSSL_VERSION}/LICENSE.txt"
  cp "$t/openssl-${OPENSSL_VERSION}/LICENSE.txt" "$d/openssl/"
  rm -rf "$t"
  cat >"$d/SOURCES.txt" <<EOF
The charon-cmd program shipped with RiftRoute is a separate program, built by
scripts/build-strongswan.sh in https://github.com/Amirhat/riftroute from these
sources (each checked against the SHA-256 below):

strongSwan ${STRONGSWAN_VERSION} (GPL-2.0-or-later, licenses/strongswan)
  ${STRONGSWAN_URL}
  sha256 ${STRONGSWAN_SHA256}
  with the changes in licenses/strongswan/*.patch applied
OpenSSL ${OPENSSL_VERSION} (Apache-2.0, licenses/openssl)
  ${OPENSSL_URL}
  sha256 ${OPENSSL_SHA256}

Both source tarballs — everything the program is built from — are attached
to every RiftRoute release that ships it.
EOF
}

fetch "$OPENSSL_URL" "$OPENSSL_SHA256"
fetch "$STRONGSWAN_URL" "$STRONGSWAN_SHA256"

if [ "$ARCH" = universal ]; then
  build_arch arm64 "${WORK}/out/arm64"
  build_arch x86_64 "${WORK}/out/x86_64"
  log "universal: lipo"
  rm -f "${OUT}/charon-cmd"
  lipo -create -output "${OUT}/charon-cmd" "${WORK}/out/arm64/charon-cmd" "${WORK}/out/x86_64/charon-cmd"
  codesign --force --sign - --identifier com.riftroute.charon-cmd "${OUT}/charon-cmd"
  check_links "${OUT}/charon-cmd"
  lipo -info "${OUT}/charon-cmd" >&2
  check_version "${OUT}/charon-cmd" "$(uname -m)"
  licenses "$OUT"
else
  build_arch "$ARCH" "${WORK}/out/${ARCH}"
  if [ "${WORK}/out/${ARCH}" != "$OUT" ]; then
    rm -rf "${OUT}/charon-cmd" "${OUT}/licenses"
    cp "${WORK}/out/${ARCH}/charon-cmd" "${OUT}/charon-cmd"
    cp -R "${WORK}/out/${ARCH}/licenses" "${OUT}/licenses"
  fi
fi
log "built ${OUT}/charon-cmd"
