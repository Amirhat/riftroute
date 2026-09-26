#!/usr/bin/env bash
# Build the openvpn that ships with RiftRoute on macOS (the daemon runs it as
# root, so it must not come from a user-writable prefix like Homebrew's, nor
# load anything from one — see THIRD_PARTY.md and internal/tunnel/binary.go).
#
#   scripts/build-openvpn.sh <arm64|x86_64|universal> <outdir>
#
# Produces <outdir>/openvpn — a static build of OpenVPN over OpenSSL, LZO and
# LZ4 that links only macOS's own libraries — plus <outdir>/licenses/.
# "universal" builds (or reuses) both architectures and joins them with lipo,
# for the app bundle; the release tarballs carry the thin ones.
#
# Every source tarball is pinned by version AND SHA-256 and checked before it
# is unpacked. Downloads come only from the projects' own sites / GitHub
# releases. Nothing is installed outside the work dir; no sudo, no Homebrew.
#
# Environment:
#   RR_OPENVPN_WORK     work dir (default: build/openvpn-work) — kept between
#                       runs; an arch whose output is already there and whose
#                       pins match is not rebuilt (RR_OPENVPN_REBUILD=1 forces)
#   RR_OPENVPN_SOURCES  a directory of pre-downloaded tarballs to use instead of
#                       downloading (still checked against the pinned hashes)
#   JOBS                parallel make jobs (default: the CPU count)
#
# Host requirements: macOS with the Xcode command line tools (clang, make, lipo,
# otool, codesign, strip) and perl (the system's is fine). Building x86_64 on an
# Apple Silicon Mac is a cross build; its --version check needs Rosetta and is
# skipped without it.
set -euo pipefail

# ---------------------------------------------------------------- pins
# Hashes: OpenSSL — openssl-3.5.8.tar.gz.sha256 on the GitHub release (same as
# openssl.org/source); LZ4 — lz4-1.10.0.tar.gz.sha256 on the GitHub release;
# OpenVPN — the GitHub release asset digest, identical to the
# swupdate.openvpn.org tarball, whose GPG signature verifies against the
# OpenVPN security key F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7; LZO — the
# site publishes only a SHA-1 (4924676a9bae5db58ef129dc1cebce3baa3c4b5d), so
# the SHA-256 is of the official download that matched it.
OPENSSL_VERSION=3.5.8 # the current 3.x LTS series (supported to 2030)
OPENSSL_SHA256=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2
OPENSSL_URL=https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz

LZO_VERSION=2.10
LZO_SHA256=c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072
LZO_URL=https://www.oberhumer.com/opensource/lzo/download/lzo-${LZO_VERSION}.tar.gz

LZ4_VERSION=1.10.0
LZ4_SHA256=537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b
LZ4_URL=https://github.com/lz4/lz4/releases/download/v${LZ4_VERSION}/lz4-${LZ4_VERSION}.tar.gz

OPENVPN_VERSION=2.6.23
OPENVPN_SHA256=4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96
OPENVPN_URL=https://github.com/OpenVPN/openvpn/releases/download/v${OPENVPN_VERSION}/openvpn-${OPENVPN_VERSION}.tar.gz

# OpenSSL's compiled-in config/cert directory. It sits inside a root-owned
# directory and is never created, so the default openssl.cnf (which can load
# providers) can't be planted by a user; the daemon also runs openvpn with
# OPENSSL_CONF=/dev/null.
OPENSSLDIR=/Library/PrivilegedHelperTools/riftroute-openvpn.d/ssl
# Go 1.25 (the daemon) needs macOS 12, so nothing older is supported anyway.
MACOS_MIN=12.0


# ---------------------------------------------------------------- args
usage() { echo "usage: $0 <arm64|x86_64|universal> <outdir>" >&2; exit 2; }
[ $# -eq 2 ] || usage
ARCH=$1
OUT=$2
case "$ARCH" in arm64|x86_64|universal) ;; *) usage ;; esac
[ "$(uname -s)" = Darwin ] || { echo "build-openvpn.sh builds the macOS openvpn; run it on a Mac" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# What an existing build must match to be reused: the pins and this script.
PINS="$(shasum -a 256 "$0" | awk '{print $1}')"
WORK="${RR_OPENVPN_WORK:-${ROOT}/build/openvpn-work}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"
mkdir -p "$WORK" "$OUT"
WORK="$(cd "$WORK" && pwd)"
OUT="$(cd "$OUT" && pwd)"

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'build-openvpn: %s\n' "$*" >&2; exit 1; }

for tool in clang make perl lipo otool codesign strip shasum curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "missing build tool: $tool (install the Xcode command line tools: xcode-select --install)"
done

# ---------------------------------------------------------------- sources
SRC="${WORK}/sources"
mkdir -p "$SRC"

# fetch <url> <sha256>: put the tarball in $SRC (from RR_OPENVPN_SOURCES or
# the network) and refuse it unless the hash matches the pin.
fetch() {
  local url=$1 want=$2 name got
  name=$(basename "$url")
  if [ ! -f "${SRC}/${name}" ] && [ -n "${RR_OPENVPN_SOURCES:-}" ] && [ -f "${RR_OPENVPN_SOURCES}/${name}" ]; then
    cp "${RR_OPENVPN_SOURCES}/${name}" "${SRC}/${name}.part"
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
  tar -xzf "${SRC}/$1" -C "$2" --strip-components 1
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
  if otool -l "$bin" | grep -q LC_RPATH; then
    die "$(basename "$bin") has an LC_RPATH; it must not look for libraries anywhere"
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
  out=$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin OPENSSL_CONF=/dev/null arch -"$arch" "$bin" --version 2>&1 || true)
  printf '%s\n' "$out" >&2
  for want in "OpenVPN ${OPENVPN_VERSION} " "OpenSSL ${OPENSSL_VERSION} " "LZO ${LZO_VERSION}" "enable_plugins=no" "enable_pkcs11=no" \
    "with_openssl_engine=no" "enable_management=yes" "[LZO]" "[LZ4]"; do
    case "$out" in *"$want"*) ;; *) die "openvpn --version doesn't show \"${want}\"" ;; esac
  done
  # OpenSSL itself must start cleanly under OPENSSL_CONF=/dev/null.
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin OPENSSL_CONF=/dev/null arch -"$arch" "$bin" --show-tls >/dev/null 2>&1 ||
    die "openvpn --show-tls fails with OPENSSL_CONF=/dev/null"
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

  if [ -z "${RR_OPENVPN_REBUILD:-}" ] && [ -x "${dest}/openvpn" ] && [ "$(cat "${dest}/.pins" 2>/dev/null)" = "$PINS" ]; then
    log "${arch}: up to date in ${dest}"
    check_links "${dest}/openvpn"
    return 0
  fi

  b="${WORK}/build-${arch}"
  prefix="${b}/prefix"
  rm -rf "$b"
  mkdir -p "$prefix/lib" "$prefix/include"

  # A clean environment: nothing from Homebrew (or the caller) may reach the
  # compiler, the linker or pkg-config.
  unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH CPPFLAGS LDFLAGS LIBS \
        PKG_CONFIG_PATH DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH OPENSSL_CONF OPENSSL_MODULES
  export PKG_CONFIG_LIBDIR="${prefix}/lib/pkgconfig" PKG_CONFIG_PATH=""
  export MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN"
  cflags="-O2 -arch ${arch} -mmacosx-version-min=${MACOS_MIN}"

  log "${arch}: OpenSSL ${OPENSSL_VERSION}"
  unpack "openssl-${OPENSSL_VERSION}.tar.gz" "${b}/openssl"
  (
    cd "${b}/openssl"
    # no-shared/no-module: static libraries, nothing loadable; no-engine and
    # no-dso: no engines, no dlopen at all; no-autoload-config: the library
    # doesn't read openssl.cnf on its own. The legacy provider (old ciphers
    # like BF-CBC) is compiled in.
    CC=clang ./Configure "$ossl_target" no-shared no-module no-engine no-dso no-autoload-config \
      no-tests no-docs no-apps \
      --prefix="$prefix" --libdir=lib --openssldir="$OPENSSLDIR" \
      -mmacosx-version-min="$MACOS_MIN" >"${b}/openssl-configure.log"
    make -j"$JOBS" build_libs >"${b}/openssl-build.log" 2>&1 || { tail -40 "${b}/openssl-build.log" >&2; exit 1; }
    make install_dev >"${b}/openssl-install.log" 2>&1 || { tail -40 "${b}/openssl-install.log" >&2; exit 1; }
  )

  log "${arch}: LZO ${LZO_VERSION}"
  unpack "lzo-${LZO_VERSION}.tar.gz" "${b}/lzo"
  (
    cd "${b}/lzo"
    ./configure --host="$host" --build="$build" --prefix="$prefix" --disable-shared --enable-static \
      CC=clang CFLAGS="$cflags" >"${b}/lzo-configure.log"
    make -j"$JOBS" >"${b}/lzo-build.log" 2>&1 || { tail -40 "${b}/lzo-build.log" >&2; exit 1; }
    make install >"${b}/lzo-install.log" 2>&1
  )

  log "${arch}: LZ4 ${LZ4_VERSION}"
  unpack "lz4-${LZ4_VERSION}.tar.gz" "${b}/lz4"
  (
    cd "${b}/lz4/lib"
    make -j"$JOBS" liblz4.a CC=clang CFLAGS="$cflags" >"${b}/lz4-build.log" 2>&1 || { tail -40 "${b}/lz4-build.log" >&2; exit 1; }
    cp liblz4.a "${prefix}/lib/"
    cp lz4.h lz4hc.h lz4frame.h "${prefix}/include/"
  )

  log "${arch}: OpenVPN ${OPENVPN_VERSION}"
  unpack "openvpn-${OPENVPN_VERSION}.tar.gz" "${b}/openvpn"
  (
    cd "${b}/openvpn"
    # No plugins, no PKCS#11 and no OpenSSL engines: nothing that loads code
    # at run time. The libraries are named by path, and our (static-only) lib
    # dir is searched first for configure's -llz4 probe, so the linker can't
    # pick a same-named dylib from a default search path instead.
    ./configure --host="$host" --build="$build" \
      --with-crypto-library=openssl --without-openssl-engine \
      --disable-plugins --disable-plugin-auth-pam --disable-plugin-down-root \
      --disable-pkcs11 --disable-dco --disable-unit-tests \
      --enable-lzo --enable-lz4 \
      CC=clang CFLAGS="$cflags" LDFLAGS="-L${prefix}/lib" \
      OPENSSL_CFLAGS="-I${prefix}/include" OPENSSL_LIBS="${prefix}/lib/libssl.a ${prefix}/lib/libcrypto.a" \
      LZO_CFLAGS="-I${prefix}/include" LZO_LIBS="${prefix}/lib/liblzo2.a" \
      LZ4_CFLAGS="-I${prefix}/include" LZ4_LIBS="${prefix}/lib/liblz4.a" \
      >"${b}/openvpn-configure.log" 2>&1 || { tail -40 "${b}/openvpn-configure.log" >&2; exit 1; }
    make -j"$JOBS" >"${b}/openvpn-build.log" 2>&1 || { tail -40 "${b}/openvpn-build.log" >&2; exit 1; }
  )

  mkdir -p "$dest"
  rm -f "${dest}/openvpn" "${dest}/.pins"
  cp "${b}/openvpn/src/openvpn/openvpn" "${dest}/openvpn"
  strip "${dest}/openvpn"
  check_links "${dest}/openvpn"
  codesign --force --sign - --identifier com.riftroute.openvpn "${dest}/openvpn"
  check_version "${dest}/openvpn" "$arch"
  licenses "$dest"
  printf '%s' "$PINS" >"${dest}/.pins"
  rm -rf "$b" # the sources stay; the build tree is large and not reused
}

# licenses <dest>: the license of every component in the binary, taken from
# the exact sources it was built from, and where to get those sources.
licenses() {
  local d="$1/licenses" t
  rm -rf "$d"
  mkdir -p "$d/openvpn" "$d/openssl" "$d/lzo" "$d/lz4"
  t=$(mktemp -d)
  tar -xzf "${SRC}/openvpn-${OPENVPN_VERSION}.tar.gz" -C "$t" "openvpn-${OPENVPN_VERSION}/COPYING" "openvpn-${OPENVPN_VERSION}/COPYRIGHT.GPL"
  cp "$t/openvpn-${OPENVPN_VERSION}/COPYING" "$t/openvpn-${OPENVPN_VERSION}/COPYRIGHT.GPL" "$d/openvpn/"
  tar -xzf "${SRC}/openssl-${OPENSSL_VERSION}.tar.gz" -C "$t" "openssl-${OPENSSL_VERSION}/LICENSE.txt"
  cp "$t/openssl-${OPENSSL_VERSION}/LICENSE.txt" "$d/openssl/"
  tar -xzf "${SRC}/lzo-${LZO_VERSION}.tar.gz" -C "$t" "lzo-${LZO_VERSION}/COPYING"
  cp "$t/lzo-${LZO_VERSION}/COPYING" "$d/lzo/"
  tar -xzf "${SRC}/lz4-${LZ4_VERSION}.tar.gz" -C "$t" "lz4-${LZ4_VERSION}/lib/LICENSE"
  cp "$t/lz4-${LZ4_VERSION}/lib/LICENSE" "$d/lz4/"
  rm -rf "$t"
  cat >"$d/SOURCES.txt" <<EOF
The openvpn program shipped with RiftRoute is a separate program, built by
scripts/build-openvpn.sh in https://github.com/Amirhat/riftroute from these
unmodified sources (each checked against the SHA-256 below):

OpenVPN ${OPENVPN_VERSION} (GPL-2.0, licenses/openvpn)
  ${OPENVPN_URL}
  sha256 ${OPENVPN_SHA256}
OpenSSL ${OPENSSL_VERSION} (Apache-2.0, licenses/openssl)
  ${OPENSSL_URL}
  sha256 ${OPENSSL_SHA256}
LZO ${LZO_VERSION} (GPL-2.0, licenses/lzo)
  ${LZO_URL}
  sha256 ${LZO_SHA256}
LZ4 ${LZ4_VERSION} library (BSD-2-Clause, licenses/lz4)
  ${LZ4_URL}
  sha256 ${LZ4_SHA256}

The same OpenVPN and LZO source tarballs are attached to every RiftRoute
release that ships this program.
EOF
}

fetch "$OPENSSL_URL" "$OPENSSL_SHA256"
fetch "$LZO_URL" "$LZO_SHA256"
fetch "$LZ4_URL" "$LZ4_SHA256"
fetch "$OPENVPN_URL" "$OPENVPN_SHA256"

if [ "$ARCH" = universal ]; then
  build_arch arm64 "${WORK}/out/arm64"
  build_arch x86_64 "${WORK}/out/x86_64"
  log "universal: lipo"
  rm -f "${OUT}/openvpn"
  lipo -create -output "${OUT}/openvpn" "${WORK}/out/arm64/openvpn" "${WORK}/out/x86_64/openvpn"
  codesign --force --sign - --identifier com.riftroute.openvpn "${OUT}/openvpn"
  check_links "${OUT}/openvpn"
  lipo -info "${OUT}/openvpn" >&2
  check_version "${OUT}/openvpn" "$(uname -m)"
  licenses "$OUT"
else
  build_arch "$ARCH" "${WORK}/out/${ARCH}"
  if [ "${WORK}/out/${ARCH}" != "$OUT" ]; then
    rm -rf "${OUT}/openvpn" "${OUT}/licenses"
    cp "${WORK}/out/${ARCH}/openvpn" "${OUT}/openvpn"
    cp -R "${WORK}/out/${ARCH}/licenses" "${OUT}/licenses"
  fi
fi
log "built ${OUT}/openvpn"
