# Third-party software

RiftRoute is MIT-licensed ([LICENSE](LICENSE)). Its Go dependencies are listed
in `go.mod`.

## openvpn (macOS)

On macOS, RiftRoute also ships a separate program: `openvpn`, which the daemon
runs (as root) for [tunnels](README.md#tunnels--an-openvpn-connection-next-to-your-main-vpn).
It is not linked into RiftRoute; RiftRoute starts it as its own process.

It is built by [`scripts/build-openvpn.sh`](scripts/build-openvpn.sh) from
these unmodified upstream releases, each pinned by version and SHA-256 and
checked before it is used:

| Component | Version | License | Source (the exact tarball) | SHA-256 |
|---|---|---|---|---|
| OpenVPN | 2.6.23 | GPL-2.0, with exceptions for linking OpenSSL and Apache-2.0 libraries | [openvpn-2.6.23.tar.gz](https://github.com/OpenVPN/openvpn/releases/download/v2.6.23/openvpn-2.6.23.tar.gz) | `4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96` |
| OpenSSL | 3.5.8 | Apache-2.0 | [openssl-3.5.8.tar.gz](https://github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz) | `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2` |
| LZO | 2.10 | GPL-2.0-or-later | [lzo-2.10.tar.gz](https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz) | `c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072` |
| LZ4 (library) | 1.10.0 | BSD-2-Clause | [lz4-1.10.0.tar.gz](https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz) | `537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b` |

Where the hashes come from: OpenSSL's `.sha256` on its GitHub release (the
same as openssl.org); LZ4's `.sha256` on its GitHub release; OpenVPN's GitHub
release asset digest, identical to the tarball on swupdate.openvpn.org, whose
GPG signature verifies with the OpenVPN security key
`F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7`. LZO's site publishes only a SHA-1
(`4924676a9bae5db58ef129dc1cebce3baa3c4b5d`); the SHA-256 is of the official
download that matched it.

Where it ships, with its licenses beside it:

- the macOS release tarballs, `riftroute_<version>_darwin_<arch>.tar.gz`:
  `openvpn` and `licenses/`;
- the app: `RiftRoute.app/Contents/Resources/bin/openvpn`, licenses in
  `Contents/Resources/licenses/`;
- once the daemon is installed: `/Library/PrivilegedHelperTools/riftroute-openvpn`.

**Source code.** The complete corresponding source of the GPL-licensed parts is
the OpenVPN and LZO tarballs above plus the build script: every RiftRoute
release that ships `openvpn` has those two tarballs attached next to the
binaries, and `scripts/build-openvpn.sh` at the release's tag is the script
that builds it. `licenses/SOURCES.txt` inside each artifact lists them too.

"OpenVPN" is a trademark of OpenVPN Inc. RiftRoute is not affiliated with or
endorsed by OpenVPN Inc.

## Linux

RiftRoute ships no openvpn for Linux: tunnels use the distribution's own
`openvpn` package.
