# IKEv2 tunnels and `.mobileconfig` — design

Status: in progress. It's built in steps, each its own PR, listed at the
end.

## What the user asked for

> Add IKEv2 and `.mobileconfig`, so users can use these profiles too.

The profile they have is Apple's configuration-profile format, carrying:

- an IKEv2 VPN (`com.apple.vpn.managed`, `VPNType` `IKEv2`);
- a personal certificate (`com.apple.security.pkcs12`, password inside,
  90 days);
- the server's root CA (`com.apple.security.root`).

The IKEv2 settings are certificate auth, AES-256-GCM / SHA2-256, DH group
20 with PFS, MOBIKE on, and a "full tunnel". Its PKCS#12 uses Apple's
legacy encryption (SHA-1 MAC, RC2-40 and 3DES), which OpenSSL 3 won't read
without its legacy provider.

As with every RiftRoute tunnel, only the networks the user lists (and the
profiles sent into it) go through it. "Full tunnel" is ignored, like
OpenVPN's redirect-gateway and WireGuard's AllowedIPs.

## Why strongSwan, and how

IKEv2 is a large, security-critical protocol: IKE plus ESP, certificates,
EAP, MOBIKE, rekeying. There's no mature Go implementation, and writing one
isn't a risk worth taking. **strongSwan** is the standard open-source
implementation on Linux and macOS. It runs as a separate program, the way
openvpn does.

The alternatives, and why not:

- **macOS's own IKEv2 client** (NEVPNManager) needs Apple's Network
  Extension entitlement, so a paid developer account. It owns the routes
  and DNS, and allows one such VPN per app. Our split model can't sit on
  it.
- **Homebrew's strongSwan** uses macOS's kernel IPsec (PF_KEY). That's
  policy-based: everything the negotiated selectors cover is encrypted,
  whatever the routes say. A full-tunnel server makes it a full tunnel,
  with no interface to route into.

**The engine setup (as built):**

- strongSwan with **`kernel-libipsec`**: ESP in userspace, over a TUN
  device (`utun` on macOS, where `tun_device.c` supports it, and `tun` on
  Linux). That's the same shape as our OpenVPN and WireGuard tunnels: an
  interface we route chosen networks into. The virtual IP goes on it
  (`kernel-pfroute` on macOS, `kernel-netlink` on Linux).
- **One `charon-cmd` per attempt** — strongSwan's single-connection
  client, not the `charon` daemon, whose PID file path is fixed at build
  time (two tunnels couldn't run side by side). It takes the connection
  on its command line (`renderIKE`, `internal/tunnel/ikeconf.go`):
  - `--host`: the server, pinned (via direct) or its name;
  - `--identity` / `--remote-identity`: the profile's identifiers;
  - `--cert` / `--priv`: the login certificate and key; one `--cert` per
    CA (charon-cmd trusts every certificate it's given). A charon-cmd
    before 6.0 (Debian's and Ubuntu's 5.9) has no `--priv` — only `--rsa`,
    for RSA keys alone — so it gets `--p12`: a PKCS#12 with a fresh random
    password, which it asks for with `getpass`. With no terminal (charon-cmd
    runs in a session of its own, so even a dev daemon's isn't its) that
    reads stdin, where the daemon writes it. (5.9 doesn't try an empty
    password first.)
  - the profile's proposals;
  - `--remote-ts 0.0.0.0/0`, plus `::/0` when the tunnel routes IPv6 —
    which is also what decides the virtual IPs it asks for.
- Its own `strongswan.conf` (`STRONGSWAN_CONF`), in the tunnel's run
  directory (0700), so nothing from a system strongSwan applies:
  - exactly the plugins it needs (`load`). Only kernel-libipsec,
    socket-default and vici are marked critical: a critical plugin needs
    every feature it has, and pem's DSA or PGP keys, or kernel-netlink's
    IPsec (kernel-libipsec's instead), would fail the session. A missing
    essential one is named from the log instead;
  - its log on stderr (the tunnel's log), with the library one level
    deeper, where a missing plugin is named — and not to syslog, where the
    default loggers go;
  - `port = 0` / `port_nat_t = 0`: random IKE ports, no clash with
    anything else on 500/4500 (charon-cmd then talks to the server's
    4500 from the start);
  - `install_routes = no` — see below;
  - the VICI socket in the run directory;
  - no `resolve`/`osx-attr` plugin, so the server's DNS is ignored; no
    `updown` scripts.
- **Routes are the engine's alone.** Upstream, `kernel-libipsec` installs a
  route for every policy whatever `install_routes` says; for a
  `0.0.0.0/0` selector `kernel-pfroute` adds two /1 halves — a full
  tunnel. So:
  - the macOS charon-cmd RiftRoute ships is built with a small patch
    (`packaging/strongswan/`) making `kernel-libipsec` honour
    `install_routes = no`, as the kernel backends do; the patch ships
    with its sources, as the GPL asks;
  - on Linux (the distribution's charon-cmd, unpatched) its routes (a
    default route into the tunnel) go to a table of their own (52520)
    whose rule matches only packets carrying a firewall mark nothing sets
    (`kernel-netlink.fwmark = 0x7f52ea21/0xffffffff`), so no lookup ever
    reaches it. Its priority, after main's and default's, is a second line
    only: on its own, a rule after main still catches every lookup main
    can't answer (a host's IPv6 on a v4-only network, say — the review
    proved it, and the Docker test now checks it with main emptied).
- **ESP always in UDP.** `kernel-libipsec` has no raw ESP on macOS, and
  charon then forces UDP encapsulation (it reports NAT) — which also
  crosses networks that drop raw ESP.
- The daemon follows the session over **VICI** (strongSwan's control
  socket; the official Go client, `github.com/strongswan/govici`, MIT),
  polling `list-sas` every second: up means an established IKE_SA with
  an installed CHILD_SA; it gives the virtual IPs, the server and the
  byte counters.
- charon-cmd exits when its first attempt fails (it tries once), but not
  when a connection it made later drops (dead peer, the server deleting
  it): the session restarts it after 5 s without one.
- Keys: the certificate, key and CAs are written as PEM files (or the
  PKCS#12) (0600) into the run directory for the attempt and removed when
  it ends (and reaped at startup after a crash) — as openvpn's rendered
  config carries its inline keys. On Linux a daemon that dies takes
  charon-cmd with it (the parent-death signal), which deletes the
  connection with the server.
- charon-cmd sets its own timers (DPD 30 s, rekey 10 h, MOBIKE on); the
  profile's aren't applied.

**Where charon comes from:**

- **macOS:** RiftRoute ships its own, like openvpn:
  - a pinned, hash-checked strongSwan build over the same static OpenSSL
    (`scripts/build-strongswan.sh`, a CI job);
  - monolithic, with only the plugins listed below;
  - installed root-owned with the daemon, and kept current by the updater.
- **Linux:** the distribution's packages: `charon-cmd` plus the
  kernel-libipsec plugin (Debian/Ubuntu `charon-cmd libcharon-extra-plugins libstrongswan-standard-plugins strongswan-swanctl`,
  Fedora `strongswan strongswan-libipsec`), 5.9 or newer. The tunnel page
  says what to install, as it does for openvpn.

**Plugins:**

- `openssl`, `nonce`, `pem`, `pkcs1`, `pkcs8`, `x509`, `pubkey`,
  `constraints`, `revocation`;
- `kernel-libipsec` and `kernel-pfroute` / `kernel-netlink`;
- `socket-default`, `vici`;
- `eap-identity` and `eap-mschapv2` (for username/password profiles).

The PKCS#12 is decoded in Go (`software.sslmate.com/src/go-pkcs12`, BSD-3,
which reads Apple's legacy encryption). Charon gets plain DER keys over
VICI, so it needs no `pkcs12` plugin and no OpenSSL legacy provider.

## Model

- A tunnel type `ikev2`. The config is the `.mobileconfig` itself: its
  text, kept like an `.ovpn`, write-only over the API.
- `ParseMobileconfig` finds the IKEv2 VPN payload, then:
  - the certificate its `PayloadCertificateUUID` names (PKCS#12 plus
    `Password`);
  - every root/intermediate CA payload.
- A signed (CMS) profile is unwrapped first.
- It refuses what it can't honor, saying why:
  - no IKEv2 payload (L2TP, Cisco IPSec, or a VPN type left for later);
  - a PKCS#12 it can't open.
- Mapping to charon:

| mobileconfig | charon (swanctl terms) |
|---|---|
| `RemoteAddress` | `remote_addrs` (resolved and pinned like other tunnels: via direct / default) |
| `RemoteIdentifier` | `remote.id` |
| `LocalIdentifier` | `local.id` |
| `AuthenticationMethod` Certificate | `local.auth = pubkey` with the PKCS#12's cert and key |
| server auth | `remote.auth = pubkey`, `remote.cacerts` = the profile's CAs (none: the system's, from its CA bundle) |
| `ServerCertificateCommonName` | not checked apart: the server must prove `RemoteIdentifier` with a certificate the CAs vouch for |
| `ExtendedAuthEnabled` + `AuthName`/`AuthPassword` | `eap-mschapv2` — later: charon-cmd asks for it on a terminal; refused at connect until then |
| `SharedSecret` | `psk` — later, likewise |
| `IKESecurityAssociationParameters` | `proposals`, e.g. `aes256gcm16-prfsha256-ecp384` |
| `ChildSecurityAssociationParameters` + `EnablePFS` | `esp_proposals`, e.g. `aes256gcm16-ecp384` |
| `LifeTimeInMinutes` | `rekey_time` (IKE and child) |
| `DisableMOBIKE` | `mobike` |
| `DeadPeerDetectionRate` None/Low/Medium/High | `dpd_delay` off / 30 min / 10 min / 1 min |
| `DisableRedirect` | ignore the server's redirect |
| (always) | `vips = 0.0.0.0, ::`, `remote_ts = 0.0.0.0/0, ::/0`, `start_action = none` |

- **State:**
  - connected when the CHILD_SA is up and the TUN holds the virtual IP
    (vetted like OpenVPN's pushed address; no virtual IP is refused);
  - reconnecting while charon-cmd is restarted, with backoff (2 s up to a
    minute);
  - failed after the attempt limit (6, for a tunnel that never connected),
    with the reason read from charon's output.
- **The certificate's expiry** shows on the card, with a warning under 14
  days. Importing a new profile replaces it.

## Everything else is the tunnels'

It gets:

- server pins (via direct);
- the vetting of its addressing;
- routes only while connected;
- profiles through it;
- When it's down (block or fallback);
- labels in the route lookup;
- resume after an update.

The driver seam (`driver{parse, engine, run}`) already carries two
protocols.

## Steps

1. **Parse** (this PR's start):
   - `ParseMobileconfig` → an IKEv2 config, with the PKCS#12 decoded;
   - the tunnel type, a config file recognized by `tunnel add` and the
     app, and an engine that says it isn't there yet;
   - tests against a generated profile (legacy and modern PKCS#12).
2. **The macOS engine:**
   - `scripts/build-strongswan.sh` (pinned, static OpenSSL, monolithic);
   - the CI job and the release assets (binaries and sources, as for
     openvpn);
   - install with the daemon; the updater keeps it current.
3. **The driver:**
   - charon-cmd supervision and VICI (done, with a fake for tests and
     `-provider fake`);
   - the Linux engine: detection and install help (done);
   - a real connection on Linux, in Docker (`test/ikev2-linux`, `make
     test-ikev2-linux`, a CI job): the daemon with Debian's charon-cmd
     (5.9), and with the 6.1 RiftRoute builds for macOS (`SWAN=6`, from the
     same source and patch), against a strongSwan server with a full
     tunnel, a virtual-IP pool and ECDSA certificates (done);
   - EAP and PSK profiles (later).
4. **The app and release:**
   - import `.mobileconfig` on the Tunnels page;
   - the certificate's expiry;
   - docs, review, release;
   - the user's test against their real server (office).
