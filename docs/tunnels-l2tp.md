# L2TP/IPsec tunnels — design

Status: in progress. It's built in steps, each its own PR, listed at the
end.

## What the user asked for

L2TP/IPsec, after WireGuard and IKEv2 (the protocol roadmap). Chosen on
2026-11-12:

- **The engine:** L2TP and PPP written in Go, inside the daemon, on a TUN
  device, as WireGuard runs (wireguard-go). IPsec comes from strongSwan.
- **Authentication:** an IPsec pre-shared key, and certificates, from the
  first release. The PPP login is a username and password.
- **L2TP without IPsec** is allowed, but only when the user says so
  explicitly; the tunnel's card then warns that nothing is encrypted.
- The final live test runs against the owner's own L2TP/IPsec server.

As with every RiftRoute tunnel, only the networks the user lists (and the
profiles sent into it) go through it, unless it carries all traffic
(docs/tunnels-full.md). The server's default route is never taken.

## Why L2TP and PPP in Go

L2TP/IPsec is three layers:

1. **IPsec**, in transport mode, between this machine and the server,
   covering only UDP port 1701. It encrypts; it routes nothing.
2. **L2TP** (RFC 2661) over that UDP: a control connection (a handful of
   messages with sequence numbers, acknowledgements and retransmission)
   and one session.
3. **PPP** inside the session: LCP, the login (PAP, CHAP-MD5 or
   MS-CHAPv2), and IPCP, which gives the address and the DNS servers.

The usual clients are `xl2tpd` + `pppd` (Linux) and Apple's `pppd` with its
L2TP plugin and `racoon` (macOS). In the daemon instead:

- **One implementation on both systems**, with the same errors: a
  rejected login, a server that never answers, an IPsec failure each say
  so, as the other tunnels do. pppd's are exit codes and log lines.
- **The interface is ours.** The engine creates the TUN (`utun` on macOS,
  `tun` on Linux) and puts the address PPP was given on it. Nothing adds a
  default route or changes DNS behind our back (pppd's `ip-up` scripts,
  `usepeerdns`). The DNS servers IPCP gives are read directly, as
  WireGuard's `DNS =` is.
- **No more programs to ship or trust.** pppd and xl2tpd aren't installed
  on most machines. On macOS Apple's `racoon` is deprecated, and running
  Apple's pppd outside its own controller is undocumented.
- **The protocols are small.** L2TP's control channel and PPP's LCP, IPCP,
  PAP and CHAP are simple state machines over small packets. MS-CHAPv2 is
  RFC 2759, with its test vectors. No MPPE: IPsec encrypts.

**What stays out of Go is IPsec.** IKE (IKEv1 Main Mode, Quick Mode,
NAT-T, certificates) is security-critical, as IKEv2 was. strongSwan does
it, as a separate program, as it does for IKEv2 tunnels.

## IPsec: strongSwan, in transport mode

charon-cmd, which IKEv2 tunnels use, can't do this. It builds only
tunnel-mode SAs (`MODE_TUNNEL`, hard-coded), and it has no plain IKEv1 PSK
profile (only `ikev1-xauth-psk`). And `kernel-libipsec`, IKEv2's userspace
ESP, supports tunnel mode only. So:

- **strongSwan's `charon`**, the IKE daemon, run by riftrouted. One
  instance holds every L2TP tunnel's connection, loaded and started over
  **VICI** (`load-conn`, `load-shared`, `initiate`, `terminate`) with the
  same Go client the IKEv2 tunnels use.
- **The kernel's IPsec, in transport mode** (`kernel-pfkey` on macOS,
  `kernel-netlink` on Linux). Its policy covers only UDP between this
  machine's address and the server's, port 1701: our L2TP socket's
  packets. Being policy-based is harmless at that width; it routes
  nothing.
- **IKEv1** (what L2TP/IPsec servers speak), Main Mode with a pre-shared
  key or certificates; IKEv2 transport mode where the server offers it.
  NAT-T always: ESP in UDP 4500 crosses NATs that drop raw ESP.
- **Where charon comes from:**
  - **macOS:** RiftRoute's own strongSwan build (`scripts/build-strongswan.sh`)
    gains the `charon` daemon with `kernel-pfkey` and `ikev1`, its PID and
    VICI socket in RiftRoute's run directory, installed root-owned beside
    charon-cmd.
  - **Linux:** the distribution's `charon` (`strongswan-charon`, or
    `charon-systemd`). To be settled in step 2:
    - a system strongSwan that's already running owns ports 500/4500 and
      the PID file;
    - RiftRoute could load its connections into that charon over its
      VICI socket, or decline and say why.
- **One charon, shared** (`internal/ipsec`), started with the first L2TP
  tunnel and stopped with the last. Two can't share a machine:
  - on macOS kernel-pfkey sets `net.inet.ipsec.esp_port`, a single
    system-wide setting, to its NAT-T port, and every PF_KEY socket hears
    every other's messages;
  - the `charon` binary's PID file path is fixed at build time.
- **Each tunnel's connection**, loaded over VICI as `rr-…`:
  - `mode = transport`;
  - `local_ts`/`remote_ts = dynamic[17/1701]`. The protocol is by number:
    a system without `/etc/protocols` (Debian slim) rejects `udp`;
  - `start_action`/`dpd_action`/`close_action = trap`. The policies stay
    while the connection is loaded, so an SA that drops (the server
    deleting it, DPD) is renegotiated by the next L2TP packet, which never
    leaves unencrypted. The Docker test cuts the SA from the server and
    checks the wire;
  - `encap = yes`;
  - IKE and ESP proposals from AES-GCM down to 3DES-SHA1/MODP-1024, which
    old servers still use;
  - the PSK is loaded for the server's address (Main Mode's identity),
    under its own id, and unloaded with the connection;
  - certificates: the PEM certificate and key, the CAs as `cacerts`.
  **IKEv1 signs both ways with the same kind of key:** an RSA client
  certificate against a server with an ECDSA key fails (AUTH_FAILED), as
  it does for any IKEv1 client.
- **Plugins:** `kdf` too. strongSwan 5.9's IKEv2 derives its keys through it
  (without it: "KDF_PRF … not supported").
- **Leftovers:**
  - a charon an earlier daemon left running (macOS: nothing ends a crashed
    daemon's children) is stopped through its PID file before a new one
    starts;
  - a policy a killed charon left is replaced by the next connection to
    that server (an update of the same selector).
- **Its own `strongswan.conf`**, as for IKEv2:
  - only the plugins it needs;
  - its log to the tunnel's log;
  - no `updown`;
  - `install_routes = no`;
  - no DNS plugins.

## L2TP and PPP: what the engine does

- **L2TP control** (RFC 2661, as a LAC):
  - SCCRQ, SCCRP and SCCCN set up the tunnel; ICRQ, ICRP and ICCN set up
    the session;
  - Ns/Nr sequencing, ZLB acknowledgements, retransmission (1 s doubling,
    5 tries);
  - HELLO keepalives both ways;
  - StopCCN and CDN with their result codes, turned into messages.
  - Hidden AVPs and tunnel authentication (a shared tunnel secret) are
    rare: refused with a clear error at first.
- **UDP 1701 on both ends.** Many servers expect the client's source port
  to be 1701 too. It's bound to this machine's address toward the server,
  which is also what the IPsec policy names.
- **PPP:**
  - **LCP:** MRU, magic number; echo replies; the server's
    authentication protocol accepted when it's one we do (PAP, CHAP-MD5,
    MS-CHAPv2) and naked toward MS-CHAPv2 otherwise; compression and
    callback rejected.
  - **The login:** MS-CHAPv2 checks the server's authenticator response,
    so a server that doesn't know the password can't pass as one. A
    rejection ends the session as "the server rejected the username or
    password", which a reconnect never retries (#37's lockout rule).
  - **IPCP:** asks for an address and the primary and secondary DNS
    servers (RFC 1877). The peer's address isn't routed: the interface
    is point-to-point.
  - **IPV6CP and CCP:** rejected (Protocol-Reject) in the first release.
    The tunnel has no IPv6; a full tunnel then blocks IPv6, as for the
    others.
- **The data path:** the TUN and the UDP socket, packets wrapped in PPP
  (protocol 0x0021) inside L2TP data messages. MTU 1400 by default,
  lowered to the MRU the server allows.

## Configuration

There's no standard L2TP file. A tunnel is made from:

- **an Apple `.mobileconfig`** with an L2TP VPN (`VPNType` `L2TP`: the `PPP`
  dictionary's server, account and password; the `IPSec` dictionary's
  `SharedSecret` or certificate, `LocalIdentifier`), which RiftRoute
  already parses for IKEv2;
- **or the fields directly** (CLI flags, a form in the app): server,
  username, password, and the IPsec pre-shared key or a certificate
  (PKCS#12), or "no IPsec".

The secrets are kept as the other tunnels' are (the store, 0600, never in
status or logs).

## Steps

1. **The L2TP and PPP engine** (`internal/l2tp`), no IPsec yet:
   - codecs and state machines, with unit tests;
   - MS-CHAPv2 against RFC 2759's vectors;
   - a Docker test: an `xl2tpd` + `pppd` server and the engine as client,
     over a Linux TUN.
2. **IPsec:**
   - charon over VICI, transport mode, PSK and certificates
     (`internal/ipsec`). Done: the Docker test runs IKEv1 with a PSK,
     IKEv1 and IKEv2 with certificates, and a wrong PSK, and checks that
     no L2TP crosses the wire unencrypted, before and after the server cuts
     the SA (42 checks, ALL PASSED);
   - the macOS build gains `charon` (kernel-pfkey, ikev1, its PID
     directory RiftRoute's).
3. **The driver:**
   - `TunnelL2TP` in the manager;
   - `.mobileconfig` L2TP and the flags;
   - the app's form and card (the "no IPsec" warning);
   - doctor;
   - full-tunnel support.
4. **Review, the live test** against the owner's server, and the release.
