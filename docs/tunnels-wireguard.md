# WireGuard tunnels — design

Status: plan, for the release after 0.3.0 (OpenVPN tunnels).

A WireGuard tunnel is a split tunnel like an OpenVPN one: only the networks the
user lists go in, the main VPN keeps the default route and DNS. Everything the
tunnel manager already does — definitions and secrets, the state machine,
pinning the server (`via direct`), applying routes through the Apply Protocol,
vetting the tunnel's addressing, resume after an update restart, doctor — is
shared. What differs is how a connection is run, so that part moves behind a
per-protocol **driver**, and WireGuard is the second driver.

## Why WireGuard runs inside the daemon

`golang.zx2c4.com/wireguard` (wireguard-go, MIT) runs in the daemon's own
process: no external program, so none of openvpn's problems exist:

- nothing to ship or install, and no root-run binary whose ownership has to be
  checked;
- no management socket, no orphan process — if the daemon dies, its tun
  device closes with it and the kernel removes the interface and its routes;
- one implementation on macOS (utun) and Linux (`/dev/net/tun`). Kernel
  WireGuard on Linux can come later as an optimisation behind the same driver.

The cost is binary size (a few MB) and throughput below kernel WireGuard on
Linux — fine for a split tunnel to private networks.

## Step 1 — the driver seam (no behaviour change)

`internal/tunnel` today is OpenVPN-shaped: `Manager.run`/`handle` speak the
management protocol. They move into an OpenVPN driver:

```go
// Driver runs one protocol's connections.
type Driver interface {
    Type() domain.TunnelType
    Engine() domain.TunnelEngine          // can it run here; how to fix it
    // Parse checks a definition's config (the allowlist, for OpenVPN) and
    // says what the manager shows and pins.
    Parse(config string) (Parsed, error)
    // Run is one session, until ctx ends or it fails; it reports through s.
    Run(ctx context.Context, s *Session) error
}

type Parsed interface {
    Servers() []string   // "host:port/proto", for display
    Remotes() []Remote   // what to resolve and pin (via direct)
    NeedsAuth() bool
    Ignored() []string   // what was dropped (pushed/declared DNS, routes, …)
}
```

`Session` carries the definition and its secrets, the resolved remotes, and
the callbacks the manager's state machine is built on: `Connecting(detail)`,
`Connected(iface, nets, localIP, server)`, `Reconnecting(reason)`,
`Failed(err)`, `Bytes(in, out)`, `Log(line)`. The manager keeps everything
else: `Connected` still goes through `vetAddressing` before any route is
applied.

`domain.TunnelType` gains `wireguard`; the API, CLI and app pick the driver by
it. Existing OpenVPN definitions are unchanged (`type: openvpn`).

## Step 2 — the WireGuard driver

**Config**: the standard `wg-quick` file every provider hands out.

| Key | Use |
|---|---|
| `[Interface] PrivateKey` | secret — kept in the root-only store, never returned |
| `Address` | the tunnel's own addresses; vetted like pushed addressing (a wide network is refused) |
| `MTU` | optional, default 1420 |
| `DNS`, `Table`, `PreUp/PostUp/PreDown/PostDown`, `SaveConfig` | **ignored** (shown as ignored): RiftRoute owns routes and DNS, and runs no scripts |
| `ListenPort`, `FwMark` | ignored (a client doesn't need them) |
| `[Peer] PublicKey`, `PresharedKey` (secret), `Endpoint`, `PersistentKeepalive` | used |
| `AllowedIPs` | used **only** for WireGuard's cryptokey routing (which peer a packet belongs to, what it accepts) — **never turned into routes**; `wg-quick` does that, and that is exactly what takes over the default route |

Multiple peers are allowed; the endpoints are all pinned (via direct).

**Session**:

1. Resolve and pin the endpoints to the physical gateway (via direct), as for
   OpenVPN.
2. `tun.CreateTUN("utun", mtu)` (macOS) / `tun.CreateTUN("rr-<name>", mtu)`
   (Linux) — the daemon is root.
3. Assign `Address` to the interface (macOS `ifconfig … inet A A netmask …`,
   `inet6 … prefixlen …`; Linux netlink/`ip addr`), bring it up.
4. `device.NewDevice(tun, conn.NewDefaultBind(), logger)`; `IpcSet` with the
   private key, peers, PSKs, keepalives, and AllowedIPs; `Up()`.
5. **Connected** once the first handshake completes (`last_handshake_time`
   from `IpcGet`, polled); **reconnecting** when the last handshake is older
   than 180 s (WireGuard's reject-after time); **failed** when no handshake in
   the first 90 s (with the likely cause: endpoint unreachable — another VPN's
   firewall — or a key the server doesn't know).
6. Bytes from `rx_bytes`/`tx_bytes`.
7. Stop: `device.Close()` closes the tun; the manager withdraws the routes.

**Endpoint changes**: an endpoint given by name is re-resolved when handshakes
stop, and the device updated (`IpcSet endpoint=`) and re-pinned — the same
rule as OpenVPN's re-resolve, without a restart.

**Tests without root**: wireguard-go's `tun/tuntest` gives an in-memory tun;
two in-process devices (the driver, and a test "server") handshake over
loopback UDP, so the whole session — handshake, connected, bytes, stale
handshake → reconnecting, stop — runs in `go test` on any machine. The
address assignment and `CreateTUN` are behind a small seam, faked in tests.

## Step 3 — app and CLI

- `riftroute tunnel add <name> <file.conf> --route …` detects WireGuard by the
  file's `[Interface]`; `--type` overrides.
- The Tunnels page: a type chooser, the import dialog accepts `.conf`, the card
  shows the last handshake and the peer instead of openvpn's phase.
- No engine banner: WireGuard is built in (the engine is always available).

## Step 4 — review and release

As for OpenVPN: an adversarial review (brief for the review session), then a
release — delivered by the updater to both the daemon and the app.

## Later

- Kernel WireGuard on Linux (wgctrl, MIT) when the module is loaded: faster;
  wireguard-go stays the fallback.
- The same driver seam takes IKEv2/IPsec (strongSwan as a separate process,
  like openvpn), L2TP/IPsec and OpenConnect (which also speaks Fortinet's
  protocol).
