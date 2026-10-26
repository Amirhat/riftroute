# Full tunnel — design (proposal)

Status: routing built (PR A, below). DNS is next. The owner asked for it on
2026-10-25 and chose the options marked **(chosen)**. It's built before L2TP,
so L2TP gets it from the start.

## What the owner asked for

A tunnel that carries **all** traffic, like an ordinary VPN, except:
- what the profiles route elsewhere: exclude profiles around the VPN, include profiles into the main VPN, tunnel-mode profiles into other tunnels;
- what other VPNs route: their networks, Tailscale's;
- what RiftRoute deliberately keeps off a tunnel: the router's network, the tunnel's own server, other tunnels' servers, the watchdog's anchors.

Today a tunnel carries only the networks listed for it, and `0.0.0.0/0` is
refused ("list the networks behind it instead").

## Routing: four quarters, and the most specific route wins

- **Routes:** a full tunnel's routes are the four quarters of the address space, `0.0.0.0/2`, `64.0.0.0/2`, `128.0.0.0/2` and `192.0.0.0/2`, on-link into its interface. With IPv6, the same for `::/0`.
- **Why quarters, not a default or two halves:**
  - The kernel always takes the most specific route. Every exception above is more specific than a /2: exclude routes, other VPNs' networks, other tunnels' routes, the LAN's connected route, server pins (/32). So they keep winning without being listed.
  - A main VPN's catch-all is a default (Windscribe on macOS) or the two /1 halves (OpenVPN's `redirect-gateway def1`). Both are wider than a /2, so the full tunnel takes over "everything" from it, and leaves its specific networks alone.
  - The existing default route stays where it is. When the tunnel drops, its quarters go and traffic falls back to it.
- **Include profiles still go into the main VPN:**
  - macOS: PF `route-to` runs before routing.
  - Linux: the rules at 5252 look up their own table before main.
- **Tailscale** (#39):
  - its networks are more specific on macOS, and looked up first (5251) on Linux;
  - with its exit node on, the quarters are copied past it (`BesideTailscale`), like every main-table route.
- **Linux beside a policy-routed VPN** (wg-quick with all traffic): wg-quick adds `lookup main suppress_prefixlength 0` ahead of its own table. That ignores only /0 routes in main, so the quarters still win. To be proven in the Docker suite.
- **Keep-outs: pinned, never carved.**
  - Carving a quarter around a kept address (as #38 does for listed routes) would make its pieces narrower than the profile and VPN routes inside it, and take their traffic. The first run on the demo daemon showed it: a /13 piece beat an exclude profile's 10.0.0.0/8.
  - So a quarter always goes in whole. What it mustn't carry gets a host route along its **usual path**, the main VPN's catch-all (on-link into its interface) or else the physical gateway (`fullTunnelPins`):
    - tunnels' servers, which no pin already holds;
    - the watchdog's anchors;
    - while it blocks (down), the resolvers it needs to connect again.
  - What a narrower route already holds needs nothing: the router's network, another VPN's network (in `Occupied`).
  - The main VPN's catch-all is its default or its two /1 halves (`resolveVPN`, which now recognizes `redirect-gateway def1`), and never one of RiftRoute's tunnels.
  - **The guardrail:** `gateway-capture` refused any route holding the physical gateway, so 192.0.0.0/2 was refused. It now allows a route **wider than the gateway's connected network** (192.0.0.0/2 or 192.168.0.0/16 around a 192.168.1.0/24 LAN), since that network keeps winning for the gateway. A route as narrow as the LAN or narrower, or any one without a connected route holding the gateway (a read error included), is still refused.
  - `route explain` says "kept out of tunnel X" for such a pin, not "via tunnel X" (`RouteDecision.KeptOutOf`).
- **Another full tunnel already up:** the second one's quarters are taken, so it's blocked with the reason, like two tunnels listing the same network.

## IPv6 when the tunnel has none: blocked **(chosen)**

A full tunnel without an IPv6 address installs **reject** routes for the v6
quarters while it's connected, so IPv6 doesn't go around it. More specific v6
routes still win: the LAN's, link-local, other VPNs'. The tunnel's card says
so.

## When it's down

- **fallback** (default): the quarters go, and traffic takes its usual path, usually the main VPN.
- **block:** the quarters become reject routes while it should be up but isn't. Only the more specific routes still go anywhere, so it works as the tunnel's own kill switch. The existing when-down machinery already does this per route.

## DNS: the tunnel's own **(chosen)**

RiftRoute never changed the system's DNS until now (split DNS aside). A full
tunnel does, while it's connected, and puts it back when it isn't.

### Getting the tunnel's DNS servers
| Type | Where they come from |
|---|---|
| OpenVPN | the server's pushed `dhcp-option DNS` / `dns server`. In full mode the pull-filter for them goes, and they're read from openvpn's `PUSH_REPLY` log line (verb ≥ 3). openvpn applies nothing itself: `script-security 1`, no up script. |
| WireGuard | the configuration's `DNS =`, ignored today, used in full mode |
| IKEv2 | the server's INTERNAL_IP4/6_DNS. charon-cmd's `resolve` plugin, pointed at a private file under the tunnel's state directory (`charon-cmd.plugins.resolve.file`), writes them there for the daemon to read. The system's resolver is never touched. |
| L2TP (later) | pppd's `usepeerdns` values |

- **Checks:** only addresses, at most 4 per family, never loopback or unspecified. The user can override them ("use these DNS servers").
- **Fallback:** a full tunnel with no DNS from its server keeps the system's DNS and says so.

### Applying them
- **Linux:** systemd-resolved, on the tunnel's link:
  - `resolvectl dns <iface> <servers>`, `resolvectl domain <iface> '~.'`, `resolvectl default-route <iface> true`;
  - on the other links, `default-route false` while it's up, so queries don't also leave there;
  - all of it reverted (`resolvectl revert`) when the tunnel goes. Without systemd-resolved, the tunnel's DNS isn't applied, and the card and doctor say why. RiftRoute never rewrites `/etc/resolv.conf`.
- **macOS:** through the dynamic store, as other VPN clients' scripts do (vpnc-script, Tunnelblick):
  - `State:/Network/Service/riftroute-<name>/DNS` (ServerAddresses);
  - `State:/Network/Service/riftroute-<name>/IPv4`, with the tunnel's interface and `OverridePrimary`, so its DNS becomes the default resolver;
  - removed when it goes.
  - To be proven first on the owner's Mac (spike below): that `OverridePrimary` on a utun with no router changes the resolver and not the routing table; that split DNS (`/etc/resolver/*`) and the wildcard loopback resolver still win for their domains; and that Wi-Fi changes don't undo it.
- **Crash safety:** the keys and links are RiftRoute's by name.
  - At start, the daemon removes any left from a run that didn't end cleanly, before the tunnels come up. So a crash can't leave the system asking a DNS server that's gone.
  - Panic and `daemon uninstall` remove them too.
- **Kill switch:** unchanged. The tunnel's DNS servers are reached through the tunnel.

### Order with split DNS and wildcard learning
- Split DNS routes still win for their domains: they're more specific (macOS resolver files, systemd-resolved routing domains).
- Wildcard learning's loopback resolver keeps answering its domains.
- Everything else goes to the tunnel's DNS.

## Interface
- **CLI:**
  - `riftroute tunnel add <name> <file> --all-traffic [--dns 10.8.0.1,…]`;
  - `tunnel edit --all-traffic=false`;
  - `--route` still works beside it, but its routes are inside the quarters anyway.
- **App, Tunnels → editor:**
  - "Send: only these networks | all traffic, except…", with a short line on what stays outside;
  - the DNS servers in use, or why none.
- **Card, status and doctor:**
  - "all traffic" and the DNS in use;
  - IPv6 blocked;
  - what's kept out.
- **Dashboard:** with a full tunnel connected, the VPN card says most traffic goes through it.
- **API:**
  - `TunnelSpec.AllTraffic bool`, `TunnelSpec.DNS []string`;
  - `TunnelStatus.AllTraffic`, `TunnelStatus.DNS` (in use), `TunnelStatus.DNSNote`.

## Telemetry
Not in the first version: the report's schema is fixed on both ends, and a
new count needs a server release first.

## Plan
1. **PR A, routing (built):**
   - the quarters, v6 blocking, `AllTraffic` in the spec, the store, the API, the CLI and the app;
   - status;
   - the Docker suites: OpenVPN and IKEv2 on Linux beside a full-tunnel main VPN, wg-quick-style;
   - review.
2. **Spike, macOS DNS** (the owner runs a script on the Mac): `OverridePrimary` behaviour, as listed above.
3. **PR B, DNS:**
   - capture per type;
   - apply and revert on Linux (systemd-resolved) and macOS (dynamic store);
   - start-up cleanup and panic;
   - doctor;
   - Docker tests on Linux, plus the owner's live test on macOS;
   - review.
4. Release, then L2TP.
