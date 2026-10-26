# Full tunnel — design (proposal)

Status: routing (PR A) and DNS (PR B) built, below. The owner asked for it on
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
  - **Its own server with no path outside it:** between networks (the main VPN just went down, and the physical gateway isn't there yet) the server can't be pinned anywhere. The quarters would then carry the tunnel's own connection into itself. The owner's live test (2026-10-26) showed the result: the server answered through the tunnel, and WireGuard followed it to the tunnel's own address 10.72.242.1, a loop that hung the tunnel's stop. So until the server has a path, nothing goes in (it's on the card); set to block, the quarters are refused. One server with a path is enough: a name with an AAAA record on an IPv4-only network has no v6 path, but the tunnel connects over v4 (the review of c4e0736). An IPv6 server of a tunnel without IPv6 never counts: its v6 quarters are refused, not carried.
  - **WireGuard never follows its server into the tunnel:** an endpoint inside the tunnel's own network or at its DNS server is set back to the configured one (`wgSession.follow`).
  - **The guardrail:** `gateway-capture` refused any route holding the physical gateway, so 192.0.0.0/2 was refused. It now allows a route **wider than the gateway's connected network** (192.0.0.0/2 or 192.168.0.0/16 around a 192.168.1.0/24 LAN), since that network keeps winning for the gateway. A route as narrow as the LAN or narrower, or any one without a connected route holding the gateway (a read error included), is still refused.
  - `route explain` says "kept out of tunnel X" for such a pin, not "via tunnel X" (`RouteDecision.KeptOutOf`).
- **Another full tunnel already up:** the second one's quarters are taken, so it's blocked with the reason, like two tunnels listing the same network.

## Beside Tailscale's exit node (Linux)
- With its exit node on, every main-table route of RiftRoute's is copied into 5253, looked up at 5260, ahead of Tailscale's capture (#39). That includes a full tunnel's quarters.
- **The LAN problem** (review of step 1): the LAN's connected route isn't RiftRoute's, so it isn't copied. A quarter's copy then won over it: the router and the LAN went into the tunnel, or were refused while blocking.
- **The fix:** while a full tunnel's quarters are copied, a rule at 5259 (`FullTunnelMainRulePrio`) looks main up first, all but /2 and wider: `lookup main suppress_prefixlength 2`. The LAN, and every other narrower route in main, wins again. The rule goes with the copies.

## Known limits
- **A TAP main VPN:** pins go on-link into the main VPN's interface, so a TAP (broadcast) main VPN, which needs a next hop, would blackhole them. Main VPNs are TUN in practice; RiftRoute's own tunnels are TUN only.
- **A gateway outside the LAN** (an `onlink` default): no connected route holds it, so the gateway guardrail refuses the quarter that contains it. The tunnel is left out, which fails closed.
- **To check on a Mac:** link-local and multicast IPv6 (`fe80::/10`, `ff02::/16`) sit inside `c000::/2`, which is refused while a tunnel without IPv6 carries all traffic. macOS sends them by scoped routes, so they should be unaffected. Check `ping6 fe80::1%en0`, `dns-sd -B _airplay._tcp`, and AirDrop.

## IPv6 when the tunnel has none: blocked **(chosen)**

A full tunnel without an IPv6 address installs **reject** routes for the v6
quarters while it's connected, so IPv6 doesn't go around it. More specific v6
routes still win: the LAN's, link-local, other VPNs'. The tunnel's card says
so.

## When it's down

- **fallback** (default): the quarters go, and traffic takes its usual path, usually the main VPN.
- **block:** the quarters become reject routes while it should be up but isn't. Only the more specific routes still go anywhere, so it works as the tunnel's own kill switch. The existing when-down machinery already does this per route.
  - Tailscale's own connections (Linux: its marked packets, looked up in main) ride the full tunnel while it's up. While it blocks they're refused too, so Tailscale's peers and DERP servers on the internet drop until it's back, as with wg-quick.

## DNS: the tunnel's own **(chosen)**

RiftRoute never changed the system's DNS until now (split DNS aside). A full
tunnel does, while it's connected, and puts it back when it isn't.

### Getting the tunnel's DNS servers
| Type | Where they come from |
|---|---|
| OpenVPN | the server's pushed `dhcp-option DNS` / `dns server`. In full mode the pull-filter for them goes, and they're read from openvpn's `PUSH_REPLY` log line (verb ≥ 3). openvpn applies nothing itself: `script-security 1`, no up script. |
| WireGuard | the configuration's `DNS =`, ignored today, used in full mode |
| IKEv2 | the server's INTERNAL_IP4/6_DNS, read from charon-cmd's log: its `resolve` plugin logs each one ("installing DNS server …"), from 5.9 to 6. See below for how it's kept from installing them. The macOS build adds `--enable-resolve`. |
| L2TP (later) | pppd's `usepeerdns` values |

- **IKEv2's resolve plugin** is loaded only for a full tunnel's session, and never where it could change the system's DNS:
  - From strongSwan 5.9.9 it takes `resolvconf.path`, and given one, runs it through a shell instead of resolvconf(8). RiftRoute gives it `:`, which does nothing. (A path that names nothing, as first built, also made it skip its file, so no DNS was read.)
  - Before 5.9.9 (Debian 12's 5.9.8) it ignores the setting and runs `/sbin/resolvconf` whenever that exists. With classic resolvconf or openresolv, that would put the IKEv2 server's DNS first in the system's resolv.conf (the review proved it in Docker). So beside a `/sbin/resolvconf` it isn't loaded: the server's DNS isn't read, and the card says to set some. Without one it writes its `file`, a private one in the run directory, never `/etc/resolv.conf`.
- **Checks:** only addresses, at most 4 per family, never loopback or unspecified. The user can override them ("use these DNS servers").
- **Fallback:** a full tunnel with no DNS from its server keeps the system's DNS and says so.

### Applying them
- **Linux:** systemd-resolved, on the tunnel's link:
  - `resolvectl dns <iface> <servers>`, `resolvectl domain <iface> '~.'`, `resolvectl default-route <iface> true` (systemd before 240 has no `default-route`; `~.` alone makes it the default);
  - proved with systemd-resolved 255 in Docker (review): names go to the tunnel's link only, and a split-DNS domain on another link still goes there;
  - **another link that also has `~.`** (Tailscale overriding the local DNS, a NetworkManager VPN taking all traffic) gets every name too: resolved asks both, and nothing outranks it. RiftRoute doesn't change links that aren't its own; the card says "DNS also goes to <link>", looked for again every 30 s while it's applied (Tailscale started later);
  - all of it reverted (`resolvectl revert`) when the tunnel goes. Without systemd-resolved, the tunnel's DNS isn't applied, and the card and doctor say why. RiftRoute never rewrites `/etc/resolv.conf`.
- **macOS: the primary service's DNS, swapped and restored, as Tunnelblick does.** DNS servers set by hand (System Settings) are the service's `Setup:` DNS, which outranks `State:`: the owner's live test showed the State swap doing nothing on such a service (Ethernet with 1.1.1.1). Its `Setup:` key is swapped too, in the dynamic store only, never in the saved preferences, with a backup of its own (`DNSSetupBackup/<service>`). configd puts the saved one back whenever the preferences are applied; the recheck takes that as the owner's rewrite. The spike on the owner's Mac (2026-10-26, macOS 15.7.2, behind an NE-based main VPN) settled it:
  - **A resolver of RiftRoute's own for every domain** (`SupplementalMatchDomains ""`) is exactly how the NE VPN there declares its DNS. Ours, from a service that isn't primary, always ranked behind it: order 104800 vs 103400, and still behind with numeric `SupplementalMatchOrders` or `SearchOrder`. macOS orders "every domain" resolvers by service rank. **Rejected.**
  - **Swapping the primary service's `ServerAddresses`** (`State:/Network/Service/<primary>/DNS`) made ours the default resolver at once. **Chosen.**
  - **…and its shape.** The owner's live test showed the servers alone aren't enough behind an NE VPN. Its resolver for every domain is "Supplemental" and scoped to its interface (`if_index utun8`), and macOS judges reach through that interface. The tunnel's server was "Not Reachable" there, so mDNSResponder sent nothing and every lookup timed out. A diagnostic run tried the variants:

    | Variant | Reach | Lookups |
    |---|---|---|
    | the servers only | Not Reachable | timed out (no query anywhere) |
    | + `InterfaceName` = the tunnel's | still scoped to utun8 | answered by the main VPN's DNS |
    | + no `SupplementalMatchDomains` | Not Reachable | failed |
    | **both** | **Reachable, unscoped** | **answered at once, the query on the tunnel's interface** |

    So the swap of such a dictionary (a VPN's: one with match domains or an `InterfaceName` of its own) also sets `InterfaceName` to the tunnel's interface and drops `SupplementalMatchDomains`/`SupplementalMatchOrders`. The resolver is then the plain default one. A restore puts them back from the backup (`""`, every domain, included). A plain primary's dictionary (Wi-Fi, Ethernet: servers only) gets the servers alone, as Tunnelblick does; the live test checks it with the main VPN off.
  - Neither touched a route; the only differences were cloned cache entries.
  - `OverridePrimary` (vpnc-script) wasn't tried: making our service primary can move the default route.
- **How the swap is made safe:**
  - **Backup:** the primary service's DNS dictionary is copied to `State:/Network/RiftRoute/DNSBackup/<service>` before it's changed, only the first time. Then only `ServerAddresses` is replaced (with the search domains, if the tunnel gives some).
  - **Holding:** whoever owns that service can rewrite it (DHCP renewal, the NE VPN reconnecting), and the primary service can change (Wi-Fi ↔ Ethernet, the main VPN up or down). Every 5 s while the swap is in place, RiftRoute checks it:
    - rewritten by its owner: take the new value as the backup, and apply again (logged);
    - rewritten 5 times in 10 minutes: let the owner have it. Held against it, the DNS would flip back for seconds at a time, with a cache flush each time. The swap stops, what still holds the tunnel's servers goes back, RiftRoute's keys go, and the card shows only why (no servers in use), until the tunnel connects again;
    - a new primary: restore the old one, then apply to the new.
  - **Restore** (the tunnel down, disconnected, panic, the daemon stopping): the backup goes back **only if the service still holds RiftRoute's servers**. A value its owner wrote since is theirs, and is left. Only what the swap changed goes back: the servers, and the search domains if it set some, into the dictionary as it is now, so what else the owner changed meanwhile stays. (The whole backup goes back if a value isn't plainly an address or a name.) Then the backup key goes. mDNSResponder's cache is flushed after each change.
  - **Beside Tailscale:** when Tailscale's service is the primary (its exit node on), the swap replaces its `ServerAddresses` (100.100.100.100), which its supplemental match domains share, so MagicDNS names go to the tunnel's servers too. Two catch-alls at once is rare.
  - The backup lives in State:, so it survives a daemon crash (until reboot, when the swap is gone too). The daemon restores leftovers at start, before tunnels come up.
- **A change that fails** (macOS between networks has no primary service; systemd-resolved restarting) is tried again on its own: in 5 s, doubling up to a minute, until it works or isn't wanted any more. Not where nothing will change (no systemd-resolved), and each failure is logged once.
- **Crash safety:** the keys and links are RiftRoute's by name.
  - At start, the daemon removes any left from a run that didn't end cleanly, before the tunnels come up. So a crash can't leave the system asking a DNS server that's gone.
  - Panic and `daemon uninstall` remove them too.
  - On macOS the keys are the system's, not the database's: a second daemon (`-provider auto -db /tmp/x`, a test) restores the service daemon's swap at its start. Test beside the installed daemon only with `-provider fake`, or with the installed one stopped.
- **Routes:** the tunnel's DNS servers go into it by host routes of their own, so a narrower route (an exclude profile's network, another VPN's) doesn't take them. Not one on the LAN (the router as DNS), a tunnel's server, or IPv6 the tunnel can't carry; and an exclude profile's route for that very host still wins.
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
2. **Spike, macOS DNS (done, 2026-10-26):** two rounds on the owner's Mac. The swap was chosen; see "Applying them".
3. **PR B, DNS (built):** `internal/tunneldns` (the macOS swap, systemd-resolved, a fake), capture in `internal/tunnel/dnscapture.go`, the manager's `syncDNS` after each tunnel apply, `revertDNS` on panic and exit, `Recover` at the daemon's start.
   - capture per type;
   - apply and revert on Linux (systemd-resolved) and macOS (dynamic store);
   - start-up cleanup and panic;
   - doctor;
   - Docker tests on Linux, plus the owner's live test on macOS;
   - review.
4. Release, then L2TP.
