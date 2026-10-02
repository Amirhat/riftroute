# Tailscale — design (proposal)

Status: proposal, for the owner's approval before any code. The owner chose
both: RiftRoute must **live beside a Tailscale already on the machine** without
breaking it, and **send chosen networks through Tailscale** as it does through
its own tunnels.

## What Tailscale does to a machine

| | Linux (`tailscaled`) | macOS (App Store / standalone app, or open-source `tailscaled`) |
|---|---|---|
| Interface | `tailscale0` | a `utun` |
| Addresses | `100.64.0.0/10` (CGNAT) and `fd7a:115c:a1e0::/48` | same |
| Routes | **table 52**, not main: tailnet peers, accepted subnet routes, the exit node's default | the main table, into its `utun` |
| Policy rules | 5210 (its own packets, fwmark `0x80000/0xff0000`) → main; 5230 → default; 5250 → unreachable for its own; **5270: everything → table 52** | — (no policy routing) |
| DNS | MagicDNS at `100.100.100.100`, through systemd-resolved or `/etc/resolv.conf` | MagicDNS at `100.100.100.100`, as a scoped resolver |
| Firewall | `ts-input`/`ts-forward`/`ts-postrouting` chains | — |
| Its own traffic | UDP 41641 to peers, DERP relays over TCP 443/UDP 3478 | same |

RiftRoute's own pieces that meet these:
- On Linux, include mode's rules sit at priority **5252**, *between* Tailscale's 5250 and 5270. Its fwmark `0x5252` doesn't overlap Tailscale's mask `0xff0000`.
- Exclude routes, tunnel routes and pins are in the **main** table, which on Linux is looked up only after Tailscale's 5270.
- The kill switch (PF, nftables) fences egress to the VPN's interface.
- The tunnel carve keeps resolvers and others' routes out (#38).

## Part A — beside a Tailscale already running

What breaks today, and what to do:

1. **Linux: an include profile can take tailnet traffic.** Its rules at 5252 are matched before Tailscale's 5270, so a profile listing `100.0.0.0/8`, or an app rule (fwmark: *any* destination), sends tailnet and MagicDNS traffic into the main VPN.
   - *Do:* read table 52 (and Tailscale's well-known ranges) as "someone else's", and cut include rules around them, as they're cut around live tunnels (`aroundTunnels`).
   - App rules can't be cut by destination. Add a rule *before* 5252 sending Tailscale's ranges to table 52: `to 100.64.0.0/10 lookup 52` at 5251, and the same for its v6 /48. The doctor reports it.
2. **Linux: with an exit node, exclude profiles stop working.** Rule 5270 sends everything to table 52, whose default is the exit node, so RiftRoute's bypass routes in main are never consulted.
   - *Do:* when Tailscale's rule 5270 is there, put exclude destinations into a table of RiftRoute's own, looked up by a rule *before* 5270 (e.g. 5260 `to <dst> lookup 5253`). This is the same machinery include mode uses, the other way round.
3. **Tunnels and Tailscale's routes.**
   - On Linux a RiftRoute tunnel route that Tailscale also routes (an accepted subnet route) never takes effect, because table 52 wins.
   - On macOS the more specific route wins, whoever's it is.
   - *Do:*
     - list table 52 (Linux) with main as `Occupied`, so the carve keeps Tailscale's networks out, as other VPNs' are;
     - keep `100.64.0.0/10`, `fd7a:115c:a1e0::/48` and `100.100.100.100` protected like a resolver;
     - say on the tunnel's card when Tailscale routes part of a destination.
4. **The kill switch.** It would cut Tailscale (its interface, UDP 41641, DERP).
   - *Do:* detect Tailscale, and offer "keep Tailscale working" (allow its interface and its own connection, as for a VPN client's helpers).
   - Or, when Tailscale's exit node *is* the main VPN, fence to `tailscale0`/its `utun` like any VPN.
5. **Which VPN is "the" VPN.** With an exit node on, Tailscale is the main VPN, and the dashboard, the VPN detection and include mode's next hop should say so.
   - *Do:* detect it: Linux by table 52's default route and rule 5270; macOS by the default route into its `utun`.
6. **Detection and display.**
   - Interface `tailscale0`, or a `utun` holding a `100.64.0.0/10` address.
   - `tailscale status --json` when the CLI is there (read-only, with a timeout, as the user): tailnet name, exit node, accepted routes, MagicDNS.
   - The dashboard shows "Tailscale: connected (exit node …)", and the doctor lists conflicts.

Everything in A is detection plus routing rules RiftRoute already knows how to make. It never runs or reconfigures Tailscale.

## Part B — chosen networks through Tailscale

Two ways. They're not exclusive, but the order matters:

**B1. Through the Tailscale already running** (the common case: the user has Tailscale and wants, say, `10.20.0.0/16` behind a tailnet node, or one site through an exit node, without sending everything there).
- A tunnel of type `tailscale` with no profile of its own. Its "interface" is Tailscale's, and its routes are the networks the user lists.
- **A tailnet node's subnet** that Tailscale accepts (`--accept-routes`): Tailscale already routes it, so RiftRoute only shows it.
  - If Tailscale *doesn't* accept routes, RiftRoute can't make WireGuard carry them: Tailscale's peer AllowedIPs decide what it sends.
  - So B1 for subnets is "turn on accept-routes in Tailscale". RiftRoute says so, and never changes Tailscale's settings itself.
- **Through an exit node, for chosen destinations only.** Tailscale has no per-destination exit node. Setting one sends everything, and RiftRoute would then have to exclude the rest (Part A, item 2) — "exit node with exceptions".
  - This works with A's machinery: exit node on in Tailscale, and RiftRoute's exclude profile for "everything except these".
  - It's a profile recipe rather than a new tunnel type.
- *So B1 is mostly A plus guidance:* little new code, and nothing that fights Tailscale.

**B2. RiftRoute's own Tailscale node** (no Tailscale on the machine, or the user wants a second identity), like openvpn and charon-cmd.
- **Engine:** the open-source `tailscaled` (BSD-3), shipped as a helper like charon-cmd (updated with the daemon, its source and license in the release).
  - It has its own state dir, socket and port.
  - Linux: its own TUN (`rrts0`). macOS: a `utun`.
  - `--accept-dns=false`, no exit node, and RiftRoute routes only the networks listed into its interface, as with WireGuard.
- **Login:** an auth key (`tskey-…`, stored like a password, write-only), or the interactive login URL shown in the app and the CLI, and the node approved in the admin console.
- **The hard part:** on Linux, two `tailscaled`s on one machine both want table 52 and rules 5210–5270, and their netfilter chains. Ours must run with
  - its own table and rule priorities (`tailscaled` has no flags for them, though it has `--netfilter-mode=off` and `--router` options), or
  - `--tun=userspace-networking` (no kernel routes: a SOCKS5/HTTP proxy, which doesn't fit RiftRoute's route-based model), or
  - Tailscale's `tsnet` / `wgengine` linked into the daemon on RiftRoute's own TUN (as WireGuard is), which needs a careful look at what it pulls in.
- *Effort:* the largest of all. A real engine, packaging and signing, login UX, and the two-daemon problem.

## Recommendation
1. **Part A first.** It fixes real breakage: an include profile taking the tailnet, exclude profiles dead under an exit node, and the kill switch cutting Tailscale. It's detection and rules RiftRoute already has, and it stops RiftRoute and Tailscale from fighting.
2. **Then B1 as guidance in the UI:**
   - show what Tailscale routes;
   - "send these through Tailscale" means accept-routes for subnets;
   - "exit node with exceptions" is a profile recipe.
3. **B2 only if it's still wanted after that.** Before building it, a spike on `tsnet`/`wgengine` on our own TUN versus a second `tailscaled`, with a short report.

Tests: Docker (Linux) with a real `tailscaled` needs a tailnet. Use a
Headscale container (open-source control server) as the tailnet, with two
nodes, a subnet router and an exit node. On macOS, the user tests live, as
for IKEv2.
