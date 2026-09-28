# When a tunnel is down — design

Status: implemented for the release after 0.4.0, with profiles through a
tunnel. Where the code differs from the plan below, it says so.

## What the user asked for

> An option: when the connection drops, the profiles and IPs that go
> through the tunnel are either **blocked until it's back**, or go **the
> system's usual path**.

So this is a per-tunnel setting, **When down**, with two values:

- `fallback` (default): while the tunnel is down, its destinations take
  whatever path they'd take without it (usually the main VPN).
- `block`: while the tunnel should be up but isn't, its destinations are
  refused. Apps get "no route to host" at once, rather than a connection
  that hangs, and nothing leaks out another way.

It covers everything the tunnel routes: its own route list, and the
destinations of the tunnel-mode profiles that point at it.

## When "down" blocks

A block-mode tunnel blocks while it is **wanted** and not connected.
"Wanted" means someone asked for it to be up and nobody has taken it down
since:

| State | fallback | block |
|---|---|---|
| connected | into the tunnel | into the tunnel |
| connecting (after Connect, auto-connect, a resume) | usual path | **blocked** |
| reconnecting (the connection dropped) | usual path | **blocked** |
| failed (gave up, or ended on its own) | usual path | **blocked** until Disconnect or a new Connect |
| disconnected by the user | usual path | usual path |
| after a panic | usual path | usual path |
| deleted | usual path | usual path |

- **Disconnect** is the way out: a failed block-mode tunnel keeps blocking
  until the user disconnects it (which clears the failure) or it connects.
- **A panic** takes every tunnel down as a disconnect and clears "wanted",
  so nothing blocks afterwards. That's the panic button's promise: back to
  the baseline.
- **A daemon restart into an update** (the one that reconnects tunnels
  afterwards) keeps the block. The tunnel is going to come back, so its
  destinations stay blocked while the daemon is gone. A plain daemon stop
  lifts it.
  - *As built:* **a rollback** lifts it too
    (`RememberForRestart(keepBlocks: false)` when the updater says
    `RollingBack`). The previous version may not know reject routes: its
    startup would forget their records, and on macOS leave them owned by
    nothing. Connected tunnels are still brought back.
  - *As built:* the updater holds the apply lock from the swap until the
    process exits, so neither of these final applies could run on the way
    down (the review's second MEDIUM finding). The updater now **lends** its
    lock to tunnel applies only (`Protocol.LendQuiesce`, applies marked
    `Options.Lendable`) as it restarts the daemon. Every other change still
    waits.
  - Known limits, each needing a second fault:
    - a boot-guard rollback after a crash loop happens before this code
      runs. If a block-mode tunnel was blocking when the new version
      crashed, a version from before this feature can leave its reject
      route until reboot;
    - the swap's database backup predates the lent applies. A boot guard
      that restores it (only after a failed update whose schema change the
      previous version can't read) loses the reject routes recorded on the
      way down;
    - a lent apply cut off by the exit is journaled, so the next start's
      crash recovery reverts it. The block lifts briefly, until the
      tunnels' startup resync puts it back.
- **At daemon start**, auto-connect and resumed block-mode tunnels count as
  wanted from the first apply, before they're started. So the previous
  run's block isn't withdrawn and then put back.
- **A crash** leaves the block in the kernel (fail closed). The next start
  keeps it for tunnels that come back, and withdraws it for the others.
  *As built:* at startup `DropTunnelRoutes` leaves a reject route alone,
  both the route and its record. It names no interface. Being recorded
  makes the tunnels' startup resync run, and that decides whether to keep
  it or withdraw it. A panic can still remove it by its record. (Forgetting
  the record would leave it in the kernel owned by nothing, because macOS
  tags no route: the review's HIGH finding.) Crash recovery puts a reject
  route back like any other route.

**Change to `fallback`:** today a *reconnecting* tunnel keeps its routes on
its interface: openvpn keeps the tun across a reconnect (persist-tun), and
WireGuard's device lives for the whole session. So traffic went into a dead
tunnel, which is neither of the two choices. Now a tunnel's routes go into
it only while it's **connected**. While it reconnects, fallback-mode
destinations take the usual path, and block-mode ones are refused.

## How it's blocked

A **reject route** per destination, in the table the tunnel's routes use:

- macOS: `route -n add -net 9.9.9.9/32 127.0.0.1 -reject` (`::1` for v6).
  The loopback gateway matters, because lo0 is what honors `RTF_REJECT`
  and answers "host unreachable". Reading it back, a route with
  `RTF_REJECT` or `RTF_BLACKHOLE` is a reject route.
- Linux: `ip route add unreachable 9.9.9.9/32 proto riftroute` (the numeric
  tag). Reading it back, type `unreachable`, `prohibit` or `blackhole` is a
  reject route.

The route model gains `Route.Reject` (no gateway, no interface).

- A reject route's identity includes it (`RouteKey`, `KernelKey`,
  `Installed`), and its destination key doesn't. So going from reject to
  into-the-tunnel, or back, is a replacement: `Reconcile` runs it
  delete-first, as it does for any next-hop change on one destination.
- The ownership table's key (family, dst, gateway, iface) is `(…, "", "")`
  for a reject route, which no other route has, so there's no migration.
- An older binary (a rollback) reads a recorded reject route as a route
  with no gateway and no interface. It can still delete it, since both
  providers delete by destination. It can't re-add it. That only matters
  for a tunnel apply journaled when the daemon died, and those commit at
  once, so the WAL format isn't bumped.

## Engine

`routing.TunnelInput` gains `Block`. The manager sets it for a block-mode
tunnel while that tunnel is wanted.

`PlanTunnels`:

- **Down with `Block`:** each destination that would go into the tunnel
  gets a reject route instead. It goes through the same checks: it's left
  out, and reported, if it holds the router, a resolver, an anchor, a
  destination someone else routes, or any tunnel's server that nothing
  holds off it. A reject route there would cut the connection, or the
  tunnel's own way back. It claims the destination like a live tunnel's
  route, and joins the plan's `nets`, so exclude routes still yield inside
  it, and include rules (Linux policy rules, macOS route-to) are still cut
  around it. Otherwise a rule that's matched before the table would carry
  the traffic past the reject route.
- **Up with `Block`:** a v6 destination the tunnel can't carry (it has no
  IPv6 address) gets a reject route instead of being left out. Otherwise a
  dual-stack name would leak over v6. It's reported in `Blocked` as
  refused.
- Live tunnels still claim first, so a destination two tunnels list goes
  into the live one.

A reject route never has a next hop to vet. The guardrails see it as a
main-table route: the gateway-capture and SSH-peer checks apply, and the
next-hop check doesn't. Two routes to one destination conflict, as before.

## Manager

- `def.WhenDown`, and `TunnelSpec` / `TunnelStatus.WhenDown`.
- `live.want`:
  - set by Connect;
  - kept when a session ends on its own (failed);
  - cleared by Disconnect, DisconnectAll (panic) and Delete;
  - kept across `RememberForRestart` → `Shutdown` for the tunnels to
    resume;
  - set at start (`New`) for auto-connect and resume-listed tunnels.
- The resume list is read in `New`, not in `StartAuto`, so the startup
  `Resync` already sees those tunnels as wanted.
- `RememberForRestart` also lists a failed block-mode tunnel: after the
  update it's tried again, rather than silently unblocked.
- `Inputs()` lists a tunnel with a session as before, and a sessionless one
  that is wanted and in block mode. `Iface` is set only while it's
  connected.
- A sessionless tunnel has no resolved servers. Its input carries the last
  session's addresses and the literal IPs in its config, so a reject route
  never blocks its own server. Connect keeps the last addresses until the
  new session resolves its own.
  - *As built:* the last addresses live in memory only. At startup, a
    via-default server given by name is unknown until its session resolves
    it, so the first apply may refuse the network that holds it.
  - A block-mode session therefore applies once its servers are resolved,
    before openvpn or WireGuard starts, as it already did for pins. That
    network is then left out, and the connection can reach its server (the
    review's MEDIUM finding).
  - Connect also asks for an apply at once, so the block starts at Connect,
    not at the session's first apply.
- Save applies when a wanted tunnel's routes or When down change, not only
  a live one's.
- `TunnelStatus.Blocking`: its destinations are refused right now.

## Status, lookup, UI, CLI

- **Lookup:**
  - `Simulate` and the fake provider report a reject match as
    `Reachable: false, Rejected: true`.
  - macOS `route get` shows `REJECT` in its flags, so it's rejected.
  - Linux `ip route get` fails. *As built:* "No route to host" (or
    "Permission denied", for prohibit) marks it rejected, not merely
    unreachable.
  - The explain path attributes a refused decision to the tunnel whose
    owned reject route holds the target: "blocked · tunnel con3 is down".
    *As built:* a kernel answer of "no route at all" counts as refused too
    when an owned reject route holds the target, in case a platform's
    lookup reports it that way.
- **Doctor:** a blocking tunnel that's connecting or reconnecting is a
  warning ("N destination(s) blocked until it's back", and which aren't in
  the table yet). *As built:* a failed one stays a failure, with the block
  and how to stop it added to its check.
- **App** (*as built*):
  - TunnelEditor has a "When it's down" group: *Use the usual path* or
    *Block its networks*;
  - the card shows a "blocks when down" badge for the setting, and a
    warning while it's blocking;
  - a failed, blocking tunnel's card offers **Stop blocking**, which is a
    Disconnect, next to Connect;
  - the Profiles card's note says "con3 is down — its targets are blocked
    until it's back";
  - the route lookup shows "blocked · tunnel con3 is down → reject", and the
    routing table shows a reject route's gateway as "reject", marked
    "blocked".
- **CLI** (*as built*):
  - `riftroute tunnel add|edit … --when-down block|fallback`;
  - `tunnel list` has a WHEN DOWN column, and a line for each tunnel that's
    blocking;
  - `table show` and `diff` print a reject route as "reject";
  - explain prints "blocked: tunnel con3 is down".

## Tests

- Engine: a block-mode tunnel that's down puts reject routes for its routes
  and its profiles' destinations. They go through the same checks as live
  routes. Exclude routes yield and include rules are cut. Up with no IPv6,
  its v6 destinations are rejected. Reject to live is a delete-first
  replacement.
- Manager: `want` across Connect, failure, Disconnect, panic, Delete,
  restart and a plain stop, and at start for auto-connect and resumed
  tunnels. Save re-applies. Carried servers.
- Providers:
  - macOS args, and the RIB flag;
  - Linux JSON and text parsing, and args;
  - the fake provider's reject routes and lookup.
- Core: explain names the tunnel, and doctor.
- API, CLI and app round-trip the setting. The card badge and the editor
  choice work.
