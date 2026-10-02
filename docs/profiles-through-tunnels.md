# Profiles through a tunnel — design

Status: implemented for the release after 0.4.0 (PR #26). Where the code
differs from the plan below, it says so.

## What the user asked for

After trying WireGuard (0.4.0), the user asked four things. The first is done
in PR #25. The other three are one feature:

1. ~~A route into a tunnel should say so in the route lookup.~~ Done: "via
   tunnel con3 · WireGuard".
2. A tunnel's routes should be visible in **Profiles**.
3. A tunnel's routes should be **switched on and off** without disconnecting
   the tunnel.
4. A **set** of destinations should go through a tunnel: CIDRs, domains
   (wildcards included), and lists — everything a profile can hold.

Today a profile has two targets: `exclude` sends its destinations around the
main VPN, over the physical gateway, and `include` sends them into the main
VPN. A tunnel has its own flat route list, CIDRs and IPs only. The feature is
a **third target: a tunnel**. Then (4) is anything a profile can hold, (2) is
the Profiles page, and (3) is the profile's existing on/off toggle, which is
also offered on the tunnel's card.

## Model

```go
// domain
const ModeTunnel Mode = "tunnel"

type Profile struct {
    …
    Mode   Mode   // exclude | include | tunnel
    Tunnel string // with ModeTunnel: the tunnel its destinations go into
}
```

- Profiles are stored as a JSON document, so there's no migration.
- The config file (YAML/TOML) gets `mode: tunnel` and `tunnel: <name>`.
- Validation:
  - `tunnel` must name a tunnel. A missing one is a warning, not an error,
    because the tunnel may be added later, and the profile then routes
    nothing.
  - `gateway` doesn't apply and is ignored.
  - `app` rules are refused for now (see Later).
- A tunnel keeps its own route list for the simple case. The two add up.

## Engine

The destinations of a tunnel-mode profile become **routes of that tunnel**:
they're added to its `routing.TunnelInput.Routes`. Everything tunnels already
do then applies to them unchanged:

- they're installed on-link into the tunnel's interface only while it is up,
  and tagged `tunnel:<name>`, so the lookup says "via tunnel …";
- what they hold that mustn't go into a tunnel (the router's network, a
  resolver, an anchor, a tunnel's server nothing holds off it) is kept out
  of them, and reported as narrowed; one for a destination another VPN
  routes exactly is left out, and reported as blocked;
- a tunnel's networks win over exclude profiles, and include rules are cut
  around them, which puts back what yielded when the tunnel goes;
- they go through the Apply Protocol, as tunnel routes do.

**Changes:**

- `routing.BuildDesired` skips tunnel-mode profiles, so they produce no
  exclude routes or include rules of their own.
- `routing.ProfileDestinations` (the yielded-record check) leaves them out:
  a tunnel-mode profile routes nothing past or into the main VPN.
- The destinations are expanded as for other profiles (`profilePrefixes`:
  CIDRs, IPs, domains through the DNS cache plus wildcard learning, lists),
  then aggregated.
- `core` adds them to the tunnel inputs it builds on:
  - **full applies** (`DesiredForApply`, `DesiredManaged`, the plan preview,
    explain, drift, doctor) use the profiles as stored;
  - **tunnel applies** (`tunnelsOnly`: connect, disconnect, and a network
    move with auto-apply off) use **the destinations the last committed full
    apply recorded**. A profile edited but not applied must not reach the
    kernel through a tunnel event: the same rule tunnel applies already
    follow for every other profile.

    This is a new record, `tunnels.profile_routes` (tunnel name →
    destinations). It is saved through the same `Options.OnCommit` as the
    yielded record, and cleared by a panic, in the same `Flushing` step.
    *As built:* the app's profile toggle saves, as it always has, and
    "Apply changes" applies. The tunnel card's toggle does the same, and the
    Tunnels page offers "Apply changes" too. So a toggle reaches the kernel
    once it's applied and confirmed; a tunnel event before that routes
    what's recorded.

## When the tunnel is down

By default the profile's destinations are not installed, so they take
whatever path they would without it. Usually that's the main VPN.

*As built:* the user answered the open question here. It's a per-tunnel
setting, not a per-profile one, and it covers the tunnel's own routes and
its profiles alike: **When it's down: use the usual path, or block** (see
`docs/tunnel-when-down.md`).

## Status, API and UI

- `TunnelStatus` gains `profiles`: each tunnel-mode profile that targets the
  tunnel (id, name, enabled, how many destinations). Its blocked routes are
  reported with the tunnel's.
- **Profiles page**:
  - the mode choice gains **Through a tunnel**, with a picker of the saved
    tunnels;
  - the card shows "→ tunnel con3 · WireGuard", the tunnel's state, and a
    note while the tunnel is down.
- **Tunnels page**: the card lists the profiles routed into it, each with
  its on/off toggle (the same `SetProfileEnabled` as the Profiles page) and a
  link to edit it.
- **CLI**:
  - `riftroute profile …` / the config file accept `mode: tunnel` and
    `tunnel: con3`;
  - `riftroute tunnel list` shows "+N from profiles".
- **Lookup**: nothing new is needed. The route is tagged `tunnel:<name>`, and
  PR #25's label applies.

## Tests

- Engine: a tunnel-mode profile with CIDRs, domains and a list goes into its
  tunnel's routes, not into exclude routes or include rules. It is blocked
  like a listed route. It's absent while the tunnel is down. It yields as a
  tunnel network does, overlapping an exclude profile and an include rule.
- Record: with auto-apply off, a tunnel connect installs the destinations the
  last full apply recorded, and not a stored-but-unapplied edit. A panic
  clears the record.
- Toggle: disabling the profile withdraws its routes while the tunnel stays up.
- Wildcards: a learned subdomain address goes into the tunnel.
- API, CLI and app: the mode round-trips, the tunnel card lists the profile
  and its toggle works, and the Profiles card shows the target.

## Later

- `app` rules through a tunnel: an include-style policy rule pointed at the
  tunnel's interface instead of the main VPN (Linux fwmark table, macOS
  route-to).
- `vetAddressing`'s `ours` exemption could count the profile destinations as
  the user's own routes. Without that, it is stricter, never looser.
