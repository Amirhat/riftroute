# RiftRoute — Product & Engineering Specification

> **Status:** Build spec, ready for implementation.
> **Audience:** A coding agent (Claude Code) that will design, implement, test, and ship this 0→100.
> **Name:** `RiftRoute` is a working title — rename freely. Binary `riftroute` (alias `rr`), daemon `riftrouted`, GUI app `RiftRoute.app`.
> **Companion doc:** Obey `AGENTS.md` (cross-platform desktop, web-UI + native shell) for *all* desktop/shell/build/signing decisions. This spec assumes it and only restates a rule where it materially constrains a RiftRoute-specific choice.

---

## 0. TL;DR for the implementing agent

Build a **split-tunneling / policy-based routing controller** for **macOS and Linux**. It lets a developer say "these destinations bypass the VPN, everything else goes through it" (or the inverse), organize those destinations into toggleable **profiles/lists**, and have the system keep the routing table correct automatically as the VPN goes up/down and the network changes — **without ever leaving the machine in a broken network state.**

Two pillars, non-negotiable, judged on every PR:

1. **Safety:** Every change is snapshotted, atomic-with-rollback, dry-runnable, ownership-scoped (never touch routes we didn't create), and protected by a **commit-confirm + connectivity watchdog** that auto-reverts if connectivity drops. A bug must degrade to "no change" or "reverted," never to "user is locked out."
2. **Observability:** A first-class **routing table visualizer**, a **route-explain simulator** ("where does traffic to X actually go, and why?"), a **desired-vs-actual diff**, a **leak detector**, and an **audit timeline**. The user is never confused about current state.

Architecture: a persistent **privileged daemon** (`riftrouted`, the only root component) that owns route mutation + network monitoring + reconciliation, exposing a local API over a **Unix domain socket**; and unprivileged **clients** — a **Wails (Go) desktop app** and a **CLI** — that talk to it. Default mutation strategy on both OSes is host-scoped routes (Model A); Linux additionally supports policy routing with a dedicated table + `ip rule` (Model B). Declarative, git-committable config is a first-class input.

Start read-only (cannot break anything), then add safe mutation, then auto-apply, then advanced routing, then domains/lists, then power features, then ship.

---

## 1. Product overview & goals

### 1.1 What it is
A controller for **policy-based routing** on a developer workstation. The core operation is: for a chosen set of destinations, install routes that send them via a *specific* next-hop/interface (typically the physical gateway) so they **bypass an active VPN's default route** — or the inverse (only a chosen set goes *through* a tunnel). Destinations are grouped into named, toggleable **profiles** and reusable **lists**, and the daemon keeps the live routing table reconciled to the enabled set as the network changes.

### 1.2 Target user & jobs-to-be-done
A developer/power-user on macOS or Linux who runs a corporate or commercial VPN and needs fine-grained control over what does and doesn't traverse it. Jobs:
- "Keep my work intranet (`10.0.0.0/8`, internal domains) on the VPN, but let video/CDN/cloud-console traffic go direct for speed."
- "Route *only* a few services through a tunnel; leave everything else on my LAN."
- "When I toggle the VPN, do the right thing automatically — and tell me clearly what it did."
- "Show me, right now, exactly where a given IP/domain's traffic is going and why."
- "Never strand me without a network because of a routing mistake."

### 1.3 Design principles
1. **Safety over features.** A change that *might* break connectivity must be revertible automatically. Fail-safe (do nothing) beats fail-dangerous.
2. **Observable by default.** State is always visible and explainable; nothing happens invisibly.
3. **Never touch what we don't own.** Only routes RiftRoute created are ever modified or deleted.
4. **Reconcile, don't blindly mutate.** Compute desired state, diff against actual, apply the minimal delta, detect drift.
5. **Decoupled.** Backend logic is independent of GUI/CLI/daemon transport and testable headless (`AGENTS.md §1`).
6. **Developer-grade ergonomics.** Declarative config, clean CLI with `--json`, shell completions, sane defaults, great empty/error states.
7. **Cross-platform parity where it exists; honest about where it doesn't.** macOS is more constrained than Linux; surface that rather than fake it.

### 1.4 Non-goals / scope
- **Not a VPN.** RiftRoute configures routing *around/with* whatever tunnel the user already runs (WireGuard, OpenVPN, corporate clients, utun/tun/wg interfaces). It does not establish tunnels.
- **Windows is out of scope for v1** (mac + linux only, per the user). Keep the platform layer pluggable so Windows can be added later; ship a no-op stub so the project always compiles (`AGENTS.md §8`).
- Not a packet-level firewall manager beyond the specific kill-switch / leak-protection features specified here.

---

## 2. The safety model — read this before writing any routing code

This section is the heart of the product. If a feature conflicts with these rules, the feature loses.

### 2.1 Safety primitives
- **Snapshot:** Before any mutation, capture full state: IPv4 + IPv6 routing tables, `ip rule` set (Linux), default-route owner, gateway, DNS config, and kill-switch/firewall state. Snapshots are stored with id + timestamp + reason and are restorable.
- **Dry-run:** Every mutation path supports `--dry-run` / a UI preview that renders the exact ordered command plan **and** its precomputed inverse, with a desired-vs-actual diff, executing nothing.
- **Atomic transaction:** A mutation is an ordered list of route ops applied as a unit. If op *k* fails, immediately execute the inverse of ops `1..k-1` and abort with the original error. Never leave partial state.
- **Ownership tagging:** RiftRoute only ever modifies/deletes routes it created (see §2.3).
- **Connectivity watchdog (deadman switch):** An independent goroutine, armed *before* the change, with a **precomputed inverse plan** so recovery needs no complex logic. It probes anchors (gateway + optional canaries) ~1×/s; if an anchor is unreachable for K consecutive probes, it fires the rollback immediately.
- **Commit-confirm:** Interactive applies require an explicit "Keep changes" within `confirm_timeout` (default 15s) or auto-revert. This is the classic network-gear "commit confirmed" pattern and is what protects a user from locking *themselves* out (especially over SSH).
- **Panic / flush:** One command + one tray button + one global hotkey removes **all** RiftRoute-managed routes and restores baseline. Idempotent, always available, even if profiles are in a weird state.
- **Read-only default:** The app opens in observe mode; mutation requires explicit action.

### 2.2 The Apply Protocol (every mutation goes through this — no exceptions)

```
1. BUILD     desired = routes implied by all enabled profiles (+ resolved domains/lists)
2. RECONCILE plan = diff(desired, actual_managed)   // ordered add/del of MANAGED routes only
3. PREPARE   inverse = exact rollback ops; snapshot = full state capture
4. PREVIEW   if dry-run: print(plan, inverse, diff); return
5. ARM       start watchdog(confirm_timeout, anchors, inverse)   // independent goroutine
6. EXECUTE   apply plan op-by-op via arg-array exec (no shell);
             on any op error -> run partial inverse -> abort(error)
7. VERIFY    re-read table; assert desired == actual; assert anchors reachable; run leak check
8. CONFIRM   interactive -> require "Keep" within confirm_timeout, else rollback
             non-interactive (--yes / daemon auto-apply) -> skip manual confirm,
                 but KEEP connectivity guard for guard_window; rollback if anchors drop
9. COMMIT    on confirm: disarm watchdog; persist new desired state; write audit entry
   ROLLBACK  on timeout / guard-fire / verify-fail / error:
                 run inverse; restore snapshot if needed; audit the rollback with reason
```

Rules:
- The watchdog owns the inverse and its own timer; it can recover even if the main apply path wedges.
- The daemon's **auto-apply** (on VPN/network change) skips the manual confirm but **always** keeps the connectivity guard, and **must never** apply a change that would sever its own control path or the gateway route.
- If no gateway/anchor can be established, the daemon **refuses to apply** (fail-safe) and surfaces why.

### 2.3 Ownership — never touch foreign routes
- **Linux:** tag every managed route with a dedicated `proto` value (register a name in `rt_protos`, e.g. `proto riftroute`). `ip route show proto riftroute` then enumerates exactly our routes. For Model B, use a dedicated routing **table number** + a dedicated `ip rule` priority band so teardown is a single table flush.
- **macOS:** the kernel route table has no arbitrary tag field. Track ownership in the daemon's state DB (destination, mask, gateway, ifscope, created-at, owning profile) and reconcile against it. On startup, re-assert managed routes from the DB and adopt/repair drift; never delete a route absent from our ownership set.
- **Invariant:** A delete is only ever issued for a route in the ownership set. A "clean foreign route" operation does not exist.

### 2.4 Guardrails — operations RiftRoute refuses or forces confirmation on
- Never route the **gateway IP itself** through a tunnel (would break everything). Refuse.
- Never remove/override the route that the daemon's **control plane** needs (local subnet for the socket peer). Refuse.
- Never add a route whose **next-hop is not on-link / not reachable** (e.g., stale gateway after subnet change). Refuse + explain.
- **SSH-session protection:** if `SSH_CONNECTION` is set or an active inbound SSH session exists, detect the peer IP and ensure any "tunnel-everything" change preserves a direct route to that peer *before* applying; otherwise refuse. (RiftRoute is a desktop app, but devs SSH into boxes — protect the session that's running the tool.)
- **Blackhole detection:** refuse/strongly-warn on a desired state that would leave no route to the internet or would 0.0.0.0/0-blackhole all traffic unintentionally.
- **IPv6 leak default:** if an IPv6 default route bypasses the intended tunnel and the profile targets dual-stack, warn loudly (and offer to manage v6 in parallel).
- **More-specific VPN route conflict:** if the VPN pushed a route *more specific* than ours (so LPM would still send the destination through the tunnel), detect it and either install a still-more-specific host route or warn that the bypass won't take effect.

### 2.5 Failure & recovery matrix (must be covered by tests, §15)

| Failure injected | Required behavior |
|---|---|
| Op *k* of N fails mid-apply | Inverse of `1..k-1` runs; state restored; error surfaced |
| Anchor unreachable after apply | Watchdog fires rollback within K probes; audited |
| User never confirms (interactive) | Auto-revert at `confirm_timeout`; audited |
| Daemon crashes mid-transaction | On restart: snapshot + ownership reconcile detect partial state and repair/rollback |
| Network change during apply | Apply is serialized; queued change re-reconciles after |
| Gateway disappears (no anchor) | Refuse new applies (fail-safe); keep existing managed routes; surface degraded status |
| `panic` invoked in any state | All managed routes removed; baseline restored; idempotent |

---

## 3. Architecture

### 3.1 Process model
Two long-lived concerns, deliberately split (mirrors `tailscaled`+GUI / `dockerd`+Docker Desktop):

- **`riftrouted` — privileged daemon (the only root component).** Owns: route mutation, network-event monitoring, the reconciliation loop, snapshots, the watchdog, persistence, and the local API. Installed once via **launchd** (macOS) / **systemd** (Linux). **Persistent** — its lifetime is *not* tied to any GUI; it must keep routes correct with no UI open.
- **Clients — unprivileged.** (a) The **Wails desktop app** (GUI), (b) the **CLI**. Both connect to `riftrouted` over a Unix domain socket and call the *same* API. Neither needs root.

> **Important lifecycle distinction vs `AGENTS.md §4`:** the "exit when no UI is connected" lifecycle applies to the **GUI app process**, *not* to `riftrouted`. `riftrouted` is persistent. The GUI is a thin client that may quit freely; routing continues.

### 3.2 Component diagram

```
┌───────────────────────────┐     ┌───────────────────────────┐
│  RiftRoute.app (Wails, Go)  │     │  riftroute CLI (Go, cobra)  │
│  webview UI  ◄─► Go bind  │     │   --json everywhere       │
└─────────────┬─────────────┘     └─────────────┬─────────────┘
              │  HTTP/JSON + SSE over Unix domain socket (peer-cred authz)
              ▼                                  ▼
        ┌─────────────────────────────────────────────────┐
        │                 riftrouted (root)                  │
        │  ┌───────────┐ ┌─────────────┐ ┌──────────────┐  │
        │  │   API     │ │ Reconciler  │ │  Watchdog    │  │
        │  │ (UDS)     │ │ desired↔act │ │ (deadman)    │  │
        │  └───────────┘ └──────┬──────┘ └──────────────┘  │
        │  ┌───────────┐ ┌──────▼──────┐ ┌──────────────┐  │
        │  │ NetMonitor│ │ RouteProvider│ │  Store(SQLite│  │
        │  │ (events)  │ │  (per-OS)    │ │ +audit+snap) │  │
        │  └───────────┘ └──────────────┘ └──────────────┘  │
        └───────────────────────┬─────────────────────────┘
                                ▼
            OS kernel: route table / ip rule / pf|nft / DNS
```

### 3.3 Tech stack
- **Language:** Go (matches routing/netlink ergonomics; `AGENTS.md` default; Tailscale precedent).
- **Desktop shell:** **Wails** (current stable — *verify version at build time*). Do **not** hand-roll a native webview/menu/lifecycle (`AGENTS.md §0`). The UI runs in **WKWebView (macOS) / WebKitGTK (Linux)** — CSS/JS must work on **WebKit, not just Chrome** (`AGENTS.md §0/§1`).
- **CLI:** `cobra` + `pflag`; output via a renderer that supports both human tables and `--json`.
- **TUI (optional, post-MVP):** `bubbletea`/`lipgloss` for a `riftroute watch` live view.
- **Persistence:** **pure-Go SQLite (`modernc.org/sqlite`)** to avoid adding cgo on top of Wails' required cgo (`AGENTS.md §8`); `bbolt` acceptable if SQL is overkill. Profiles, lists, settings, snapshots, ownership map, audit log.
- **Linux netlink:** prefer a maintained netlink lib for monitoring/reads; for *mutations* prefer shelling out to `ip`/`route` with **machine-readable output** and **arg-array exec (never a shell string)** for fidelity + injection safety (`AGENTS.md §10`, §12 here).
- **GeoIP/ASN:** embeddable MMDB reader (e.g. an MaxMind-format reader) with a user-supplied or downloadable DB; never bundle a license-restricted DB without checking terms.

### 3.4 Repo layout (suggested)

```
riftroute/
  cmd/
    riftrouted/        # daemon entrypoint
    riftroute/         # CLI entrypoint
  desktop/           # Wails app (Go backend bindings + frontend/)
    frontend/        # web UI — React 18 + TypeScript + Vite (see §3.5)
  internal/
    routing/         # engine: reconcile, diff, LPM simulator, CIDR aggregation
    provider/        # RouteProvider interface + macos/ linux/ fake/ implementations
    netmon/          # network event monitor (per-OS)
    safety/          # snapshot, transaction, watchdog, panic
    domain/          # entities (Profile, Rule, List, Snapshot, AuditEvent)
    lists/           # remote list fetch/refresh, geoip/asn
    dns/             # split-DNS, leak checks
    killswitch/      # pf (macos) / nft (linux)
    api/             # UDS server: HTTP/JSON + SSE, peer-cred authz
    apiclient/       # shared client used by GUI + CLI
    store/           # SQLite persistence
    config/          # declarative config parse + validate
    platform/        # paths, privilege, service install (launchd/systemd)
  test/
    netns/           # Linux network-namespace integration tests
    fixtures/        # captured real outputs of ip/route/netstat across OS versions
  packaging/         # dmg, deb, AppImage, brew tap, launchd plist, systemd unit
  .github/workflows/ # CI matrix (macOS + Linux runners)
```

### 3.5 Frontend stack (decided — do not re-litigate)

Chosen to optimize three things at once: **runs smoothly in a WebKit webview**, **low error rate when written by an AI agent or a human**, and **easy ongoing development**.

- **React 18 + TypeScript (`strict`) + Vite** — the Wails official `react-ts` template. Rationale: it is by far the **densest, most stable target in an AI agent's training**, so first-pass code is more likely correct; `strict` TypeScript catches a large class of bugs before runtime; the ecosystem has a battle-tested answer for every hard part below. (Runner-up: Svelte — lighter runtime, less boilerplate — but its smaller training corpus and the Svelte-4-vs-5-runes ambiguity raise an agent's error rate, which is the user's explicit top concern. Bundle size is irrelevant for a local desktop app, so React's main "cost" doesn't bite here.)
- **Auto-generated Wails TS bindings = end-to-end type safety.** Wails generates TypeScript clients from the Go backend's bound methods and structs. The frontend↔backend contract is therefore **typed and generated, not hand-written** — this removes the single biggest source of frontend/backend integration bugs. Treat the generated bindings as the only way the UI calls the backend.
- **TanStack Query** wrapping those generated bindings for all data access — managed loading/error/stale/refetch states (kills a whole class of manual-fetch bugs). `queryFn` calls a Wails-bound Go method; a live event triggers `invalidateQueries`.
- **TanStack Virtual** for the routing table, audit log, and diff. This is **mandatory**, not optional: it is how we satisfy `AGENTS.md §6` "never block the single webview thread with an unbounded render." Only visible rows mount; thousands of routes stay smooth.
- **Styling: Tailwind CSS driven by semantic CSS-variable tokens.** Define semantic tokens in `:root` and `[data-theme="light"|"dark"]` (e.g. `--surface`, `--text`, `--muted`, `--accent`, `--danger`) and a **named z-index scale** (`--z-dropdown: 40 … --z-toast: 110`); map them into Tailwind and use only **semantic utilities** (`bg-surface`, `text-default`, `z-modal`). **Never hardcode a hex value in a component class** — a theme is a pure variable swap (`AGENTS.md §6/§8.3`). Tailwind is chosen because utility classes are local and composable, so an agent rarely creates global-cascade bugs.
- **In-app routing: React Router** (or a minimal state view-switcher — there are only ~8 screens). Keep it trivial.
- **i18n: `react-i18next`** (or a tiny custom `t()`), every user-facing string via `t()`, **CSS logical properties**, `dir` attribute toggled for RTL, and **forced `direction: ltr` on all code/route/diff/log panes** (`AGENTS.md §7`). The maintainer writes Persian → RTL must work; address/CIDR panes must not mirror.
- **Headless a11y primitives only where needed** (accessible dialogs/menus): hand-roll, or add a minimal headless lib (Radix-style) **only** for the dialog/menu/tooltip cases. Keep the dependency tree small — fewer deps = lower error/maintenance surface.
- **Tests: Vitest** (unit/component) + a **Playwright/WebDriver smoke** of critical flows, with the `AGENTS.md §10` caveat that WKWebView automation is limited — also exercise UI logic against the dev/browser path.
- **When actually building the UI, consult `/mnt/skills/public/frontend-design/SKILL.md`** for visual/aesthetic direction so it doesn't read as a templated default.

**Data path (important — the React app never opens a socket):**

```
React frontend  ──Wails typed bindings (calls)──►  Desktop app Go side  ──apiclient: HTTP/JSON over UDS──►  riftrouted
React frontend  ◄──Wails runtime events (push)──   Desktop app Go side  ◄──SSE stream over UDS────────────   riftrouted
```

The desktop app's **Go side** holds the UDS connection to `riftrouted` (including its SSE stream) and re-emits updates to the React layer as **Wails runtime events**; React never speaks HTTP/SSE/sockets directly. (The CLI uses the same `apiclient` independently.)

---

## 4. Platform abstraction layer

### 4.1 The `RouteProvider` interface
All kernel interaction goes through one interface so the engine is testable headless and Windows can slot in later.

```go
type RouteProvider interface {
    // Reads
    ListRoutes(ctx, family) ([]Route, error)            // family: v4|v6
    ListRules(ctx, family) ([]Rule, error)              // Linux; empty on macOS
    LookupRoute(ctx, dst netip.Addr) (RouteDecision, error) // kernel's answer: route get / ip route get
    DefaultGateway(ctx, family) (gw netip.Addr, iface string, err error)
    Interfaces(ctx) ([]Iface, error)                    // up/down, addrs, kind (phys/utun/tun/wg)
    DNSConfig(ctx) (DNSState, error)

    // Mutations (idempotent; arg-array exec; tagged-owned)
    AddRoute(ctx, r ManagedRoute) error
    DelRoute(ctx, r ManagedRoute) error
    AddRule(ctx, r ManagedRule) error                   // Linux Model B
    DelRule(ctx, r ManagedRule) error
    FlushOwned(ctx) error                               // remove all RiftRoute-owned routes/rules

    Capabilities() Capabilities                         // what this OS supports (policy routing, fwmark, ...)
}
```

`Capabilities` lets the UI honestly disable features the OS can't do (e.g., per-app routing on macOS).

### 4.2 macOS backend
- Add host route: `route -n add -host <ip> <gateway>` (or `/32` form). Scoped variant where useful: `route -n add -host -ifscope <iface> <ip> <gateway>`.
- Read table: `netstat -rn` (+ `-f inet` / `-f inet6`). Per-dest: `route -n get <ip>`.
- Default router independent of VPN: `ipconfig getoption <iface> router`; or `route -n get default` / scoped get.
- Monitor: `route -n monitor` (BSD route socket) and/or SystemConfiguration (`scutil`, SCDynamicStore / NWPathMonitor) for VPN up/down + primary-service changes.
- Kill switch / leak block: `pf` via `pfctl` with a dedicated anchor.
- **Constraints:** no policy-routing tables, no `fwmark`/per-app routing, no `proto` tag — use DB-tracked ownership and interface scoping. Surface these limits via `Capabilities`.

### 4.3 Linux backend
- Add (Model A): `ip route add <cidr> via <gw> dev <iface> proto riftroute [metric N]`.
- Model B (policy routing): `ip route add default via <gw> dev <iface> table <T> proto riftroute` + `ip rule add <selector> lookup <T> priority <P>`. Selectors: `to <cidr>`, `from <cidr>`, `uidrange`, `fwmark`.
- Read: `ip -j route show [table T]`, `ip -j rule show`, `ip -j route get <ip>` (use `-j` JSON where available; keep a text parser fallback for old `iproute2`).
- Owned enumeration: `ip route show proto riftroute`, table flush for Model B teardown.
- Monitor: `ip monitor route link addr` / netlink subscription for link + route + addr events; integrate NetworkManager/systemd-networkd/dhclient signals where present.
- Per-app routing: cgroup v2 + packet mark (nftables `meta cgroup` or `-m owner`) → `fwmark` → `ip rule ... fwmark X table Y`.
- Kill switch: `nftables` with a dedicated table/chain.

### 4.4 Gateway detection
- **When VPN is down:** read the default route's next-hop directly.
- **When VPN is up** (default is the tunnel): do **not** infer the physical gateway from `default`. Instead read it from the interface independent of the default route (macOS: `ipconfig getoption <iface> router`; Linux: `table main` on-link route / DHCP lease) and/or use the value **cached while the VPN was down**. `gateway: auto` in config resolves via this logic; explicit gateway always wins.

### 4.5 Network event monitor (`netmon`)
Emits debounced events the reconciler subscribes to: `VPNUp{iface}`, `VPNDown{iface}`, `DefaultRouteChanged`, `LinkChanged{iface,up}`, `AddrChanged`, `DNSChanged`, `Wake` (sleep/wake), `DHCPLeaseChanged`. Debounce flapping interfaces. On each relevant event the reconciler re-derives desired state and runs the Apply Protocol (auto-apply path).

### 4.6 Fake backend
An in-memory `RouteProvider` with a fully simulated table + rule set + clock, used to test the engine, reconciler, watchdog, and Apply Protocol with **zero** risk to any host (§15).

---

## 5. Domain model

### 5.1 Entities
- **Profile:** `{ id, name, enabled, mode (exclude|include), gateway (auto|IP), priority, rules[], lists[], ip_version }`. The unit users toggle.
- **Rule:** one of `cidr` | `ip` | `domain` | `asn` | `country` (GeoIP) | `app` (Linux). Has an optional comment.
- **List:** named reusable set of rules; may be `static` (inline) or `remote` (`source` URL + `refresh` interval + last-fetched + checksum). Examples: `rfc1918`, `cloudflare-ranges`, `google-asn`.
- **RouteEntry (Route):** a kernel route as read: `{ dst_cidr, gateway, iface, metric, proto/owner, family, source }`. `owner ∈ {system, riftroute, vpn?}` (best-effort classification).
- **ManagedRoute / ManagedRule:** a route/rule RiftRoute intends to own; carries owning profile id + creation metadata.
- **Snapshot:** full captured state + id + timestamp + reason.
- **Transaction:** ordered ops + precomputed inverse + result.
- **AuditEvent:** `{ ts, actor (ui|cli|daemon-auto), action, profile?, plan (exact commands), result, rollback?, reason }`.

### 5.2 CIDR aggregation & LPM
- **Store per-IP if the user gives per-IP** (for per-destination toggles + stats), but at **apply** time **aggregate contiguous IPs into the smallest covering CIDRs** so the kernel table stays small. Expanding a `/16` into 65 536 `/32`s is forbidden by default — it bloats the table, slows lookups, and can hit limits. Only emit a `/32` when a *more-specific-than-the-target* host route is genuinely required (see §2.4 VPN conflict).
- Implement an exact **longest-prefix-match simulator** over desired state (used by route-explain and conflict detection) plus a parallel call to the kernel's real lookup, so the UI can show **both** "what we intend" and "what the kernel actually does" and highlight drift.

### 5.3 Routing modes
- **exclude (default):** everything goes through the VPN; the profile's destinations bypass it via the physical gateway. (The user's original use-case.)
- **include (inverse):** nothing goes through the tunnel by default; only the profile's destinations are routed into the tunnel. On Linux best done with Model B (default-in-table + rules). On macOS, more limited; surface constraints.

### 5.4 Two routing strategies
- **Model A — host/CIDR routes in the main table** (macOS + Linux; simplest; MVP). For each bypass destination, a route via the physical gateway that is more specific than the VPN default. Good for "a handful of exceptions."
- **Model B — policy routing with a dedicated table + `ip rule`** (Linux only; powerful). Enables per-app, per-uid, source-based, and inverse routing, and **clean teardown** (flush one table). Use `Capabilities` to expose Model-B-only features only on Linux.

---

## 6. Feature catalog (phased)

**MVP (must ship first, safe + observable):**

| Feature | Notes |
|---|---|
| Routing table viewer | Virtualized, classified (system/riftroute/vpn), filter/search, force LTR |
| Route explain / simulator | "Where does traffic to X go, and why?" — kernel answer + our simulation + drift |
| Interface / VPN / DNS status panel | Detected tunnels, default-route owner, DNS in effect, IPv6 status |
| Desired-vs-actual diff | Even when desired is empty (read-only) |
| Snapshot + restore | Full state capture; restorable |
| Dry-run | Exact plan + inverse, executes nothing |
| Atomic transaction + rollback | Per §2.2 |
| Connectivity watchdog + commit-confirm | The deadman switch |
| Panic / flush | CLI + tray + hotkey |
| Profiles with enable/disable | exclude mode, Model A |
| Audit log / timeline | Every change with exact commands |
| Declarative config apply | `riftroute apply file.yaml` |
| Daemon install/uninstall/status | launchd/systemd |

**v1:**

| Feature | Notes |
|---|---|
| Auto-apply on VPN up/down + network change | The "magic"; via `netmon` + reconciler |
| Gateway auto-detection (`auto`) | VPN-independent read + cache |
| include / inverse mode | Linux Model B |
| CIDR aggregation | Per §5.2 |
| IPv6 parity | First-class, not an afterthought |
| Conflict & overlap detection | Between profiles/lists; shadowed rules |
| Leak detector | IPv6 default leak, DNS leak, egress-interface probe |
| Doctor (diagnostics) | One-click battery → readable report |
| Remote subscribable lists + refresh | e.g. Cloudflare ranges, with auto-update |

**v2 (power features):**

| Feature | Notes |
|---|---|
| Domain-based routing | Resolve A+AAAA, route results, background re-resolver for CDNs |
| GeoIP / ASN rules | "All of Google's ASNs", country-based |
| Kill switch | pf (macOS) / nftables (Linux) — block egress if tunnel drops |
| Split-DNS | Per-domain resolver selection |
| Per-app routing (Linux) | cgroup + fwmark + ip rule |
| Live flow/traffic monitor | Active connections → which route/interface |
| MTU/MSS inspection + clamp helper | Detect tunnel MTU blackholes |
| TUI `riftroute watch` | bubbletea live view |
| Menu-bar/tray quick toggles | Per-profile toggles without opening the app |

---

## 7. Monitoring, visualization & debugging (first-class — equal weight to routing)

The user explicitly wants the operator to **never be confused**. These are product surfaces, not afterthoughts.

### 7.1 Routing table viewer
- **Virtualized** table — the table can have thousands of rows; never render unbounded synchronously (`AGENTS.md §6` — a synchronous mega-render freezes the single webview thread). Cap/virtualize with a "showing N of M" affordance.
- Columns: destination CIDR, gateway, interface, metric/priority, family (v4/v6), **owner** (system / **riftroute** / vpn?), source profile.
- **Color-coded** by owner; conflicts/overlaps flagged inline.
- Filter + full-text search; group by interface / profile / owner; toggle v4/v6.
- **Force `direction: ltr`** on this and every IP/CIDR/diff/log container even in an RTL UI (`AGENTS.md §7`) — addresses must not mirror.
- Use **CSS Grid** for the tabular layout (not nested flexboxes with placeholder cells — `AGENTS.md §6`).

### 7.2 Route explain / simulator (the killer debugging tool)
Input an IP or domain → output the full decision:
> `8.8.8.8` → matches `8.8.8.0/24` (riftroute, profile *google-direct*) → via `192.168.88.1` dev `en0` → **DIRECT (bypasses VPN)**

Show **two answers side by side**: (a) the **kernel's** real decision (`route get` / `ip route get`), (b) RiftRoute's **simulated** decision over desired state — and **highlight any drift** (means actual ≠ intended → something needs reconciling). For domains, show each resolved A/AAAA and its decision.

### 7.3 Desired-vs-actual diff
- A **CSS Grid** diff (additions/removals/changes color-coded; `AGENTS.md §6`) of managed routes: what enabled profiles imply vs what's installed.
- Drives the dry-run preview and a persistent "drift" indicator when reconciliation is pending.

### 7.4 Live flow / traffic monitor (v2)
- Parse active connections (macOS `netstat -an`/`lsof -i`; Linux `ss -tunp`), correlate each with the route that carries it, label by interface (e.g., "→ utun3 (VPN)" vs "→ en0 (direct)"). Helps answer "is *this* actually going through the tunnel?"

### 7.5 VPN / interface / DNS status
- Detected tunnel interfaces (utun/tun/wg) with up/down; current default-route owner per family; DNS servers in effect (+ whether they match expectation); IPv6 on/off; kill-switch state.

### 7.6 Leak detector
- **IPv6 leak:** default v6 route bypassing the intended tunnel while a dual-stack profile is active → warn.
- **DNS leak:** queries egressing somewhere other than the expected resolver/interface.
- **Egress probe:** for a destination that *should* be tunneled, verify it actually egresses the tunnel (and vice-versa) — surface mismatches.

### 7.7 Audit log / timeline
- Every change: timestamp, actor (ui/cli/daemon-auto), action, owning profile, the **exact commands run**, success/failure, and any rollback + reason. Filterable, searchable, exportable (JSON). This is both a debugging aid and the trust mechanism for a root-level tool.

### 7.8 Conflict & overlap detection
- Two profiles/lists claiming the same IP; a rule shadowed by a broader rule; a bypass that won't take effect because the VPN pushed something more specific (§2.4). Each warning is explainable in plain language with the offending entries linked.

### 7.9 Doctor (diagnostics)
- `riftroute doctor` / a UI button runs a battery: gateway resolution, route resolution for canaries, DNS resolution + leak, MTU/MSS sanity, interface reachability, daemon health, ownership-vs-actual drift. Produces a **readable report** with pass/warn/fail + suggested fixes. Think "network self-test."

### 7.10 Connectivity & MTU
- Continuous latency/reachability to gateway + canaries (sparkline). Per-interface MTU display + detection of likely MTU blackholes (common with tunnels) + an MSS-clamp helper suggestion.

---

## 8. Desktop application (Wails) — UI/UX spec

### 8.1 Window, menu, tray, lifecycle
- Wails owns window/menu/dialogs/tray/single-instance/packaging — **don't hand-roll** (`AGENTS.md §0/§1/§3`).
- **GUI lifecycle** (the *app* process, not `riftrouted`): close-to-quit the GUI, free its dev port, signal handlers, grace periods per `AGENTS.md §4`. Closing the GUI must **not** stop routing (that's `riftrouted`).
- **Native menu bridged to UI actions** — menu items call the same actions the UI exposes; never reimplement logic in the menu (`AGENTS.md §3`).
- **Standard Edit menu** (Undo/Cut/Copy/Paste/Select-All) so ⌘C/⌘V work in inputs inside the webview (`AGENTS.md §3`).
- **Tray / menu-bar:** status glance + per-profile quick toggles + **Panic** + open-app. Quick-toggles call the same API.
- **Single-instance:** focus the existing window instead of launching a second (`AGENTS.md §2/§3`).
- Set the **app icon** explicitly (`AGENTS.md §3`).
- **Dev loop** (`AGENTS.md §2`): `wails dev` watch-rebuild-restart; serve UI from disk in dev, embed for release; distinct dev port with single-instance handoff; **verify in the real WebKit window**, not Chrome.

### 8.2 Screens
1. **Dashboard:** VPN/interface status, default-route owner, active profiles, drift indicator, connectivity sparkline, big **Panic** button, recent audit entries.
2. **Routing Table:** §7.1 viewer.
3. **Explain:** §7.2 simulator (a prominent search box — "where does X go?").
4. **Profiles:** list with toggles; editor (rules: cidr/ip/domain/asn/country/app; gateway auto/explicit; mode; lists); **dry-run preview** before apply with the §7.3 diff + **commit-confirm** countdown.
5. **Lists:** static + remote (source, refresh, last-fetched, checksum), preview resolved entries.
6. **Diagnostics:** Doctor report, leak detector, flow monitor (v2), MTU.
7. **History:** audit timeline + snapshot restore.
8. **Settings:** ip_version, default_mode, auto-apply, kill switch, connectivity-guard (anchors, confirm_timeout, guard_window), theme, language, daemon status/install.

### 8.3 Webview rules (apply from line one — `AGENTS.md §6`)
- **Theme via CSS variables** in `:root`; design **light + dark in parallel**; never hardcode hex in component rules. A theme is a variable swap (`[data-theme]`).
- **Explicit z-index layer scale** up front (e.g. base 0, dropdown 40, drawer 60, sheet 70, modal 90, dialog 100, toast 110) — prevents runtime overlays opening *behind* static ones and looking like a freeze.
- **Never block the main thread** with unbounded renders — virtualize the table, the diff, the audit log (`AGENTS.md §6`). Symptom of violation: screenshot/eval hangs.
- **CSS Grid** for table/diff/data layouts (not placeholder-flex). **Force `direction:ltr`** on all code/route/diff/log containers (`AGENTS.md §7`).
- **Gate interactive styling on a mode flag** — the route/diff component is mostly read-only; selection/edit styling must not leak into read-only views (`AGENTS.md §6`).
- **Escape ALL untrusted content** injected into the DOM — hostnames (from DNS/lists), interface names, list names, route comments, remote-list contents are **untrusted input** (`AGENTS.md §11`). Use arg-array exec on the backend (§12) and HTML-escape on the frontend.
- **Center glyphs with transforms**, not magic pixels (`AGENTS.md §6`).
- **Verify computed styles**, don't eyeball screenshots (`AGENTS.md §6/§10`).

### 8.4 i18n / RTL
- Build **i18n-ready** even if shipping English first: every user-facing string via `t()`; **CSS logical properties** (`margin-inline-start`, not `margin-left`); direction-agnostic layouts; language switch behind a flag (`AGENTS.md §7`). The maintainer writes Persian, so **RTL must work** — and code/route/diff/log panes stay **forced LTR** regardless.

---

## 9. CLI specification

Principles: every command supports `--json`; mutating commands support `--dry-run` and `--yes`; ship shell completions; human output is a clean table, machine output is stable JSON.

```
riftroute status [--json]                      # VPN, default owner, profiles, drift, daemon health
riftroute table show [--managed|--system|--conflicts] [-6] [--json]
riftroute route explain <ip|domain> [--json]   # kernel + simulated decision + drift
riftroute diff [--json]                         # desired vs actual

riftroute profile list [--json]
riftroute profile show <name> [--json]
riftroute profile enable <name> [--dry-run] [--yes]
riftroute profile disable <name> [--dry-run] [--yes]

riftroute apply [file] [--dry-run] [--yes]      # declarative config; default file: ./riftroute.yaml
riftroute list refresh [name|--all]

riftroute snapshot list [--json]
riftroute snapshot restore <id> [--yes]
riftroute panic                                 # flush all managed routes, restore baseline (idempotent)

riftroute doctor [--json]                        # diagnostics battery → report
riftroute watch                                  # live TUI (post-MVP)
riftroute logs [--follow] [--since ...] [--json] # audit timeline

riftroute daemon install|uninstall|status|restart
riftroute completion bash|zsh|fish
riftroute version
```

Exit codes are stable (0 ok; distinct non-zero for refused-guardrail vs apply-failed-but-rolled-back vs daemon-unreachable) so scripts can branch.

---

## 10. Declarative config file (git-committable, first-class)

YAML (accept TOML too). Validated with clear, line-referenced errors. `riftroute apply` reconciles live state to this file via the Apply Protocol.

```yaml
version: 1

settings:
  ip_version: [v4, v6]
  default_mode: exclude          # exclude | include
  auto_apply_on_change: true     # react to VPN up/down, link, sleep/wake
  kill_switch: false
  connectivity_guard:
    enabled: true
    anchors: [gateway, "1.1.1.1"]
    confirm_timeout: 15s         # interactive auto-revert
    guard_window: 30s            # non-interactive guard after auto-apply

profiles:
  - name: work-direct            # corp intranet stays direct (bypasses VPN)
    enabled: true
    mode: exclude
    gateway: auto                # or "192.168.88.1"
    priority: 100
    rules:
      - { type: cidr,   value: "10.0.0.0/8",  comment: "corp LAN" }
      - { type: domain, value: "jira.internal.example.com" }
    lists: [rfc1918]

  - name: only-tunnel-banking
    enabled: false
    mode: include                # ONLY these go through the tunnel
    rules:
      - { type: domain, value: "mybank.example.com" }
      - { type: asn,    value: "AS13335", comment: "Cloudflare" }

lists:
  - name: rfc1918
    static:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
  - name: cloudflare-ranges
    source: "https://www.cloudflare.com/ips-v4"
    refresh: 24h
```

Validation rules: every `cidr`/`ip` parses; domains are syntactically valid; `gateway` is `auto` or a valid IP; unknown list refs error; `include` profiles warn on macOS where Model B is unavailable; durations parse. Validation never mutates anything.

---

## 11. IPC / daemon API contract

- **Transport:** HTTP/JSON over a **Unix domain socket** at a fixed path (e.g. `/var/run/riftroute.sock`), plus an **SSE** stream for live events (status changes, drift, applied/rolled-back, audit appends). The desktop app's **Go side** (and the CLI) hold this connection via the shared `apiclient`; the React layer receives updates as **Wails runtime events**, never HTTP/SSE directly (§3.5). `riftrouted` does **not** quit when a client drops.
- **Authz:** OS **peer-credential** check (`SO_PEERCRED` Linux / `LOCAL_PEERCRED`/`getpeereid` macOS) — only the installing user / an allowed admin group may call mutating endpoints. Optionally a token handshake.
- **No TCP, never `0.0.0.0`** (`AGENTS.md §11`). If a debug TCP endpoint ever exists, bind `127.0.0.1` only and gate it behind a flag.

Endpoints (illustrative; shared by GUI + CLI via `apiclient`):

```
GET  /state                      # vpn, interfaces, default owners, profiles, drift, health
GET  /routes?family=&owner=      # routing table (paged)
GET  /rules?family=              # Linux rules
POST /route/explain   {target}   # kernel + simulated decision
GET  /diff                       # desired vs actual
POST /plan            {desired}  # build plan + inverse (no apply)  -> dry-run
POST /apply           {desired, options:{dry_run,yes,confirm_timeout}}
POST /confirm         {tx_id}    # keep changes (cancels auto-revert)
POST /rollback        {tx_id|snapshot_id}
GET  /snapshots ; POST /snapshots/{id}/restore
POST /panic
GET  /audit?since=&follow=
GET  /interfaces ; GET /dns
POST /doctor
GET  /events  (SSE)
POST /lists/{name}/refresh
POST /profiles/{name}/{enable|disable}
```

All mutating calls are serialized server-side (one apply at a time); concurrent requests queue.

---

## 12. Privilege & security model

- `riftrouted` runs as root via **launchd**/**systemd**, installed by `riftroute daemon install` (admin auth once). GUI + CLI are unprivileged.
- **Never build shell command strings.** Use `exec.Command(path, args...)` with explicit argument arrays — no shell interpolation — so a malicious remote-list entry or odd interface name **cannot** inject. Additionally **strictly validate** every value before exec (must be a valid CIDR/IP/known iface/etc.).
- **Escape untrusted content in the DOM** (hostnames, list contents, interface names, route comments) — `AGENTS.md §11`.
- **Remote lists:** HTTPS only, response **size limits**, content **validated as CIDR/IP**, checksum stored; list contents are **never executed**, only parsed.
- **"Powerful feature" awareness** (`AGENTS.md §11`): root route mutation is exactly the kind of capability that's safe locally but catastrophic if the control channel were exposed — hence UDS + peer-cred + serialized applies + guardrails.
- **Secrets/PII hygiene before open-sourcing** (`AGENTS.md §11`): scrub internal hostnames, sample IPs, usernames from fixtures/screenshots/**commit history**; if leaked, rewrite history + force-push.

---

## 13. Persistence & state
- SQLite (pure-Go) owned by `riftrouted`, stored in a system location (e.g. `/var/lib/riftroute` Linux, `/usr/local/var/riftroute` or `/Library/Application Support/RiftRoute` macOS — daemon runs as root). Tables: profiles, rules, lists (+ cache), settings, ownership map, snapshots, audit log.
- The GUI/CLI read state **via the API**, never by touching the daemon's files directly.
- **Shutdown policy:** on **clean** `daemon stop`, managed routes **persist** by default (so a restart doesn't surprise-change routing); `--flush` removes them. On **crash**, routes persist and are **reconciled/repaired on restart** (snapshot + ownership). `panic`/`uninstall` removes them.

---

## 14. Build, cross-compile, signing, packaging, distribution (`AGENTS.md §8/§9`)

- **cgo split** (Wails needs cgo for the native webview): **macOS slice** built on a **macOS runner** (`CGO_ENABLED=1`, cross arches with `clang -arch x86_64|arm64`); **Linux slice** on a **Linux runner** (WebKitGTK). The CLI + daemon core stay cgo-free where possible; keep **pure-Go SQLite** to avoid extra cgo.
- **Always-compiles fallback:** a build-tagged stub for unsupported configs (and the future Windows target) so every configuration builds — daemon + CLI must build even where the GUI's native shell can't (`AGENTS.md §8`).
- **CI matrix** on real runners (mac + linux); `-trimpath` and `-ldflags "-s -w -X main.version=…"`.
- **Signing/notarization (macOS spectrum, pick deliberately, `AGENTS.md §9`):** unsigned → "damaged"; ad-hoc (`codesign --sign -`) → runs on Apple Silicon but first launch needs right-click→Open; Developer ID + notarized (`notarytool … --wait` + `stapler staple`) → zero prompts. **Gate signing CI on secrets** so contributors without Apple creds still get a working ad-hoc build. Document the install step that matches the chosen level.
- The **privileged-helper install** (launchd plist / systemd unit) must be signed/owned correctly and documented; the GUI guides the one-time admin auth.
- **Packaging:** macOS `.dmg` + Homebrew tap; Linux `.deb` + AppImage (+ AUR optional); the daemon unit/plist ships with the package and is enabled by `riftroute daemon install`.
- **Auto-update (`AGENTS.md §9`):** check GitHub Releases, notify with a link. Update the **GUI** freely; update **`riftrouted` safely** — snapshot, install new binary, restart, **verify routing still correct**, rollback the binary if the new daemon fails its self-check. Never break routing during an update.

---

## 15. Testing & verification strategy (`AGENTS.md §10`)

- **Unit (pure logic):** CIDR aggregation, LPM simulator, reconcile/diff, config parse+validate, ownership tracking, plan/inverse generation, watchdog timing (with a **fake clock**), conflict detection.
- **Engine against the `fake` provider:** exercise the **entire Apply Protocol** — including the §2.5 **failure & recovery matrix** — with zero risk to any host: inject op failures, anchor loss, missed confirms, mid-transaction "crash" (drop + restart), concurrent network events. Assert full rollback / repair / idempotent panic.
- **Linux real integration in a network namespace (`ip netns`):** the perfect "throwaway real state" (`AGENTS.md §10`) — run the **real** `ip` add/del/rule/get inside an isolated namespace, assert real resulting state, all offline and safe. Exercises the real Linux backend + parser.
- **Parser tests against captured real fixtures:** `netstat -rn`, `ip [-j] route/rule show`, `route get`, `ip route get` across OS/iproute2 versions (Appendix C). macOS real-mutation tests gated behind an explicit opt-in flag (CI uses fixtures + fake by default; never mutate the runner's table unguarded).
- **Connectivity guard / deadman:** test with fake reachability + fake clock that rollback fires within K probes and that confirm cancels it.
- **Frontend:** at least a **smoke test** (Playwright/WebDriver) of critical flows; note WKWebView automation is limited, so also test UI logic against the browser-mode/dev path. Verify computed styles, not screenshots, for exact styling.
- **Adversarial review pass** before any large change merges — a reviewer whose job is to **refute** each change; reliably catches the plausible-looking subtle routing bug (`AGENTS.md §10`).
- **Shell-out fidelity:** wrap `ip`/`route`/`pfctl`/`nft` rather than reimplementing; parse machine-readable output; set non-interactive env; put a **timeout on every external call** (`AGENTS.md §10`).

**Definition of "safe enough to mutate":** the failure matrix suite (fake + netns) is green, panic is proven idempotent from arbitrary state, and the watchdog is proven to recover from anchor loss and missed confirms.

---

## 16. Observability & logging
- Structured logs in `riftrouted` (levels; rotation). The **audit log** is the user-facing, queryable record (§7.7) — distinct from debug logs.
- A `--verbose` mode surfaces every executed command + its raw output (helps the user trust and debug).
- `riftroute doctor --json` and `riftroute status --json` are designed to be pasted into bug reports.

---

## 17. Implementation plan (milestones — build in this order)

> Each milestone is independently shippable/testable. Early milestones **cannot break the system** (read-only), which front-loads confidence.

**M0 — Scaffolding & spine.** Repo layout; `wails init` with the **`react-ts` template** + Tailwind (CSS-variable tokens) + TanStack Query/Virtual wired to the generated Wails bindings (§3.5); daemon skeleton + UDS API + SSE + peer-cred authz; `apiclient`; CLI skeleton with `--json`; **fake `RouteProvider`**; config parser+validator; CI matrix (mac+linux) with cgo split + always-compiles fallback; SQLite store. *Exit:* `riftroute status` talks to `riftrouted` end-to-end; the desktop app renders live state in the real WebKit window; everything builds on both runners.

**M1 — Read-only core (cannot break anything).** Real read paths (table, rules, route get, interfaces, DNS, gateway detection) for macOS + Linux; **Routing Table viewer**, **Route Explain simulator**, **Status panel**, **diff (vs empty desired)**; CLI `table`/`explain`/`status`/`diff`; daemon install/uninstall. *Exit:* a user can fully inspect and understand their routing with zero mutation.

**M2 — Safe mutation + the entire safety apparatus.** Snapshot/restore; transaction + precomputed inverse; **Apply Protocol** (dry-run, atomic, verify); **watchdog/deadman + commit-confirm**; ownership tagging (Linux `proto` + DB; macOS DB); **panic**; exclude-mode **Model A**; profile enable/disable; **audit log**; guardrails (§2.4). Tests: full **failure & recovery matrix** on fake + Linux netns. *Exit:* first real route change is provably revertible and ownership-scoped.

**M3 — Auto-apply (the "magic").** `netmon` (VPN up/down, link, addr, DNS, sleep/wake, DHCP) with debounce; reconciler subscribes and runs the auto-apply path (guard kept, confirm skipped); `gateway: auto`. *Exit:* toggling the VPN reconciles routes automatically and safely, audited.

**M4 — Advanced routing.** include/inverse mode; **Linux Model B** (dedicated table + `ip rule`, clean teardown); **CIDR aggregation**; **IPv6 parity**; **conflict/overlap detection**. *Exit:* inverse routing + dual-stack work and are explained in the UI.

**M5 — Domains & lists.** Domain rules (resolve A+AAAA, route results) + **background re-resolver** for CDNs; **remote subscribable lists** with refresh+checksum; **GeoIP/ASN** lookup + ASN/country rules. *Exit:* `route by domain` and `subscribe to a range list` work.

**M6 — Power features & deep observability.** **Kill switch** (pf/nft); **split-DNS**; **per-app routing (Linux)**; **leak detector**; **flow/traffic monitor**; **MTU/MSS**; **Doctor** battery; `riftroute watch` TUI. *Exit:* the diagnostics suite is genuinely useful and the leak/kill-switch protections work.

**M7 — Polish & ship.** Theming (light/dark, CSS vars); tray/menu-bar quick toggles + Panic; menu bridging + Edit menu; i18n-ready + RTL with forced-LTR code panes; signing/notarization; packaging (dmg/brew/deb/AppImage); safe auto-update; docs (README with install step matching signing level); **adversarial review**; smoke tests; secret scrub. *Exit:* a stranger can install it, understand it, use it safely, and never get stranded.

---

## 18. Acceptance criteria / Definition of Done

- **Safety:** Every mutation is snapshotted, atomic-with-rollback, dry-runnable, ownership-scoped. The watchdog auto-reverts on anchor loss; commit-confirm auto-reverts on missed confirmation. `panic` restores baseline idempotently from any state. The full §2.5 failure matrix is green on fake + Linux netns. **No code path can leave the user without connectivity without auto-reverting.**
- **Never touches foreign routes:** proven by tests that pre-seed system routes and assert they're untouched across apply/rollback/panic.
- **Observability:** table viewer (virtualized, classified, LTR), route-explain (kernel+simulated+drift), desired-vs-actual diff, leak detector, audit timeline, doctor — all present and accurate on both OSes.
- **Core UX:** profiles toggle and reconcile; declarative `apply` works and is idempotent; auto-apply reacts to VPN up/down and network changes; CLI `--json` everywhere with stable exit codes; config validation gives line-referenced errors.
- **Desktop quality (`AGENTS.md`):** renders correctly in **WKWebView + WebKitGTK** (not just Chrome); native menu bridged + Edit menu; close-to-quit GUI (routing persists); single-instance; theming via CSS vars (light+dark); explicit z-index scale; no main-thread-blocking renders; tray quick-toggles + Panic; i18n-ready + RTL with forced-LTR code panes.
- **Build/ship:** CI green on mac + linux; cgo split + always-compiles fallback; `-trimpath` + version stamp; signed/notarized (or documented ad-hoc) builds; dmg/brew/deb/AppImage; daemon install via launchd/systemd; safe auto-update; README documents the signing-matched install step.
- **Security:** UDS + peer-cred authz; never `0.0.0.0`; arg-array exec (no shell) + strict input validation; untrusted content escaped in the DOM; remote lists validated/size-limited/never executed; secrets scrubbed from history.
- **Verification:** real-window manual run + adversarial review pass + frontend smoke test completed before ship.

---

## 19. Risks & edge cases (must be explicitly handled)

VPN pushes a route more specific than ours (bypass silently fails) · multiple/nested VPNs · IPv6 default leak · Wi-Fi/subnet change → stale gateway → unreachable next-hop · DHCP lease change · interface flapping (debounce) · sleep/wake → re-assert · gateway not on-link · metric collisions with the VPN · routing the gateway itself (refuse) · removing the control-path route (refuse) · SSH-session self-lockout (protect) · macOS scoped-route quirks · old `iproute2` without `-j` (text-parser fallback) · macOS lacking policy routing / fwmark (Capabilities-gated UI) · huge tables (virtualize) · malicious remote-list contents (validate + arg-array exec) · daemon crash mid-transaction (reconcile/repair on restart).

---

## Appendix A — Canonical platform commands (reference)

**macOS**
```
route -n add -host <ip> <gateway>                 # add host route (bypass)
route -n add -host -ifscope <if> <ip> <gateway>   # scoped variant
route -n delete -host <ip> <gateway>
netstat -rn          (-f inet | -f inet6)         # show table
route -n get <ip>                                  # kernel decision
route -n get default
ipconfig getoption <if> router                     # physical gateway, VPN-independent
route -n monitor                                    # route socket events
scutil / SCDynamicStore / NWPathMonitor            # VPN up/down, primary service
pfctl -a riftroute ...                                # kill switch / leak block
scutil --dns                                        # DNS state
netstat -an ; lsof -i                               # active connections
```

**Linux**
```
ip route add <cidr> via <gw> dev <if> proto riftroute [metric N]
ip route del <cidr> proto riftroute
ip route add default via <gw> dev <if> table <T> proto riftroute   # Model B
ip rule add to <cidr> lookup <T> priority <P>                     # selectors: to/from/uidrange/fwmark
ip -j route show [table <T>]      ;  ip -j rule show
ip -j route get <ip>                                              # kernel decision
ip route show proto riftroute                                       # owned routes
ip monitor route link addr                                        # netlink events
nft add table/chain ...                                           # kill switch
resolvectl / /etc/resolv.conf                                     # DNS state
ss -tunp                                                          # active connections
# per-app: cgroup v2 + nft 'meta cgroup' (or -m owner) -> fwmark -> ip rule fwmark X table Y
```

## Appendix B — Glossary
**Split tunneling** — sending some traffic through a VPN and some directly. **Policy-based routing** — routing decisions based on more than destination (source, uid, mark). **LPM (longest-prefix-match)** — kernel picks the most-specific matching route; a `/16` beats a `/0` default automatically. **Model A** — host/CIDR routes in the main table. **Model B** — dedicated routing table + `ip rule` (Linux). **fwmark** — packet mark used to steer rules. **Anchor/canary** — host used to verify connectivity. **Deadman/watchdog** — independent auto-revert on connectivity loss. **Commit-confirm** — apply that auto-reverts unless explicitly confirmed. **Ownership** — RiftRoute only mutates routes it created (Linux `proto` tag / macOS DB).

## Appendix C — Output parsing notes & fixtures
Capture and commit real outputs as test fixtures across versions: macOS `netstat -rn`/`route get` (multiple macOS releases), Linux `ip -j route show`/`ip -j rule show`/`ip route get` (new iproute2) **and** the non-`-j` text forms (older iproute2) — the Linux parser must handle both. Include dual-stack, scoped routes, policy-routing tables, and a VPN-up snapshot for each. These power the §15 parser tests and the netns integration baseline.