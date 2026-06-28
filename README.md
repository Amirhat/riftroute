# RiftRoute

**Split-tunneling / policy-based routing controller for macOS & Linux.**

RiftRoute lets a developer say *"these destinations bypass the VPN, everything
else goes through it"* (or the inverse), organize those destinations into
toggleable profiles/lists, and have the system keep the routing table correct
automatically as the VPN goes up/down and the network changes — **without ever
leaving the machine in a broken network state.**

> Status: **M0 (scaffolding & spine) complete.** The read-only core (M1) is next.
> No code path can mutate the routing table yet.

## Two non-negotiable pillars

- **Safety** — every route change goes through the Apply Protocol: snapshot →
  reconcile → dry-run → arm watchdog → atomic apply with precomputed inverse →
  verify → commit-confirm → rollback. Changes are ownership-scoped (RiftRoute
  never touches routes it didn't create). A bug degrades to *"no change"* or
  *"auto-reverted"*, never to *"user has no network"*.
- **Observability** — a routing-table viewer, a route-explain simulator
  (*"where does traffic to X go, and why?"*), a desired-vs-actual diff, a leak
  detector, and an audit timeline. The operator is never confused.

## Architecture

```
RiftRoute.app (Wails/React)  ─┐
                              ├─ HTTP/JSON + SSE over a Unix domain socket ─►  riftrouted (root)
riftroute  CLI (cobra)       ─┘        (peer-credential authz)                 owns all route mutation
```

- **`riftrouted`** — the persistent, privileged daemon; the **only** root
  component. Owns route mutation, network monitoring, reconciliation, snapshots,
  the watchdog, persistence (pure-Go SQLite), and the local API.
- **`riftroute`** — unprivileged CLI; `--json` everywhere, stable exit codes.
- **`RiftRoute.app`** — unprivileged Wails GUI. Its Go side holds the daemon
  connection and re-emits updates to React as Wails events; React never speaks
  HTTP/SSE/sockets directly. Closing the GUI does **not** stop routing.

See [`riftroute-spec.md`](riftroute-spec.md) for the full spec and
[`AGENTS.md`](AGENTS.md) for the desktop/shell/build rules.

## Prerequisites

- **Go 1.25+** (a transitive dep requires it; the toolchain auto-downloads).
- **Node 20+** and **npm** (for the GUI frontend).
- **Wails v2.12**: `go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0`
- **macOS**: Xcode Command Line Tools. **Linux**: `libgtk-3-dev`,
  `libwebkit2gtk-4.1-dev` (build the GUI with `-tags webkit2_41`).

## Build & run

```bash
make build           # daemon + CLI -> ./bin (cgo-free)
make run-daemon      # run riftrouted on a dev socket with the fake provider
./bin/riftroute --socket /tmp/riftroute-dev.sock status   # talk to it

make dev             # GUI with hot reload (wails dev)
make desktop         # build RiftRoute.app / native binary
make test            # daemon/CLI/engine tests
make cross           # prove every target compiles (incl. Windows fallback)
```

In M0 the daemon defaults to an **in-memory fake provider** (`-provider fake`),
so the whole UI/CLI/daemon spine runs with **no root and no real network**.
`-provider auto` selects the real per-OS backend (read paths land in M1).

## Install (macOS, current signing level)

M0 builds are **ad-hoc signed** (`codesign --sign -`). On first launch macOS
requires **right-click → Open** once (or clear the quarantine attribute); after
that it opens normally. Developer ID signing + notarization (zero prompts) is
gated on Apple credentials and lands in M7.

## Milestones

`M0` scaffolding ✓ · `M1` read-only core · `M2` safe mutation + full safety
apparatus (gated on the §2.5 failure-matrix being green on the fake provider
**and** a Linux netns) · `M3` auto-apply · `M4` advanced routing · `M5`
domains/lists · `M6` power features & deep observability · `M7` polish & ship.

The read-only milestones come first by design: they physically cannot break the
system, which front-loads confidence before any real route mutation ships.
