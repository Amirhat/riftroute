# Contributing to RiftRoute

Thanks for your interest in RiftRoute. This guide covers the dev environment,
how to build/run/test, the code conventions, and the **safety rules** that are
non-negotiable for a tool that mutates the routing table.

## Golden rule: never break the host

RiftRoute owns the routing table on real machines. While developing:

- **Never** mutate the live host's routes, firewall, or DNS. Run the daemon with
  the in-memory fake provider (`-provider fake`, the default) for all local work.
- Real route/firewall mutation is verified **only** on the fake provider and in a
  **Linux network namespace** (`test/netns`, run in CI). Do not run
  `riftroute daemon install` or `-provider auto` + apply as part of development.
- Every route change must go through the Apply Protocol (snapshot → dry-run →
  watchdog → atomic apply with precomputed inverse → verify → commit-confirm →
  rollback). Don't add code paths that mutate outside it.
- Changes are ownership-scoped: RiftRoute only touches routes it created
  (`proto riftroute` on Linux, the ownership DB on macOS). Preserve that.

See [`AGENTS.md`](AGENTS.md) and [`riftroute-spec.md`](riftroute-spec.md) — the
spec is the source of truth.

## Prerequisites

- **Go 1.25+** (a transitive dep requires it; the toolchain auto-downloads)
- **Node 20+** and **npm** (GUI frontend)
- **Wails v2.12**: `go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0`
- **macOS**: Xcode Command Line Tools.
  **Linux**: `libgtk-3-dev`, `libwebkit2gtk-4.1-dev` (GUI built with
  `-tags webkit2_41`); the tray also needs `libayatana-appindicator3-dev`.

## Build & run

```bash
make build           # daemon + CLI -> ./bin (cgo-free)
make run-daemon      # riftrouted on a dev socket with the fake provider
./bin/riftroute --socket /tmp/riftroute-dev.sock status

make dev             # GUI with hot reload (wails dev)
make desktop         # build RiftRoute.app / native binary
make tray            # menu-bar companion (cgo + native tray libs)
```

## Testing

All tests are host-safe and (except the GUI build) offline.

```bash
make test            # Go unit/integration tests (fake provider)
go test -race ./internal/... ./cmd/...   # the race-clean suite CI runs
make test-e2e        # real end-to-end: builds binaries, drives the daemon
                     # over a live socket through apply/confirm/rollback/panic
make cross           # prove every target compiles, cgo-free

# Linux only (CI): real `ip` inside a namespace
sudo go test -tags netns ./test/netns/...

# Frontend smoke tests (Vitest + jsdom)
cd desktop/frontend && npm install && npm test
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs all of the
above on every PR: Go tests (race), the e2e suite, the Linux netns suite,
cgo-free cross builds, the native GUI builds, and the frontend tests. **A PR
must keep CI green.**

## Code style

- **Go**: run `gofmt -s -w .` (or `make fmt`) and `go vet ./internal/... ./cmd/...`
  before committing. Match the surrounding code; keep comments explaining *why*.
- **Frontend**: TypeScript strict; the production build runs `tsc && vite build`.
  Never use `window.confirm/alert/prompt` — they are no-ops in the Wails
  WKWebView; use the in-app `ConfirmModal` instead.
- Keep the daemon + CLI **cgo-free**. Anything needing cgo (GUI, tray) lives
  behind a build tag with a cgo-free stub so `go build ./cmd/...` stays portable.

## Commits & pull requests

- Use clear, conventional commit subjects (e.g. `fix(gui): …`, `test: …`,
  `feat(routing): …`). Explain the *why* in the body.
- One logical change per PR. Include tests for new behavior.
- Fill in the PR template; confirm host-safety (fake/netns only) and that
  `make test`, `make test-e2e`, and the frontend tests pass.

## Project layout

```
cmd/riftrouted     privileged daemon (route mutation, monitor, API)
cmd/riftroute      unprivileged CLI
cmd/riftroute-tray menu-bar companion (build tag: tray)
internal/safety    Apply Protocol (watchdog, commit-confirm, rollback)
internal/routing   engine: desired state, reconcile, aggregation, simulate
internal/provider  fake / macos / linux route providers
internal/core      headless service the API/CLI/GUI render
internal/api       UDS HTTP/JSON + SSE server (peer-cred authz)
internal/{netmon,reconcile,dns,lists,killswitch,perapp,splitdns,update}
desktop            Wails GUI (Go bindings + React/TS frontend)
test/netns         Linux real-`ip` integration tests
test/e2e           real daemon ↔ socket ↔ client ↔ CLI end-to-end tests
```

## Reporting security issues

Do **not** open a public issue for vulnerabilities — see
[`SECURITY.md`](SECURITY.md).

By contributing you agree your contributions are licensed under the
[MIT License](LICENSE).
