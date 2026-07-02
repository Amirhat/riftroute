# Changelog

All notable changes to RiftRoute are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release candidate — the complete M0–M7 product. Everything below is part of
the initial release.

### Added

**Core & safety**
- Privileged daemon (`riftrouted`) owning all route mutation; unprivileged CLI
  (`riftroute`) and Wails desktop app (`RiftRoute.app`) over a peer-cred-gated
  Unix domain socket (HTTP/JSON + SSE).
- Apply Protocol: snapshot → reconcile → dry-run → watchdog → atomic apply with
  precomputed inverse → verify → commit-confirm → rollback. The §2.5 failure &
  recovery matrix is green on the fake provider and the Linux netns suite.
- Ownership-scoped mutation (`proto riftroute` on Linux; ownership DB on macOS).
- Crash recovery via ownership reconcile on startup.

**Routing**
- Exclude mode (Model A: host/CIDR routes) and include mode (Linux **Model B**:
  dedicated table `5252` + `ip rule … proto riftroute`).
- Rule types: `cidr`, `ip`, `domain` (scheduled re-resolution), `asn`/`country`
  (with a MaxMind MMDB), and `app` (Linux cgroup + fwmark per-app routing).
- Safe CIDR aggregation, conflict/overlap detection, and an LPM route-explain
  simulator with drift detection.
- Subscribable lists (HTTPS-only, size-capped, checksummed, never executed).

**Auto-apply & monitoring**
- Network-change monitor + debounced reconciler (auto-apply on VPN up/down etc.,
  guardrails kept), and a background domain re-resolver.

**Power features & observability**
- Kill switch (nftables on Linux / pf on macOS) with a reconnect allow-list.
- Doctor diagnostics battery + IPv6/DNS leak detector + MTU/blackhole check.
- Live flow monitor (per-connection via-VPN vs direct correlation).
- Per-domain split-DNS (macOS scoped resolvers / Linux resolvectl).
- `riftroute watch` live TUI; menu-bar/tray companion with quick toggles + Panic.
- Safe update check against GitHub Releases (SHA-256 verified; never self-replaces).

**Desktop GUI**
- Dashboard, Routing Table, Route Explain, Profiles (staged changes +
  commit-confirm countdown), History (audit timeline + snapshots), Diagnostics,
  and a Settings screen (theme, behavior, daemon & capabilities).
- In-app daemon setup — no terminal required: a first-run "Set up RiftRoute"
  screen installs + starts the privileged service via the native admin prompt,
  and Settings → Daemon service offers start / stop / restart / uninstall. The
  daemon is installed with `-allow-uid <desktop user>` so the unprivileged GUI
  can control a root daemon (socket handed to that user; writes still peer-cred
  gated). The CLI + daemon are bundled inside the app.

**Tooling & release**
- Cross-compiled CLI/daemon tarballs + checksums; `.deb`, `.dmg`, AppImage, and
  Homebrew packaging; tag-driven release workflow (code signing/notarization
  gated on Apple secrets).
- CI: Go race tests, real end-to-end suite, Linux netns suite, cgo-free cross
  builds, native GUI builds, and frontend smoke tests.

### Security & host-safety (pre-ship audit)
- **Crash-safe apply.** A write-ahead journal records how to undo a transaction
  *before* the kernel is touched; on startup, any in-flight/on-probation tx is
  reverted (fail-safe) — the only recovery that works on macOS, where kernel
  routes carry no owner tag. Closes SIGKILL/power-loss orphan routes and the
  "killed while the watchdog was armed" gap. (netns-tested on a real kernel.)
- **LPE fix.** The root daemon binary now installs to `/Library/PrivilegedHelper
  Tools` (root-only), not `/usr/local/bin` (admin-writable on macOS → root code
  swap). Binary/plist/unit are chowned to root and rejected if symlinked; the log
  dir is hardened.
- **Uninstall restores the host.** Uninstall now flushes all managed routes/rules
  (while the daemon is live — its DB is authoritative on macOS) before removing
  the service and binary, instead of leaving them installed.
- **No crash strands the user.** Every long-lived daemon goroutine (poller,
  reconciler, watchdog, tx-resolver) recovers from panics; an apply/resolve panic
  forces a rollback rather than freezing a half-applied change with a dead
  watchdog.
- **Fail-safe on unreadable gateway.** A transient gateway read (DHCP renewal,
  Wi-Fi↔Ethernet) no longer silently disables the gateway-capture guardrail or
  fires spurious reconciles; main-table changes are refused until the gateway is
  verifiable.
- **Conflicting routes refused** before apply; rollback reports its true outcome
  (keeps ownership + journal on an incomplete revert instead of a false success).

### Fixed
- **macOS daemon install now actually starts** (was "installed but never ran"):
  switched the launchd verbs from the legacy `launchctl load` to `bootstrap
  system` / `bootout` / `kickstart` (validated on macOS 15); the escalated install
  strips download-quarantine from the bundled CLIs first so Gatekeeper can't block
  them; the GUI reconnects to the system socket after install; and install now
  waits for the socket and surfaces the daemon log on failure instead of failing
  silently.
- macOS `.dmg` no longer reported "damaged": the app is re-signed (ad-hoc when no
  Developer ID) after the CLIs are bundled, so the signature stays valid.
- New minimal app icon (a clean split-route fork on an indigo tile).
- GUI Panic and kill-switch confirmations were no-ops because `window.confirm()`
  is unimplemented in the Wails WKWebView; replaced with an in-app confirm modal.
- GUI degraded/real-provider `null` slices (`interfaces`/`defaults`/`servers`/
  `addrs`) no longer crash the dashboard (null-guards + error boundary).
- GUI showed a blank window with the real provider: macOS interfaces with no
  address marshal `addrs: null` and the dashboard dereferenced `addrs[0]`. Added
  null guards + an error boundary so one bad field can't blank the whole app.
- Broken Settings gear icon (a mangled SVG arc path rendered as a tangle of
  loops); replaced with a correct gear.

### Notes
- The agent never mutates the host: all route/firewall/DNS mutation is verified on
  the fake provider and the Linux netns suite only.
- GeoIP/ASN rules require a user-supplied MaxMind MMDB.

[Unreleased]: https://github.com/Amirhat/riftroute/commits/main
