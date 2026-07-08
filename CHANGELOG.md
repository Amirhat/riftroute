# Changelog

All notable changes to RiftRoute are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] — 2026-07-08

Follow-up round hardening the routing table, wildcard domains, and toggles from
hands-on testing.

### Added
- **Full edit/delete of external routes** (added via terminal, DHCP, a VPN
  client — anything RiftRoute doesn't own): the Routing Table gains per-row
  Edit and Delete, run through a new plan-level Apply Protocol path
  (`ApplyPlan`) with the same WAL journal, connectivity watchdog, and
  commit-confirm countdown as a profile apply — but **without** ownership
  records, so a user's edit of system state is never re-touched by panic or
  crash recovery. The default route is protected (delete refused; edit allowed),
  and the guard catches a non-canonical `128.0.0.0/0` the kernel would mask to
  the real default. Managed routes are refused with a pointer to their profile.
- **Wildcard subdomains route end-to-end** (`*.example.com`): a loopback DNS
  learner, pointed at by per-domain resolver files (macOS) or systemd-resolved
  (`resolvectl`, Linux), relays lookups verbatim while learning the real
  subdomain addresses apps resolve — which then route automatically. Learned
  answers carry a TTL, are recency-capped, persist across restarts, and drive a
  debounced reconcile. A new `wildcard-dns` doctor check reports learner health.

### Fixed
- **Toggle switches** rendered with the knob outside the track (WebKit derived
  an unanchored absolute child's position from the button's centered text) —
  anchored with `left-0`; ON/OFF now read clearly in both light and dark mode.
- **Route-op guardrail**: default-route detection is by prefix length after
  parsing, and destinations are canonicalized to their masked form, so no
  non-canonical prefix can bypass the keep-default guard; the managed-route
  check matches by destination+table+family (the kernel's delete granularity).
- **DNS learner robustness**: in-flight handlers drain on stop and are
  concurrency-bounded; persistence is coalesced behind a 60s maintenance tick
  (no DB thrash under a lookup flood) that also GCs expired addresses and keeps
  upstreams current as resolvers change; resolver files are installed only when
  the proxy has an upstream, so a scoped resolver can never blackhole a domain.
- **Split-DNS precedence**: an explicit user resolver for a domain always wins
  over a wildcard learner entry for the same domain; the non-atomic resolver
  rewrite is serialized.
- Per-app builder copy clarifies macOS matches by the user a process runs as
  (PF socket owner); the edit-route gateway field rejects the profile-only
  `auto` value.

## [0.2.1] — 2026-07-07

A comprehensive UX and functionality overhaul across every screen.

### Added
- **Routing Table overhaul**: free-text filtering with owner chips; a "Where
  does traffic go?" lookup answering which gateway/route an IP *or domain*
  takes (kernel + simulated decision, matched row highlighted); routes sorted
  by real kernel lookup precedence (most-specific first, then metric); a
  policy-rules card showing how include-mode/per-app traffic is steered; and
  **manual routes** — add/delete single destinations (via VPN or bypass)
  backed by well-known profiles so they ride the full Apply Protocol
  (validation → guardrails → WAL → commit-confirm) and survive restarts.
- **Searchable pickers for per-app rules**: new `/system/users` and
  `/system/apps` catalogs (macOS Directory Services users; Linux cgroup-v2
  units) feed a keyboard-navigable Combobox in the Profile Builder — no more
  free-text-only uid entry (free text remains valid).
- **Snapshot restore**: snapshots now capture the pre-change profile set and
  `POST /snapshots/{id}/restore` puts the policy back exactly (including
  removing later profiles), reconciling through the protocol with
  commit-confirm. Retention keeps the newest 50. The History panel refreshes
  live and offers Restore per snapshot.
- **Flows filters**: free-text (process/pid/address/state), protocol chips,
  and interface chips derived from live data; process PIDs now captured from
  `ss`/`lsof` and displayed.
- **Diagnostics troubleshooting card**: kill switch, panic flush, daemon
  restart, and copy-report-as-JSON in one place; checks carry plain-language
  names and explanations, with report freshness shown and 10s auto-refresh.

### Fixed
- **Managed count / drift on macOS**: the dashboard derived "managed" from
  kernel owner tags that only exist on Linux — macOS showed 0 managed routes
  and permanent drift, and the doctor false-warned. The core service now reads
  the same ownership map the apply protocol uses; state additionally reports
  `managed_rule_count` so PF/per-app-only policies don't read as "0 managed".
- **Wildcard domains**: `*.example.com` passed validation but resolved as a
  literal DNS query, silently installing nothing. Wildcards now resolve their
  apex consistently across the resolver, the re-resolver, and split-DNS.
- **Domain rules on v4-only networks**: AAAA answers no longer make a whole
  exclude-mode profile unappliable — the family without a physical path
  degrades fail-safe (destinations stay tunneled) as long as the other family
  applies; no path at all is still an error so drift shows attention.
- **Linux visibility gaps**: `ip route` listing now includes the Model B
  table (5252) — include-mode routes were invisible to the table view, the
  ownership tag-scan, and crash repair. The per-app cgroup→fwmark nft marker
  is now actually wired (it previously had no callers), synced with enabled
  include-profiles on startup and every profile change.
- **Profile Builder**: the dry-run Review now renders the +adds/−removes diff
  (previously fetched and discarded), clears when the form changes, and
  scrolls into view; partial success ("saved but reconcile failed", e.g.
  include mode with the VPN down) is reported as `apply_error` with the save
  acknowledged instead of a bare failure; per-app rules in exclude mode are
  rejected with a clear message instead of silently ignored; the decorative
  never-persisted strategy dropdown was removed; the priority field can be
  blanked while retyping.
- **Toggles**: the dark-mode knob was surface-on-surface (invisible). New
  knob/track tokens contrast in both themes, plus a focus ring, disabled
  state, and a danger tone; the kill switch is the same Toggle everywhere.
- The standalone Explain page merged into the Routing Table; deep views
  (rules, snapshots, audit) refresh on live state events.

## [0.2.0] — 2026-07-06

The complete M0–M7 product, now with full macOS routing parity and a GUI that
covers the entire configuration surface. Supersedes v0.1.0 (which shipped a
subset of this list); everything below is part of this release.

### Security
- Dev-toolchain dependency upgrades resolving all open Dependabot advisories
  (5: 1 critical, 1 high, 3 moderate — none shipped in release binaries):
  vitest 2.x → 3.2.7 (critical: UI-server arbitrary file read/execute),
  vite 5.x → 6.4.3 (`server.fs.deny` bypass, dep-map path traversal,
  launch-editor NTLM hash disclosure), esbuild → 0.25.12 (dev-server CORS).
  `npm audit`: 0 vulnerabilities.

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
- Exclude mode (Model A: host/CIDR routes) and include mode — Linux **Model B**
  (dedicated table `5252` + `ip rule … proto riftroute`) or macOS **PF
  `route-to`** anchors (the Darwin analogue), bringing policy-routing and per-app
  parity to macOS. The abstract policy rule flows through the same plan / inverse /
  write-ahead journal / reconcile machinery; the provider renders it into its
  native primitive.
- Rule types: `cidr`, `ip`, `domain` (scheduled re-resolution), `asn`/`country`
  (with a MaxMind MMDB), and `app` — Linux cgroup + fwmark, or macOS PF matching
  the socket owner (uid/username).
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
- **Interactive Profile Builder** on the Profiles screen — a fully visual
  create/edit designer: name + description + enabled toggle, an Include/Exclude
  mode selector, and dynamic add/remove managers for CIDR/IP targets, domain rules,
  and per-app rules (a strategy dropdown: by uid/username on macOS, by application
  on Linux). Every field validates inline as you type (a bad IP like `999.999.999`
  shows an error next to the input, never freezing the window); a live banner shows
  the staged changeset (`+N routes · +M domains · +K app rules`); **Preview**
  dry-runs the real plan; **Apply Changes Safely** serializes to the backend model,
  re-validates over IPC, journals (WAL), and commits atomically with commit-confirm.
  Profiles can also be deleted (guarded). Backed by a single-profile save/delete API
  (`POST`/`DELETE /profiles`) that shares the config file's strict validation but
  touches only that one profile (lists and split-DNS untouched).
- **Import / Apply Config File** on the Profiles screen — a native file picker
  brings `riftroute apply file.yaml` into the window: pick a `.yaml`/`.yml`, get
  daemon-side strict validation with line-referenced errors, a visual `+X / −Y`
  preview, and an atomic commit-confirmed apply. No terminal required; corrupt or
  invalid files render inline instead of crashing the UI.
- **Visual lists manager** on the Profiles screen — create/edit/delete reusable
  rule lists without YAML: static CIDR/IP entries with inline validation, or a
  remote (subscribable) https source with a refresh interval and a "Refresh now"
  action. Deleting a list a profile still references is refused with a friendly
  message. The Profile Builder attaches lists as toggleable references. Backed by
  `POST`/`DELETE /lists`.
- **Split-DNS editor** in Settings — per-domain resolver routes are now edited
  visually, persisted (they survive daemon restarts; startup re-applies them),
  and applied live (`GET`/`PUT /splitdns`). The declarative `/config` path
  persists the same selection, so file and UI stay in sync.
- **Live Flows view** — the flow monitor joins the GUI: every active connection
  with its process, remote, interface, and a via-VPN/direct verdict,
  auto-refreshing, with an all/VPN/direct filter.
- **Export config** in Settings — everything assembled visually (profiles, lists,
  split-DNS) serializes back to the same git-committable `riftroute.yaml` via the
  native save dialog; the export round-trips through the importer.
- **Update check** in Settings — queries GitHub Releases and shows the newer
  version + download URL; nothing is ever self-installed.
- **Auto-apply is now a live toggle** in Settings (was display-only): it flips
  reconcile-on-network-change at runtime — no daemon restart — and the choice is
  persisted, so it survives restarts. The reconcile loops always run and gate
  each pass on the toggle; the connectivity guard still protects every apply.
- The Capabilities card credits each platform's native backend (`pf` on macOS,
  `nftables` on Linux) and no longer shows macOS as merely "missing" the Linux-only
  fwmark / proto-tag primitives.
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
- The macOS `.dmg` is now a **universal** build — the GUI (`wails -platform
  darwin/universal`) and the bundled CLI + daemon (`lipo` of arm64 + x86_64) run
  on every Mac, Apple Silicon and Intel.
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

### Hardening (pre-ship production review)
A multi-angle adversarial review of the whole change set, with every finding
verified against the real system where possible:
- **PF labels rewritten** — pfctl caps rule labels at 63 chars (verified:
  "rule label too long"); the original base64 identity labels could never load.
  Ownership is now a short constant label and rule identity is parsed from
  pfctl's canonical rule text (normalizations captured from a real `pfctl -nvf`
  run: appended `flags S/SA keep state`, bare host IPs, `user = 501`, parenless
  gateway-less `route-to`). Every rendered rule form is accepted by the real
  pfctl parser (parse-only; nothing loaded).
- **Rule identity includes the route-to gateway** — a VPN re-handshake that keeps
  the utun but moves the peer gateway now plans a replace instead of silently
  keeping a stale (blackholing) rule.
- **PF anchor read failures abort mutations** — a transient pfctl error can no
  longer cause a read-modify-write to rewrite the anchor from an empty base and
  drop every other owned rule.
- **`/etc/pf.conf` is written atomically** (same-dir temp + fsync + rename,
  original permissions preserved) — a crash mid-write can't truncate the system
  firewall config. The `pfctl -E` enable reference is token-tracked and released
  (`pfctl -X`) on teardown, so PF's enabled state is restored too.
- **Per-app values are strictly validated on macOS** (uid/username charset) at
  config validation AND in the engine — one bad value can no longer fail the
  whole anchor load (or inject rule tokens).
- **Data-loss guards**: editing a profile no longer drops asn/country rules the
  builder doesn't display; a profiles-only YAML import no longer wipes the
  persisted split-DNS selection; GUI-created profiles get collision-proof IDs
  (rename + recreate could previously overwrite another profile); list renames
  are locked (upsert-by-name would have created a duplicate).
- **Honest status**: when desired state can't be computed (e.g. include mode
  while the VPN is down — matched traffic fail-safes into the tunnel-less
  blackhole rather than leaking), the dashboard now shows Drift "Attention" with
  the reason instead of a false "in sync".
- **Efficiency**: anchor reads are TTL-cached and state broadcasts skip entirely
  when no client is connected (an idle headless daemon no longer forks
  pfctl/netstat every 3 s); the Flows table caps its synchronous render.
- **Error transparency**: daemon refusals now surface their real reason in the
  GUI (not "request failed"), and delete/save flows refresh even when the
  follow-up reconcile fails.

### Notes
- All route/firewall/DNS mutation logic is verified on the fake provider, the
  Linux netns suite, pure round-trip/generator unit tests, and parse-only
  (`pfctl -nf`) acceptance checks against the real pfctl grammar.
- The macOS PF backend was additionally **verified live on real hardware**
  (`scripts/live-pf-test.sh`, run as root by the operator): the `route-to`
  anchor loads into `/dev/pf`, survives a daemon restart with zero drift, and
  panic restores baseline exactly — anchor emptied, `pf.conf` byte-identical,
  and the PF enable token released (PF returned to its prior disabled state).
  The kernel's canonical rule echo matched the parser's test fixtures verbatim.
- GeoIP/ASN rules require a user-supplied MaxMind MMDB.

[0.2.2]: https://github.com/Amirhat/riftroute/releases/tag/v0.2.2
[0.2.1]: https://github.com/Amirhat/riftroute/releases/tag/v0.2.1
[0.2.0]: https://github.com/Amirhat/riftroute/releases/tag/v0.2.0
