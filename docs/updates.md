# Signed automatic updates (phase 2)

Status: built (steps 1–4); the server side and the first signed release are
not yet live. Decisions already made by the owner (2026-09-23):
auto-install is the default (notify-only and off stay available); our server
is the primary source and GitHub Releases the fallback, both carrying the same
ed25519-signed manifest; the signing key lives only on the owner's Mac — never
on the server, never in GitHub Secrets; the daemon updates itself, the desktop
app only notifies.

## Trust model

- **One thing is trusted: the signature.** A manifest is accepted only if it
  verifies against a public key compiled into the binary. Where it came from
  (our server, GitHub, a cache) doesn't matter.
- The manifest lists every release asset with its **SHA-256 and size**. The
  daemon installs only a download whose hash matches the signed entry.
- **Never backwards.** A manifest offering a version older than (or equal to)
  the running one is ignored, so replaying an old signed manifest does nothing.
- **Unsigned server advice can only hold back, never push.** The server adds
  unsigned `rollout_percent` and `halt` fields next to the signed manifest; a
  compromised server can at most delay an update, not deliver one.
- **Key rotation:** the binary carries up to two public keys (current + next),
  each with a key ID; a new release can introduce the next key before the old
  one retires.

## Keys and signing (owner's Mac only)

- New tool `cmd/riftroute-release` (built locally, never shipped):
  - `keygen` — creates an ed25519 key pair; the private key is encrypted with a
    passphrase (scrypt + XChaCha20-Poly1305, `golang.org/x/crypto`) and written
    to `~/.config/riftroute/release-key` (0600). Prints the public key and key
    ID to paste into `internal/update/keys.go`. Passphrase is typed at a
    prompt, never an argument or env var. Clew's key is never read.
  - `sign <tag>` — downloads the tag's `checksums.txt` and asset list from
    GitHub, builds the manifest, checks every hash against the published
    checksums, prompts for the passphrase, and writes `manifest.json` +
    `manifest.json.sig`.
  - `publish <tag>` — uploads both files to the GitHub release (`gh release
    upload`) and to the server (scp into its data dir, like deploy).
- CI (`release.yml`) is unchanged: it builds and publishes assets as today. A
  release reaches users only after the owner signs and publishes its manifest.

## Manifest

```json
{
  "schema": 1,
  "channel": "stable",
  "version": "0.2.6",
  "published": "2026-10-01T12:00:00Z",
  "notes_url": "https://github.com/Amirhat/riftroute/releases/tag/v0.2.6",
  "min_from": "0.2.4",
  "assets": [
    {"os": "darwin", "arch": "arm64", "kind": "tarball",
     "url": "https://github.com/Amirhat/riftroute/releases/download/v0.2.6/riftroute_0.2.6_darwin_arm64.tar.gz",
     "sha256": "…", "size": 12345678}
  ]
}
```

`manifest.json.sig` = ed25519 signature over the exact manifest bytes, with
the key ID. `min_from` lets a release say "don't auto-jump from older than
this" (then: notify only).

## Where clients look

1. `https://riftroute.tellnew.tech/api/v1/update/stable` → the signed manifest
   and signature, plus unsigned advice `{rollout_percent, halt}`. The daemon
   remembers the server's last advice on the newest release.
2. If that fails (network, 404, 5xx, bad signature):
   `https://github.com/Amirhat/riftroute/releases/latest/download/manifest.json`
   (+ `.sig`). That copy obeys the server's last advice on the same version
   (so a halt the daemon has seen holds even when the server is unreachable);
   a release the server never advised on is held for 7 days after it was
   published before it installs from GitHub — time to halt or pull it.
3. **Halting a release** = Halt on the admin page. To pull one completely,
   also delete `manifest.json` from its GitHub release.
4. If the server can't read its own advice it answers 503 (fail closed), and
   the daemon goes by the last advice it saw.

The request carries no identifier: no install ID, no version in the URL; the
User-Agent is just `riftroute`. The server keeps no access log.

## The daemon's update loop (macOS launchd, Linux systemd)

- Runs when preference `updates` is `auto` or `notify`: 10 minutes after
  start, then every 6 h ± 30 min jitter. `off` = no update traffic at all
  ("Check for updates" still works on demand).
- **Rollout bucket:** a random number 0–99 generated once per install and
  stored locally; the update is offered when `bucket < rollout_percent`.
  Nothing about the bucket is sent anywhere.
- **notify:** record "0.2.6 available" in State; app and CLI show it with an
  Install button / `riftroute update install`.
- "Check now" and "Install now" run on the daemon's own lifetime: the request
  returns with the verdict, the download and self-test carry on, and clients
  follow along through `GET /update` / State.
- **auto:** download → verify SHA-256 and size against the signed entry →
  unpack the daemon into a root-only staging dir of its own
  (`update-staging/<version>/`) → **self-test the new binary**: its
  `-version` must be the signed version, and `riftrouted -selftest` — run
  with the service's own arguments, pointed at a *copy* of the database —
  must migrate that copy and initialise the provider → wait for the **idle
  gate** → look once more (a halt or a newer release since staging stops it;
  the staged file's hash is re-checked) → swap.
- A release is **skipped** only when it is itself broken (its self-test runs
  and fails, its tarball lacks a proper `riftrouted`, its version doesn't
  match). A cancelled, interrupted or I/O-failed attempt is retried later.
- **Idle gate:** the daemon takes its apply lock only if nothing is being
  applied, nothing awaits confirmation, and no change started in the last 10
  minutes — and keeps it from the swap until it exits, so no change can
  start in between. User rollbacks wait for the same quiet moment.
- **Swap:** back up the database, keep the current binary as `riftrouted.prev`,
  atomically rename the new one into place, write an "update pending" marker,
  exit; launchd/systemd restart the daemon (KeepAlive / Restart=always).
- **Health gate + offline rollback:** before opening its database, the new
  daemon reads the marker. It must answer `GET /healthz` on its socket
  (checked from 20 s after start) within 5 minutes; a start that doesn't
  counts as failed. After **three failed starts** that early code restores
  `riftrouted.prev` — and the pre-update database only if the previous
  version can't read the new one (a breaking migration raised
  `schema_min_reader` past it) — records who rolled back and from what, and
  exits so the service manager starts the old binary. No network needed. A
  rolled-back version is not offered again until a newer one appears. If the
  rollback itself can't be done, that is recorded and shown, and the current
  binary starts (no restart loop).
- A crash between writing the marker and replacing the binary changed
  nothing; the next start clears the marker without skipping the release.
- Only the daemon binary is replaced. The CLI inside the app bundle (or
  wherever it was installed) and the desktop app are not touched.
- `daemon install` / `uninstall` clear the previous binary, the database
  backup and any pending marker.
- **macOS:** the release tarball's daemon is ad-hoc signed; if the installed
  one came from a Developer-ID-signed build, macOS may show its "background
  item" notice once after the first automatic update.

## Where auto-install is NOT used

- **Linux `.deb` installs** — the package manager owns those files; the daemon
  only notifies. (Detected by whether the `riftroute` package is installed.)
- **The desktop app** (`RiftRoute.app` / AppImage) — notify with a download
  link; macOS app bundles need re-signing and the app replaces itself poorly.
- A daemon that is not installed as a service (dev runs) never updates itself.

## Server (riftroute-server)

- `GET /api/v1/update/{channel}` — serves the stored signed manifest + advice.
  The server verifies the signature on upload/load too, and refuses a manifest
  that doesn't verify or goes backwards.
- Admin page "Releases": current version per channel, rollout percent (0 / 5 /
  25 / 50 / 100), Halt / Resume. Changes are written to the server's log.
- Re-publishing the same version (e.g. to add an asset) keeps its rollout and
  halt; a new version starts at the percent given to publish (default 100).
- No counting of update checks in this phase (that belongs to telemetry,
  phase 3, with its own consent rules).

## Surfaces

- API/State: `update` block — `{mode, last_check, available, status, error,
  rolled_back_from}`.
- CLI: `riftroute update [status|check|install|rollback]`.
- App: Settings → Updates shows the same, with Check now / Install now /
  Roll back; the "app is older than the daemon" note links to the download.

## Build order

1. `internal/update`: manifest types, signature verification, key IDs,
   asset selection, version rules — pure and fully tested.
2. `cmd/riftroute-release`: keygen / sign / publish.
3. Server endpoint + admin Releases page + publish path.
4. Daemon: checker, downloader, self-test mode, idle gate, swap, marker +
   rollback, State/API/CLI/GUI.
5. End-to-end rehearsal: a local fake server and a throwaway install on the
   fake provider; then the first real signed release, with a root test the
   owner runs on their Mac (update → forced failure → automatic rollback).
