# Telemetry and monitoring — design

Status: being built (branch `feat/telemetry`). The choices below were made by
the owner on 2026-09-23 (opt-out, transparent, three levels, hard limits) and
are not reopened here; this document turns them into a payload, a schedule,
a server, and a dashboard.

## What it's for

RiftRoute changes routing tables on people's machines, mostly where nobody
reports problems. Telemetry answers, release by release:

- Is this version healthy? Starts, crashes, updates installed and rolled
  back, helpers repaired.
- Do changes work? How many applies, how many fail or roll back and why,
  how long they take.
- Do tunnels connect? Per protocol: connects, failed attempts by diagnosed
  cause, drops.
- What's used? Profiles, rule kinds, tunnel types, kill switch, split DNS —
  to know what may be changed or dropped.

Monitoring is the server side: a dashboard that shows these per version and
day, so a bad release is seen (and its rollout halted — the update server
already can) before most installs take it; and a read-only summary API the
owner can hand to tools.

## Hard limits (every level)

Never in a report, in any form, hashed or not: IP addresses or networks,
domain or host names, profile/list/app/user/tunnel names, network names
(SSID), interface names, paths, the public address, free text, log lines or
error messages. The client never sends the machine's own address — the
server never records the one it sees (no access log; Caddy and Cloudflare in
front, as for updates).

This is enforced by construction, not by review: a report holds only
numbers, booleans, and values from fixed enumerations (`internal/telemetry`),
and both ends reject anything else — the daemon's builder can't produce a
string it didn't get from a fixed list, and the server's decoder refuses
unknown fields, unknown keys and out-of-range values.

## Levels

| Level | Sends |
|---|---|
| `full` (default) | basic, plus usage (what's configured, counted) and outcomes (applies, tunnels, error codes) |
| `basic` | version, channel, OS, OS major version, architecture; starts and unclean starts; update outcomes |
| `off` | nothing: no request is made at all |

Changing the level applies to the next report; switching to `off` deletes the
pending counters.

## The report

One JSON document a day (schema 1), e.g. at `full`:

```json
{
  "schema": 1,
  "install": "3f9a…(32 hex)",
  "level": "full",
  "day": "2026-10-02",
  "app": {"version": "0.7.0", "channel": "stable", "os": "darwin", "os_major": 15, "arch": "arm64", "service": true},
  "daemon": {"starts": 2, "unclean": 0},
  "updates": {"installed": 1, "rolled_back_health": 0, "rolled_back_user": 0, "skipped_broken": 0, "helpers_repaired": 1},
  "usage": {
    "profiles": 4, "profiles_enabled": 3, "profiles_via_tunnel": 1,
    "rules": {"cidr": 12, "domain": 6, "wildcard": 2, "list": 1, "app": 0},
    "tunnels": {"openvpn": 1, "wireguard": 0, "ikev2": 1},
    "kill_switch": true, "split_dns": false, "auto_apply": true
  },
  "applies": {
    "applied": 31, "failed": 1, "refused": 0, "slow": 2,
    "rolled_back": {"watchdog": 0, "unconfirmed": 0, "requested": 1, "shutdown": 0},
    "ms": {"lt250": 20, "lt1000": 8, "lt5000": 3, "ge5000": 0}
  },
  "tunnel_sessions": {
    "ikev2": {"connected": 3, "drops": 1, "failed": {"auth": 0, "proposal": 0, "identity": 0, "cert": 0, "unreachable": 1, "plugin": 0, "other": 0}}
  },
  "events": {"killswitch_safe_mode": 0, "dns_failures": 4}
}
```

- `install` is random (128 bits) and replaced every 30 days: reports from one
  machine can be counted per day, not followed for long.
- `day` is the UTC day the counts are for; times are never sent.
- `os_major` only (macOS 15, not 15.6.1; a Linux distribution's major
  version from os-release `VERSION_ID`, its `ID` from a fixed list or
  `other`).
- Counts come from what the daemon already records where possible (the
  audit log for applies, the updater's state for updates) and from counters
  kept in its database otherwise (tunnel outcomes, starts), so a restart
  loses nothing; they're cleared once a report is accepted.
- Codes are fixed: a tunnel failure's code comes from the same diagnosis
  that writes the message the user sees — never the message itself.

## When

- At most one report a day, a random time within the day (so installs
  don't all report at once), only while the daemon runs; a missed day is
  folded into the next report (one report, the days' counts summed, `day`
  the last one).
- The first report waits until the user has been told (below), or for 7
  days after the first start where nobody can be told (a headless server
  with no app or CLI use) — the daemon also logs it at startup.
- Over the normal route, like an update check (not only when a tunnel is
  up: reports from machines whose VPN is broken matter most). A failed send
  is retried at the next day's slot; nothing is queued beyond the counters.
- To `https://riftroute.tellnew.tech/api/v1/telemetry`; no fallback host.

## Transparency

- **First-run notice.** The app shows, once, what is sent and the one-click
  `Turn off` beside `See what's sent`; the CLI prints it on the first
  `riftroute status` / `doctor`. Either marks it seen.
- **The exact next report.** `GET /telemetry/preview` returns the document
  the daemon would send now, byte for byte; the app's Settings shows it
  (Telemetry → `See what's sent`), the CLI prints it
  (`riftroute telemetry show`). Also the last report sent, and when.
- **Off is off.** No request, no counters kept.

## Server

- `POST /api/v1/telemetry`: at most 16 KiB, JSON only, decoded strictly
  (unknown fields, keys or values refused with 400); one report per install
  per day (a repeat replaces it); a global rate limit. No address is
  recorded; the response carries nothing back but a status.
- Stored in the server's SQLite (`telemetry_reports`: day, install, level,
  version, os, arch and the validated document); kept 180 days, then
  deleted (daily sweep).
- **Dashboard** (`/admin/telemetry`, behind the admin login): for the last
  7/30 days — active installs per day, by version / OS / level; updates
  (installed, rolled back by health or user, skipped); unclean starts per
  version; applies (failure and rollback rates and reasons, slow share,
  duration buckets) per version; tunnel sessions per protocol (connect
  share, failure codes, drops); usage shares. A version whose rollback,
  unclean-start or apply-failure rate stands out from the previous
  version's is flagged — the place to decide to halt its rollout.
- **Summary API** (`GET /api/v1/telemetry/summary?days=7`): the same
  aggregates as JSON, behind a read-only bearer token the owner creates on
  the server (`riftroute-server telemetry-token`, shown once, stored
  hashed); it can read the summary and nothing else.

## Deploy

The server change ships with `scripts/deploy-server.sh` (the database
migrates itself; nothing changes in Caddy: same site, same block). The
deploy plan is shown to the owner first, as always. Clients send only from
the release that has this, and only to a server that answers.
