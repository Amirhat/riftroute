# Telemetry and monitoring — design

Status: built for 0.7.0. The choices below were made by
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

One JSON document a day (schema 1, `internal/telemetry`), e.g. at `full`:

```json
{
  "schema": 1,
  "install": "3f9a…(32 hex)",
  "level": "full",
  "day": "2026-10-02",
  "app": {"version": "0.7.0", "channel": "stable", "os": "darwin", "os_major": 15, "arch": "arm64", "service": true},
  "daemon": {"starts": 2, "unclean": 0},
  "updates": {"installed": 1, "rolled_back_health": 0, "rolled_back_user": 0, "skipped_broken": 0, "helpers_repaired": 1, "check_failed": 0},
  "usage": {
    "profiles": 4, "profiles_enabled": 3, "profile_modes": {"exclude": 2, "tunnel": 1},
    "rules": {"cidr": 12, "domain": 6, "wildcard": 2},
    "lists": 2, "lists_remote": 1,
    "tunnels": {"ikev2": 1}, "tunnels_block": 0, "tunnels_direct": 1,
    "kill_switch": true, "split_dns": false, "auto_apply": true
  },
  "applies": {
    "applied": 31, "auto": 25, "failed": 1, "slow": 2,
    "refused": {"gateway-capture": 1},
    "rolled_back": {"requested": 1},
    "ms": {"lt250": 20, "lt1000": 8, "lt5000": 3}
  },
  "tunnel_sessions": {
    "ikev2": {"connected": 3, "drops": 1, "gave_up": 0, "failed": {"unreachable": 1}}
  },
  "events": {"killswitch_safe_mode": 0, "dns_failures": 4}
}
```

At `basic` it stops after `updates`. Every enumerated value comes from a
fixed list in the schema (`other` where a list has one); every count is
0–1,000,000.

- `install` is random (128 bits) and replaced every 30 days: reports from one
  machine can be counted per day, not followed for long.
- `day` is the UTC day the report was built; times are never sent.
- `version` is a release's (`0.7.0`), or `dev` for any other build.
- `os_major` only (macOS 15, not 15.6.1; a Linux distribution's
  `VERSION_ID` major), and on Linux the distribution's os-release `ID`
  from a fixed list, or `other`.
- `service`: the daemon is the installed system service.

Where each count comes from:

| Field | Source |
|---|---|
| `daemon.starts`, `daemon.unclean` | each start; a run marker beside the database (`riftrouted.running`) found at start means the last run didn't stop cleanly (crash, kill, power loss, failed start) |
| `daemon.panics` | panics the daemon's loops recovered from |
| `updates.*` | the updater: a confirmed update, a failed check, a release skipped as broken, helpers repaired; a rollback is counted by the boot guard (in the version gone back to) |
| `usage` | the configuration, read when the report is built |
| `applies` | the audit log since the last report: results, the guardrail rules that refused, the rollback reasons, the apply timing |
| `tunnel_sessions` | each tunnel's state changes; a failure's code is read from the same diagnosis that writes the message the user sees — the message itself never leaves |
| `events.killswitch_safe_mode` | the audit log (the daemon turning the kill switch off) |
| `events.dns_failures` | domain-rule lookups that failed |

Counts the daemon keeps itself live in `telemetry-counters.json` beside its
database (0600), so a restart loses nothing; what a report carried is taken
off only once the server accepted it. Off deletes the file and counts
nothing.

## When

- At most one report a day, at a random time in the next UTC day (so
  installs don't all report at once), only while the daemon runs. A missed
  day isn't sent late: its counts go with the next report.
- The first report waits until the user has been told (below), or for 7
  days after the first start where nobody can be told (a headless server
  with no app or CLI use) — the daemon also logs at every start that
  telemetry is on.
- Over the normal route, like an update check (not only when a tunnel is
  up: reports from machines whose VPN is broken matter most).
- **Counted once.** A report the server didn't answer (it may have taken
  it) is sent again — the same report, its day too — 10 minutes later, then
  less often (up to every 4 hours), until the server answers: it keeps one
  report per install and day, so a copy it already had is replaced, not
  counted twice. Only then do the counters lose what it carried, settled
  by the report's id so a crash in between can't take them off twice. A
  report the server refused isn't sent again, and its counts go with the
  next one (the server doesn't have them). One built for a day the server
  no longer takes, or at a level the user has since changed, isn't sent
  again either, but the server may have it: its counts are taken as sent
  — a possible undercount rather than an overcount that would make a
  release look broken. Nothing is queued beyond that one report and the
  counters.
- To `https://riftroute.tellnew.tech/api/v1/telemetry`; no fallback host.
  A daemon under `-provider fake` sends nothing unless given
  `-telemetry-url` (for testing against a local server).

## Transparency

- **First-run notice.** The app shows, once, a banner saying what is sent,
  with `See what's sent`, a one-click `Turn off`, and `OK`. The CLI prints
  it on the first `riftroute status` or `riftroute doctor` on a terminal
  (never into `--json` or a pipe); `riftroute telemetry` counts as being
  told. Any of these marks it seen (`POST /telemetry/notice`).
- **The exact next report.** `GET /telemetry` returns the report the daemon
  would send now, and the last one sent; the app's banner and Settings →
  Telemetry show it, the CLI prints it (`riftroute telemetry show`).
- **Off is off.** No request, no counters kept.

## Server

- `POST /api/v1/telemetry`: JSON only, at most 8 KiB (the largest valid
  report is about 2.5 KiB), decoded strictly (unknown fields, keys or
  values refused with 400); its `day` must be within a day of the server's;
  one report per install per day (a repeat replaces it). Throttled to 30
  an hour per client and 2,000 an hour in all — the client is known only as
  a keyed hash, in memory, for the hour. No address is recorded; the
  response carries nothing back but a status.
- **It can't take the shared host's disk**, however many are sent: at most
  5,000 reports are kept a day (a repeat of one already kept replaces it and
  doesn't count; a day at the cap is about 12 MiB, and the dashboard flags
  it), and none while the database is past 512 MiB or the disk has less
  than 1 GiB free. A refusal is a 503 — the client sends the report again
  later — logged at most hourly, without the sender.
- A summary (the dashboard's, the API's) reads the reports one at a time,
  keeping per install only its id, and is worked out at most once a minute
  per window.
- Stored in the server's SQLite (`telemetry_reports`: day, install, level,
  version, os, arch, channel, and the validated report encoded again —
  never the bytes that came in); kept 180 days, then deleted (hourly
  sweep).
- **Dashboard** (`/admin/telemetry`, behind the admin login; a summary on
  `/admin`), for the last 7, 30 or 90 days: installs reporting per day; per
  version — installs, starts and unclean starts, panics, updates installed,
  rolled back and skipped, changes applied, failed and slow, tunnel
  failures; tunnel sessions per protocol (connect rate, failures by code,
  drops); changes refused by rule, rolled back by reason, and how long they
  took; platforms; usage shares among installs at `full`. It's plain HTML
  (no scripts, as the rest of the site).
- **Flags**, weighed by installs, not by counts: reports are anonymous
  and their install ids self-chosen, so one forged report must not
  outweigh real installs.
  - Each report counts for at most one machine's day: 100 starts (unclean
    ones no more than its starts), 100 panics, 10 of each update outcome,
    5,000 changes, 500 of each tunnel count. `Validate` refuses unclean
    starts above starts.
  - A version's rates are the share of its installs with an unclean start,
    and its installs' own rates of failed and slow changes and failed
    tunnel attempts, averaged — shown from 10 installs.
  - A version is flagged when such a rate is more than twice the previous
    version's, clearly higher (by 5, 2 and 10 points), **and** enough
    installs show it — at least 3, and at least 5% of the version's
    installs; or when that many recovered from panics and none on the
    previous version did. Health-check rollbacks on that many installs (of
    the window's) are flagged too: they're reported by the version the
    install went back to, so the newest release is the one to look at.
  - A flag is a hint, the place to decide to halt a rollout — someone who
    makes up many installs can still move it, within the throttle and the
    daily cap.
- **Summary API** (`GET /api/v1/telemetry/summary?days=7`, up to 90): the
  same numbers as JSON, behind a read-only bearer token the owner creates
  on the server (`riftroute-server telemetry-token`: printed once, only
  its hash kept, a new one replaces the old); it can read the summary and
  nothing else.

## Deploy

The server change ships with `scripts/deploy-server.sh` (the database
migrates itself; nothing changes in Caddy: same site, same block). The
deploy plan is shown to the owner first, as always. Clients send only from
the release that has this, and only to a server that answers.
