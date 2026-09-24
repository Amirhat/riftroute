# riftroute-server runbook

`riftroute-server` serves **riftroute.tellnew.tech**: the bilingual landing page
and the admin dashboard (later: the signed update API, telemetry ingest and
bug-report upload). It runs on a host **shared with Clew** — nothing here ever
touches Clew's files, service, account or Caddy block.

| | |
|---|---|
| Host | `$RR_SERVER_HOST` (Ubuntu 24.04, x86_64) — the address is never written into this repository |
| Listens | `127.0.0.1:7780` only (Caddy terminates TLS; Cloudflare proxies; Caddy accepts only Cloudflare for this site) |
| Account | `riftroute-server` (system, no shell, no home) |
| Binary | `/opt/riftroute-server/bin/riftroute-server` (+ `.prev` after a deploy) |
| Data | `/var/lib/riftroute-server` (`server.db`, `admin.hash`), mode 0700 |
| Unit | `/etc/systemd/system/riftroute-server.service` (from `packaging/server/`) |
| Logs | `journalctl -u riftroute-server` — never contains client addresses |

## One-time setup

Each step is run only after it has been reviewed. All commands run from the
repo root on the developer's Mac, with the host (and, if ssh's own config
doesn't pick the key, the key) in the environment:

```bash
export RR_SERVER_HOST=root@<server> RR_SERVER_KEY=<path to the ssh key>
S="ssh -o BatchMode=yes -i $RR_SERVER_KEY $RR_SERVER_HOST"
```

**0. Look (read-only).** Architecture, disk, memory, listening ports, that
Clew and Caddy are up, that nothing of ours exists yet, the Caddyfile's sites.

**1. Account and directories.**

```bash
$S 'id riftroute-server >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin riftroute-server
install -d -o root -g root -m 0755 /opt/riftroute-server /opt/riftroute-server/bin
install -d -o riftroute-server -g riftroute-server -m 0700 /var/lib/riftroute-server'
```

**2. Service unit.**

```bash
scp -i "$RR_SERVER_KEY" packaging/server/riftroute-server.service "$RR_SERVER_HOST:/etc/systemd/system/riftroute-server.service"
$S 'chmod 0644 /etc/systemd/system/riftroute-server.service && systemd-analyze verify /etc/systemd/system/riftroute-server.service && systemctl daemon-reload && systemctl enable riftroute-server'
```

**3. First deploy** (builds from a clean tree, uploads, checksums, starts,
and checks that the new commit is the one answering):

```bash
scripts/deploy-server.sh
```

**4. Admin password — typed by the owner, never on a command line:**

```bash
ssh -t -i "$RR_SERVER_KEY" "$RR_SERVER_HOST" 'sudo -u riftroute-server /opt/riftroute-server/bin/riftroute-server passwd -data /var/lib/riftroute-server'
```

It must run as `riftroute-server` (it refuses otherwise: a file written by
root would be unreadable to the service).

**5. Caddy — append one block, validate, reload (not restart), check both
sites.** Everything is scoped to this one site block; nothing global changes.

- `abort` anything that doesn't come from Cloudflare: otherwise anyone who
  learns the origin address can skip Cloudflare's protection and set their own
  `CF-Connecting-IP` (which the login throttle keys on).
- `handle_errors`: while the service restarts, Caddy answers 503 itself; an
  unhandled proxy error would be logged at ERROR level *with the client's
  address and headers*, a handled one only at DEBUG (below Caddy's default).
- No `log` directive: no access log.

```bash
$S 'set -e
cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%Y%m%d%H%M%S)
cat >> /etc/caddy/Caddyfile <<CADDY

riftroute.tellnew.tech {
	@outside not remote_ip 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
	abort @outside
	reverse_proxy 127.0.0.1:7780
	encode zstd gzip
	header Strict-Transport-Security "max-age=31536000; includeSubDomains"
	handle_errors {
		respond "Temporarily unavailable" 503
	}
}
CADDY
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy'
curl -sS -o /dev/null -w 'clew %{http_code}\n' https://clew.tellnew.tech
curl -sS https://riftroute.tellnew.tech/healthz
```

The ranges are Cloudflare's published list (<https://www.cloudflare.com/ips/>,
checked 2026-09-23). They change rarely; if Cloudflare adds one, visitors
routed through it get a dropped connection — refresh the list in the block.

If `caddy validate` fails, restore the backup before anything reloads:
`cp -a /etc/caddy/Caddyfile.bak-<stamp> /etc/caddy/Caddyfile`.

## Deploy and roll back

```bash
scripts/deploy-server.sh              # new build → live, previous kept as .prev
scripts/deploy-server.sh --rollback   # previous build back
```

The deploy refuses a dirty tree, checks the upload's sha256 on the server
before replacing anything, and puts the previous binary back by itself if the
new one fails its health check.

## Change the admin password

Step 4 again. It signs out every session and forgets every remembered device.

## Sign-in protection

- Each attempt counts when it starts (so a burst can't slip past the check
  while the slow hash runs): 5 per client per 15 minutes, 50 overall. An IPv6
  client counts as its /64.
- Password checks run one at a time (each takes 64 MiB); a request that waits
  more than 3 s gets "busy" and its attempt back.
- A browser that has signed in before carries a device cookie (180 days) and is
  held only to its own limit, never the global one — a flood from elsewhere
  can't lock the owner out.

## Remove everything (full rollback)

```bash
$S 'set -e
systemctl disable --now riftroute-server || true
rm -f /etc/systemd/system/riftroute-server.service && systemctl daemon-reload
cp -a /etc/caddy/Caddyfile.bak-<stamp> /etc/caddy/Caddyfile && caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
userdel riftroute-server || true
rm -rf /opt/riftroute-server /var/lib/riftroute-server'
curl -sS -o /dev/null -w 'clew %{http_code}\n' https://clew.tellnew.tech
```
