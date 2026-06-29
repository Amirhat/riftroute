# Security Policy

RiftRoute runs a privileged daemon that mutates the host routing table, so we
take security seriously. Thank you for helping keep users safe.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via either:

- **GitHub Security Advisories** — the "Report a vulnerability" button under the
  repository's **Security** tab (preferred), or
- **Email** — a.h.amani.t@gmail.com with subject `RiftRoute security`.

Please include: affected version/commit, OS, a description of the issue and its
impact, and reproduction steps or a proof of concept if you have one.

You can expect an acknowledgement within **5 business days**. We'll work with you
on a fix and coordinate a disclosure timeline; please allow a reasonable window
before any public disclosure. We're happy to credit reporters who wish to be.

## Supported versions

RiftRoute is pre-1.0. Security fixes target the latest release and `main`.

| Version | Supported |
|---------|-----------|
| latest release / `main` | ✅ |
| older releases | ❌ |

## Security model (what to keep in mind)

- **One privileged component.** Only `riftrouted` runs as root; it owns all route
  mutation. The CLI and GUI are unprivileged and talk to it over a Unix domain
  socket using **peer-credential authorization** (only the permitted uid, and
  root, may call mutating endpoints; reads are open to local peers who can reach
  the `0600` socket).
- **Ownership-scoped mutation.** RiftRoute only modifies routes it created
  (`proto riftroute` tag on Linux; an ownership map on macOS). It never touches
  foreign routes.
- **Fail-safe by design.** Every change runs through the Apply Protocol
  (snapshot, precomputed inverse, watchdog, commit-confirm, atomic rollback). A
  bug degrades to "no change" or "auto-reverted", never "no network".
- **Remote inputs are data, never code.** Subscribable lists are HTTPS-only,
  size-capped, and checksummed; they are parsed as CIDR/IP entries and never
  executed. The kill switch fails closed but always keeps a reconnect path open.

### In scope
- Privilege escalation via the daemon or its socket
- Authorization bypass on mutating endpoints
- Path/command injection in route/firewall/DNS application
- A route change that can leave the host without connectivity (Apply Protocol bypass)
- Leaks the leak detector should catch but doesn't

### Out of scope
- Issues requiring an already-root attacker on the same machine
- Vulnerabilities in third-party VPN clients RiftRoute coexists with
- Social-engineering or physical-access attacks
