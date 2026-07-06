// Pure, synchronous client-side validators that mirror the daemon's strict rules,
// so the Profile Builder can show inline errors instantly as the user types. The
// daemon re-validates on apply and remains the authority — these just make the UI
// responsive and catch malformed input (e.g. "999.999.999") before it's sent.

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/

// Pragmatic IPv6 matcher: full, compressed (::), zone id, and v4-mapped tails.
const IPV6 =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}|:((:[0-9a-fA-F]{1,4}){1,7}|:))(%[0-9a-zA-Z.]+)?$/

/** validateRouteTarget accepts an IPv4/IPv6 address or CIDR (e.g. 10.0.0.0/8, 1.1.1.1, fd00::/8). */
export function validateRouteTarget(v: string): string | null {
  const s = v.trim()
  if (!s) return 'required'
  const slash = s.indexOf('/')
  const addr = slash < 0 ? s : s.slice(0, slash)
  const prefix = slash < 0 ? null : s.slice(slash + 1)
  const v4 = IPV4.test(addr)
  const v6 = !v4 && IPV6.test(addr)
  if (!v4 && !v6) return 'not a valid IP or CIDR'
  if (prefix !== null) {
    if (!/^\d+$/.test(prefix)) return 'prefix must be a number'
    const n = Number(prefix)
    const max = v4 ? 32 : 128
    if (n < 0 || n > max) return `prefix must be 0–${max}`
  }
  return null
}

const DOMAIN_LABEL = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/

/** validateDomain mirrors the daemon's isValidDomain: ≥2 labels, ≤253 chars, one optional leading "*." */
export function validateDomain(v: string): string | null {
  let s = v.trim().replace(/\.$/, '')
  if (!s || s.length > 253) return 'invalid domain'
  s = s.replace(/^\*\./, '')
  const labels = s.split('.')
  if (labels.length < 2) return 'need at least two labels (e.g. example.com)'
  for (const l of labels) if (!DOMAIN_LABEL.test(l)) return 'invalid domain'
  return null
}

export type AppStrategy = 'uid' | 'app'

/** validateAppValue checks a per-app selector: a uid/username (macOS PF) or an app id (Linux). */
export function validateAppValue(v: string, strategy: AppStrategy): string | null {
  const s = v.trim()
  if (!s) return 'required'
  if (strategy === 'uid' && !/^[a-zA-Z0-9_.-]+$/.test(s)) return 'uid or username (letters, digits, _ - .)'
  return null
}

/** validateProfileName requires a non-empty name unique among `taken` — exactly
 * the daemon's rule set, no extra client-only policy (a stricter mirror would
 * refuse to re-save profiles the daemon itself considers valid). */
export function validateProfileName(v: string, taken: string[]): string | null {
  const s = v.trim()
  if (!s) return 'required'
  if (taken.includes(s)) return 'a profile with this name already exists'
  return null
}

/** validateGateway accepts "auto" or a bare IP address. */
export function validateGateway(v: string): string | null {
  const s = v.trim()
  if (!s || s === 'auto') return null
  if (!IPV4.test(s) && !IPV6.test(s)) return 'must be "auto" or a valid IP'
  return null
}
