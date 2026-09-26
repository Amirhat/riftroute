import type { Owner } from '../types'

export function fmtUptime(seconds: number): string {
  if (seconds < 0 || !Number.isFinite(seconds)) return '—'
  const s = Math.floor(seconds % 60)
  const m = Math.floor((seconds / 60) % 60)
  const h = Math.floor((seconds / 3600) % 24)
  const d = Math.floor(seconds / 86400)
  const parts: string[] = []
  if (d) parts.push(`${d}d`)
  if (h) parts.push(`${h}h`)
  if (m) parts.push(`${m}m`)
  parts.push(`${s}s`)
  return parts.join(' ')
}

// friendly turns a thrown value into a readable message. Wails rejects binding
// calls with a string or an Error depending on the failure path — one unwrapper
// for every component, so a fix for a new rejection shape lands everywhere.
export function friendly(e: unknown, fallback = 'Something went wrong.'): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  return fallback
}

export function ownerTone(owner: Owner): 'accent' | 'vpn' | 'muted' {
  switch (owner) {
    case 'riftroute':
      return 'accent'
    case 'vpn':
      return 'vpn'
    default:
      return 'muted'
  }
}

// fmtBuildMeta renders the commit + commit date of a build ("a5e49c2 · 2026-08-13");
// empty for daemons that predate build reporting.
export function fmtBuildMeta(b?: { commit?: string; commit_time?: string; modified?: boolean }): string {
  if (!b?.commit) return ''
  const parts = [b.commit.slice(0, 7) + (b.modified ? '-dirty' : '')]
  if (b.commit_time) parts.push(b.commit_time.slice(0, 10))
  return parts.join(' · ')
}

// fmtBytes renders a byte count compactly (1.4 MB); binary steps, SI-style labels.
export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`
}
