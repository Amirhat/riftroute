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
