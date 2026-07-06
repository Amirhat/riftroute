import type { ReactNode } from 'react'
import type { Owner } from '../types'

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-xl border border-line bg-surface ${className}`}>{children}</div>
}

export function CardHeader({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-line px-4 py-3">
      <h2 className="text-sm font-semibold tracking-wide text-default">{title}</h2>
      {hint != null && <div className="text-xs text-muted">{hint}</div>}
    </div>
  )
}

export function Label({ children }: { children: ReactNode }) {
  return <div className="text-[11px] font-medium uppercase tracking-wider text-muted">{children}</div>
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div>
      <Label>{label}</Label>
      <div className={`mt-1 text-lg font-semibold ${tone ?? 'text-default'}`}>{value}</div>
    </div>
  )
}

type BadgeTone = 'accent' | 'success' | 'warning' | 'danger' | 'muted' | 'vpn'

const badgeTones: Record<BadgeTone, string> = {
  accent: 'bg-accent/15 text-accent',
  success: 'bg-success/15 text-success',
  warning: 'bg-warning/15 text-warning',
  danger: 'bg-danger/15 text-danger',
  muted: 'bg-elevated text-muted',
  vpn: 'bg-vpn/15 text-vpn',
}

export function Badge({ tone = 'muted', children, title }: { tone?: BadgeTone; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${badgeTones[tone]}`}>
      {children}
    </span>
  )
}

export function Dot({ tone = 'muted' }: { tone?: BadgeTone }) {
  const color: Record<BadgeTone, string> = {
    accent: 'bg-accent',
    success: 'bg-success',
    warning: 'bg-warning',
    danger: 'bg-danger',
    muted: 'bg-muted',
    vpn: 'bg-vpn',
  }
  return <span className={`inline-block h-2 w-2 rounded-full ${color[tone]}`} />
}

const ownerStyle: Record<Owner, string> = {
  system: 'bg-owner-system/15 text-owner-system',
  riftroute: 'bg-owner-riftroute/15 text-owner-riftroute',
  vpn: 'bg-owner-vpn/15 text-owner-vpn',
  unknown: 'bg-elevated text-muted',
}

export function OwnerBadge({ owner }: { owner: Owner }) {
  return (
    <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px] font-medium ${ownerStyle[owner] ?? ownerStyle.unknown}`}>
      {owner}
    </span>
  )
}

/** Monospace, force-LTR cell for addresses/CIDRs (AGENTS §7). */
export function Addr({ children }: { children: ReactNode }) {
  return <span className="ltr font-mono text-sm">{children}</span>
}

/** Toggle is the app-wide on/off switch (profiles, builder status, settings). */
export function Toggle({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      role="switch"
      aria-checked={on}
      className={`relative h-6 w-11 rounded-full transition-colors ${on ? 'bg-accent' : 'bg-elevated'}`}
    >
      <span
        className={`absolute top-0.5 h-5 w-5 rounded-full bg-surface shadow transition-transform ${on ? 'translate-x-[22px]' : 'translate-x-0.5'}`}
      />
    </button>
  )
}

/** fieldCls is the shared form-input class set; pass the field's current error. */
export function fieldCls(error?: string | null): string {
  const base =
    'w-full rounded-lg border bg-elevated px-3 py-2 text-sm text-default outline-none placeholder:text-muted focus:border-accent'
  return `${base} ${error ? 'border-danger' : 'border-line'}`
}

// Linux kernel primitives whose JOB a non-Linux backend covers natively (pf on
// macOS): shown as "via <backend>" instead of a bare missing marker. One list,
// shared by every screen that renders capabilities.
const LINUX_ONLY_CAPS = new Set(['fwmark', 'proto_tag'])
const LINUX_BACKENDS = new Set(['nftables', 'fake'])

/** CapBadge renders one platform capability honestly: native ✓, covered-by-backend, or absent. */
export function CapBadge({ capKey, ok, label, backend }: { capKey?: string; ok: boolean; label: string; backend?: string }) {
  if (ok) return <Badge tone="success">✓ {label}</Badge>
  if (capKey && LINUX_ONLY_CAPS.has(capKey) && backend && !LINUX_BACKENDS.has(backend)) {
    return (
      <Badge tone="muted" title={`Linux kernel feature; ${backend} handles this natively on this platform`}>
        {label} · via {backend}
      </Badge>
    )
  }
  return <Badge tone="muted">— {label}</Badge>
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-elevated ${className}`} />
}
