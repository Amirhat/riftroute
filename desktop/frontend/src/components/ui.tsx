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

export function Badge({ tone = 'muted', children }: { tone?: BadgeTone; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${badgeTones[tone]}`}>
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

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-elevated ${className}`} />
}
