import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardHeader, Badge, Skeleton } from '../components/ui'
import type { AuditEvent } from '../types'

export function History() {
  const auditQ = useQuery({ queryKey: ['audit'], queryFn: api.audit, refetchInterval: 4000 })
  const snapsQ = useQuery({ queryKey: ['snapshots'], queryFn: api.snapshots })

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <Card className="flex h-full flex-col">
          <CardHeader title="Audit timeline" hint="every change, with the exact commands" />
          {auditQ.isLoading && <div className="space-y-2 p-4">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>}
          {!auditQ.isLoading && (auditQ.data ?? []).length === 0 && (
            <div className="p-8 text-center text-sm text-muted">No changes yet — the timeline records every apply, rollback, and panic.</div>
          )}
          <div className="max-h-[70vh] divide-y divide-line overflow-auto">
            {(auditQ.data ?? []).map((ev) => (
              <AuditRow key={ev.id} ev={ev} />
            ))}
          </div>
        </Card>
      </div>

      <div>
        <Card className="flex h-full flex-col">
          <CardHeader title="Snapshots" hint="restore points" />
          {snapsQ.isLoading && <div className="space-y-2 p-4">{[0, 1].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>}
          {!snapsQ.isLoading && (snapsQ.data ?? []).length === 0 && (
            <div className="p-8 text-center text-sm text-muted">No snapshots yet.</div>
          )}
          <div className="divide-y divide-line overflow-auto">
            {(snapsQ.data ?? []).map((s) => (
              <div key={s.id} className="px-4 py-3">
                <div className="font-mono text-xs text-default">{s.id}</div>
                <div className="mt-0.5 text-xs text-muted">{fmtTime(s.created_at)} · {s.reason}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}

function AuditRow({ ev }: { ev: AuditEvent }) {
  const tone = resultTone(ev.result, ev.rollback)
  return (
    <div className="px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge tone={tone}>{ev.result}</Badge>
          <span className="text-sm font-medium text-default">{ev.action}</span>
          {ev.profile && <span className="text-xs text-muted">{ev.profile}</span>}
        </div>
        <div className="text-xs text-muted">
          {ev.actor} · {fmtTime(ev.ts)}
        </div>
      </div>
      {ev.reason && <div className="mt-1 text-xs text-muted">{ev.reason}</div>}
      {ev.plan && ev.plan.ops.length > 0 && (
        <div className="ltr mt-2 space-y-0.5 rounded-md bg-base p-2 font-mono text-[11px] text-muted">
          {ev.plan.ops.slice(0, 6).map((op, i) => (
            <div key={i}>{op.command.join(' ')}</div>
          ))}
          {ev.plan.ops.length > 6 && <div>… {ev.plan.ops.length - 6} more</div>}
        </div>
      )}
    </div>
  )
}

function resultTone(result: string, rollback?: boolean): 'success' | 'warning' | 'danger' | 'accent' | 'muted' {
  if (rollback || result === 'rolled_back') return 'warning'
  if (result === 'committed') return 'success'
  if (result === 'failed' || result === 'refused') return 'danger'
  if (result === 'applied' || result === 'panicked') return 'accent'
  return 'muted'
}

function fmtTime(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString()
}
