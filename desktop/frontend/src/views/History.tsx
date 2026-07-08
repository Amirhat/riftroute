import { useCallback, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey } from '../lib/queries'
import { Card, CardHeader, Badge, Skeleton } from '../components/ui'
import { ConfirmModal } from '../components/ConfirmModal'
import { CommitConfirm } from '../components/CommitConfirm'
import { friendly } from '../lib/format'
import type { ApplyResult, AuditEvent, Snapshot } from '../types'

const CONFIRM_SECONDS = 15

export function History() {
  const qc = useQueryClient()
  const auditQ = useQuery({ queryKey: ['audit'], queryFn: api.audit, refetchInterval: 4000 })
  const snapsQ = useQuery({ queryKey: ['snapshots'], queryFn: api.snapshots, refetchInterval: 4000 })
  const [restoring, setRestoring] = useState<Snapshot | null>(null)
  const [pending, setPending] = useState<ApplyResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const refresh = useCallback(() => {
    qc.invalidateQueries({ queryKey: ['snapshots'] })
    qc.invalidateQueries({ queryKey: ['audit'] })
    qc.invalidateQueries({ queryKey: ['profiles'] })
    qc.invalidateQueries({ queryKey: ['routes'] })
    qc.invalidateQueries({ queryKey: stateKey })
  }, [qc])

  const onKeep = useCallback(async () => {
    if (!pending?.tx_id) return setPending(null)
    try {
      await api.confirm(pending.tx_id)
    } finally {
      setPending(null)
      refresh()
    }
  }, [pending, refresh])

  const onRevert = useCallback(async () => {
    if (!pending?.tx_id) return setPending(null)
    try {
      await api.rollback(pending.tx_id)
    } finally {
      setPending(null)
      refresh()
    }
  }, [pending, refresh])

  async function doRestore() {
    const snap = restoring
    setRestoring(null)
    if (!snap) return
    setError(null)
    setNotice(null)
    setBusy(true)
    try {
      const res = await api.restoreSnapshot(snap.id)
      if (res.apply_error) {
        setNotice(`Profiles restored — routes not re-applied yet: ${res.apply_error}`)
      } else if (res.result?.needs_confirm && res.result.tx_id) {
        setPending(res.result)
      }
      refresh()
    } catch (e) {
      setError(friendly(e, 'restore failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      {error && <Card className="border-danger/40 p-3 text-sm text-danger">{error}</Card>}
      {notice && <Card className="border-warning/40 bg-warning/5 p-3 text-sm text-warning">{notice}</Card>}

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
            <CardHeader title="Snapshots" hint="pre-change restore points" />
            {snapsQ.isLoading && <div className="space-y-2 p-4">{[0, 1].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>}
            {!snapsQ.isLoading && (snapsQ.data ?? []).length === 0 && (
              <div className="p-8 text-center text-sm text-muted">
                No snapshots yet — one is taken automatically before every applied change.
              </div>
            )}
            <div className="divide-y divide-line overflow-auto">
              {(snapsQ.data ?? []).map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-2 px-4 py-3">
                  <div className="min-w-0">
                    <div className="text-sm text-default">{fmtTime(s.created_at)}</div>
                    <div className="mt-0.5 flex min-w-0 items-center gap-1.5 text-xs text-muted">
                      <span className="ltr min-w-0 truncate font-mono" title={s.id}>
                        {s.id}
                      </span>
                      <span className="shrink-0">· {s.reason === 'pre-apply' ? 'before an apply' : s.reason}</span>
                    </div>
                  </div>
                  {s.restorable ? (
                    <button
                      onClick={() => setRestoring(s)}
                      disabled={busy}
                      className="shrink-0 rounded-lg border border-line px-2.5 py-1 text-xs text-muted hover:text-default disabled:opacity-50"
                    >
                      Restore
                    </button>
                  ) : (
                    <span className="shrink-0 text-[11px] text-muted" title="Taken by an older version, before policy capture existed">
                      not restorable
                    </span>
                  )}
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      <ConfirmModal
        open={restoring !== null}
        title={`Restore snapshot from ${restoring ? fmtTime(restoring.created_at) : ''}`}
        message="Puts your profiles back exactly as they were at that moment, then re-applies routing safely (guarded by commit-confirm — you can revert)."
        confirmLabel="Restore"
        onConfirm={doRestore}
        onCancel={() => setRestoring(null)}
      />

      {pending && <CommitConfirm result={pending} seconds={CONFIRM_SECONDS} onKeep={onKeep} onRevert={onRevert} />}
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
