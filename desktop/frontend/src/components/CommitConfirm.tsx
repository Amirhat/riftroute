import { useEffect, useState } from 'react'
import { Modal } from './Modal'
import { Badge, Addr } from './ui'
import type { ApplyResult } from '../types'

// CommitConfirm is the commit-confirm countdown (spec §2.1/§8.2): after an
// interactive apply it shows the diff and a live countdown; Keep confirms,
// Revert (or timeout) rolls back. The daemon holds an independent longer
// backstop in case the UI dies.
export function CommitConfirm({
  result,
  seconds,
  onKeep,
  onRevert,
}: {
  result: ApplyResult
  seconds: number
  onKeep: () => void
  onRevert: () => void
}) {
  const [left, setLeft] = useState(seconds)

  useEffect(() => {
    if (left <= 0) {
      onRevert()
      return
    }
    const t = setTimeout(() => setLeft(left - 1), 1000)
    return () => clearTimeout(t)
    // onRevert is stable (useCallback in parent); intentionally not a dep.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [left])

  const pct = Math.max(0, (left / seconds) * 100)
  const entries = result.diff.entries ?? []

  return (
    <Modal>
      <div className="p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-default">Keep these changes?</h2>
          <Badge tone={left <= 5 ? 'danger' : 'warning'}>{left}s</Badge>
        </div>
        <p className="mt-1 text-sm text-muted">
          Auto-reverting unless you keep them — your connectivity is protected.
        </p>

        <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-elevated">
          <div className="h-full rounded-full bg-accent transition-[width] duration-1000 ease-linear" style={{ width: `${pct}%` }} />
        </div>

        <div className="mt-4 max-h-52 overflow-auto rounded-lg border border-line">
          {entries.length === 0 && <div className="px-3 py-2 text-sm text-muted">No managed-route changes.</div>}
          {entries.map((e, i) => (
            <div key={i} className="ltr flex items-center gap-2 border-b border-line/60 px-3 py-1.5 text-sm last:border-0">
              <span className={e.action === 'add' ? 'text-success' : 'text-danger'}>{e.action === 'add' ? '+' : '−'}</span>
              <Addr>{e.route.dst_cidr}</Addr>
              <span className="text-muted">
                via {e.route.gateway || 'on-link'} dev {e.route.iface}
              </span>
            </div>
          ))}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            onClick={onRevert}
            className="rounded-lg border border-line px-4 py-2 text-sm text-muted hover:text-default"
          >
            Revert now
          </button>
          <button
            onClick={onKeep}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90"
          >
            Keep changes
          </button>
        </div>
      </div>
    </Modal>
  )
}
