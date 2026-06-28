import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey, useStateQuery } from '../lib/queries'
import { Card, CardHeader, Badge, Skeleton } from '../components/ui'
import type { DoctorCheck } from '../types'

export function Diagnostics() {
  const qc = useQueryClient()
  const doctorQ = useQuery({ queryKey: ['doctor'], queryFn: api.doctor })
  const leaksQ = useQuery({ queryKey: ['leaks'], queryFn: api.leaks })
  const stateQ = useStateQuery()

  const rerun = () => {
    qc.invalidateQueries({ queryKey: ['doctor'] })
    qc.invalidateQueries({ queryKey: ['leaks'] })
  }

  const killOn = stateQ.data?.kill_switch ?? false
  async function toggleKill() {
    if (!killOn && !confirm('Enable the kill switch? This blocks all egress except through the tunnel until disabled.')) return
    try {
      await api.setKillSwitch(!killOn)
    } finally {
      qc.invalidateQueries({ queryKey: stateKey })
      rerun()
    }
  }

  const rep = doctorQ.data
  const leaks = leaksQ.data ?? []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {rep ? (
            <>
              <Badge tone="success">{rep.pass} pass</Badge>
              {rep.warn > 0 && <Badge tone="warning">{rep.warn} warn</Badge>}
              {rep.fail > 0 && <Badge tone="danger">{rep.fail} fail</Badge>}
              <span className="text-sm text-muted">{rep.ok ? 'healthy' : 'attention needed'}</span>
            </>
          ) : (
            <span className="text-sm text-muted">running diagnostics…</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={toggleKill}
            className={`rounded-lg px-3 py-1.5 text-sm font-medium ${
              killOn ? 'bg-danger/15 text-danger' : 'border border-line text-muted hover:text-default'
            }`}
          >
            Kill switch: {killOn ? 'ON' : 'off'}
          </button>
          <button onClick={rerun} className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90">
            Run again
          </button>
        </div>
      </div>

      <Card>
        <CardHeader title="Doctor" hint="network self-test" />
        {doctorQ.isLoading && <div className="space-y-2 p-4">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-8 w-full" />)}</div>}
        {doctorQ.isError && <div className="p-4 text-sm text-danger">Failed: {(doctorQ.error as Error)?.message}</div>}
        <div className="divide-y divide-line">
          {rep?.checks.map((c) => <CheckRow key={c.name} c={c} />)}
        </div>
      </Card>

      <Card>
        <CardHeader title="Leak detector" hint="IPv6 + DNS" />
        {leaks.length === 0 ? (
          <div className="p-4 text-sm text-success">✓ no leaks detected</div>
        ) : (
          <div className="divide-y divide-line">
            {leaks.map((lk, i) => (
              <div key={i} className="flex items-start gap-3 px-4 py-3">
                <Badge tone={lk.severity === 'fail' ? 'danger' : 'warning'}>{lk.kind}</Badge>
                <span className="text-sm text-default">{lk.detail}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function CheckRow({ c }: { c: DoctorCheck }) {
  const tone = c.status === 'pass' ? 'success' : c.status === 'warn' ? 'warning' : 'danger'
  const markColor = c.status === 'pass' ? 'text-success' : c.status === 'warn' ? 'text-warning' : 'text-danger'
  const mark = c.status === 'pass' ? '✓' : c.status === 'warn' ? '!' : '✗'
  return (
    <div className="flex items-start gap-3 px-4 py-2.5">
      <span className={`mt-0.5 text-sm font-bold ${markColor}`}>{mark}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-default">{c.name}</span>
          <Badge tone={tone}>{c.status}</Badge>
        </div>
        <div className="ltr text-sm text-muted">{c.detail}</div>
        {c.fix && c.status !== 'pass' && <div className="mt-0.5 text-xs text-muted">↳ {c.fix}</div>}
      </div>
    </div>
  )
}
