import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey, useStateQuery } from '../lib/queries'
import { Card, CardHeader, Badge, Skeleton, Toggle } from '../components/ui'
import { ConfirmModal } from '../components/ConfirmModal'
import { useDaemon } from '../lib/useDaemon'
import { friendly } from '../lib/format'
import type { DoctorCheck } from '../types'

// Plain-language names + one-line explanations for the doctor's checks, so the
// page reads as answers ("is my internet path OK?") rather than internals.
const CHECK_INFO: Record<string, { label: string; explain: string }> = {
  daemon: { label: 'Daemon', explain: 'The background service that owns routing is up.' },
  gateway: { label: 'Physical gateway', explain: 'A real (non-VPN) router to fall back to.' },
  'default-route': { label: 'Default route', explain: 'Where traffic goes when nothing more specific matches.' },
  dns: { label: 'DNS resolvers', explain: 'Name servers the system currently uses.' },
  drift: { label: 'Routes in sync', explain: 'Installed routes match the enabled profiles.' },
  conflicts: { label: 'Route conflicts', explain: 'Managed routes don’t fight system or VPN routes.' },
  'wildcard-dns': {
    label: 'Wildcard DNS learner',
    explain: 'Learns subdomain addresses for *.domain rules as apps look them up.',
  },
}

function checkInfo(name: string): { label: string; explain: string } {
  if (CHECK_INFO[name]) return CHECK_INFO[name]
  if (name.startsWith('mtu:')) {
    return { label: `MTU — ${name.slice(4)}`, explain: 'Tunnel packet size; too small causes stalls on some sites.' }
  }
  if (name.startsWith('leak:')) {
    return { label: `Leak — ${name.slice(5)}`, explain: 'Traffic that bypasses the tunnel while the VPN is up.' }
  }
  return { label: name, explain: '' }
}

export function Diagnostics() {
  const qc = useQueryClient()
  // Kept fresh automatically (10s while the page is open) AND on demand — the
  // report timestamp below makes freshness visible instead of guessable.
  const doctorQ = useQuery({ queryKey: ['doctor'], queryFn: api.doctor, refetchInterval: 10_000 })
  const leaksQ = useQuery({ queryKey: ['leaks'], queryFn: api.leaks, refetchInterval: 10_000 })
  const stateQ = useStateQuery()
  const d = useDaemon()
  const [confirmKill, setConfirmKill] = useState(false)
  const [confirmPanic, setConfirmPanic] = useState(false)
  const [copied, setCopied] = useState(false)
  const [actionErr, setActionErr] = useState<string | null>(null)

  const rerun = () => {
    qc.invalidateQueries({ queryKey: ['doctor'] })
    qc.invalidateQueries({ queryKey: ['leaks'] })
  }
  const refreshing = doctorQ.isFetching || leaksQ.isFetching

  const killOn = stateQ.data?.kill_switch ?? false
  const [killBusy, setKillBusy] = useState(false)
  async function setKill(enabled: boolean) {
    setKillBusy(true)
    try {
      await api.setKillSwitch(enabled)
    } finally {
      setKillBusy(false)
      qc.invalidateQueries({ queryKey: stateKey })
      rerun()
    }
  }

  async function doPanic() {
    setActionErr(null)
    try {
      await api.panic()
    } catch (e) {
      setActionErr(friendly(e, 'panic flush failed'))
    } finally {
      qc.invalidateQueries()
    }
  }

  async function copyReport() {
    setActionErr(null)
    try {
      const payload = { doctor: doctorQ.data, leaks: leaksQ.data, state: stateQ.data }
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (e) {
      setActionErr(friendly(e, 'copy failed'))
    }
  }

  const rep = doctorQ.data
  const leaks = leaksQ.data ?? []
  const checkedAt = rep?.generated_at ? new Date(rep.generated_at).toLocaleTimeString() : null

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          {rep ? (
            <>
              <Badge tone="success">{rep.pass} pass</Badge>
              {rep.warn > 0 && <Badge tone="warning">{rep.warn} warn</Badge>}
              {rep.fail > 0 && <Badge tone="danger">{rep.fail} fail</Badge>}
              <span className="text-sm text-muted">
                {rep.ok ? 'healthy' : 'attention needed'}
                {checkedAt ? ` · checked ${checkedAt}` : ''}
              </span>
            </>
          ) : (
            <span className="text-sm text-muted">running diagnostics…</span>
          )}
        </div>
        <button
          onClick={rerun}
          disabled={refreshing}
          className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-60"
        >
          {refreshing ? 'Checking…' : 'Run again'}
        </button>
      </div>

      <Card>
        <CardHeader title="Health checks" hint="auto-refreshes every 10s while open" />
        {doctorQ.isLoading && <div className="space-y-2 p-4">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-8 w-full" />)}</div>}
        {doctorQ.isError && <div className="p-4 text-sm text-danger">Failed: {(doctorQ.error as Error)?.message}</div>}
        <div className="divide-y divide-line">
          {rep?.checks.map((c) => <CheckRow key={c.name} c={c} />)}
        </div>
      </Card>

      <Card>
        <CardHeader title="Leak detector" hint="is anything bypassing the tunnel?" />
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

      <Card>
        <CardHeader title="Troubleshooting" hint="safe, reversible actions" />
        <div className="divide-y divide-line">
          <ActionRow
            title="Kill switch"
            desc="Fence all egress to the tunnel; a reconnect path stays open."
            control={
              <Toggle
                on={killOn}
                tone="danger"
                disabled={killBusy}
                ariaLabel="Kill switch"
                onClick={() => (killOn ? void setKill(false) : setConfirmKill(true))}
              />
            }
          />
          <ActionRow
            title="Panic flush"
            desc="Remove every RiftRoute-managed route and restore the baseline immediately."
            control={
              <button
                onClick={() => setConfirmPanic(true)}
                className="rounded-lg border border-danger/50 px-3 py-1.5 text-sm font-medium text-danger hover:bg-danger/10"
              >
                Flush now
              </button>
            }
          />
          <ActionRow
            title="Restart daemon"
            desc="Restart the background service; managed state is re-asserted on startup."
            control={
              <button
                onClick={() => void d.restart()}
                disabled={d.busy === 'restart'}
                className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default disabled:opacity-50"
              >
                {d.busy === 'restart' ? 'Restarting…' : 'Restart'}
              </button>
            }
          />
          <ActionRow
            title="Copy report"
            desc="Copy the full diagnostics (checks, leaks, state) as JSON for a bug report."
            control={
              <button
                onClick={() => void copyReport()}
                className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default"
              >
                {copied ? '✓ Copied' : 'Copy JSON'}
              </button>
            }
          />
        </div>
        {(actionErr || d.error) && (
          <div className="border-t border-line px-4 py-2 text-sm text-danger">{actionErr ?? d.error}</div>
        )}
      </Card>

      <ConfirmModal
        open={confirmKill}
        danger
        title="Enable kill switch"
        message="This blocks all egress except through the tunnel until disabled. A reconnect path (loopback, tunnel, gateway/LAN, DHCP) stays open."
        confirmLabel="Enable"
        onConfirm={() => {
          setConfirmKill(false)
          void setKill(true)
        }}
        onCancel={() => setConfirmKill(false)}
      />

      <ConfirmModal
        open={confirmPanic}
        danger
        title="Panic — flush all managed routes"
        message="Remove ALL RiftRoute-managed routes and restore the baseline. This is immediate and affects every profile."
        confirmLabel="Flush all"
        onConfirm={() => {
          setConfirmPanic(false)
          void doPanic()
        }}
        onCancel={() => setConfirmPanic(false)}
      />
    </div>
  )
}

function ActionRow({ title, desc, control }: { title: string; desc: string; control: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3">
      <div>
        <div className="text-sm text-default">{title}</div>
        <div className="text-xs text-muted">{desc}</div>
      </div>
      {control}
    </div>
  )
}

function CheckRow({ c }: { c: DoctorCheck }) {
  const info = checkInfo(c.name)
  const tone = c.status === 'pass' ? 'success' : c.status === 'warn' ? 'warning' : 'danger'
  const markColor = c.status === 'pass' ? 'text-success' : c.status === 'warn' ? 'text-warning' : 'text-danger'
  const mark = c.status === 'pass' ? '✓' : c.status === 'warn' ? '!' : '✗'
  return (
    <div className="flex items-start gap-3 px-4 py-2.5">
      <span className={`mt-0.5 text-sm font-bold ${markColor}`}>{mark}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-default" title={info.explain}>
            {info.label}
          </span>
          <Badge tone={tone}>{c.status}</Badge>
        </div>
        <div className="ltr text-sm text-muted">{c.detail}</div>
        {c.status !== 'pass' && (
          <div className="mt-0.5 text-xs text-muted">
            {info.explain && <span>{info.explain} </span>}
            {c.fix && <span>↳ {c.fix}</span>}
          </div>
        )}
      </div>
    </div>
  )
}
