import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { friendly } from '../lib/format'
import { stateKey, useStateQuery } from '../lib/queries'
import type { TelemetryPreview } from '../types'
import { Modal } from './Modal'

// What is never sent, at any level (docs/telemetry.md's hard limits).
export const TELEMETRY_NEVER =
  'IP addresses or networks, domains, profile, list, app, user or tunnel names, network or host names, or anything you typed.'

const when = (t?: string) => (t ? new Date(t).toLocaleString() : '')

/** TelemetrySchedule says when the next report goes, and when the last went. */
export function TelemetrySchedule({ p }: { p: TelemetryPreview }) {
  let next = ''
  if (p.level !== 'off')
    next = p.waiting ? `Next report: waiting ${p.waiting}.` : p.next_at ? `Next report: around ${when(p.next_at)}.` : ''
  return (
    <p className="text-xs text-muted">
      {next && <span>{next} </span>}
      {p.last_sent ? `Last sent ${when(p.last_sent)}.` : 'Nothing sent yet.'}
    </p>
  )
}

/**
 * TelemetryReportModal shows the exact report the daemon would send now —
 * the JSON as it goes — and the last one sent. Opening it counts as having
 * been told about telemetry.
 */
export function TelemetryReportModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [p, setP] = useState<TelemetryPreview | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    api
      .telemetryNoticeSeen()
      .catch(() => {})
      .finally(() => qc.invalidateQueries({ queryKey: stateKey }))
    api
      .telemetryPreview()
      .then((r) => live && setP(r))
      .catch((e) => live && setErr(friendly(e, 'could not build the report')))
    return () => {
      live = false
    }
  }, [qc])

  return (
    <Modal onBackdrop={onClose} className="max-w-3xl">
      <div className="flex items-center justify-between border-b border-line px-4 py-3">
        <h2 className="text-sm font-semibold text-default">What RiftRoute sends</h2>
        <button onClick={onClose} aria-label="Close" className="text-muted hover:text-default">
          ✕
        </button>
      </div>
      <div className="space-y-3 p-4">
        <p className="text-xs text-muted">
          Once a day, counts and versions only. <span className="font-medium text-default">Never sent:</span>{' '}
          {TELEMETRY_NEVER}
        </p>
        {!p && !err && <p className="text-sm text-muted">Building the report…</p>}
        {err && <p className="text-sm text-danger">{err}</p>}
        {p && (
          <>
            <TelemetrySchedule p={p} />
            {p.next ? (
              <pre
                aria-label="Next report"
                className="ltr max-h-[45vh] overflow-auto whitespace-pre rounded-lg border border-line bg-base p-3 font-mono text-[11px] leading-relaxed text-default"
              >
                {JSON.stringify(p.next, null, 2)}
              </pre>
            ) : (
              <p className="text-sm text-muted">Telemetry is off: nothing is sent, and no request is made.</p>
            )}
            {p.last && (
              <details className="text-xs text-muted">
                <summary className="cursor-pointer">The last report sent</summary>
                <pre
                  aria-label="Last report"
                  className="ltr mt-2 max-h-[30vh] overflow-auto whitespace-pre rounded-lg border border-line bg-base p-3 font-mono text-[11px] leading-relaxed text-default"
                >
                  {JSON.stringify(p.last, null, 2)}
                </pre>
              </details>
            )}
          </>
        )}
      </div>
      <div className="flex justify-end border-t border-line px-4 py-3">
        <button
          onClick={onClose}
          className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
        >
          Close
        </button>
      </div>
    </Modal>
  )
}

/**
 * TelemetryNoticeBanner tells the user, once, that an anonymous report is
 * sent, with what's in it a click away and a one-click way to stop it.
 * Reports don't start before this is seen (or a week has passed).
 */
export function TelemetryNoticeBanner() {
  const qc = useQueryClient()
  const { data: s } = useStateQuery()
  const [gone, setGone] = useState(false)
  const [viewing, setViewing] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function done(turnOff: boolean) {
    setErr(null)
    try {
      if (turnOff) await api.setPreferences({ telemetry: 'off' })
      await api.telemetryNoticeSeen()
      setGone(true)
    } catch (e) {
      setErr(friendly(e))
    } finally {
      qc.invalidateQueries({ queryKey: stateKey })
    }
  }

  if (viewing) return <TelemetryReportModal onClose={() => setViewing(false)} />
  if (gone || !s?.telemetry_notice) return null
  return (
    <div
      role="status"
      aria-label="Telemetry notice"
      className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-accent/10 px-5 py-2 text-sm text-default"
    >
      <span className="min-w-0 flex-1">
        RiftRoute sends an anonymous report once a day, so a broken release is caught early: versions, and counts of
        what worked and what failed. Never addresses, domains or names.
        {err && <span className="ms-2 text-danger">{err}</span>}
      </span>
      <span className="flex gap-2">
        <button
          onClick={() => setViewing(true)}
          className="rounded-lg border border-line px-3 py-1 text-sm text-muted hover:text-default"
        >
          See what’s sent
        </button>
        <button
          onClick={() => void done(true)}
          className="rounded-lg border border-line px-3 py-1 text-sm text-muted hover:text-default"
        >
          Turn off
        </button>
        <button
          onClick={() => void done(false)}
          className="rounded-lg bg-accent px-3 py-1 text-sm font-medium text-accent-contrast hover:opacity-90"
        >
          OK
        </button>
      </span>
    </div>
  )
}
