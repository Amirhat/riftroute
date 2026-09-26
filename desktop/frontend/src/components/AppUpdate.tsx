import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { onAppUpdate } from '../lib/events'
import { friendly } from '../lib/format'
import type { AppUpdateStatus } from '../types'

// The app updates itself after the daemon: once the daemon runs a newer
// release, the app installs the same one (in the daemon's update mode) and
// asks for a restart. These show that.

/** useAppUpdate follows the app's own update status. */
export function useAppUpdate(): AppUpdateStatus | undefined {
  const [st, setSt] = useState<AppUpdateStatus>()
  useEffect(() => {
    let live = true
    api
      .appUpdate()
      .then((s) => live && setSt(s))
      .catch(() => {})
    const off = onAppUpdate((s) => setSt(s))
    return () => {
      live = false
      off()
    }
  }, [])
  return st
}

function RestartButton({ className = '' }: { className?: string }) {
  const [err, setErr] = useState<string | null>(null)
  return (
    <>
      <button
        onClick={() => api.restartApp().catch((e) => setErr(friendly(e)))}
        className={`rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-accent-contrast hover:opacity-90 ${className}`}
      >
        Restart RiftRoute
      </button>
      {err && <span className="text-xs text-danger">{err}</span>}
    </>
  )
}

/** AppUpdateBanner asks for a restart once the new app is in place. */
export function AppUpdateBanner({ st }: { st?: AppUpdateStatus }) {
  if (st?.state !== 'ready') return null
  return (
    <div role="status" className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-accent/10 px-5 py-2 text-sm text-default">
      <span>RiftRoute {st.target} is installed. Restart the app to use it — nothing else stops.</span>
      <RestartButton />
    </div>
  )
}

/** AppUpdateSection is the app's line in Settings → Updates. */
export function AppUpdateSection({ st }: { st?: AppUpdateStatus }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  if (!st) return null

  async function install() {
    setBusy(true)
    setErr(null)
    try {
      await api.installAppUpdate()
    } catch (e) {
      setErr(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  let line: React.ReactNode
  switch (st.state) {
    case 'available':
      line = <span className="text-default">The app can move to {st.target} too.</span>
      break
    case 'downloading':
      line = <span className="text-default">Downloading and verifying the {st.target} app…</span>
      break
    case 'installing':
      line = <span className="text-default">Installing the {st.target} app…</span>
      break
    case 'ready':
      line = <span className="text-default">The {st.target} app is installed — restart it to use it.</span>
      break
    case 'error':
      line = (
        <span className="text-danger">
          The app couldn’t update to {st.target}: {st.error}. It tries again within the hour.
        </span>
      )
      break
    case 'unsupported':
      line = <span className="text-muted">The app doesn’t update itself here: {st.why}.</span>
      break
    default:
      line = <span className="text-muted">The app follows the daemon: it updates once the daemon has.</span>
  }
  return (
    <div className="space-y-2 border-t border-line pt-2 text-sm" aria-live="polite">
      <p>
        <span className="text-xs text-muted">App {st.current} · </span>
        {line}
      </p>
      {err && <p className="text-xs text-danger">{err}</p>}
      {(st.state === 'available' || st.state === 'error') && (
        <button
          onClick={() => void install()}
          disabled={busy}
          className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-accent-contrast disabled:opacity-50"
        >
          {busy ? 'Updating the app…' : `Update the app to ${st.target}`}
        </button>
      )}
      {st.state === 'ready' && <RestartButton />}
    </div>
  )
}
