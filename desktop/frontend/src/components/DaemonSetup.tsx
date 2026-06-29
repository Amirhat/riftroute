import { useDaemon } from '../lib/useDaemon'

// DaemonSetup is the actionable offline screen: instead of telling the user to
// run terminal commands, it installs/starts the privileged daemon for them with
// a native admin prompt. Shown whenever the daemon isn't reachable.
export function DaemonSetup({ message, onRetry }: { message?: string; onRetry: () => void }) {
  const d = useDaemon()
  const info = d.info
  const busy = d.busy !== null

  let title = 'Connecting to RiftRoute…'
  let body = 'Checking the background service.'
  let action: { label: string; run: () => void } | null = null

  if (info) {
    if (!info.can_manage) {
      title = 'Daemon not reachable'
      body = 'The RiftRoute daemon isn’t answering on this platform.'
    } else if (!info.installed) {
      title = 'Set up RiftRoute'
      body =
        'RiftRoute runs a small background service (riftrouted) that owns the routing ' +
        'table and keeps working even when this window is closed. Install it once — ' +
        'macOS will ask for your password to set it up.'
      action = { label: d.busy === 'install' ? 'Installing…' : 'Install & start', run: d.install }
    } else if (!info.loaded || !info.reachable) {
      title = 'Daemon is installed but not running'
      body = 'Start the RiftRoute background service. You’ll be asked for your password.'
      action = { label: d.busy === 'start' ? 'Starting…' : 'Start daemon', run: d.start }
    } else {
      title = 'Daemon is running'
      body = 'Reconnecting…'
    }
  }

  return (
    <div className="flex h-full flex-col items-center justify-center p-8">
      <div className="w-full max-w-md rounded-xl border border-line bg-surface p-6 text-center">
        <div className="text-lg font-semibold text-default">{title}</div>
        <p className="mt-2 text-sm text-muted">{body}</p>

        {info && !info.can_manage && (
          <p className="mt-3 font-mono text-xs text-muted">sudo riftroute daemon install</p>
        )}

        {d.error && (
          <p className="mt-3 max-w-full break-words rounded-lg bg-danger/10 px-3 py-2 font-mono text-xs text-danger">
            {d.error}
          </p>
        )}
        {message && !d.error && (
          <p className="mt-3 break-words font-mono text-[11px] text-muted">{message}</p>
        )}

        <div className="mt-5 flex items-center justify-center gap-2">
          {action && (
            <button
              onClick={action.run}
              disabled={busy}
              className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
            >
              {action.label}
            </button>
          )}
          <button
            onClick={() => {
              void d.refresh()
              onRetry()
            }}
            disabled={busy}
            className="rounded-lg border border-line px-4 py-2 text-sm text-muted hover:text-default disabled:opacity-50"
          >
            Retry
          </button>
        </div>

        {info?.installed && (
          <div className="mt-4 text-[11px] text-muted">
            service: {info.manager} · installed{info.loaded ? ' · running' : ''}
          </div>
        )}
      </div>
    </div>
  )
}
