import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey, tunnelEngineKey, useStateQuery, useTunnelEngineQuery } from '../lib/queries'
import { fmtBytes, fmtUptime, friendly } from '../lib/format'
import { copyText, openURL } from '../lib/system'
import { Addr, Badge, Card, Dot, Label, Skeleton } from '../components/ui'
import { ConfirmModal } from '../components/ConfirmModal'
import { TunnelEditor } from '../components/TunnelEditor'
import type { TunnelEngine, TunnelState, TunnelStatus } from '../types'

const stateTone: Record<TunnelState, 'success' | 'warning' | 'danger' | 'muted'> = {
  connected: 'success',
  connecting: 'warning',
  reconnecting: 'warning',
  failed: 'danger',
  disconnected: 'muted',
}

type EditorState = { mode: 'new' } | { mode: 'edit'; tunnel: TunnelStatus } | null

// Tunnels lists the VPN connections RiftRoute runs itself. Status comes from
// the live state push, so connect progress shows without polling.
export function Tunnels() {
  const qc = useQueryClient()
  const stateQ = useStateQuery()
  const [editor, setEditor] = useState<EditorState>(null)
  const [deleting, setDeleting] = useState<TunnelStatus | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const engineQ = useTunnelEngineQuery()
  // An older daemon without the check (or a failed read) must not block
  // connecting: openvpn's own error still explains what's wrong.
  const engine = engineQ.data
  const canConnect = !engine || engine.available

  const tunnels = stateQ.data?.tunnels ?? []
  const refresh = () => {
    qc.invalidateQueries({ queryKey: stateKey })
    qc.invalidateQueries({ queryKey: ['routes'] })
    qc.invalidateQueries({ queryKey: tunnelEngineKey })
  }

  // run performs one tunnel action. A new action clears the last one's
  // messages; notice is what to show with this one (the editor's warnings
  // when saving and connecting in one go).
  async function run(name: string, fn: () => Promise<unknown>, notice: string | null = null) {
    setError(null)
    setNotice(notice)
    setBusy(name)
    try {
      await fn()
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusy(null)
      refresh()
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted">
          Run an OpenVPN profile next to your main VPN. Only the networks you list go through it — the server can't take
          over your default route or DNS.
        </p>
        {tunnels.length > 0 && (
          <button
            onClick={() => setEditor({ mode: 'new' })}
            className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
          >
            + Add Tunnel
          </button>
        )}
      </div>

      {engine && !engine.available && (
        <EngineBanner engine={engine} checking={engineQ.isFetching} onRecheck={() => engineQ.refetch()} />
      )}
      {error && (
        <Card tone="danger" className="p-3 text-sm text-danger">
          {error}
        </Card>
      )}
      {notice && (
        <Card tone="warning" className="flex items-center justify-between gap-3 p-3 text-sm">
          <span className="text-warning">{notice}</span>
          <button
            onClick={() => setNotice(null)}
            aria-label="Dismiss"
            className="shrink-0 text-muted hover:text-default"
          >
            ✕
          </button>
        </Card>
      )}

      {stateQ.isLoading ? (
        <Skeleton className="h-40" />
      ) : tunnels.length === 0 ? (
        <Card className="p-8 text-center">
          <div className="mx-auto max-w-md space-y-3">
            <h2 className="text-base font-semibold text-default">No tunnels yet</h2>
            <p className="text-sm text-muted">
              Import an <span className="font-mono">.ovpn</span> profile to reach private networks (say{' '}
              <Addr>192.168.70.0/24</Addr>) while your main VPN carries everything else. RiftRoute runs the{' '}
              <span className="font-mono">openvpn</span> program, which you install yourself — the OpenVPN Connect app
              isn't needed.
            </p>
            <button
              onClick={() => setEditor({ mode: 'new' })}
              className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
            >
              + Add Tunnel
            </button>
          </div>
        </Card>
      ) : (
        tunnels.map((t) => (
          <TunnelCard
            key={t.name}
            t={t}
            busy={busy === t.name}
            canConnect={canConnect}
            onConnect={() => run(t.name, () => api.connectTunnel(t.name))}
            onDisconnect={() => run(t.name, () => api.disconnectTunnel(t.name))}
            onEdit={() => setEditor({ mode: 'edit', tunnel: t })}
            onDelete={() => setDeleting(t)}
          />
        ))
      )}

      {editor && (
        <TunnelEditor
          existing={editor.mode === 'edit' ? editor.tunnel : undefined}
          takenNames={tunnels.map((t) => t.name)}
          canConnect={canConnect}
          onClose={() => setEditor(null)}
          onSaved={(t, warnings, connect) => {
            setEditor(null)
            const note = warnings.length ? warnings.join(' ') : null
            if (connect) {
              run(t.name, () => api.connectTunnel(t.name), note)
            } else {
              setError(null)
              setNotice(note)
              refresh()
            }
          }}
        />
      )}
      <ConfirmModal
        open={!!deleting}
        danger
        title={`Delete tunnel ${deleting?.name ?? ''}`}
        message="Disconnects it, removes its routes, and deletes its saved profile and password."
        confirmLabel="Delete"
        onConfirm={() => {
          const t = deleting
          setDeleting(null)
          if (t) run(t.name, () => api.deleteTunnel(t.name))
        }}
        onCancel={() => setDeleting(null)}
      />
    </div>
  )
}

// EngineBanner explains, before the user tries to connect, that tunnels need
// the openvpn program and how to install it on this system. RiftRoute never
// installs it itself; the daemon notices it once it's there.
function EngineBanner({
  engine,
  checking,
  onRecheck,
}: {
  engine: TunnelEngine
  checking: boolean
  onRecheck: () => void
}) {
  const inst = engine.install
  const cmds = inst?.commands ?? []
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      setCopied(await copyText(cmds.join('\n')))
    } catch {
      setCopied(false)
    }
  }
  return (
    <Card tone="warning" className="p-4">
      <div role="status" className="space-y-3 text-sm">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <h2 className="font-semibold text-warning">{engine.problem || "OpenVPN isn't usable"}</h2>
            <p className="text-muted">
              {engine.path ? (
                <>
                  RiftRoute found <span className="ltr font-mono">{engine.path}</span> but can't use it.
                </>
              ) : (
                <>
                  Tunnels run on the <span className="font-mono">openvpn</span> program, which you install yourself.
                </>
              )}
              {cmds.length > 0 && inst?.system ? ` On ${inst.system}, run this in a terminal:` : ''}
            </p>
          </div>
          <button
            onClick={onRecheck}
            disabled={checking}
            className="shrink-0 rounded-lg border border-line px-3 py-1.5 text-sm text-default hover:bg-elevated disabled:opacity-50"
          >
            {checking ? 'Checking…' : 'Check again'}
          </button>
        </div>
        {cmds.length > 0 && (
          <div className="flex items-start gap-2 rounded-lg border border-line bg-surface p-3">
            <pre className="ltr min-w-0 flex-1 overflow-x-auto font-mono text-sm text-default">{cmds.join('\n')}</pre>
            <button
              onClick={copy}
              className="shrink-0 rounded-md px-2 py-1 text-xs text-muted hover:bg-elevated hover:text-default"
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        )}
        {inst?.note && <p className="text-muted">{inst.note}</p>}
        {inst?.url && (
          <button onClick={() => openURL(inst.url!)} className="ltr text-accent hover:underline">
            {inst.url}
          </button>
        )}
        <p className="text-xs text-muted">RiftRoute picks it up as soon as it's installed — no restart needed.</p>
      </div>
    </Card>
  )
}

function TunnelCard({
  t,
  busy,
  canConnect,
  onConnect,
  onDisconnect,
  onEdit,
  onDelete,
}: {
  t: TunnelStatus
  busy: boolean
  canConnect: boolean
  onConnect: () => void
  onDisconnect: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const live = t.state === 'connected' || t.state === 'connecting' || t.state === 'reconnecting'
  const since = t.since ? Date.parse(t.since) : NaN
  const uptime = t.state === 'connected' && Number.isFinite(since)
  const routes = t.routes ?? []
  const blocked = new Map((t.blocked ?? []).map((b) => [b.route, b.reason]))
  const detail = t.detail && t.detail !== t.state ? t.detail : ''
  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-default">{t.name}</h2>
          <Badge tone={stateTone[t.state]}>
            <Dot tone={stateTone[t.state]} />
            {t.state}
            {detail && t.state !== 'connected' ? ` · ${detail.replace(/_/g, ' ')}` : ''}
          </Badge>
          {t.auto_connect && <Badge tone="muted">auto-connect</Badge>}
        </div>
        <div className="flex items-center gap-2">
          {/* Every card has these buttons: the names say which tunnel. */}
          <button
            onClick={onEdit}
            disabled={busy}
            aria-label={`Edit ${t.name}`}
            className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default disabled:opacity-50"
          >
            Edit
          </button>
          <button
            onClick={onDelete}
            disabled={busy}
            aria-label={`Delete ${t.name}`}
            className="rounded-lg border border-danger/40 px-3 py-1.5 text-sm text-danger hover:bg-danger/10 disabled:opacity-50"
          >
            Delete
          </button>
          {live ? (
            <button
              onClick={onDisconnect}
              disabled={busy}
              aria-label={`${busy ? 'Disconnecting' : 'Disconnect'} ${t.name}`}
              className="rounded-lg border border-line px-3 py-1.5 text-sm text-default hover:bg-elevated disabled:opacity-50"
            >
              {busy ? 'Disconnecting…' : 'Disconnect'}
            </button>
          ) : (
            <button
              onClick={onConnect}
              disabled={busy || !canConnect}
              aria-label={`${busy ? 'Connecting' : 'Connect'} ${t.name}`}
              title={canConnect ? undefined : 'Install OpenVPN first (see above)'}
              className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
            >
              {busy ? 'Connecting…' : 'Connect'}
            </button>
          )}
        </div>
      </div>
      <div className="space-y-4 p-4">
        {t.last_error && <div className="rounded-lg bg-danger/10 px-3 py-2 text-sm text-danger">{t.last_error}</div>}
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <Field label="Server">
            <Addr>{t.server || (t.servers ?? []).join(', ') || '—'}</Addr>
          </Field>
          <Field label="Interface">
            {t.iface ? (
              <Addr>
                {t.iface} · {t.local_ip}
              </Addr>
            ) : (
              <span className="text-muted">—</span>
            )}
          </Field>
          <Field label={uptime ? 'Connected for' : 'Reaches server'}>
            {uptime ? (
              <ConnectedFor since={since} />
            ) : (
              <span>{t.via === 'direct' ? 'directly' : 'through main VPN'}</span>
            )}
          </Field>
          <Field label="Traffic">
            {live ? (
              <span className="ltr">
                ↓ {fmtBytes(t.bytes_in)} · ↑ {fmtBytes(t.bytes_out)}
              </span>
            ) : (
              <span className="text-muted">—</span>
            )}
          </Field>
        </div>
        <div>
          <Label>Routed through this tunnel</Label>
          {routes.length === 0 ? (
            <p className="mt-1 text-sm text-warning">Nothing yet — edit the tunnel to list the networks behind it.</p>
          ) : (
            <>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {routes.map((r) =>
                  blocked.has(r) ? (
                    <span
                      key={r}
                      title={`Not installed on this network: ${blocked.get(r)}`}
                      className="rounded-md bg-warning/15 px-2 py-0.5 text-warning line-through"
                    >
                      <Addr>{r}</Addr>
                    </span>
                  ) : (
                    <span key={r} className="rounded-md bg-elevated px-2 py-0.5">
                      <Addr>{r}</Addr>
                    </span>
                  ),
                )}
              </div>
              {[...blocked].map(([r, why]) => (
                <p key={r} className="mt-1.5 text-xs text-warning">
                  <span className="ltr font-mono">{r}</span> isn't installed on this network: {why}.
                </p>
              ))}
            </>
          )}
        </div>
        {(t.ignored ?? []).length > 0 && (
          <p className="text-xs text-muted">
            Ignored from the profile: <span className="ltr font-mono">{(t.ignored ?? []).join(', ')}</span>
          </p>
        )}
      </div>
    </Card>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <Label>{label}</Label>
      <div className="mt-1 text-sm text-default">{children}</div>
    </div>
  )
}

// ConnectedFor ticks "connected for" between state pushes. The timer lives
// here, so each second re-renders this one line (not the page, or an open
// editor), and it's mounted only while its tunnel is connected.
function ConnectedFor({ since }: { since: number }) {
  const now = useNow(1000)
  return <>{fmtUptime((now - since) / 1000)}</>
}

function useNow(ms: number): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms])
  return now
}
