import { useEffect, useId, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey, tunnelEngineKey, useStateQuery, useTunnelEngineQuery } from '../lib/queries'
import { fmtBytes, fmtUptime, friendly } from '../lib/format'
import { copyText, openURL } from '../lib/system'
import { Addr, Badge, Card, Dot, Label, Skeleton, Toggle } from '../components/ui'
import { CommitConfirm } from '../components/CommitConfirm'
import { ConfirmModal } from '../components/ConfirmModal'
import { TunnelEditor } from '../components/TunnelEditor'
import type {
  ApplyResult,
  TunnelEngine,
  TunnelProfileRef,
  TunnelState,
  TunnelStatus,
  UpdateStatus,
} from '../types'

const CONFIRM_SECONDS = 15
const DAEMON_BACKSTOP_SEC = 60

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
export function Tunnels({ onOpenUpdates }: { onOpenUpdates?: () => void } = {}) {
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
  // The banner's heading: why Connect is off, for its accessible description.
  const engineProblemId = useId()

  const tunnels = stateQ.data?.tunnels ?? []
  // A profile toggled here is saved, as on the Profiles page; "Apply
  // changes" applies it, and the change is confirmed like any other.
  const [pending, setPending] = useState<ApplyResult | null>(null)
  const [applying, setApplying] = useState(false)
  const drift = stateQ.data?.drift
  // openvpn matters to OpenVPN tunnels only — and before there's any
  // tunnel, to say what a first one would need. WireGuard is built in.
  const openvpnMatters = tunnels.length === 0 || tunnels.some((t) => (t.type || 'openvpn') === 'openvpn')
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

  async function toggleProfile(p: TunnelProfileRef) {
    setError(null)
    setNotice(null)
    try {
      await api.setProfileEnabled(p.name, !p.enabled)
    } catch (e) {
      setError(friendly(e))
    } finally {
      refresh()
    }
  }

  async function applyChanges() {
    setError(null)
    setApplying(true)
    try {
      const res = await api.apply(false /* interactive */, DAEMON_BACKSTOP_SEC)
      if (res.violations && res.violations.length > 0) {
        setError('Refused by guardrails: ' + res.violations.map((v) => v.rule).join(', '))
      } else if (res.needs_confirm) {
        setPending(res)
      }
    } catch (e) {
      setError(friendly(e))
    } finally {
      setApplying(false)
      refresh()
    }
  }

  async function settle(keep: boolean) {
    const tx = pending?.tx_id
    setPending(null)
    if (!tx) return
    try {
      await (keep ? api.confirm(tx) : api.rollback(tx))
    } finally {
      refresh()
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted">
          Run an OpenVPN or WireGuard connection next to your main VPN. Only the networks you list go through it — the
          server can't take over your default route or DNS.
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

      {engine && !engine.available && openvpnMatters && (
        <EngineBanner
          engine={engine}
          headingId={engineProblemId}
          update={stateQ.data?.update}
          checking={engineQ.isFetching}
          onRecheck={() => engineQ.refetch()}
          onOpenUpdates={onOpenUpdates}
        />
      )}
      {drift?.pending && tunnels.some((t) => (t.profiles ?? []).length > 0) && (
        <Card tone="warning" className="flex items-center justify-between gap-3 p-3 text-sm">
          <span>
            <span className="font-semibold text-warning">Pending changes</span>
            <span className="ms-2 text-muted">
              {drift.adds ?? 0} to add · {drift.dels ?? 0} to remove
            </span>
          </span>
          <button
            onClick={applyChanges}
            disabled={applying}
            className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
          >
            {applying ? 'Applying…' : 'Apply changes'}
          </button>
        </Card>
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
              Import an OpenVPN profile (<span className="font-mono">.ovpn</span>) or a WireGuard configuration (
              <span className="font-mono">.conf</span>) to reach private networks (say <Addr>192.168.70.0/24</Addr>)
              while your main VPN carries everything else. WireGuard is built in. For OpenVPN, RiftRoute runs the{' '}
              <span className="font-mono">openvpn</span> program itself — the OpenVPN Connect app isn't needed. On
              macOS it comes with RiftRoute; on Linux it's your distribution's{' '}
              <span className="font-mono">openvpn</span> package.
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
        tunnels.map((t) =>
          t.unreadable ? (
            <UnreadableCard key={t.name} t={t} busy={busy === t.name} onDelete={() => setDeleting(t)} />
          ) : (
            <TunnelCard
              key={t.name}
              t={t}
              busy={busy === t.name}
              canConnect={t.type === 'wireguard' || canConnect}
              whyNotId={engineProblemId}
              onConnect={() => run(t.name, () => api.connectTunnel(t.name))}
              onDisconnect={() => run(t.name, () => api.disconnectTunnel(t.name))}
              onEdit={() => setEditor({ mode: 'edit', tunnel: t })}
              onDelete={() => setDeleting(t)}
              onToggleProfile={toggleProfile}
            />
          ),
        )
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
        message={
          deleting?.unreadable
            ? 'Deletes its saved definition, which RiftRoute can’t read, with its profile and password. You can add it again afterwards.'
            : 'Disconnects it, removes its routes, and deletes its saved profile and password.'
        }
        confirmLabel="Delete"
        onConfirm={() => {
          const t = deleting
          setDeleting(null)
          if (t) run(t.name, () => api.deleteTunnel(t.name))
        }}
        onCancel={() => setDeleting(null)}
      />
      {pending && (
        <CommitConfirm
          result={pending}
          seconds={CONFIRM_SECONDS}
          onKeep={() => settle(true)}
          onRevert={() => settle(false)}
        />
      )}
    </div>
  )
}

// EngineBanner explains, before the user tries to connect, that tunnels need
// openvpn and how to get it on this system. On macOS that's the openvpn that
// ships with RiftRoute: when it's missing, the daemon's update check installs
// the one the newest release ships, so the banner offers that check; when
// it's there but unusable, reinstalling the daemon puts it back. On Linux
// it's the distribution's package, with the commands to install it. Either
// way the daemon notices it once it's there.
function EngineBanner({
  engine,
  headingId,
  update,
  checking,
  onRecheck,
  onOpenUpdates,
}: {
  engine: TunnelEngine
  headingId: string
  update?: UpdateStatus
  checking: boolean
  onRecheck: () => void
  onOpenUpdates?: () => void
}) {
  const qc = useQueryClient()
  const inst = engine.install
  const cmds = inst?.commands ?? []
  // Daemons from before the action field: macOS help was RiftRoute's own
  // openvpn then too.
  const action = inst?.action ?? (inst?.system === 'macOS' ? 'reinstall' : 'install')
  // Only the installed service updates itself, so only it can fetch
  // openvpn; until the state says, assume it is.
  const canFetch = action === 'update' && (update ? update.self_updatable : true)
  const [copied, setCopied] = useState(false)
  const [fetching, setFetching] = useState<{
    busy: boolean
    done: boolean
    error: string | null
    installing: string | null // the update the check is installing instead
  }>({ busy: false, done: false, error: null, installing: null })
  async function copy() {
    try {
      setCopied(await copyText(cmds.join('\n')))
    } catch {
      setCopied(false)
    }
  }
  // checkForUpdates runs the daemon's update check, which installs a missing
  // openvpn before it answers — unless it's installing an update, which
  // brings openvpn with it — then looks at openvpn again.
  async function checkForUpdates() {
    setFetching({ busy: true, done: false, error: null, installing: null })
    let error: string | null = null
    let installing: string | null = null
    try {
      const st = await api.checkUpdate()
      error = st.error || null
      if (!error && st.action === 'install') installing = st.latest || 'the update'
    } catch (e) {
      error = friendly(e)
    }
    setFetching({ busy: false, done: true, error, installing })
    qc.invalidateQueries({ queryKey: stateKey })
    onRecheck()
  }
  return (
    <Card tone="warning" className="p-4">
      <div role="status" className="space-y-3 text-sm">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <h2 id={headingId} className="font-semibold text-warning">
              {engine.problem || "OpenVPN isn't usable"}
            </h2>
            <p className="text-muted">
              {engine.path ? (
                <>
                  RiftRoute found <span className="ltr font-mono">{engine.path}</span> but can't use it.
                </>
              ) : action === 'install' ? (
                <>
                  Tunnels run on the <span className="font-mono">openvpn</span> program from your system's packages.
                </>
              ) : (
                <>
                  Tunnels run on the <span className="font-mono">openvpn</span> that ships with RiftRoute.
                </>
              )}
              {cmds.length > 0 && inst?.system ? ` On ${inst.system}, run this in a terminal:` : ''}
            </p>
          </div>
          {canFetch ? (
            <button
              onClick={checkForUpdates}
              disabled={fetching.busy}
              className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
            >
              {fetching.busy ? 'Checking for updates…' : 'Check for updates'}
            </button>
          ) : (
            <button
              onClick={onRecheck}
              disabled={checking}
              className="shrink-0 rounded-lg border border-line px-3 py-1.5 text-sm text-default hover:bg-elevated disabled:opacity-50"
            >
              {checking ? 'Checking…' : 'Check again'}
            </button>
          )}
        </div>
        {action === 'update' ? (
          <>
            {canFetch ? (
              <p className="text-muted">Checking for updates installs it from RiftRoute's newest signed release.</p>
            ) : (
              <p className="text-muted">
                This daemon isn't running as the installed service, so it can't fetch it. Install the daemon from a
                current release: Settings → Daemon service, or{' '}
                <span className="ltr font-mono">sudo riftroute daemon install</span>.
              </p>
            )}
            {canFetch && update?.mode === 'off' && (
              <p className="text-muted">
                Updates are off, so RiftRoute doesn't check on its own — checking here still works.{' '}
                {onOpenUpdates && (
                  <button onClick={onOpenUpdates} className="text-accent hover:underline">
                    Settings → Updates
                  </button>
                )}
              </p>
            )}
            {fetching.done &&
              (fetching.error ? (
                <p className="text-danger">The update check failed: {fetching.error}</p>
              ) : fetching.installing ? (
                <p className="text-muted">
                  RiftRoute is installing {fetching.installing}, which brings openvpn with it; the daemon restarts
                  when it's in place.
                </p>
              ) : (
                <p className="text-muted">
                  Checked. If openvpn is still missing in a minute, reinstall the daemon from a current release.
                </p>
              ))}
            {inst?.url && (
              <p className="text-muted">
                Current release:{' '}
                <button onClick={() => openURL(inst.url!)} className="ltr text-accent hover:underline">
                  {inst.url}
                </button>
              </p>
            )}
          </>
        ) : (
          <InstallSteps inst={inst} copied={copied} onCopy={copy} />
        )}
        <p className="text-xs text-muted">RiftRoute picks it up as soon as it's installed — no restart needed.</p>
      </div>
    </Card>
  )
}

// InstallSteps shows the daemon's own steps: the commands to run (with Copy),
// its note and a link.
function InstallSteps({
  inst,
  copied,
  onCopy,
}: {
  inst?: TunnelEngine['install']
  copied: boolean
  onCopy: () => void
}) {
  const cmds = inst?.commands ?? []
  return (
    <>
      {cmds.length > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-line bg-surface p-3">
          <pre className="ltr min-w-0 flex-1 overflow-x-auto font-mono text-sm text-default">{cmds.join('\n')}</pre>
          <button
            onClick={onCopy}
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
    </>
  )
}

// UnreadableCard is a tunnel whose saved definition the daemon can't read.
// Its other fields are placeholders (via "direct", no routes or servers), so
// none are shown as if they were its settings; it can't connect or be
// edited — only deleted, and added again.
function UnreadableCard({ t, busy, onDelete }: { t: TunnelStatus; busy: boolean; onDelete: () => void }) {
  return (
    <Card tone="danger">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-default">{t.name}</h2>
          <Badge tone="danger">
            <Dot tone="danger" />
            can't be read
          </Badge>
        </div>
        <button
          onClick={onDelete}
          disabled={busy}
          aria-label={`Delete ${t.name}`}
          className="rounded-lg border border-danger/40 px-3 py-1.5 text-sm text-danger hover:bg-danger/10 disabled:opacity-50"
        >
          Delete
        </button>
      </div>
      <div className="space-y-2 p-4 text-sm">
        <p className="rounded-lg bg-danger/10 px-3 py-2 text-danger">
          {t.last_error || "Its saved definition can't be read; delete it and add it again."}
        </p>
        <p className="text-muted">
          RiftRoute can't connect or edit this tunnel. Delete it, then add it again from its profile (
          <span className="font-mono">.ovpn</span>) or configuration (<span className="font-mono">.conf</span>).
        </p>
      </div>
    </Card>
  )
}

function TunnelCard({
  t,
  busy,
  canConnect,
  whyNotId,
  onConnect,
  onDisconnect,
  onEdit,
  onDelete,
  onToggleProfile,
}: {
  t: TunnelStatus
  busy: boolean
  canConnect: boolean
  // The element that says why Connect is off (the engine banner's heading).
  whyNotId: string
  onConnect: () => void
  onDisconnect: () => void
  onEdit: () => void
  onDelete: () => void
  onToggleProfile: (p: TunnelProfileRef) => void
}) {
  const live = t.state === 'connected' || t.state === 'connecting' || t.state === 'reconnecting'
  const since = t.since ? Date.parse(t.since) : NaN
  const uptime = t.state === 'connected' && Number.isFinite(since)
  const routes = t.routes ?? []
  const profilesOn = (t.profiles ?? []).some((p) => p.enabled)
  const blocked = new Map((t.blocked ?? []).map((b) => [b.route, b.reason]))
  const detail = t.detail && t.detail !== t.state ? t.detail : ''
  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-default">{t.name}</h2>
          <Badge tone="muted">{t.type === 'wireguard' ? 'WireGuard' : 'OpenVPN'}</Badge>
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
              aria-describedby={canConnect ? undefined : whyNotId}
              title={canConnect ? undefined : "OpenVPN isn't usable yet (see above)"}
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
          {routes.length === 0 && profilesOn ? (
            <p className="mt-1 text-sm text-muted">Only what its profiles send in (below).</p>
          ) : routes.length === 0 ? (
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
              {(t.captured ?? []).map((c) => (
                <p key={'cap-' + c.route} className="mt-1.5 text-xs text-warning">
                  <span className="ltr font-mono">{c.route}</span> is installed, but some traffic still goes past it: {c.reason}.
                </p>
              ))}
            </>
          )}
        </div>
        {(t.profiles ?? []).length > 0 && (
          <div>
            <Label>Profiles through this tunnel</Label>
            <div className="mt-1.5 space-y-1.5">
              {(t.profiles ?? []).map((p) => (
                <div key={p.id} className="flex items-center justify-between gap-3 text-sm">
                  <span className="min-w-0 truncate">
                    <span className="text-default">{p.name}</span>
                    <span className="ms-2 text-xs text-muted">
                      {p.enabled ? `${p.routes} destination${p.routes === 1 ? '' : 's'}` : 'off'}
                    </span>
                  </span>
                  <Toggle
                    on={p.enabled}
                    onClick={() => onToggleProfile(p)}
                    ariaLabel={`Send profile ${p.name} through ${t.name}`}
                  />
                </div>
              ))}
            </div>
            <p className="mt-1.5 text-xs text-muted">A change here is applied with “Apply changes”. Edit the profiles on the Profiles page.</p>
          </div>
        )}
        {(t.ignored ?? []).length > 0 && (
          <p className="text-xs text-muted">
            Ignored from the {t.type === 'wireguard' ? 'configuration' : 'profile'}:{' '}
            <span className="ltr font-mono">{(t.ignored ?? []).join(', ')}</span>
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
