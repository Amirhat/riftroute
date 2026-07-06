import { useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey, useStateQuery } from '../lib/queries'
import { Card, CardHeader, Badge, Stat, Skeleton, CapBadge } from '../components/ui'
import { ConfirmModal } from '../components/ConfirmModal'
import { SplitDNSEditor } from '../components/SplitDNSEditor'
import { useDaemon } from '../lib/useDaemon'
import { fmtUptime, friendly } from '../lib/format'
import type { UpdateResult } from '../types'

type Theme = 'dark' | 'light'

const CAP_LABELS: Record<string, string> = {
  policy_routing: 'policy routing',
  per_app_routing: 'per-app routing',
  kill_switch: 'kill switch',
  ipv6: 'IPv6',
  iface_scoping: 'iface scoping',
  fwmark: 'fwmark',
  proto_tag: 'proto tag',
}

export function Settings({ theme, onToggleTheme }: { theme: Theme; onToggleTheme: () => void }) {
  const qc = useQueryClient()
  const stateQ = useStateQuery()
  const s = stateQ.data
  const [confirmKill, setConfirmKill] = useState(false)
  const d = useDaemon()
  const [confirmDaemon, setConfirmDaemon] = useState<null | 'stop' | 'uninstall'>(null)

  async function setKill(enabled: boolean) {
    try {
      await api.setKillSwitch(enabled)
    } finally {
      qc.invalidateQueries({ queryKey: stateKey })
    }
  }
  const killOn = s?.kill_switch ?? false

  return (
    <div className="max-w-3xl space-y-4">
      <Card>
        <CardHeader title="Appearance" />
        <div className="flex items-center justify-between px-4 py-3">
          <span className="text-sm text-default">Theme</span>
          <div className="flex overflow-hidden rounded-lg border border-line text-sm">
            {(['light', 'dark'] as Theme[]).map((t) => (
              <button
                key={t}
                onClick={() => {
                  if (t !== theme) onToggleTheme()
                }}
                className={`px-3 py-1.5 capitalize ${theme === t ? 'bg-accent text-accent-contrast' : 'text-muted hover:text-default'}`}
              >
                {t === 'dark' ? '☾ Dark' : '☀ Light'}
              </button>
            ))}
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader title="Behavior" hint="how the daemon reconciles" />
        {!s ? (
          <div className="p-4"><Skeleton className="h-8 w-full" /></div>
        ) : (
          <div className="divide-y divide-line">
            <div className="flex items-center justify-between px-4 py-3">
              <div>
                <div className="text-sm text-default">Auto-apply on network change</div>
                <div className="text-xs text-muted">Reconcile automatically when the VPN/network changes (daemon flag / config).</div>
              </div>
              <Badge tone={s.auto_apply ? 'success' : 'muted'}>{s.auto_apply ? 'on' : 'off'}</Badge>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <div>
                <div className="text-sm text-default">Kill switch</div>
                <div className="text-xs text-muted">Fence all egress to the tunnel; a reconnect path stays open.</div>
              </div>
              <button
                onClick={() => (killOn ? void setKill(false) : setConfirmKill(true))}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium ${
                  killOn ? 'bg-danger/15 text-danger' : 'border border-line text-muted hover:text-default'
                }`}
              >
                {killOn ? 'ON' : 'off'}
              </button>
            </div>
          </div>
        )}
      </Card>

      <Card>
        <CardHeader title="Daemon service" hint="background service (riftrouted)" />
        {!d.info ? (
          <div className="p-4"><Skeleton className="h-10 w-full" /></div>
        ) : !d.info.can_manage ? (
          <div className="p-4 text-sm text-muted">
            Service management isn’t supported on this platform. Install manually:
            <span className="font-mono text-default"> sudo riftroute daemon install</span>
          </div>
        ) : (
          <div className="space-y-3 p-4">
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted">{d.info.manager}</span>
              <Badge tone={d.info.installed ? 'success' : 'muted'}>{d.info.installed ? 'installed' : 'not installed'}</Badge>
              {d.info.installed && (
                <Badge tone={d.info.reachable ? 'success' : 'warning'}>{d.info.reachable ? 'running' : 'stopped'}</Badge>
              )}
            </div>
            <p className="text-xs text-muted">
              Privileged actions ask for your password. The daemon owns the routing table and keeps
              running when this window is closed.
            </p>
            <div className="flex flex-wrap gap-2">
              {!d.info.installed && (
                <DaemonBtn onClick={d.install} busy={d.busy === 'install'} primary>Install &amp; start</DaemonBtn>
              )}
              {d.info.installed && !d.info.reachable && (
                <DaemonBtn onClick={d.start} busy={d.busy === 'start'} primary>Start</DaemonBtn>
              )}
              {d.info.installed && d.info.reachable && (
                <>
                  <DaemonBtn onClick={d.restart} busy={d.busy === 'restart'}>Restart</DaemonBtn>
                  <DaemonBtn onClick={() => setConfirmDaemon('stop')} busy={d.busy === 'stop'}>Stop</DaemonBtn>
                </>
              )}
              {d.info.installed && (
                <DaemonBtn onClick={() => setConfirmDaemon('uninstall')} busy={d.busy === 'uninstall'} danger>
                  Uninstall
                </DaemonBtn>
              )}
            </div>
            {d.error && (
              <p className="break-words rounded-lg bg-danger/10 px-3 py-2 font-mono text-xs text-danger">{d.error}</p>
            )}
          </div>
        )}
      </Card>

      <Card>
        <CardHeader title="Daemon & connection" hint={s ? `as of ${new Date(s.generated_at).toLocaleTimeString()}` : ''} />
        {!s ? (
          <div className="p-4"><Skeleton className="h-16 w-full" /></div>
        ) : (
          <div className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3">
            <Stat label="Status" value={<Badge tone={s.health.daemon === 'ok' ? 'success' : 'warning'}>{s.health.daemon}</Badge>} />
            <Stat label="Provider" value={s.health.provider} />
            <Stat label="Platform" value={s.capabilities.platform} />
            <Stat label="Version" value={s.health.version} />
            <Stat label="PID" value={s.health.pid} />
            <Stat label="Uptime" value={fmtUptime(s.health.uptime_seconds)} />
          </div>
        )}
      </Card>

      <SplitDNSEditor />

      {s && (
        <Card>
          <CardHeader title="Platform capabilities" hint={`platform: ${s.capabilities.platform}${s.capabilities.backend ? ` · backend: ${s.capabilities.backend}` : ''}`} />
          <div className="flex flex-wrap gap-2 p-4">
            {Object.entries(CAP_LABELS).map(([key, label]) => (
              <CapBadge
                key={key}
                capKey={key}
                ok={(s.capabilities as unknown as Record<string, boolean>)[key]}
                label={label}
                backend={s.capabilities.backend}
              />
            ))}
          </div>
        </Card>
      )}

      <ConfigCard />

      <UpdateCard />

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
        open={confirmDaemon !== null}
        danger
        title={confirmDaemon === 'uninstall' ? 'Uninstall the daemon?' : 'Stop the daemon?'}
        message={
          confirmDaemon === 'uninstall'
            ? 'Removes the RiftRoute background service. Managed routes are restored to baseline and policy enforcement stops until reinstalled.'
            : 'Stops the background service. Policy enforcement pauses (managed routes are removed) until you start it again.'
        }
        confirmLabel={confirmDaemon === 'uninstall' ? 'Uninstall' : 'Stop'}
        onConfirm={() => {
          const which = confirmDaemon
          setConfirmDaemon(null)
          if (which === 'uninstall') void d.uninstall()
          else if (which === 'stop') void d.stop()
        }}
        onCancel={() => setConfirmDaemon(null)}
      />
    </div>
  )
}

// ConfigCard: everything is UI-configurable, and the whole policy exports to the
// same git-committable YAML the CLI applies (round-trips through the importer).
function ConfigCard() {
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function doExport() {
    setMsg(null)
    setErr(null)
    setBusy(true)
    try {
      const path = await api.exportConfig()
      if (path) setMsg(`Exported to ${path}`)
    } catch (e) {
      setErr(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title="Configuration"
        hint={
          <button onClick={doExport} disabled={busy} className="rounded-lg border border-accent/50 px-2.5 py-1 text-xs font-medium text-accent hover:bg-accent/10 disabled:opacity-50">
            {busy ? 'Exporting…' : 'Export config…'}
          </button>
        }
      />
      <div className="space-y-2 p-4 text-sm text-muted">
        <p>
          Everything here is configurable in the app — profiles and lists on the
          Profiles screen, split-DNS above. Export writes it all as declarative YAML
          (<span className="font-mono text-accent">riftroute.yaml</span>) so your policy stays
          reviewable and git-committable; the Profiles screen imports the same file back.
        </p>
        <p>GeoIP/ASN rules require a user-supplied MaxMind MMDB.</p>
        {msg && <p className="ltr font-mono text-xs text-success">{msg}</p>}
        {err && <p className="text-xs text-danger">{err}</p>}
      </div>
    </Card>
  )
}

// UpdateCard checks GitHub Releases for a newer version. It never self-installs —
// applying an update stays a deliberate, checksum-verified step.
function UpdateCard() {
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<UpdateResult | null>(null)
  const [err, setErr] = useState<string | null>(null)

  async function check() {
    setBusy(true)
    setErr(null)
    setRes(null)
    try {
      setRes(await api.checkUpdate())
    } catch (e) {
      setErr(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title="Updates"
        hint={
          <button onClick={check} disabled={busy} className="rounded-lg border border-line px-2.5 py-1 text-xs text-muted hover:text-default disabled:opacity-50">
            {busy ? 'Checking…' : 'Check for updates'}
          </button>
        }
      />
      <div className="p-4 text-sm">
        {!res && !err && <p className="text-muted">Checks GitHub Releases; nothing is installed automatically.</p>}
        {err && <p className="text-danger">Update check failed: {err}</p>}
        {res && !res.available && (
          <p className="text-success">✓ Up to date ({res.current}{res.latest ? `; latest ${res.latest}` : ''})</p>
        )}
        {res && res.available && (
          <div className="space-y-1">
            <p className="text-default">
              Update available: <span className="font-mono">{res.current}</span> → <span className="font-mono text-accent">{res.latest}</span>
            </p>
            {res.url && <p className="ltr break-all font-mono text-xs text-muted">{res.url}</p>}
            <p className="text-xs text-muted">Download the asset for your platform, verify its SHA-256 against the release checksums, then reinstall.</p>
          </div>
        )}
      </div>
    </Card>
  )
}

function DaemonBtn({
  onClick,
  busy,
  primary,
  danger,
  children,
}: {
  onClick: () => void
  busy?: boolean
  primary?: boolean
  danger?: boolean
  children: ReactNode
}) {
  const tone = danger
    ? 'border border-danger/50 text-danger hover:bg-danger/10'
    : primary
      ? 'bg-accent text-accent-contrast hover:opacity-90'
      : 'border border-line text-muted hover:text-default'
  return (
    <button onClick={onClick} disabled={busy} className={`rounded-lg px-3 py-1.5 text-sm font-medium disabled:opacity-50 ${tone}`}>
      {busy ? '…' : children}
    </button>
  )
}
