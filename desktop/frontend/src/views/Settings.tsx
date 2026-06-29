import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey, useStateQuery } from '../lib/queries'
import { Card, CardHeader, Badge, Stat, Skeleton } from '../components/ui'
import { ConfirmModal } from '../components/ConfirmModal'
import { fmtUptime } from '../lib/format'

type Theme = 'dark' | 'light'

const CAP_LABELS: Record<string, string> = {
  policy_routing: 'policy routing',
  fwmark: 'fwmark',
  per_app_routing: 'per-app routing',
  proto_tag: 'proto tag',
  ipv6: 'IPv6',
  kill_switch: 'kill switch',
  iface_scoping: 'iface scoping',
}

export function Settings({ theme, onToggleTheme }: { theme: Theme; onToggleTheme: () => void }) {
  const qc = useQueryClient()
  const stateQ = useStateQuery()
  const s = stateQ.data
  const [confirmKill, setConfirmKill] = useState(false)

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

      {s && (
        <Card>
          <CardHeader title="Platform capabilities" hint={`platform: ${s.capabilities.platform}`} />
          <div className="flex flex-wrap gap-x-4 gap-y-2 p-4 text-sm">
            {Object.entries(CAP_LABELS).map(([key, label]) => {
              const on = (s.capabilities as unknown as Record<string, boolean>)[key]
              return (
                <span key={key} className={on ? 'text-success' : 'text-muted line-through'}>
                  {on ? '✓' : '✗'} {label}
                </span>
              )
            })}
          </div>
        </Card>
      )}

      <Card>
        <CardHeader title="Configuration" hint="declarative" />
        <div className="space-y-2 p-4 text-sm text-muted">
          <p>
            Profiles, lists, split-DNS, IP version, default mode, and the connectivity
            guard are managed declaratively in the config file
            (<span className="font-mono text-accent">riftroute.yaml</span>) and applied
            with <span className="font-mono text-accent">riftroute apply</span> — so your
            policy is reviewable and git-committable.
          </p>
          <p>GeoIP/ASN rules require a user-supplied MaxMind MMDB.</p>
        </div>
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
    </div>
  )
}
