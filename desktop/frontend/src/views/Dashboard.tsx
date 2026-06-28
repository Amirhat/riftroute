import { useStateQuery } from '../lib/queries'
import { Card, CardHeader, Label, Badge, Dot, Addr, Skeleton } from '../components/ui'
import { fmtUptime } from '../lib/format'
import type { State } from '../types'

export function Dashboard() {
  const { data, isLoading, isError, error, refetch } = useStateQuery()

  if (isLoading) return <DashboardSkeleton />
  if (isError || !data) return <Disconnected message={(error as Error)?.message} onRetry={() => refetch()} />

  return <DashboardContent state={data} />
}

function DashboardContent({ state }: { state: State }) {
  const v4 = state.defaults.find((d) => d.family === 'v4')
  const degraded = state.health.daemon !== 'ok'

  return (
    <div className="space-y-4">
      {/* headline stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <HeadlineCard
          label="VPN"
          value={state.vpn.active ? 'Active' : 'Inactive'}
          tone={state.vpn.active ? 'vpn' : 'muted'}
          sub={state.vpn.active ? state.vpn.interfaces.join(', ') : 'no tunnel detected'}
        />
        <HeadlineCard
          label="Default route (v4)"
          value={v4?.present ? (v4.via_vpn ? 'via VPN' : 'direct') : 'none'}
          tone={v4?.via_vpn ? 'vpn' : v4?.present ? 'success' : 'danger'}
          sub={v4?.present ? `${v4.gateway || 'on-link'} · ${v4.iface}` : 'no default'}
        />
        <HeadlineCard
          label="Managed routes"
          value={String(state.managed_route_count)}
          tone={state.managed_route_count > 0 ? 'accent' : 'muted'}
          sub="installed by RiftRoute"
        />
        <HeadlineCard
          label="Drift"
          value={state.drift.pending ? 'Pending' : 'None'}
          tone={state.drift.pending ? 'warning' : 'success'}
          sub={state.drift.pending ? `+${state.drift.adds} −${state.drift.dels} ~${state.drift.changes}` : 'desired = actual'}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Daemon */}
        <Card>
          <CardHeader
            title="Daemon"
            hint={
              <div className="flex items-center gap-2">
                <Badge tone={state.auto_apply ? 'accent' : 'muted'}>auto-apply {state.auto_apply ? 'on' : 'off'}</Badge>
                <Badge tone={degraded ? 'danger' : 'success'}>
                  <Dot tone={degraded ? 'danger' : 'success'} />
                  {state.health.daemon}
                </Badge>
              </div>
            }
          />
          <div className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
            <Field label="Provider" value={state.health.provider} />
            <Field label="Version" value={state.health.version} />
            <Field label="PID" value={String(state.health.pid)} />
            <Field label="Uptime" value={fmtUptime(state.health.uptime_seconds)} />
          </div>
          {state.health.reason && <div className="px-4 pb-4 text-sm text-danger">{state.health.reason}</div>}
        </Card>

        {/* DNS */}
        <Card>
          <CardHeader title="DNS" hint={state.dns.iface ? `via ${state.dns.iface}` : undefined} />
          <div className="space-y-2 p-4">
            {state.dns.servers.length === 0 && <div className="text-sm text-muted">No resolvers reported.</div>}
            {state.dns.servers.map((s) => (
              <div key={s} className="flex items-center gap-2">
                <Dot tone="accent" />
                <Addr>{s}</Addr>
              </div>
            ))}
            {state.dns.search_domains && state.dns.search_domains.length > 0 && (
              <div className="pt-1 text-xs text-muted">search: {state.dns.search_domains.join(', ')}</div>
            )}
          </div>
        </Card>

        {/* Default routes */}
        <Card>
          <CardHeader title="Default routes" />
          <div className="divide-y divide-line">
            {state.defaults.map((d) => (
              <div key={d.family} className="flex items-center justify-between px-4 py-3">
                <div className="flex items-center gap-3">
                  <Badge tone="muted">{d.family}</Badge>
                  {d.present ? (
                    <Addr>
                      {d.gateway || 'on-link'} <span className="text-muted">dev</span> {d.iface}
                    </Addr>
                  ) : (
                    <span className="text-sm text-muted">none</span>
                  )}
                </div>
                {d.present && (
                  <Badge tone={d.via_vpn ? 'vpn' : 'success'}>{d.via_vpn ? 'via VPN' : 'direct'}</Badge>
                )}
              </div>
            ))}
          </div>
        </Card>

        {/* Interfaces */}
        <Card>
          <CardHeader title="Interfaces" hint={`${state.interfaces.filter((i) => i.up).length}/${state.interfaces.length} up`} />
          <div className="divide-y divide-line">
            {state.interfaces.map((ifc) => (
              <div key={ifc.name} className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-3">
                  <Dot tone={ifc.up ? 'success' : 'muted'} />
                  <span className="font-mono text-sm text-default">{ifc.name}</span>
                  {ifc.is_vpn && <Badge tone="vpn">vpn</Badge>}
                </div>
                <div className="ltr text-right text-xs text-muted">
                  {ifc.addrs[0] ?? ifc.kind}
                  {ifc.mtu ? ` · mtu ${ifc.mtu}` : ''}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Capabilities */}
      <Card>
        <CardHeader title="Capabilities" hint={`platform: ${state.capabilities.platform}`} />
        <div className="flex flex-wrap gap-2 p-4">
          <CapBadge ok={state.capabilities.policy_routing} label="policy routing" />
          <CapBadge ok={state.capabilities.fwmark} label="fwmark" />
          <CapBadge ok={state.capabilities.per_app_routing} label="per-app routing" />
          <CapBadge ok={state.capabilities.proto_tag} label="proto tag" />
          <CapBadge ok={state.capabilities.ipv6} label="IPv6" />
          <CapBadge ok={state.capabilities.kill_switch} label="kill switch" />
          <CapBadge ok={state.capabilities.iface_scoping} label="iface scoping" />
        </div>
      </Card>
    </div>
  )
}

function HeadlineCard({ label, value, sub, tone }: { label: string; value: string; sub: string; tone: 'vpn' | 'success' | 'danger' | 'warning' | 'accent' | 'muted' }) {
  const toneText: Record<string, string> = {
    vpn: 'text-vpn',
    success: 'text-success',
    danger: 'text-danger',
    warning: 'text-warning',
    accent: 'text-accent',
    muted: 'text-default',
  }
  return (
    <Card className="p-4">
      <Label>{label}</Label>
      <div className={`mt-1 text-2xl font-semibold ${toneText[tone]}`}>{value}</div>
      <div className="mt-1 text-xs text-muted">{sub}</div>
    </Card>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Label>{label}</Label>
      <div className="mt-1 text-sm font-medium text-default">{value}</div>
    </div>
  )
}

function CapBadge({ ok, label }: { ok: boolean; label: string }) {
  return <Badge tone={ok ? 'success' : 'muted'}>{ok ? '✓' : '—'} {label}</Badge>
}

function DashboardSkeleton() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Card key={i} className="p-4">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="mt-3 h-7 w-24" />
            <Skeleton className="mt-2 h-3 w-28" />
          </Card>
        ))}
      </div>
      <Skeleton className="h-48 w-full" />
    </div>
  )
}

function Disconnected({ message, onRetry }: { message?: string; onRetry: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
      <div className="text-lg font-semibold text-default">Can’t reach riftrouted</div>
      <p className="max-w-md text-sm text-muted">
        The RiftRoute daemon isn’t answering. Routing is unaffected — this app is just a viewer.
        Start it with <span className="font-mono text-default">riftrouted</span> or check{' '}
        <span className="font-mono text-default">riftroute daemon status</span>.
      </p>
      {message && <p className="max-w-md break-words font-mono text-xs text-muted">{message}</p>}
      <button onClick={onRetry} className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90">
        Retry
      </button>
    </div>
  )
}
