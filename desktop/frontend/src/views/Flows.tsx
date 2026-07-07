import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardHeader, Badge, Addr, Skeleton } from '../components/ui'
import type { Flow } from '../types'

type PathFilter = 'all' | 'vpn' | 'direct'
type ProtoFilter = '' | 'tcp' | 'udp'

/** filterFlows composes the filter bar: path, proto, interface, and free-text
 * over process/pid/remote/local/state. Pure — unit-tested directly. */
export function filterFlows(flows: Flow[], path: PathFilter, proto: ProtoFilter, iface: string, q: string): Flow[] {
  const needle = q.trim().toLowerCase()
  return flows.filter((f) => {
    if (path !== 'all' && (path === 'vpn') !== f.via_vpn) return false
    if (proto && f.proto !== proto) return false
    if (iface && (f.iface ?? '') !== iface) return false
    if (!needle) return true
    return [f.process ?? '', f.pid ?? '', f.remote, f.local, f.state ?? '', f.iface ?? ''].some((v) =>
      v.toLowerCase().includes(needle),
    )
  })
}

// Flows is the live flow monitor (spec §7.4): every active connection correlated
// to the route that carries it — the direct answer to "is THIS app actually going
// through the tunnel right now?". Auto-refreshes while open.
export function Flows() {
  const [path, setPath] = useState<PathFilter>('all')
  const [proto, setProto] = useState<ProtoFilter>('')
  const [iface, setIface] = useState('')
  const [q, setQ] = useState('')
  const query = useQuery({
    queryKey: ['flows'],
    queryFn: api.flows,
    refetchInterval: 2000,
  })

  const flows = query.data ?? []
  // Interface chips come from the data itself, so only real choices show up.
  const ifaces = useMemo(() => {
    const s = new Set<string>()
    for (const f of flows) if (f.iface) s.add(f.iface)
    return [...s].sort()
  }, [flows])

  if (query.isLoading) return <Skeleton className="h-64 w-full" />
  if (query.isError) {
    return (
      <Card className="p-6 text-sm text-muted">
        Couldn’t read flows: <span className="text-danger">{(query.error as Error)?.message}</span>
      </Card>
    )
  }

  const viaVPN = flows.filter((f) => f.via_vpn).length
  const matching = filterFlows(flows, path, proto, iface, q)
  // Cap the synchronous render (AGENTS §6): a busy host can report thousands of
  // sockets, and this table re-renders every 2s on the webview's only thread.
  const RENDER_CAP = 500
  const shown = matching.slice(0, RENDER_CAP)
  const truncated = matching.length - shown.length

  const chip = (active: boolean) =>
    `rounded-md px-2.5 py-1 text-xs font-medium ${active ? 'bg-accent/15 text-accent' : 'text-muted hover:bg-elevated hover:text-default'}`

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 text-sm text-muted">
          <span>
            <span className="font-semibold text-default">{flows.length}</span> active connection{flows.length === 1 ? '' : 's'}
          </span>
          <Badge tone="vpn">{viaVPN} via VPN</Badge>
          <Badge tone="success">{flows.length - viaVPN} direct</Badge>
        </div>
        <div className="flex overflow-hidden rounded-lg border border-line text-sm">
          {(['all', 'vpn', 'direct'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setPath(f)}
              className={`px-3 py-1.5 capitalize ${path === f ? 'bg-accent text-accent-contrast' : 'text-muted hover:text-default'}`}
            >
              {f === 'vpn' ? 'via VPN' : f}
            </button>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader title="Live flows" hint="auto-refreshing every 2s" />

        {/* filter bar */}
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter — process, pid, address, state…"
            spellCheck={false}
            aria-label="Filter flows"
            className="ltr min-w-48 flex-1 rounded-lg border border-line bg-base px-3 py-1.5 font-mono text-sm text-default outline-none placeholder:text-muted focus:border-accent"
          />
          <div className="flex items-center gap-1" role="group" aria-label="Protocol filter">
            {(
              [
                ['', 'any proto'],
                ['tcp', 'tcp'],
                ['udp', 'udp'],
              ] as Array<[ProtoFilter, string]>
            ).map(([p, label]) => (
              <button key={p || 'any'} onClick={() => setProto(p)} className={chip(proto === p)}>
                {label}
              </button>
            ))}
          </div>
          {ifaces.length > 0 && (
            <div className="flex items-center gap-1" role="group" aria-label="Interface filter">
              <button onClick={() => setIface('')} className={chip(iface === '')}>
                any iface
              </button>
              {ifaces.map((i) => (
                <button key={i} onClick={() => setIface(iface === i ? '' : i)} className={chip(iface === i)}>
                  {i}
                </button>
              ))}
            </div>
          )}
        </div>

        {shown.length === 0 ? (
          <div className="p-6 text-sm text-muted">No matching connections right now.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-start text-xs uppercase tracking-wider text-muted">
                  <th className="px-4 py-2 font-medium">Process</th>
                  <th className="px-4 py-2 font-medium">Proto</th>
                  <th className="px-4 py-2 font-medium">Remote</th>
                  <th className="px-4 py-2 font-medium">State</th>
                  <th className="px-4 py-2 font-medium">Interface</th>
                  <th className="px-4 py-2 font-medium">Path</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/60">
                {shown.map((f, i) => (
                  <FlowRow key={`${f.proto}-${f.local}-${f.remote}-${i}`} flow={f} />
                ))}
              </tbody>
            </table>
            {(truncated > 0 || matching.length !== flows.length) && (
              <div className="border-t border-line px-4 py-2 text-xs text-muted">
                {truncated > 0
                  ? `Showing the first ${shown.length} of ${matching.length} matching connections.`
                  : `${matching.length} of ${flows.length} connections match the filter.`}
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}

function FlowRow({ flow }: { flow: Flow }) {
  return (
    <tr>
      <td className="px-4 py-2 text-default">
        {flow.process || '—'}
        {flow.pid && <span className="ms-1 text-xs text-muted">({flow.pid})</span>}
      </td>
      <td className="px-4 py-2 uppercase text-muted">{flow.proto}</td>
      <td className="px-4 py-2">
        <Addr>{flow.remote}</Addr>
      </td>
      <td className="px-4 py-2 text-muted">{flow.state || '—'}</td>
      <td className="px-4 py-2 font-mono text-muted">{flow.iface || '—'}</td>
      <td className="px-4 py-2">
        <Badge tone={flow.via_vpn ? 'vpn' : 'success'}>{flow.via_vpn ? 'via VPN' : 'direct'}</Badge>
      </td>
    </tr>
  )
}
