import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardHeader, Badge, Addr, Skeleton } from '../components/ui'
import type { Flow } from '../types'

// Flows is the live flow monitor (spec §7.4): every active connection correlated
// to the route that carries it — the direct answer to "is THIS app actually going
// through the tunnel right now?". Auto-refreshes while open.
export function Flows() {
  const [filter, setFilter] = useState<'all' | 'vpn' | 'direct'>('all')
  const q = useQuery({
    queryKey: ['flows'],
    queryFn: api.flows,
    refetchInterval: 2000,
  })

  if (q.isLoading) return <Skeleton className="h-64 w-full" />
  if (q.isError) {
    return (
      <Card className="p-6 text-sm text-muted">
        Couldn’t read flows: <span className="text-danger">{(q.error as Error)?.message}</span>
      </Card>
    )
  }

  const flows = q.data ?? []
  const viaVPN = flows.filter((f) => f.via_vpn).length
  const matching = flows.filter((f) => (filter === 'all' ? true : filter === 'vpn' ? f.via_vpn : !f.via_vpn))
  // Cap the synchronous render (AGENTS §6): a busy host can report thousands of
  // sockets, and this table re-renders every 2s on the webview's only thread.
  const RENDER_CAP = 500
  const shown = matching.slice(0, RENDER_CAP)
  const truncated = matching.length - shown.length

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
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
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 capitalize ${filter === f ? 'bg-accent text-accent-contrast' : 'text-muted hover:text-default'}`}
            >
              {f === 'vpn' ? 'via VPN' : f}
            </button>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader title="Live flows" hint="auto-refreshing every 2s" />
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
            {truncated > 0 && (
              <div className="border-t border-line px-4 py-2 text-xs text-muted">
                Showing the first {shown.length} of {matching.length} connections.
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
      <td className="px-4 py-2 text-default">{flow.process || '—'}</td>
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
