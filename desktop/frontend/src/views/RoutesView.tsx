import { useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRoutesQuery } from '../lib/queries'
import { Card, CardHeader, OwnerBadge, Skeleton } from '../components/ui'
import type { Family } from '../types'

type FamilyFilter = '' | Family

// CSS Grid template for the tabular layout (AGENTS §6 — Grid, not placeholder
// flexboxes). Columns: destination | gateway | iface | metric | owner.
const COLS = 'grid grid-cols-[minmax(0,1.4fr)_minmax(0,1.2fr)_90px_70px_110px] gap-3'

export function RoutesView() {
  const [family, setFamily] = useState<FamilyFilter>('')
  const { data, isLoading, isError, error } = useRoutesQuery(family)
  const parentRef = useRef<HTMLDivElement>(null)

  const routes = data ?? []
  const virtualizer = useVirtualizer({
    count: routes.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 12,
  })

  return (
    <Card className="flex h-full flex-col overflow-hidden">
      <CardHeader
        title="Routing table"
        hint={
          <div className="flex items-center gap-1">
            {(['', 'v4', 'v6'] as FamilyFilter[]).map((f) => (
              <button
                key={f || 'all'}
                onClick={() => setFamily(f)}
                className={[
                  'rounded-md px-2 py-1 text-xs font-medium',
                  family === f ? 'bg-accent/15 text-accent' : 'text-muted hover:bg-elevated hover:text-default',
                ].join(' ')}
              >
                {f === '' ? 'all' : f}
              </button>
            ))}
          </div>
        }
      />

      {/* column header */}
      <div className={`${COLS} border-b border-line px-4 py-2 text-[11px] font-medium uppercase tracking-wider text-muted`}>
        <div>Destination</div>
        <div>Gateway</div>
        <div>Interface</div>
        <div className="text-right">Metric</div>
        <div>Owner</div>
      </div>

      {isLoading && (
        <div className="space-y-2 p-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </div>
      )}

      {isError && <div className="p-4 text-sm text-danger">Failed to load routes: {(error as Error)?.message}</div>}

      {!isLoading && !isError && routes.length === 0 && (
        <div className="p-8 text-center text-sm text-muted">No routes for this family.</div>
      )}

      {!isLoading && !isError && routes.length > 0 && (
        <div ref={parentRef} className="ltr flex-1 overflow-auto">
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {virtualizer.getVirtualItems().map((vi) => {
              const r = routes[vi.index]
              return (
                <div
                  key={vi.key}
                  className={`${COLS} items-center border-b border-line/60 px-4 text-sm`}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: vi.size,
                    transform: `translateY(${vi.start}px)`,
                  }}
                >
                  <div className="truncate font-mono text-default">{r.dst_cidr}</div>
                  <div className="truncate font-mono text-muted">{r.gateway || '—'}</div>
                  <div className="truncate font-mono text-muted">{r.iface}</div>
                  <div className="text-right font-mono text-muted">{r.metric}</div>
                  <div>
                    <OwnerBadge owner={r.owner} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="border-t border-line px-4 py-2 text-xs text-muted">
        showing {routes.length} route{routes.length === 1 ? '' : 's'} (virtualized)
      </div>
    </Card>
  )
}
