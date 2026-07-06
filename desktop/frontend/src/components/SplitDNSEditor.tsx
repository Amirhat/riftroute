import { useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardHeader, Skeleton, fieldCls } from './ui'
import { validateDomain, validateGateway } from '../lib/validate'
import { friendly } from '../lib/format'
import type { SplitDNSRoute } from '../types'

type Row = { id: number; domain: string; resolver: string }
let seq = 0
const rowOf = (r?: SplitDNSRoute): Row => ({ id: ++seq, domain: r?.domain ?? '', resolver: r?.resolver ?? '' })

// SplitDNSEditor manages the persisted per-domain resolver selection visually
// (previously YAML-only): each row sends one domain suffix to a specific
// resolver. Saving validates, persists (survives daemon restarts), and applies
// through the platform backend (scoped resolvers on macOS / resolvectl on Linux).
export function SplitDNSEditor() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['splitdns'], queryFn: api.splitDNS })
  const [rows, setRows] = useState<Row[] | null>(null) // null = not editing (mirror server)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  // Memoized so row ids (React keys) stay stable across re-renders while
  // mirroring the server — fresh ids every render would remount the inputs and
  // drop focus mid-keystroke whenever a background refetch lands.
  const serverRows = useMemo(() => (q.data ?? []).map(rowOf), [q.data])
  const editing = rows !== null
  const shown = rows ?? serverRows

  const domainErr = (v: string) => (v.trim() ? validateDomain(v) : null)
  // a resolver is a bare IP; validateGateway accepts IPs (and "auto"/"" which we exclude)
  const resolverErr = (v: string) => {
    if (!v.trim()) return null
    if (v.trim() === 'auto') return 'must be an IP address'
    return validateGateway(v) ? 'must be an IP address' : null
  }
  const anyInvalid = shown.some(
    (r) => (r.domain.trim() || r.resolver.trim()) && (domainErr(r.domain) || resolverErr(r.resolver) || !r.domain.trim() || !r.resolver.trim()),
  )

  function update(id: number, patch: Partial<Row>) {
    setRows((rs) => (rs ?? serverRows).map((r) => (r.id === id ? { ...r, ...patch } : r)))
  }

  async function save() {
    setError(null)
    setBusy(true)
    try {
      const routes = shown
        .filter((r) => r.domain.trim() && r.resolver.trim())
        .map((r) => ({ domain: r.domain.trim(), resolver: r.resolver.trim() }))
      await api.setSplitDNS(routes)
      setRows(null)
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
      qc.invalidateQueries({ queryKey: ['splitdns'] })
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader title="Split-DNS" hint="send specific domains to a specific resolver" />
      {q.isLoading ? (
        <div className="p-4"><Skeleton className="h-8 w-full" /></div>
      ) : (
        <div className="space-y-3 p-4">
          {shown.length === 0 && <div className="text-sm text-muted">No split-DNS routes — all lookups use the system resolver.</div>}
          {shown.map((r) => {
            const dErr = domainErr(r.domain)
            const rErr = resolverErr(r.resolver)
            return (
              <div key={r.id}>
                <div className="flex items-center gap-2">
                  <input
                    value={r.domain}
                    onChange={(e) => update(r.id, { domain: e.target.value })}
                    placeholder="corp.example.com"
                    className={`ltr flex-1 ${inputCls(dErr)}`}
                  />
                  <span className="text-muted">→</span>
                  <input
                    value={r.resolver}
                    onChange={(e) => update(r.id, { resolver: e.target.value })}
                    placeholder="10.0.0.53"
                    className={`ltr w-40 ${inputCls(rErr)}`}
                  />
                  <button
                    onClick={() => setRows((rs) => (rs ?? serverRows).filter((x) => x.id !== r.id))}
                    aria-label="Remove route"
                    className="rounded-lg border border-line px-2.5 py-2 text-sm text-muted hover:text-danger"
                  >
                    ✕
                  </button>
                </div>
                {(dErr || rErr) && <div className="mt-1 text-xs text-danger">{dErr ?? rErr}</div>}
              </div>
            )
          })}
          <div className="flex items-center justify-between">
            <button onClick={() => setRows([...(rows ?? serverRows), rowOf()])} className="text-sm font-medium text-accent hover:opacity-80">
              + Add DNS route
            </button>
            {(editing || saved) && (
              <div className="flex items-center gap-2">
                {saved && <span className="text-xs text-success">applied ✓</span>}
                {editing && (
                  <>
                    <button onClick={() => setRows(null)} disabled={busy} className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default disabled:opacity-50">
                      Discard
                    </button>
                    <button
                      onClick={save}
                      disabled={busy || anyInvalid}
                      className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
                    >
                      {busy ? 'Applying…' : 'Save & apply'}
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
          {error && <div className="rounded-lg border border-danger/40 bg-danger/5 p-3 text-sm text-danger">{error}</div>}
        </div>
      )}
    </Card>
  )
}

const inputCls = fieldCls
