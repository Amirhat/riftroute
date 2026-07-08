import { useCallback, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { FormEvent } from 'react'
import { api } from '../lib/api'
import { stateKey, useRoutesQuery, useStateQuery } from '../lib/queries'
import { Card, CardHeader, OwnerBadge, Badge, Addr, Skeleton, Label, fieldCls } from '../components/ui'
import { CommitConfirm } from '../components/CommitConfirm'
import { ConfirmModal } from '../components/ConfirmModal'
import { Modal } from '../components/Modal'
import { Combobox } from '../components/Combobox'
import { friendly } from '../lib/format'
import { validateGateway, validateRouteTarget } from '../lib/validate'
import type { ApplyResult, ConfigImportResult, Family, Owner, Profile, Route, RouteDecision, RouteExplain } from '../types'

type FamilyFilter = '' | Family
type OwnerFilter = '' | Owner

const CONFIRM_SECONDS = 15

// Manual routes live in ordinary profiles with well-known ids, so single-route
// add/delete rides the full Apply Protocol (validation → guardrails → WAL →
// commit-confirm) instead of bypassing safety, survives restarts, shows up in
// drift, and exports to YAML like everything else.
export const MANUAL_PROFILES = {
  vpn: { id: 'manual-vpn', name: 'Manual routes (via VPN)', mode: 'include' },
  bypass: { id: 'manual-bypass', name: 'Manual routes (bypass VPN)', mode: 'exclude' },
} as const
export type ManualKind = keyof typeof MANUAL_PROFILES

/** isDefaultRoute: main-table 0/0 — deletion is guarded server-side too. */
function isDefaultRoute(r: Route): boolean {
  return !r.table && (r.dst_cidr === '0.0.0.0/0' || r.dst_cidr === '::/0')
}

/** filterRoutes narrows the table by owner and free-text substring (destination,
 * gateway, interface, owner, profile, table). Pure — unit-tested directly. */
export function filterRoutes(routes: Route[], q: string, owner: OwnerFilter): Route[] {
  const needle = q.trim().toLowerCase()
  return routes.filter((r) => {
    if (owner && r.owner !== owner) return false
    if (!needle) return true
    return [r.dst_cidr, r.gateway ?? '', r.iface, r.owner, r.profile ?? '', r.table ?? ''].some((f) =>
      f.toLowerCase().includes(needle),
    )
  })
}

export function RoutesView() {
  const qc = useQueryClient()
  const [pending, setPending] = useState<ApplyResult | null>(null)
  const [matched, setMatched] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<Route | null>(null)
  const [editing, setEditing] = useState<Route | null>(null)
  const [opError, setOpError] = useState<string | null>(null)

  const refresh = useCallback(() => {
    qc.invalidateQueries({ queryKey: ['routes'] })
    qc.invalidateQueries({ queryKey: ['rules'] })
    qc.invalidateQueries({ queryKey: ['profiles'] })
    qc.invalidateQueries({ queryKey: stateKey })
  }, [qc])

  // Shared result handling for external-route ops: guardrail refusals render
  // inline; an interactive tx hands off to commit-confirm.
  const handleOpResult = useCallback(
    (res: ConfigImportResult) => {
      const r = res.result
      if (r?.violations && r.violations.length > 0) {
        setOpError('Refused: ' + r.violations.map((v) => v.detail || v.rule).join('; '))
        return
      }
      if (r?.error) {
        setOpError(r.error)
        return
      }
      setOpError(null)
      refresh()
      if (r?.needs_confirm && r.tx_id) setPending(r)
    },
    [refresh],
  )

  async function doDelete() {
    const r = deleting
    setDeleting(null)
    if (!r) return
    try {
      handleOpResult(await api.routeOp('delete', r))
    } catch (e) {
      setOpError(friendly(e, 'delete failed'))
    }
  }

  const onKeep = useCallback(async () => {
    if (!pending?.tx_id) return setPending(null)
    try {
      await api.confirm(pending.tx_id)
    } finally {
      setPending(null)
      refresh()
    }
  }, [pending, refresh])

  const onRevert = useCallback(async () => {
    if (!pending?.tx_id) return setPending(null)
    try {
      await api.rollback(pending.tx_id)
    } finally {
      setPending(null)
      refresh()
    }
  }, [pending, refresh])

  return (
    <div className="space-y-4">
      <RouteLookup onResult={(r) => setMatched(r.kernel?.matched_cidr ?? null)} />
      <ManualRoutes onPending={setPending} onApplied={refresh} />
      {opError && (
        <Card className="flex items-center justify-between border-danger/40 p-3 text-sm text-danger">
          <span>{opError}</span>
          <button onClick={() => setOpError(null)} aria-label="Dismiss" className="text-muted hover:text-default">
            ✕
          </button>
        </Card>
      )}
      <RouteTable matched={matched} onEdit={setEditing} onDelete={setDeleting} />
      <PolicyRules />

      <ConfirmModal
        open={deleting !== null}
        danger
        title={`Delete route ${deleting?.dst_cidr ?? ''}`}
        message="This route was added outside RiftRoute (system, DHCP, a VPN client…). Removing it is guarded: you'll get a Keep/Revert countdown, and the change auto-reverts if connectivity breaks."
        confirmLabel="Delete route"
        onConfirm={doDelete}
        onCancel={() => setDeleting(null)}
      />

      {editing && (
        <EditRouteDialog
          route={editing}
          onClose={() => setEditing(null)}
          onResult={(res) => {
            setEditing(null)
            handleOpResult(res)
          }}
          onError={(m) => {
            setEditing(null)
            setOpError(m)
          }}
        />
      )}

      {pending && <CommitConfirm result={pending} seconds={CONFIRM_SECONDS} onKeep={onKeep} onRevert={onRevert} />}
    </div>
  )
}

// EditRouteDialog swaps one external route atomically (delete + add in a
// single guarded transaction). Destination, gateway, and interface are all
// editable; the daemon re-validates and commit-confirm protects the change.
function EditRouteDialog({
  route,
  onClose,
  onResult,
  onError,
}: {
  route: Route
  onClose: () => void
  onResult: (res: ConfigImportResult) => void
  onError: (msg: string) => void
}) {
  const [dst, setDst] = useState(route.dst_cidr)
  const [gateway, setGateway] = useState(route.gateway ?? '')
  const [iface, setIface] = useState(route.iface)
  const [busy, setBusy] = useState(false)
  const ifacesQ = useQuery({ queryKey: ['interfaces'], queryFn: () => api.interfaces() })

  const dstErr = validateRouteTarget(dst)
  // Gateway may be blank (on-link) — otherwise it must be a plain IP.
  const gwErr = gateway.trim() === '' ? null : validateGateway(gateway) ? 'must be an IP address or empty (on-link)' : null
  const ifaceErr = iface.trim() === '' ? 'required' : null
  const invalid = !!(dstErr || gwErr || ifaceErr)

  async function save() {
    if (invalid) return
    setBusy(true)
    try {
      const updated: Route = {
        ...route,
        dst_cidr: dst.includes('/') ? dst.trim() : `${dst.trim()}/${dst.includes(':') ? 128 : 32}`,
        gateway: gateway.trim(),
        iface: iface.trim(),
      }
      onResult(await api.routeOp('replace', route, updated))
    } catch (e) {
      onError(friendly(e, 'edit failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal onBackdrop={busy ? undefined : onClose} className="max-w-lg">
      <div className="flex items-center justify-between border-b border-line px-5 py-3">
        <h2 className="text-base font-semibold text-default">Edit route</h2>
        <button onClick={onClose} disabled={busy} className="text-muted hover:text-default disabled:opacity-50" aria-label="Close">
          ✕
        </button>
      </div>
      <div className="space-y-4 p-5">
        <div>
          <Label>Destination</Label>
          <input
            value={dst}
            onChange={(e) => setDst(e.target.value)}
            spellCheck={false}
            aria-label="Route destination"
            className={`ltr mt-1 font-mono ${fieldCls(dstErr)}`}
          />
          {dstErr && <div className="mt-1 text-xs text-danger">{dstErr}</div>}
        </div>
        <div>
          <Label>Gateway</Label>
          <input
            value={gateway}
            onChange={(e) => setGateway(e.target.value)}
            placeholder="empty = on-link (via the interface)"
            spellCheck={false}
            aria-label="Route gateway"
            className={`ltr mt-1 font-mono ${fieldCls(gwErr)}`}
          />
          {gwErr && <div className="mt-1 text-xs text-danger">{gwErr}</div>}
        </div>
        <div>
          <Label>Interface</Label>
          <div className="mt-1">
            <Combobox
              value={iface}
              onChange={setIface}
              options={(ifacesQ.data ?? []).map((i) => ({
                value: i.name,
                label: i.name,
                sub: `${i.kind}${i.is_vpn ? ' · vpn' : ''}${i.up ? '' : ' · down'}`,
              }))}
              loading={ifacesQ.isLoading}
              ariaLabel="Route interface"
              invalid={!!ifaceErr}
            />
          </div>
          {ifaceErr && <div className="mt-1 text-xs text-danger">{ifaceErr}</div>}
        </div>
        <p className="text-xs text-muted">
          Applied as one atomic swap through the safety protocol — Keep/Revert countdown included.
        </p>
      </div>
      <div className="flex justify-end gap-2 border-t border-line px-5 py-3">
        <button onClick={onClose} disabled={busy} className="rounded-lg border border-line px-4 py-2 text-sm text-muted hover:text-default disabled:opacity-50">
          Cancel
        </button>
        <button
          onClick={() => void save()}
          disabled={busy || invalid}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
        >
          {busy ? 'Applying…' : 'Apply change'}
        </button>
      </div>
    </Modal>
  )
}

// --- "Where does traffic go?" — IP/domain lookup over the explain engine ---

function RouteLookup({ onResult }: { onResult: (r: RouteExplain) => void }) {
  const [target, setTarget] = useState('')
  const m = useMutation({
    mutationFn: (t: string) => api.explain(t),
    onSuccess: onResult,
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const t = target.trim()
    if (t) m.mutate(t)
  }

  return (
    <Card>
      <CardHeader title="Where does traffic go?" hint="look up an IP or domain to see the route it takes" />
      <form onSubmit={submit} className="flex gap-2 p-4 pb-3">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="IP or domain — e.g. 8.8.8.8, netflix.com"
          spellCheck={false}
          aria-label="Lookup target"
          className="ltr flex-1 rounded-lg border border-line bg-base px-3 py-2 font-mono text-sm text-default outline-none placeholder:text-muted focus:border-accent"
        />
        <button
          type="submit"
          disabled={m.isPending || !target.trim()}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
        >
          {m.isPending ? 'Resolving…' : 'Look up'}
        </button>
      </form>

      {m.isError && <div className="px-4 pb-4 text-sm text-danger">{friendly(m.error, 'lookup failed')}</div>}

      {m.data && (
        <div className="space-y-2 px-4 pb-4">
          {m.data.note && <div className="text-xs text-muted">{m.data.note}</div>}
          {(m.data.resolved ?? []).length > 0 && (
            <div className="ltr flex flex-wrap items-center gap-1.5 text-xs text-muted">
              resolves to
              {(m.data.resolved ?? []).map((ip) => (
                <Badge key={ip} tone="muted">
                  {ip}
                </Badge>
              ))}
            </div>
          )}
          <DecisionRow label="Now (kernel)" d={m.data.kernel} />
          {m.data.simulated && <DecisionRow label="After apply (desired)" d={m.data.simulated} drift={m.data.drift} />}
        </div>
      )}
    </Card>
  )
}

function DecisionRow({ label, d, drift }: { label: string; d: RouteDecision; drift?: boolean }) {
  const answered = d.iface || d.reachable
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-elevated/50 px-3 py-2 text-sm">
      <span className="w-36 shrink-0 text-xs font-medium uppercase tracking-wide text-muted">{label}</span>
      {!answered ? (
        <span className="text-muted">no route — unreachable</span>
      ) : (
        <>
          <Badge tone={d.via_vpn ? 'vpn' : 'success'}>{d.via_vpn ? 'via VPN' : 'direct'}</Badge>
          <span className="ltr font-mono text-default">
            {d.matched_cidr || '—'} → {d.gateway || 'on-link'} <span className="text-muted">dev</span> {d.iface}
          </span>
          {d.profile && <Badge tone="accent">profile: {d.profile}</Badge>}
        </>
      )}
      {drift && <Badge tone="warning">differs from current — drift</Badge>}
    </div>
  )
}

// --- Manual routes: add/delete single destinations, profile-backed ---

function ManualRoutes({ onPending, onApplied }: { onPending: (r: ApplyResult) => void; onApplied: () => void }) {
  const stateQ = useStateQuery()
  const profilesQ = useQuery({ queryKey: ['profiles'], queryFn: api.profiles })
  const [dst, setDst] = useState('')
  const [kind, setKind] = useState<ManualKind>('bypass')
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const vpnActive = !!stateQ.data?.vpn.active
  const profiles = profilesQ.data ?? []
  const byId = (id: string) => profiles.find((p) => p.id === id || p.name === MANUAL_PROFILES[id === 'manual-vpn' ? 'vpn' : 'bypass'].name)
  const manual: Array<{ kind: ManualKind; profile: Profile; value: string }> = []
  for (const k of ['vpn', 'bypass'] as ManualKind[]) {
    const p = byId(MANUAL_PROFILES[k].id)
    for (const r of p?.rules ?? []) manual.push({ kind: k, profile: p!, value: r.value })
  }

  const dstErr = dst.trim() ? validateRouteTarget(dst) : touched ? 'required' : null
  const dup = manual.find((m) => m.value === dst.trim())

  async function saveManual(p: Profile) {
    const res = await api.saveProfile(p, false)
    if ((res.issues ?? []).some((i) => i.severity === 'error')) {
      throw new Error(res.issues!.map((i) => i.msg).join('; '))
    }
    const r = res.result
    if (r?.violations && r.violations.length > 0) {
      throw new Error('Refused by guardrails: ' + r.violations.map((v) => v.rule).join(', '))
    }
    onApplied()
    if (r?.needs_confirm && r.tx_id) onPending(r)
  }

  async function add(e: FormEvent) {
    e.preventDefault()
    setTouched(true)
    setError(null)
    const v = dst.trim()
    if (!v || validateRouteTarget(v)) return
    if (dup) {
      setError(`${v} is already a manual route (${dup.kind === 'vpn' ? 'via VPN' : 'bypass'}) — remove it first.`)
      return
    }
    const spec = MANUAL_PROFILES[kind]
    const existing = byId(spec.id)
    const rule = { type: v.includes('/') ? 'cidr' : 'ip', value: v }
    const profile: Profile = existing
      ? { ...existing, rules: [...(existing.rules ?? []), rule] }
      : {
          id: spec.id,
          name: spec.name,
          description: 'Routes added from the Routing Table page.',
          enabled: true,
          mode: spec.mode,
          gateway: 'auto',
          priority: 0,
          rules: [rule],
        }
    setBusy(true)
    try {
      await saveManual(profile)
      setDst('')
      setTouched(false)
    } catch (err) {
      setError(friendly(err, 'failed to add route'))
    } finally {
      setBusy(false)
    }
  }

  async function remove(entry: { profile: Profile; value: string }) {
    setError(null)
    setBusy(true)
    try {
      const rest = (entry.profile.rules ?? []).filter((r) => r.value !== entry.value)
      if (rest.length === 0 && (entry.profile.lists ?? []).length === 0) {
        const res = await api.deleteProfile(entry.profile.name)
        onApplied()
        if (res.result?.needs_confirm && res.result.tx_id) onPending(res.result)
      } else {
        await saveManual({ ...entry.profile, rules: rest })
      }
    } catch (err) {
      setError(friendly(err, 'failed to remove route'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title="Manual routes"
        hint="steer a single destination through or around the VPN — applied safely, revertible"
      />
      <form onSubmit={add} className="flex flex-wrap items-start gap-2 p-4 pb-3">
        <div className="min-w-52 flex-1">
          <input
            value={dst}
            onChange={(e) => setDst(e.target.value)}
            placeholder="Destination IP or CIDR — e.g. 203.0.113.7 or 10.10.0.0/16"
            spellCheck={false}
            aria-label="Manual route destination"
            className={[
              'ltr w-full rounded-lg border bg-base px-3 py-2 font-mono text-sm text-default outline-none placeholder:text-muted focus:border-accent',
              dstErr ? 'border-danger/60' : 'border-line',
            ].join(' ')}
          />
          {dstErr && <div className="mt-1 text-xs text-danger">{dstErr}</div>}
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-line p-1" role="radiogroup" aria-label="Route path">
          {(
            [
              ['bypass', 'Bypass VPN', true],
              ['vpn', 'Via VPN', vpnActive],
            ] as Array<[ManualKind, string, boolean]>
          ).map(([k, label, enabled]) => (
            <button
              key={k}
              type="button"
              role="radio"
              aria-checked={kind === k}
              disabled={!enabled}
              title={enabled ? undefined : 'Needs an active VPN tunnel'}
              onClick={() => setKind(k)}
              className={[
                'rounded-md px-2.5 py-1.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-40',
                kind === k ? 'bg-accent/15 text-accent' : 'text-muted hover:text-default',
              ].join(' ')}
            >
              {label}
            </button>
          ))}
        </div>
        <button
          type="submit"
          disabled={busy}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
        >
          {busy ? 'Applying…' : 'Add route'}
        </button>
      </form>

      {error && <div className="px-4 pb-3 text-sm text-danger">{error}</div>}

      {manual.length > 0 && (
        <div className="divide-y divide-line border-t border-line">
          {manual.map((m) => (
            <div key={`${m.kind}:${m.value}`} className="flex items-center justify-between px-4 py-2">
              <div className="ltr flex items-center gap-2 text-sm">
                <Addr>{m.value}</Addr>
                <Badge tone={m.kind === 'vpn' ? 'vpn' : 'success'}>{m.kind === 'vpn' ? 'via VPN' : 'bypass'}</Badge>
              </div>
              <button
                onClick={() => remove(m)}
                disabled={busy}
                className="rounded-md px-2 py-1 text-xs text-danger hover:bg-danger/10 disabled:opacity-50"
                aria-label={`Remove manual route ${m.value}`}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}
      {manual.length === 0 && !profilesQ.isLoading && (
        <div className="border-t border-line px-4 py-3 text-xs text-muted">
          No manual routes yet. Other routes are managed by profiles — edit those on the Profiles page.
        </div>
      )}
    </Card>
  )
}

// --- The routing table itself ---

const COLS = 'grid grid-cols-[minmax(0,1.5fr)_minmax(0,1.2fr)_90px_60px_minmax(0,1fr)_72px] gap-3'

function RouteTable({
  matched,
  onEdit,
  onDelete,
}: {
  matched: string | null
  onEdit: (r: Route) => void
  onDelete: (r: Route) => void
}) {
  const [family, setFamily] = useState<FamilyFilter>('')
  const [owner, setOwner] = useState<OwnerFilter>('')
  const [q, setQ] = useState('')
  const { data, isLoading, isError, error } = useRoutesQuery(family)
  const parentRef = useRef<HTMLDivElement>(null)

  const all = data ?? []
  const routes = filterRoutes(all, q, owner)
  const virtualizer = useVirtualizer({
    count: routes.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 12,
  })

  const chip = (active: boolean) =>
    [
      'rounded-md px-2 py-1 text-xs font-medium',
      active ? 'bg-accent/15 text-accent' : 'text-muted hover:bg-elevated hover:text-default',
    ].join(' ')

  return (
    <Card className="flex flex-col overflow-hidden">
      <CardHeader
        title="Routing table"
        hint={
          <div className="flex items-center gap-1">
            {(['', 'v4', 'v6'] as FamilyFilter[]).map((f) => (
              <button key={f || 'all'} onClick={() => setFamily(f)} className={chip(family === f)}>
                {f === '' ? 'all' : f}
              </button>
            ))}
            <span className="mx-1 h-4 w-px bg-line" />
            {(
              [
                ['', 'any owner'],
                ['system', 'system'],
                ['riftroute', 'riftroute'],
                ['vpn', 'vpn'],
              ] as Array<[OwnerFilter, string]>
            ).map(([o, label]) => (
              <button key={o || 'any'} onClick={() => setOwner(o)} className={chip(owner === o)}>
                {label}
              </button>
            ))}
          </div>
        }
      />

      <div className="border-b border-line px-4 py-2">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter routes — destination, gateway, interface, profile…"
          spellCheck={false}
          aria-label="Filter routes"
          className="ltr w-full rounded-lg border border-line bg-base px-3 py-1.5 font-mono text-sm text-default outline-none placeholder:text-muted focus:border-accent"
        />
      </div>

      {/* column header */}
      <div className={`${COLS} border-b border-line px-4 py-2 text-[11px] font-medium uppercase tracking-wider text-muted`}>
        <div>Destination</div>
        <div>Gateway</div>
        <div>Interface</div>
        <div className="text-right">Metric</div>
        <div>Owner</div>
        <div className="text-right">Actions</div>
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
        <div className="p-8 text-center text-sm text-muted">
          {all.length === 0 ? 'No routes for this family.' : 'No routes match the current filter.'}
        </div>
      )}

      {!isLoading && !isError && routes.length > 0 && (
        <div ref={parentRef} className="ltr max-h-[26rem] flex-1 overflow-auto">
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {virtualizer.getVirtualItems().map((vi) => {
              const r = routes[vi.index]
              const hit = matched !== null && r.dst_cidr === matched
              return (
                <div
                  key={vi.key}
                  className={[
                    `${COLS} items-center border-b border-line/60 px-4 text-sm`,
                    hit ? 'bg-accent/10' : '',
                  ].join(' ')}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: vi.size,
                    transform: `translateY(${vi.start}px)`,
                  }}
                >
                  <div className="flex min-w-0 items-center gap-1.5">
                    <span className="truncate font-mono text-default">{r.dst_cidr}</span>
                    {r.table && <Badge tone="muted">table {r.table}</Badge>}
                  </div>
                  <div className="truncate font-mono text-muted">{r.gateway || '—'}</div>
                  <div className="truncate font-mono text-muted">{r.iface}</div>
                  <div className="text-right font-mono text-muted">{r.metric || '—'}</div>
                  <div className="flex min-w-0 items-center gap-1.5">
                    <OwnerBadge owner={r.owner} />
                    {r.profile && (
                      <span className="truncate text-xs text-muted" title={`managed by profile ${r.profile}`}>
                        {r.profile}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center justify-end gap-1">
                    {r.owner === 'riftroute' ? (
                      <span className="text-[11px] text-muted" title={`Managed by profile ${r.profile || '—'} — edit it on the Profiles page (or under Manual routes above).`}>
                        via profile
                      </span>
                    ) : (
                      <>
                        <button
                          onClick={() => onEdit(r)}
                          aria-label={`Edit route ${r.dst_cidr}`}
                          title="Edit this route (guarded swap)"
                          className="rounded-md px-1.5 py-1 text-xs text-muted hover:bg-elevated hover:text-default"
                        >
                          ✎
                        </button>
                        <button
                          onClick={() => onDelete(r)}
                          disabled={isDefaultRoute(r)}
                          aria-label={`Delete route ${r.dst_cidr}`}
                          title={isDefaultRoute(r) ? 'The default route is protected — edit it instead' : 'Delete this route (guarded)'}
                          className="rounded-md px-1.5 py-1 text-xs text-danger hover:bg-danger/10 disabled:cursor-not-allowed disabled:opacity-30"
                        >
                          ✕
                        </button>
                      </>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="border-t border-line px-4 py-2 text-xs text-muted">
        showing {routes.length} of {all.length} route{all.length === 1 ? '' : 's'} · sorted by lookup precedence (most
        specific first)
      </div>
    </Card>
  )
}

// --- Policy rules (Linux ip rules / macOS PF route-to) ---

function PolicyRules() {
  const rulesQ = useQuery({ queryKey: ['rules'], queryFn: api.rules })
  const rules = rulesQ.data ?? []
  if (rules.length === 0) return null

  return (
    <Card>
      <CardHeader
        title="Policy rules"
        hint="how include-mode and per-app traffic is steered (evaluated before the table above)"
      />
      <div className="divide-y divide-line">
        {rules.map((r, i) => (
          <div key={i} className="ltr flex flex-wrap items-center gap-2 px-4 py-2 text-sm">
            <Badge tone="muted">prio {r.priority}</Badge>
            <span className="font-mono text-default">{r.selector}</span>
            <span className="text-muted">→</span>
            <span className="font-mono text-muted">
              {r.route_to_iface ? `route-to ${r.route_to_iface}${r.route_to_gw ? ` ${r.route_to_gw}` : ''}` : `table ${r.table}`}
            </span>
            <Badge tone="muted">{r.family}</Badge>
            {r.proto === 'riftroute' && <OwnerBadge owner="riftroute" />}
          </div>
        ))}
      </div>
    </Card>
  )
}
