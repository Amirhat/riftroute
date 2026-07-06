import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Modal } from './Modal'
import { Label, Toggle, fieldCls } from './ui'
import { friendly } from '../lib/format'
import { api } from '../lib/api'
import {
  validateRouteTarget,
  validateDomain,
  validateAppValue,
  validateProfileName,
  validateGateway,
  type AppStrategy,
} from '../lib/validate'
import type { ApplyResult, ConfigImportResult, Plan, Profile, Rule } from '../types'

// ProfileBuilder is the visual, interactive split-tunneling designer: metadata,
// a routing-mode selector, and dynamic managers for CIDR/IP, domain, and per-app
// rules. It validates every field inline (never freezing the window), shows a live
// staged-changes banner, can dry-run a real plan preview, and applies atomically
// over IPC with commit-confirm. On apply it serializes to the backend Profile
// model; the daemon re-validates, journals (WAL), and commits.

let __rowSeq = 0
const nextRowId = () => ++__rowSeq

type Row = { id: number; value: string; strategy?: AppStrategy }

function newRow(strategy?: AppStrategy): Row {
  return { id: nextRowId(), value: '', strategy }
}

// decompose splits an existing profile's flat rule list into the three visual
// managers (route targets / domains / per-app). Rule types the builder has no
// editor for (asn/country — they need a GeoIP DB) are carried through untouched:
// editing a profile must never silently delete rules it doesn't display.
function decompose(p: Profile | undefined, defStrategy: AppStrategy) {
  const routes: Row[] = []
  const domains: Row[] = []
  const apps: Row[] = []
  const others: Rule[] = []
  for (const r of p?.rules ?? []) {
    if (r.type === 'cidr' || r.type === 'ip') routes.push({ id: nextRowId(), value: r.value })
    else if (r.type === 'domain') domains.push({ id: nextRowId(), value: r.value })
    else if (r.type === 'app') apps.push({ id: nextRowId(), value: r.value, strategy: defStrategy })
    else others.push(r)
  }
  return { routes, domains, apps, others }
}

export function ProfileBuilder({
  initial,
  existingNames,
  platform,
  onPending,
  onApplied,
  onClose,
}: {
  initial?: Profile
  existingNames: string[]
  platform?: string
  onPending: (r: ApplyResult) => void
  onApplied: () => void
  onClose: () => void
}) {
  const defStrategy: AppStrategy = platform === 'linux' ? 'app' : 'uid'
  const decomposed = useMemo(() => decompose(initial, defStrategy), [initial, defStrategy])

  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [enabled, setEnabled] = useState(initial?.enabled ?? true)
  const [mode, setMode] = useState<'include' | 'exclude'>((initial?.mode as 'include' | 'exclude') || 'exclude')
  const [gateway, setGateway] = useState(initial?.gateway ?? 'auto')
  const [priority, setPriority] = useState<number>(initial?.priority ?? 0)
  const [routes, setRoutes] = useState<Row[]>(decomposed.routes)
  const [domains, setDomains] = useState<Row[]>(decomposed.domains)
  const [apps, setApps] = useState<Row[]>(decomposed.apps)
  const [listRefs, setListRefs] = useState<string[]>(initial?.lists ?? [])

  // Known reusable lists, offered as toggleable references.
  const listsQ = useQuery({ queryKey: ['lists'], queryFn: api.lists })
  const knownLists = listsQ.data ?? []

  const [submitted, setSubmitted] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [issues, setIssues] = useState<ConfigImportResult['issues']>(undefined)
  const [previewPlan, setPreviewPlan] = useState<Plan | null>(null)

  // Names other profiles already use (exclude the one being edited).
  const takenNames = useMemo(
    () => existingNames.filter((n) => n !== initial?.name),
    [existingNames, initial?.name],
  )

  const nameErr = validateProfileName(name, takenNames)
  const gatewayErr = validateGateway(gateway)

  const routeErr = (r: Row) => validateRouteTarget(r.value)
  const domainErr = (r: Row) => validateDomain(r.value)
  const appErr = (r: Row) => validateAppValue(r.value, r.strategy ?? defStrategy)

  // A non-empty row that fails validation blocks apply; empty rows are ignored.
  const anyRowInvalid =
    routes.some((r) => r.value.trim() && routeErr(r)) ||
    domains.some((r) => r.value.trim() && domainErr(r)) ||
    apps.some((r) => r.value.trim() && appErr(r))

  const hasErrors = nameErr !== null || gatewayErr !== null || anyRowInvalid

  // Live staged-changes counts (valid, non-empty rows only).
  const staged = {
    routes: routes.filter((r) => r.value.trim() && !routeErr(r)).length,
    domains: domains.filter((r) => r.value.trim() && !domainErr(r)).length,
    apps: apps.filter((r) => r.value.trim() && !appErr(r)).length,
  }

  function serialize(): Profile {
    const rules: Rule[] = []
    for (const r of routes) {
      const v = r.value.trim()
      if (v) rules.push({ type: v.includes('/') ? 'cidr' : 'ip', value: v })
    }
    for (const r of domains) {
      const v = r.value.trim()
      if (v) rules.push({ type: 'domain', value: v })
    }
    for (const r of apps) {
      const v = r.value.trim()
      if (v) rules.push({ type: 'app', value: v })
    }
    rules.push(...decomposed.others) // rule types the builder doesn't edit are preserved
    return {
      id: initial?.id ?? '',
      name: name.trim(),
      description: description.trim() || undefined,
      enabled,
      mode,
      gateway: gateway.trim() || 'auto',
      priority: Number.isFinite(priority) ? priority : 0,
      rules,
      lists: listRefs.length > 0 ? listRefs : undefined,
    }
  }

  async function preview() {
    setSubmitted(true)
    setError(null)
    setIssues(undefined)
    if (hasErrors) return
    setBusy(true)
    try {
      const res = await api.saveProfile(serialize(), true)
      if ((res.issues ?? []).length > 0) setIssues(res.issues)
      setPreviewPlan(res.plan ?? { ops: [], inverse: [] })
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  async function apply() {
    setSubmitted(true)
    setError(null)
    setIssues(undefined)
    if (hasErrors) return
    setBusy(true)
    try {
      const res = await api.saveProfile(serialize(), false)
      if ((res.issues ?? []).some((i) => i.severity === 'error')) {
        setIssues(res.issues)
        return
      }
      const r = res.result
      if (r?.violations && r.violations.length > 0) {
        setError('Refused by guardrails: ' + r.violations.map((v) => v.rule).join(', '))
        return
      }
      onApplied()
      onClose()
      if (r?.needs_confirm && r.tx_id) onPending(r)
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  const errorIssues = (issues ?? []).filter((i) => i.severity === 'error')

  return (
    <Modal onBackdrop={busy ? undefined : onClose} className="max-w-2xl">
      <div className="flex items-center justify-between border-b border-line px-5 py-3">
        <h2 className="text-base font-semibold text-default">{initial ? 'Edit profile' : 'New profile'}</h2>
        <button onClick={onClose} disabled={busy} className="text-muted hover:text-default disabled:opacity-50" aria-label="Close">
          ✕
        </button>
      </div>

      <div className="space-y-5 p-5">
        {/* Metadata */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Profile name" error={submitted || name ? nameErr : null}>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. work-vpn"
              className={inputCls(submitted || !!name ? nameErr : null)}
            />
          </Field>
          <div className="flex items-end justify-between gap-3">
            <Field label="Description" className="flex-1">
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="optional note"
                className={inputCls(null)}
              />
            </Field>
            <div className="pb-1">
              <Label>Status</Label>
              <div className="mt-2 flex items-center gap-2">
                <Toggle on={enabled} onClick={() => setEnabled((v) => !v)} />
                <span className="text-sm text-muted">{enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Routing mode */}
        <div>
          <Label>Routing mode</Label>
          <div className="mt-2 grid grid-cols-2 gap-2">
            <ModeCard
              active={mode === 'exclude'}
              onClick={() => setMode('exclude')}
              title="Exclude"
              desc="These targets bypass the VPN (everything else stays tunneled)."
            />
            <ModeCard
              active={mode === 'include'}
              onClick={() => setMode('include')}
              title="Include"
              desc="Only these targets go through the tunnel (everything else is direct)."
            />
          </div>
        </div>

        {/* Route targets */}
        <RuleManager
          title="Route targets (CIDR / IP)"
          addLabel="Add route target"
          placeholder="10.0.0.0/8 or 1.1.1.1"
          rows={routes}
          setRows={setRoutes}
          errorFor={(r) => (submitted || r.value.trim() ? routeErr(r) : null)}
          newRow={() => newRow()}
        />

        {/* Domains */}
        <RuleManager
          title="Domain rules"
          addLabel="Add domain"
          placeholder="*.corp.example.com"
          rows={domains}
          setRows={setDomains}
          errorFor={(r) => (submitted || r.value.trim() ? domainErr(r) : null)}
          newRow={() => newRow()}
        />

        {/* Per-app rules */}
        <AppManager
          rows={apps}
          setRows={setApps}
          defStrategy={defStrategy}
          errorFor={(r) => (submitted || r.value.trim() ? appErr(r) : null)}
        />

        {/* Reusable list references */}
        {knownLists.length > 0 && (
          <div>
            <Label>Reusable lists</Label>
            <div className="mt-2 flex flex-wrap gap-2">
              {knownLists.map((l) => {
                const on = listRefs.includes(l.name)
                return (
                  <button
                    key={l.name}
                    onClick={() =>
                      setListRefs((refs) => (on ? refs.filter((r) => r !== l.name) : [...refs, l.name]))
                    }
                    aria-pressed={on}
                    className={`rounded-lg border px-3 py-1.5 text-sm transition-colors ${
                      on ? 'border-accent bg-accent/10 text-accent' : 'border-line text-muted hover:text-default'
                    }`}
                  >
                    {on ? '✓ ' : ''}
                    {l.name}
                  </button>
                )
              })}
            </div>
            <p className="mt-1 text-xs text-muted">Attach shared entry lists (managed below on the Profiles screen).</p>
          </div>
        )}

        {/* Advanced */}
        <details className="rounded-lg border border-line">
          <summary className="cursor-pointer select-none px-3 py-2 text-sm text-muted">Advanced</summary>
          <div className="grid grid-cols-2 gap-4 border-t border-line p-3">
            <Field label="Gateway" error={gatewayErr}>
              <input value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder="auto" className={inputCls(gatewayErr)} />
            </Field>
            <Field label="Priority">
              <input
                type="number"
                value={priority}
                onChange={(e) => setPriority(parseInt(e.target.value, 10) || 0)}
                className={inputCls(null)}
              />
            </Field>
          </div>
        </details>

        {/* Live staged-changes banner */}
        <div className="rounded-lg border border-accent/30 bg-accent/5 px-4 py-2.5 text-sm">
          <span className="font-medium text-accent">Staged configuration</span>
          <span className="ms-2 text-muted">
            +{staged.routes} route{staged.routes === 1 ? '' : 's'} · +{staged.domains} domain
            {staged.domains === 1 ? '' : 's'} · +{staged.apps} app rule{staged.apps === 1 ? '' : 's'}
            {listRefs.length > 0 ? ` · ${listRefs.length} list${listRefs.length === 1 ? '' : 's'}` : ''} · mode: {mode}
          </span>
          {decomposed.others.length > 0 && (
            <div className="mt-1 text-xs text-muted">
              {decomposed.others.length} advanced rule{decomposed.others.length === 1 ? '' : 's'} (asn/country) kept as-is.
            </div>
          )}
        </div>

        {/* Backend validation issues / errors */}
        {error && <div className="rounded-lg border border-danger/40 bg-danger/5 p-3 text-sm text-danger">{error}</div>}
        {errorIssues.length > 0 && (
          <ul className="rounded-lg border border-danger/30">
            {errorIssues.map((i, k) => (
              <li key={k} className="ltr border-b border-danger/20 px-3 py-1.5 text-sm text-danger last:border-0">
                {i.field ? <span className="text-muted">{i.field}: </span> : null}
                {i.msg}
              </li>
            ))}
          </ul>
        )}

        {/* Dry-run plan preview */}
        {previewPlan && (
          <div className="rounded-lg border border-line">
            <div className="border-b border-line px-3 py-1.5 text-xs font-medium text-muted">
              Plan preview — {previewPlan.ops.length} op(s)
            </div>
            {previewPlan.ops.length === 0 && <div className="px-3 py-2 text-sm text-muted">No changes — already in sync.</div>}
            {previewPlan.ops.map((op, i) => (
              <div key={i} className="ltr flex items-center gap-2 border-b border-line/60 px-3 py-1.5 text-sm last:border-0">
                <span className={op.kind.startsWith('add') ? 'text-success' : 'text-danger'}>{op.kind.startsWith('add') ? '+' : '−'}</span>
                <span className="font-mono text-muted">{op.command.join(' ')}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between gap-2 border-t border-line px-5 py-3">
        <button onClick={onClose} disabled={busy} className="rounded-lg border border-line px-4 py-2 text-sm text-muted hover:text-default disabled:opacity-50">
          Cancel
        </button>
        <div className="flex gap-2">
          <button
            onClick={preview}
            disabled={busy || hasErrors}
            className="rounded-lg border border-line px-4 py-2 text-sm text-muted hover:text-default disabled:opacity-50"
          >
            Preview
          </button>
          <button
            onClick={apply}
            disabled={busy || hasErrors}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
          >
            {busy ? 'Applying…' : 'Apply Changes Safely'}
          </button>
        </div>
      </div>
    </Modal>
  )
}

// --- dynamic rule managers ---

function RuleManager({
  title,
  addLabel,
  placeholder,
  rows,
  setRows,
  errorFor,
  newRow,
}: {
  title: string
  addLabel: string
  placeholder: string
  rows: Row[]
  setRows: React.Dispatch<React.SetStateAction<Row[]>>
  errorFor: (r: Row) => string | null
  newRow: () => Row
}) {
  const update = (id: number, value: string) => setRows((rs) => rs.map((r) => (r.id === id ? { ...r, value } : r)))
  const remove = (id: number) => setRows((rs) => rs.filter((r) => r.id !== id))
  return (
    <div>
      <Label>{title}</Label>
      <div className="mt-2 space-y-2">
        {rows.length === 0 && <div className="text-sm text-muted">None yet.</div>}
        {rows.map((r) => {
          const err = errorFor(r)
          return (
            <div key={r.id}>
              <div className="flex items-center gap-2">
                <input
                  value={r.value}
                  onChange={(e) => update(r.id, e.target.value)}
                  placeholder={placeholder}
                  className={`ltr flex-1 ${inputCls(err)}`}
                />
                <button onClick={() => remove(r.id)} aria-label="Remove" className="rounded-lg border border-line px-2.5 py-2 text-sm text-muted hover:text-danger">
                  ✕
                </button>
              </div>
              {err && <div className="mt-1 text-xs text-danger">{err}</div>}
            </div>
          )
        })}
      </div>
      <button onClick={() => setRows((rs) => [...rs, newRow()])} className="mt-2 text-sm font-medium text-accent hover:opacity-80">
        + {addLabel}
      </button>
    </div>
  )
}

function AppManager({
  rows,
  setRows,
  defStrategy,
  errorFor,
}: {
  rows: Row[]
  setRows: React.Dispatch<React.SetStateAction<Row[]>>
  defStrategy: AppStrategy
  errorFor: (r: Row) => string | null
}) {
  const update = (id: number, patch: Partial<Row>) => setRows((rs) => rs.map((r) => (r.id === id ? { ...r, ...patch } : r)))
  const remove = (id: number) => setRows((rs) => rs.filter((r) => r.id !== id))
  return (
    <div>
      <Label>Per-app rules</Label>
      <div className="mt-2 space-y-2">
        {rows.length === 0 && <div className="text-sm text-muted">None yet.</div>}
        {rows.map((r) => {
          const strat = r.strategy ?? defStrategy
          const err = errorFor(r)
          return (
            <div key={r.id}>
              <div className="flex items-center gap-2">
                <select
                  value={strat}
                  onChange={(e) => update(r.id, { strategy: e.target.value as AppStrategy })}
                  className="rounded-lg border border-line bg-elevated px-2 py-2 text-sm text-default"
                >
                  <option value="uid">By UID / Username (macOS)</option>
                  <option value="app">By Application (Linux)</option>
                </select>
                <input
                  value={r.value}
                  onChange={(e) => update(r.id, { value: e.target.value })}
                  placeholder={strat === 'uid' ? '501 or alice' : 'app id / cgroup'}
                  className={`ltr flex-1 ${inputCls(err)}`}
                />
                <button onClick={() => remove(r.id)} aria-label="Remove" className="rounded-lg border border-line px-2.5 py-2 text-sm text-muted hover:text-danger">
                  ✕
                </button>
              </div>
              {err && <div className="mt-1 text-xs text-danger">{err}</div>}
            </div>
          )
        })}
      </div>
      <button
        onClick={() => setRows((rs) => [...rs, { id: nextRowId(), value: '', strategy: defStrategy }])}
        className="mt-2 text-sm font-medium text-accent hover:opacity-80"
      >
        + Add app rule
      </button>
    </div>
  )
}

// --- small UI atoms ---

function Field({ label, error, children, className = '' }: { label: string; error?: string | null; children: React.ReactNode; className?: string }) {
  return (
    <div className={className}>
      <Label>{label}</Label>
      <div className="mt-1">{children}</div>
      {error && <div className="mt-1 text-xs text-danger">{error}</div>}
    </div>
  )
}

function ModeCard({ active, onClick, title, desc }: { active: boolean; onClick: () => void; title: string; desc: string }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-lg border p-3 text-left transition-colors ${active ? 'border-accent bg-accent/10' : 'border-line hover:border-line/80'}`}
    >
      <div className={`text-sm font-semibold ${active ? 'text-accent' : 'text-default'}`}>{title}</div>
      <div className="mt-0.5 text-xs text-muted">{desc}</div>
    </button>
  )
}

const inputCls = fieldCls
