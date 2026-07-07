import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Modal } from './Modal'
import { Combobox } from './Combobox'
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
import type { ApplyResult, ConfigImportResult, Diff, Plan, Profile, Rule } from '../types'

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
  onWarning,
  onClose,
}: {
  initial?: Profile
  existingNames: string[]
  platform?: string
  onPending: (r: ApplyResult) => void
  onApplied: () => void
  onWarning?: (msg: string) => void
  onClose: () => void
}) {
  const defStrategy: AppStrategy = platform === 'linux' ? 'app' : 'uid'
  const decomposed = useMemo(() => decompose(initial, defStrategy), [initial, defStrategy])

  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [enabled, setEnabled] = useState(initial?.enabled ?? true)
  const [mode, setMode] = useState<'include' | 'exclude'>((initial?.mode as 'include' | 'exclude') || 'exclude')
  const [gateway, setGateway] = useState(initial?.gateway ?? 'auto')
  // Kept as raw text so the field can be blanked while retyping (a number
  // state snapped an emptied input straight back to 0).
  const [priority, setPriority] = useState(String(initial?.priority ?? 0))
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
  const [previewDiff, setPreviewDiff] = useState<Diff | null>(null)
  const previewRef = useRef<HTMLDivElement>(null)

  // Any edit invalidates a shown preview — a stale plan next to changed inputs
  // reads as "the Preview button is broken".
  useEffect(() => {
    setPreviewPlan(null)
    setPreviewDiff(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name, enabled, mode, gateway, priority, routes, domains, apps, listRefs])

  // A fresh preview renders at the bottom of a tall modal — bring it into view.
  useEffect(() => {
    if (previewPlan) previewRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' })
  }, [previewPlan])

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

  // Per-app rules only take effect in include mode (the daemon rejects them in
  // exclude) — block apply with the same message instead of a late failure.
  const appModeErr =
    mode === 'exclude' && apps.some((r) => r.value.trim())
      ? 'Per-app rules only take effect in Include mode — switch the mode or remove them.'
      : null

  const hasErrors = nameErr !== null || gatewayErr !== null || anyRowInvalid || appModeErr !== null

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
      priority: parseInt(priority, 10) || 0,
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
      setPreviewDiff(res.diff ?? null)
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
      if (res.apply_error) {
        // Partial success: the profile persisted but the reconcile didn't run
        // (e.g. include mode with no live tunnel). The profile list is correct;
        // surface why nothing was installed yet.
        onWarning?.(`Profile saved — not applied yet: ${res.apply_error}`)
        return
      }
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
              desc="Only these targets go through the tunnel (everything else is direct). Needs an active VPN."
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
          hint="Wildcards (*.example.com) route the domain itself; subdomains follow via split-DNS in Settings."
          rows={domains}
          setRows={setDomains}
          errorFor={(r) => (submitted || r.value.trim() ? domainErr(r) : null)}
          newRow={() => newRow()}
        />

        {/* Per-app rules */}
        <AppManager
          rows={apps}
          setRows={setApps}
          platform={platform}
          mode={mode}
          modeError={appModeErr}
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
                onChange={(e) => setPriority(e.target.value)}
                placeholder="0"
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
          <div ref={previewRef} className="rounded-lg border border-line">
            <div className="flex items-center justify-between border-b border-line px-3 py-1.5 text-xs font-medium text-muted">
              <span>Review — what applying will change</span>
              {previewDiff && (
                <span>
                  <span className="text-success">+{previewDiff.adds} to add</span>
                  <span className="mx-1">·</span>
                  <span className="text-danger">−{previewDiff.dels} to remove</span>
                </span>
              )}
            </div>
            {previewPlan.ops.length === 0 && (
              <div className="px-3 py-2 text-sm text-muted">No changes — this configuration is already applied.</div>
            )}
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
  hint,
  rows,
  setRows,
  errorFor,
  newRow,
}: {
  title: string
  addLabel: string
  placeholder: string
  hint?: string
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
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  )
}

// AppManager edits per-app rules with a platform-appropriate searchable picker:
// macOS matches an app's traffic by its running user (PF socket owner), Linux
// by cgroup v2 unit. Free text stays valid — the catalogs are suggestions.
function AppManager({
  rows,
  setRows,
  platform,
  mode,
  modeError,
  errorFor,
}: {
  rows: Row[]
  setRows: React.Dispatch<React.SetStateAction<Row[]>>
  platform?: string
  mode: 'include' | 'exclude'
  modeError: string | null
  errorFor: (r: Row) => string | null
}) {
  const isLinux = platform === 'linux'
  const active = rows.some((r) => r.value.trim())
  // Catalogs load lazily: only once the section is in use (or being added to).
  const [wantCatalog, setWantCatalog] = useState(false)
  const usersQ = useQuery({
    queryKey: ['sysusers'],
    queryFn: api.systemUsers,
    enabled: !isLinux && (wantCatalog || active),
    staleTime: 60_000,
  })
  const appsQ = useQuery({
    queryKey: ['sysapps'],
    queryFn: api.systemApps,
    enabled: isLinux && (wantCatalog || active),
    staleTime: 60_000,
  })

  const options = isLinux
    ? (appsQ.data ?? []).map((a) => ({ value: a.value, label: a.name, sub: a.value }))
    : (usersQ.data ?? []).map((u) => ({
        value: u.username,
        label: `${u.username} (uid ${u.uid})`,
        sub: u.full_name,
      }))

  const update = (id: number, value: string) => setRows((rs) => rs.map((r) => (r.id === id ? { ...r, value } : r)))
  const remove = (id: number) => setRows((rs) => rs.filter((r) => r.id !== id))

  return (
    <div>
      <Label>{isLinux ? 'Per-app rules — applications' : 'Per-app rules — by user'}</Label>
      <div className="mt-2 space-y-2">
        {rows.length === 0 && <div className="text-sm text-muted">None yet.</div>}
        {rows.map((r) => {
          const err = errorFor(r)
          return (
            <div key={r.id}>
              <div className="flex items-center gap-2">
                <Combobox
                  value={r.value}
                  onChange={(v) => update(r.id, v)}
                  options={options}
                  loading={isLinux ? appsQ.isLoading : usersQ.isLoading}
                  placeholder={isLinux ? 'Search applications (cgroup units)…' : 'Search users — name or uid…'}
                  ariaLabel="App rule value"
                  invalid={!!err}
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
        onClick={() => {
          setWantCatalog(true)
          setRows((rs) => [...rs, { id: nextRowId(), value: '' }])
        }}
        className="mt-2 text-sm font-medium text-accent hover:opacity-80"
      >
        + Add app rule
      </button>
      {modeError ? (
        <p className="mt-1 text-xs text-danger">{modeError}</p>
      ) : (
        mode === 'exclude' &&
        rows.length === 0 && (
          <p className="mt-1 text-xs text-muted">Per-app rules steer an app into the tunnel — they need Include mode.</p>
        )
      )}
      {!isLinux && mode === 'include' && (
        <p className="mt-1 text-xs text-muted">macOS steers an app by the user it runs as (PF socket owner).</p>
      )}
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
