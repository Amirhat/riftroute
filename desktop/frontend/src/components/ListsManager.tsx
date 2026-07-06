import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardHeader, Badge, Label, fieldCls } from './ui'
import { Modal } from './Modal'
import { ConfirmModal } from './ConfirmModal'
import { validateRouteTarget } from '../lib/validate'
import { friendly } from '../lib/format'
import type { List } from '../types'

// ListsManager is the visual editor for reusable rule lists — the last piece of
// the config file that previously required YAML. Static lists take CIDR/IP
// entries with inline validation; remote lists take an https source (fetched
// immediately, size-capped and checksummed by the daemon) plus a refresh
// interval. Edits stage only: a referencing profile shows drift and the change
// rides the next guarded Apply.
export function ListsManager() {
  const qc = useQueryClient()
  const listsQ = useQuery({ queryKey: ['lists'], queryFn: api.lists })
  const [editing, setEditing] = useState<List | 'new' | null>(null)
  const [deleting, setDeleting] = useState<List | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busyRefresh, setBusyRefresh] = useState<string | null>(null)

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['lists'] })
    qc.invalidateQueries({ queryKey: ['profiles'] })
  }

  async function doDelete() {
    const l = deleting
    setDeleting(null)
    if (!l) return
    setError(null)
    try {
      await api.deleteList(l.name)
      refresh()
    } catch (e) {
      setError(friendly(e)) // e.g. "list X is used by profile Y"
    }
  }

  async function doRefresh(name: string) {
    setError(null)
    setBusyRefresh(name)
    try {
      await api.refreshList(name)
      refresh()
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusyRefresh(null)
    }
  }

  const lists = listsQ.data ?? []

  return (
    <Card>
      <CardHeader
        title="Reusable lists"
        hint={
          <button onClick={() => setEditing('new')} className="rounded-lg border border-accent/50 px-2.5 py-1 text-xs font-medium text-accent hover:bg-accent/10">
            + New List
          </button>
        }
      />
      {error && <div className="border-b border-danger/30 bg-danger/5 px-4 py-2 text-sm text-danger">{error}</div>}
      {lists.length === 0 ? (
        <div className="p-4 text-sm text-muted">
          No lists yet. Lists bundle CIDR/IP entries (inline or from a subscribable URL) so profiles can share them.
        </div>
      ) : (
        <div className="divide-y divide-line">
          {lists.map((l) => {
            const remote = !!l.source
            const count = (l.static?.length ?? 0) + (l.resolved?.length ?? 0)
            return (
              <div key={l.name} className="flex items-center justify-between gap-3 px-4 py-2.5">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-default">{l.name}</span>
                    <Badge tone={remote ? 'accent' : 'muted'}>{remote ? 'remote' : 'static'}</Badge>
                    <span className="text-xs text-muted">{count} entr{count === 1 ? 'y' : 'ies'}</span>
                  </div>
                  {remote && (
                    <div className="ltr mt-0.5 truncate text-xs text-muted">
                      {l.source}
                      {l.last_fetched ? ` · fetched ${new Date(l.last_fetched).toLocaleString()}` : ' · not fetched yet'}
                    </div>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  {remote && (
                    <button
                      onClick={() => void doRefresh(l.name)}
                      disabled={busyRefresh === l.name}
                      className="rounded-lg border border-line px-2.5 py-1 text-xs text-muted hover:text-default disabled:opacity-50"
                    >
                      {busyRefresh === l.name ? 'Fetching…' : 'Refresh'}
                    </button>
                  )}
                  <button onClick={() => setEditing(l)} className="rounded-lg border border-line px-2.5 py-1 text-xs text-muted hover:text-default">
                    Edit
                  </button>
                  <button onClick={() => setDeleting(l)} className="rounded-lg border border-danger/40 px-2.5 py-1 text-xs text-danger hover:bg-danger/10">
                    Delete
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {editing !== null && (
        <ListEditor
          initial={editing === 'new' ? undefined : editing}
          existingNames={lists.map((l) => l.name)}
          onSaved={() => {
            setEditing(null)
            refresh()
          }}
          onClose={() => setEditing(null)}
        />
      )}

      <ConfirmModal
        open={deleting !== null}
        danger
        title={`Delete list "${deleting?.name ?? ''}"`}
        message="Profiles referencing this list keep working until you remove the reference — deletion is refused while it's still in use."
        confirmLabel="Delete list"
        onConfirm={doDelete}
        onCancel={() => setDeleting(null)}
      />
    </Card>
  )
}

// ListEditor is the create/edit form: static entries with per-row validation, or
// a remote https source with a refresh interval.
export function ListEditor({
  initial,
  existingNames,
  onSaved,
  onClose,
}: {
  initial?: List
  existingNames: string[]
  onSaved: () => void
  onClose: () => void
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [kind, setKind] = useState<'static' | 'remote'>(initial?.source ? 'remote' : 'static')
  const [entries, setEntries] = useState<string[]>(initial?.static?.length ? [...initial.static] : [''])
  const [source, setSource] = useState(initial?.source ?? '')
  const [refresh, setRefresh] = useState(initial?.refresh ?? '24h')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [submitted, setSubmitted] = useState(false)

  // Lists are keyed by name on the daemon (upsert), so renaming here would
  // CREATE a second list and leave the old one installed — the name is fixed
  // once created (delete + recreate to rename).
  const renameLocked = initial !== undefined
  const takenNames = existingNames.filter((n) => n !== initial?.name)
  const nameErr = !name.trim() ? 'required' : takenNames.includes(name.trim()) ? 'a list with this name already exists' : null
  const entryErr = (v: string) => (v.trim() ? validateRouteTarget(v) : null)
  const nonEmpty = entries.filter((e) => e.trim())
  const staticErr = kind === 'static' && nonEmpty.length === 0 ? 'add at least one CIDR/IP entry' : null
  const anyEntryInvalid = kind === 'static' && entries.some((e) => e.trim() && entryErr(e))
  const sourceErr = kind === 'remote' && !/^https:\/\/.+/.test(source.trim()) ? 'must be an https:// URL' : null
  // Mirrors Go's time.ParseDuration closely enough for UX: one or more
  // number+unit segments ("24h", "1h30m", "90m") — a bare repeated unit ("24hh")
  // does NOT match because each segment requires its own number.
  const refreshErr =
    kind === 'remote' && refresh.trim() && !/^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(refresh.trim())
      ? 'e.g. 24h, 1h30m'
      : null
  const hasErrors = !!(nameErr || staticErr || anyEntryInvalid || sourceErr || refreshErr)

  async function save() {
    setSubmitted(true)
    setError(null)
    if (hasErrors) return
    setBusy(true)
    try {
      const l: List = { name: name.trim() }
      if (kind === 'static') l.static = nonEmpty.map((e) => e.trim())
      else {
        l.source = source.trim()
        if (refresh.trim()) l.refresh = refresh.trim()
      }
      await api.saveList(l)
      onSaved()
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal onBackdrop={busy ? undefined : onClose}>
      <div className="p-5">
        <h2 className="text-base font-semibold text-default">{initial ? 'Edit list' : 'New list'}</h2>

        <div className="mt-4 space-y-4">
          <div>
            <FieldLabel>List name</FieldLabel>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. corp-nets"
              disabled={renameLocked}
              className={`${inputCls(submitted || name ? nameErr : null)} disabled:opacity-60`}
            />
            {(submitted || name) && nameErr && <FieldError>{nameErr}</FieldError>}
            {renameLocked && <p className="mt-1 text-xs text-muted">Names are fixed once created — delete and recreate to rename.</p>}
          </div>

          <div>
            <FieldLabel>Type</FieldLabel>
            <div className="mt-1 flex overflow-hidden rounded-lg border border-line text-sm">
              {(['static', 'remote'] as const).map((k) => (
                <button
                  key={k}
                  onClick={() => setKind(k)}
                  className={`flex-1 px-3 py-1.5 capitalize ${kind === k ? 'bg-accent text-accent-contrast' : 'text-muted hover:text-default'}`}
                >
                  {k === 'static' ? 'Static entries' : 'Remote (subscribable)'}
                </button>
              ))}
            </div>
          </div>

          {kind === 'static' ? (
            <div>
              <FieldLabel>Entries (CIDR / IP)</FieldLabel>
              <div className="mt-1 space-y-2">
                {entries.map((e, i) => {
                  const err = submitted || e.trim() ? entryErr(e) : null
                  return (
                    <div key={i}>
                      <div className="flex items-center gap-2">
                        <input
                          value={e}
                          onChange={(ev) => setEntries((es) => es.map((x, j) => (j === i ? ev.target.value : x)))}
                          placeholder="10.0.0.0/8"
                          className={`ltr flex-1 ${inputCls(err)}`}
                        />
                        <button
                          onClick={() => setEntries((es) => es.filter((_, j) => j !== i))}
                          aria-label="Remove entry"
                          className="rounded-lg border border-line px-2.5 py-2 text-sm text-muted hover:text-danger"
                        >
                          ✕
                        </button>
                      </div>
                      {err && <FieldError>{err}</FieldError>}
                    </div>
                  )
                })}
              </div>
              <button onClick={() => setEntries((es) => [...es, ''])} className="mt-2 text-sm font-medium text-accent hover:opacity-80">
                + Add entry
              </button>
              {submitted && staticErr && <FieldError>{staticErr}</FieldError>}
            </div>
          ) : (
            <>
              <div>
                <FieldLabel>Source URL (https only)</FieldLabel>
                <input
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="https://example.com/ranges.txt"
                  className={`ltr ${inputCls(submitted || source ? sourceErr : null)}`}
                />
                {(submitted || source) && sourceErr && <FieldError>{sourceErr}</FieldError>}
                <p className="mt-1 text-xs text-muted">Fetched over HTTPS, size-capped and checksummed — entries are parsed, never executed.</p>
              </div>
              <div>
                <FieldLabel>Refresh interval</FieldLabel>
                <input value={refresh} onChange={(e) => setRefresh(e.target.value)} placeholder="24h" className={inputCls(refreshErr)} />
                {refreshErr && <FieldError>{refreshErr}</FieldError>}
              </div>
            </>
          )}

          {error && <div className="rounded-lg border border-danger/40 bg-danger/5 p-3 text-sm text-danger">{error}</div>}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} disabled={busy} className="rounded-lg border border-line px-4 py-2 text-sm text-muted hover:text-default disabled:opacity-50">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={busy || hasErrors}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
          >
            {busy ? 'Saving…' : 'Save list'}
          </button>
        </div>
      </div>
    </Modal>
  )
}

const FieldLabel = Label
function FieldError({ children }: { children: React.ReactNode }) {
  return <div className="mt-1 text-xs text-danger">{children}</div>
}
const inputCls = (error: string | null | undefined) => `mt-1 ${fieldCls(error)}`
