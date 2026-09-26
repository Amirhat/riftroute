import { useId, useState } from 'react'
import { Modal } from './Modal'
import { Badge, Label, Toggle, fieldCls } from './ui'
import { api } from '../lib/api'
import { friendly } from '../lib/format'
import { validateRouteTarget } from '../lib/validate'
import type { ConfigIssue, TunnelProfileFile, TunnelStatus, TunnelVia } from '../types'

const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/

// parseRoutes reads the networks box: one IP or CIDR per line (commas and
// spaces separate too). Each bad entry is reported with its line, as the
// Profile Builder does per row, so it shows before Save.
function parseRoutes(text: string): { routes: string[]; errors: RouteError[] } {
  const routes: string[] = []
  const errors: RouteError[] = []
  text.split('\n').forEach((line, i) => {
    for (const r of line.split(/[\s,]+/).filter(Boolean)) {
      routes.push(r)
      const msg = validateRouteTarget(r)
      if (msg) errors.push({ line: i + 1, value: r, msg })
    }
  })
  return { routes, errors }
}

type RouteError = { line: number; value: string; msg: string }

// TunnelEditor adds or edits a RiftRoute-run OpenVPN tunnel: the profile, the
// login, the networks that go through it, and how its own connection reaches
// the server. The profile and password are write-only: an edit that leaves
// them alone keeps what the daemon has saved.
export function TunnelEditor({
  existing,
  takenNames,
  canConnect,
  onClose,
  onSaved,
}: {
  existing?: TunnelStatus
  takenNames: string[]
  // False when the openvpn program isn't usable: saving still works, but
  // connecting would only fail.
  canConnect: boolean
  onClose: () => void
  onSaved: (t: TunnelStatus, warnings: string[], connect: boolean) => void
}) {
  const editing = !!existing
  const [name, setName] = useState(existing?.name ?? '')
  const [profile, setProfile] = useState<TunnelProfileFile | null>(null)
  const [username, setUsername] = useState(existing?.username ?? '')
  const [password, setPassword] = useState('')
  const [routesText, setRoutesText] = useState((existing?.routes ?? []).join('\n'))
  const [via, setVia] = useState<TunnelVia>(existing?.via ?? 'direct')
  const [autoConnect, setAutoConnect] = useState(existing?.auto_connect ?? false)
  const [issues, setIssues] = useState<ConfigIssue[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const engineHintId = useId()

  const needsAuth = profile ? profile.needs_auth : !!existing?.needs_auth
  const servers = profile ? (profile.servers ?? []) : (existing?.servers ?? [])
  const ignored = profile ? (profile.ignored ?? []) : (existing?.ignored ?? [])
  const nameError =
    !editing && name !== '' && !NAME_RE.test(name)
      ? 'Lowercase letters, digits, - or _'
      : !editing && takenNames.includes(name)
        ? 'A tunnel with this name exists'
        : null
  const issuesFor = (field: string) => issues.filter((i) => i.field === field)
  const errorFor = (field: string) => issuesFor(field).find((i) => i.severity === 'error')?.msg ?? null
  // Issues for a field this form doesn't show (or doesn't show right now)
  // go under the form, so a refused save never looks like a no-op.
  const shownFields = ['config', 'name', 'routes', ...(needsAuth ? ['username', 'password'] : [])]
  const otherIssues = issues.filter((i) => !i.field || !shownFields.includes(i.field))
  const parsed = parseRoutes(routesText)
  const files = profile?.files ?? []

  async function pickProfile() {
    setError(null)
    try {
      const f = await api.openTunnelProfile()
      if (!f.path) return // cancelled
      setProfile(f)
      if (f.username) setUsername(f.username)
      if (f.password) setPassword(f.password)
      if (!editing && !name) {
        const base = f.name
          .replace(/\.(ovpn|conf)$/i, '')
          .toLowerCase()
          .replace(/[^a-z0-9_-]+/g, '-')
        setName(base.replace(/^[-_]+/, '').slice(0, 32))
      }
    } catch (e) {
      setError(friendly(e))
    }
  }

  async function save(connect: boolean) {
    setError(null)
    setIssues([])
    setBusy(true)
    try {
      const res = await api.saveTunnel({
        name,
        type: 'openvpn',
        config: profile?.config || undefined,
        username: username || undefined,
        password: password || undefined,
        via,
        routes: parsed.routes,
        auto_connect: autoConnect,
      })
      const errs = (res.issues ?? []).filter((i) => i.severity === 'error')
      if (errs.length > 0 || !res.tunnel) {
        setIssues(res.issues ?? [])
        return
      }
      onSaved(
        res.tunnel,
        (res.issues ?? []).map((i) => i.msg),
        connect,
      )
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  const canSave =
    !busy && name !== '' && !nameError && parsed.errors.length === 0 && (editing || (profile && !profile.error))

  return (
    <Modal onBackdrop={busy ? undefined : onClose} className="max-w-xl">
      <div className="space-y-5 p-5">
        <div>
          <h2 className="text-base font-semibold text-default">
            {editing ? `Edit tunnel ${existing.name}` : 'Add an OpenVPN tunnel'}
          </h2>
          <p className="mt-1 text-sm text-muted">
            RiftRoute runs the connection itself and sends only the networks you list through it. Your main VPN keeps
            everything else.
          </p>
        </div>

        <div className="space-y-1.5">
          <Label>OpenVPN profile</Label>
          <div className="flex items-center gap-3">
            <button
              onClick={pickProfile}
              disabled={busy}
              className="rounded-lg border border-line px-3 py-1.5 text-sm text-default hover:bg-elevated disabled:opacity-50"
            >
              {profile || editing ? 'Replace .ovpn…' : 'Choose .ovpn…'}
            </button>
            <span className="truncate text-sm text-muted">
              {profile ? profile.name : editing ? 'keeping the saved profile' : 'no file chosen'}
            </span>
          </div>
          {profile?.error && <p className="text-sm text-danger">{profile.error}</p>}
          <IssueList issues={issuesFor('config')} />
          {servers.length > 0 && (
            <p className="text-xs text-muted">
              Server <span className="ltr font-mono text-default">{servers.join(', ')}</span>
            </p>
          )}
          {ignored.length > 0 && (
            <p className="text-xs text-muted">
              Ignored from the profile: <span className="ltr font-mono">{ignored.join(', ')}</span> — RiftRoute decides
              routes and DNS, so your main VPN isn't pushed aside.
            </p>
          )}
          {files.length > 0 && (
            <p className="text-xs text-muted">
              Also read: <span className="ltr font-mono">{files.join(', ')}</span>
            </p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label>Name</Label>
          <input
            value={name}
            disabled={editing}
            onChange={(e) => setName(e.target.value)}
            placeholder="infra"
            aria-label="Name"
            className={fieldCls(nameError || errorFor('name'))}
          />
          {nameError ? <p className="text-sm text-danger">{nameError}</p> : <IssueList issues={issuesFor('name')} />}
        </div>

        {needsAuth && (
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Username</Label>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
                aria-label="Username"
                className={fieldCls(errorFor('username'))}
              />
              <IssueList issues={issuesFor('username')} />
            </div>
            <div className="space-y-1.5">
              <Label>Password</Label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="off"
                placeholder={existing?.has_password ? 'saved — leave blank to keep' : ''}
                aria-label="Password"
                className={fieldCls(errorFor('password'))}
              />
              <IssueList issues={issuesFor('password')} />
            </div>
          </div>
        )}

        <div className="space-y-1.5">
          <Label>Networks through this tunnel</Label>
          <textarea
            value={routesText}
            onChange={(e) => setRoutesText(e.target.value)}
            rows={4}
            spellCheck={false}
            placeholder={'192.168.70.0/24\n192.168.72.11'}
            aria-label="Networks through this tunnel"
            aria-invalid={parsed.errors.length > 0 || !!errorFor('routes')}
            className={`ltr font-mono ${fieldCls(parsed.errors[0]?.msg ?? errorFor('routes'))}`}
          />
          <p className="text-xs text-muted">One IP or CIDR per line. Everything else stays on your main VPN.</p>
          {parsed.errors.map((e) => (
            <p key={`${e.line}:${e.value}`} className="text-sm text-danger">
              Line {e.line}: <span className="ltr font-mono">{e.value}</span> — {e.msg}
            </p>
          ))}
          <IssueList issues={issuesFor('routes')} />
        </div>

        <div className="space-y-2">
          <Label>Reach the OpenVPN server</Label>
          {(
            [
              ['direct', 'Directly', 'Around your main VPN, over your own network (like OpenVPN Connect does).'],
              [
                'default',
                'Through the main VPN',
                'A tunnel inside a tunnel — for servers that expect your VPN address.',
              ],
            ] as const
          ).map(([v, title, hint]) => (
            <label key={v} className="flex cursor-pointer items-start gap-2.5">
              <input type="radio" name="via" checked={via === v} onChange={() => setVia(v)} className="mt-1" />
              <span>
                <span className="text-sm text-default">{title}</span>
                {v === 'direct' && (
                  <span className="ms-2">
                    <Badge tone="accent">recommended</Badge>
                  </span>
                )}
                <span className="block text-xs text-muted">{hint}</span>
              </span>
            </label>
          ))}
        </div>

        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-default">Connect automatically</div>
            <div className="text-xs text-muted">Whenever the RiftRoute service starts.</div>
          </div>
          <Toggle on={autoConnect} onClick={() => setAutoConnect((v) => !v)} ariaLabel="Connect automatically" />
        </div>

        <IssueList issues={otherIssues} />
        {error && <p className="rounded-lg bg-danger/10 px-3 py-2 text-sm text-danger">{error}</p>}

        <div className="flex items-center justify-end gap-2 border-t border-line pt-4">
          {!canConnect && (
            <p id={engineHintId} className="me-auto text-xs text-muted">
              OpenVPN isn't usable yet — save now, connect once it is (see the Tunnels page).
            </p>
          )}
          <button
            onClick={onClose}
            disabled={busy}
            className="rounded-lg px-3 py-1.5 text-sm text-muted hover:text-default"
          >
            Cancel
          </button>
          <button
            onClick={() => save(false)}
            disabled={!canSave}
            className="rounded-lg border border-line px-3 py-1.5 text-sm text-default hover:bg-elevated disabled:opacity-50"
          >
            Save
          </button>
          {/* A live tunnel reconnects by itself when its connection settings change. */}
          {(!editing || existing.state === 'disconnected' || existing.state === 'failed') && (
            <button
              onClick={() => save(true)}
              disabled={!canSave || !canConnect}
              title={canConnect ? undefined : "OpenVPN isn't usable yet (see the Tunnels page)"}
              aria-describedby={canConnect ? undefined : engineHintId}
              className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
            >
              Save &amp; connect
            </button>
          )}
        </div>
      </div>
    </Modal>
  )
}

// IssueList renders the daemon's issues for one field: errors in red,
// warnings (the tunnel still saves) in amber.
function IssueList({ issues }: { issues: ConfigIssue[] }) {
  return (
    <>
      {issues.map((i) => (
        <p key={i.msg} className={`text-sm ${i.severity === 'error' ? 'text-danger' : 'text-warning'}`}>
          {i.msg}
        </p>
      ))}
    </>
  )
}
