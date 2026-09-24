import { useState } from 'react'
import { Modal } from './Modal'
import { Badge, Label, Toggle, fieldCls } from './ui'
import { api } from '../lib/api'
import { friendly } from '../lib/format'
import type { ConfigIssue, TunnelProfileFile, TunnelStatus, TunnelVia } from '../types'

const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/

// TunnelEditor adds or edits a RiftRoute-run OpenVPN tunnel: the profile, the
// login, the networks that go through it, and how its own connection reaches
// the server. The profile and password are write-only: an edit that leaves
// them alone keeps what the daemon has saved.
export function TunnelEditor({
  existing,
  takenNames,
  onClose,
  onSaved,
}: {
  existing?: TunnelStatus
  takenNames: string[]
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

  const needsAuth = profile ? profile.needs_auth : !!existing?.needs_auth
  const servers = profile ? (profile.servers ?? []) : (existing?.servers ?? [])
  const ignored = profile ? (profile.ignored ?? []) : (existing?.ignored ?? [])
  const nameError =
    !editing && name !== '' && !NAME_RE.test(name)
      ? 'Lowercase letters, digits, - or _'
      : !editing && takenNames.includes(name)
        ? 'A tunnel with this name exists'
        : null
  const issueFor = (field: string) => issues.filter((i) => i.field === field).map((i) => i.msg)

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
        routes: routesText
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
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

  const canSave = !busy && name !== '' && !nameError && (editing || (profile && !profile.error))

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
          {issueFor('config').map((m) => (
            <p key={m} className="text-sm text-danger">
              {m}
            </p>
          ))}
          {servers.length > 0 && (
            <p className="text-xs text-muted">
              Server <span className="ltr font-mono text-default">{servers.join(', ')}</span>
            </p>
          )}
          {ignored.length > 0 && (
            <p className="text-xs text-muted">
              Ignored from the profile: <span className="font-mono">{ignored.join(', ')}</span> — RiftRoute decides
              routes and DNS, so your main VPN isn't pushed aside.
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
            className={fieldCls(nameError || issueFor('name')[0])}
          />
          {(nameError || issueFor('name')[0]) && (
            <p className="text-sm text-danger">{nameError || issueFor('name')[0]}</p>
          )}
        </div>

        {needsAuth && (
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Username</Label>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
                className={fieldCls(issueFor('username')[0])}
              />
              {issueFor('username').map((m) => (
                <p key={m} className="text-sm text-danger">
                  {m}
                </p>
              ))}
            </div>
            <div className="space-y-1.5">
              <Label>Password</Label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="off"
                placeholder={existing?.has_password ? 'saved — leave blank to keep' : ''}
                className={fieldCls(issueFor('password')[0])}
              />
              {issueFor('password').map((m) => (
                <p key={m} className="text-sm text-danger">
                  {m}
                </p>
              ))}
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
            className={`ltr font-mono ${fieldCls(issueFor('routes').find((m) => !m.includes('router')))}`}
          />
          <p className="text-xs text-muted">One IP or CIDR per line. Everything else stays on your main VPN.</p>
          {issueFor('routes').map((m) => (
            <p key={m} className="text-sm text-danger">
              {m}
            </p>
          ))}
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
                  <span className="ml-2">
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

        {error && <p className="rounded-lg bg-danger/10 px-3 py-2 text-sm text-danger">{error}</p>}

        <div className="flex justify-end gap-2 border-t border-line pt-4">
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
              disabled={!canSave}
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
