// Dev-only Wails shim: lets the real UI run in a PLAIN BROWSER against a live
// riftrouted. Wire-up:
//
//   ./bin/riftrouted -socket /tmp/rr-dev.sock -db /tmp/rr-dev.db -provider fake &
//   go run ./tools/devbridge -uds /tmp/rr-dev.sock &   # TCP 127.0.0.1:8787
//   npm run dev                                        # vite proxies /rr-api → 8787
//
// main.tsx imports this ONLY when import.meta.env.DEV and window.go is absent,
// so nothing here ships in a production build. Native-dialog and daemon-
// lifecycle bindings are stubbed — everything else hits the real API.

type Json = Record<string, unknown> | unknown[] | null

class ApiError extends Error {
  body: Json
  constructor(msg: string, body: Json) {
    super(msg)
    this.body = body
  }
}

async function req(method: string, path: string, body?: unknown, raw?: string): Promise<any> {
  const res = await fetch('/rr-api' + path, {
    method,
    headers: body !== undefined || raw !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: raw !== undefined ? raw : body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data: Json = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (!res.ok) {
    const msg =
      (data && !Array.isArray(data) && ((data as Record<string, unknown>).error as string)) || `HTTP ${res.status}`
    throw new ApiError(String(msg), data)
  }
  return data
}

// Mirrors desktop/app.go: a 4xx whose body carries validation issues is a
// RESULT for the UI to render inline, not a rejection.
async function issuesAreResults(p: Promise<any>): Promise<any> {
  try {
    return await p
  } catch (e) {
    if (e instanceof ApiError && e.body && !Array.isArray(e.body) && (e.body as Record<string, unknown>).issues) {
      return e.body
    }
    throw e
  }
}

const notInBrowser = (what: string) => () =>
  Promise.reject(new Error(`${what} needs the desktop app (browser dev mode)`))

const App = {
  GetState: () => req('GET', '/state'),
  GetRoutes: (f: string, o: string) => req('GET', `/routes?family=${f}&owner=${o}`).then((b) => b.routes ?? []),
  GetRules: () => req('GET', '/rules').then((b) => b.rules ?? []),
  GetInterfaces: () => req('GET', '/interfaces').then((b) => b.interfaces ?? []),
  Explain: (t: string) => req('POST', '/route/explain', { target: t }),
  GetProfiles: () => req('GET', '/profiles').then((b) => b.profiles ?? []),
  GetAudit: () => req('GET', '/audit').then((b) => b.events ?? []),
  GetSnapshots: () => req('GET', '/snapshots').then((b) => b.snapshots ?? []),
  RestoreSnapshot: (id: string) => issuesAreResults(req('POST', `/snapshots/${encodeURIComponent(id)}/restore`)),
  GetDoctor: () => req('GET', '/doctor'),
  GetLeaks: () => req('GET', '/leaks').then((b) => b.leaks ?? []),
  GetFlows: () => req('GET', '/flows').then((b) => b.flows ?? []),
  GetLists: () => req('GET', '/lists').then((b) => b.lists ?? []),
  SaveList: (l: unknown) => req('POST', '/lists', l),
  DeleteList: (n: string) => req('DELETE', `/lists/${encodeURIComponent(n)}`).then(() => undefined),
  RefreshList: (n: string) => req('POST', `/lists/${encodeURIComponent(n)}/refresh`, {}),
  GetSplitDNS: () => req('GET', '/splitdns'),
  SetSplitDNS: (r: unknown[]) => req('PUT', '/splitdns', r).then(() => req('GET', '/splitdns')),
  GetSystemUsers: () => req('GET', '/system/users').then((b) => b.users ?? []),
  GetSystemApps: () => req('GET', '/system/apps').then((b) => b.apps ?? []),
  SetKillSwitch: (e: boolean) => req('POST', '/killswitch', { enabled: e }).then((b) => b.kill_switch),
  SetAutoApply: (e: boolean) => req('PUT', '/autoapply', { enabled: e }).then((b) => b.auto_apply),
  PlanPreview: () => req('POST', '/plan', {}).then((b) => b.plan),
  Apply: (yes: boolean, t: number) => req('POST', '/apply', { dry_run: false, yes, confirm_timeout_sec: t }),
  Confirm: (tx: string) => req('POST', '/confirm', { tx_id: tx }).then((b) => b.result),
  Rollback: (tx: string) => req('POST', '/rollback', { tx_id: tx }).then((b) => b.result),
  PanicFlush: () => req('POST', '/panic', {}).then(() => undefined),
  SetProfileEnabled: (name: string, enable: boolean) =>
    req('POST', `/profiles/${encodeURIComponent(name)}/${enable ? 'enable' : 'disable'}?apply=false`, {}),
  SaveProfile: (p: unknown, dry: boolean) =>
    issuesAreResults(req('POST', `/profiles${dry ? '?dry_run=1' : ''}`, p)),
  DeleteProfile: (n: string) => issuesAreResults(req('DELETE', `/profiles/${encodeURIComponent(n)}`)),
  ApplyConfigContent: (content: string, format: string, dry: boolean, yes: boolean) =>
    issuesAreResults(req('POST', `/config?format=${format}&dry_run=${dry ? 1 : 0}&yes=${yes ? 1 : 0}`, undefined, content)),
  RouteOp: (action: string, route: unknown, newRoute: unknown) =>
    issuesAreResults(
      req('POST', '/routes/ops', { action, route, new_route: action === 'replace' ? newRoute : undefined }),
    ),
  Reachable: () =>
    req('GET', '/healthz')
      .then(() => true)
      .catch(() => false),
  Version: () => req('GET', '/healthz').then((b) => `${b.version ?? '?'} · browser dev`),
  GetDaemonInfo: () =>
    Promise.resolve({ installed: true, reachable: true, can_manage: false, manager: 'browser dev bridge' }),
  InstallDaemon: notInBrowser('Daemon install'),
  StartDaemon: notInBrowser('Daemon start'),
  StopDaemon: notInBrowser('Daemon stop'),
  RestartDaemon: notInBrowser('Daemon restart'),
  UninstallDaemon: notInBrowser('Daemon uninstall'),
  // Native file dialogs: empty path = user cancelled (the UI treats it as a no-op).
  OpenConfigDialog: () => Promise.resolve({ path: '', name: '', format: 'yaml', content: '' }),
  ExportConfigDialog: () => Promise.resolve(''),
  CheckUpdate: () => Promise.resolve({ available: false, current: 'browser-dev' }),
}

;(window as unknown as Record<string, unknown>).go = { main: { App } }
console.info('[riftroute] browser dev shim active — bindings proxied via /rr-api')

export {}
