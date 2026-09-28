// Hand-mirrored TypeScript views of the Go domain JSON. The CALL surface goes
// through the generated Wails bindings (see lib/api.ts); these interfaces are
// the component-facing shapes so the UI is insulated from binding-model codegen
// quirks (e.g. time.Time). Keep field names in sync with internal/domain/*.go.

export type Family = 'v4' | 'v6'
export type Owner = 'system' | 'riftroute' | 'vpn' | 'unknown'

// DaemonInfo mirrors desktop/daemon.go — the system-service + connection state
// the setup screen renders.
export interface DaemonInfo {
  manager: string // launchd | systemd | unsupported
  installed: boolean
  loaded: boolean
  reachable: boolean
  version?: string
  can_manage: boolean
}

// BuildInfo mirrors internal/domain/build.go.
export interface BuildInfo {
  version: string
  module_version?: string
  commit?: string
  commit_time?: string
  modified?: boolean
  go_version?: string
  platform?: string
  summary?: string
}

export interface Health {
  daemon: 'ok' | 'degraded'
  reason?: string
  version: string
  provider: string
  uptime_seconds: number
  pid: number
  // Absent from daemons that predate build reporting.
  build?: BuildInfo
  binary?: string
  started_at?: string
  restart_required?: boolean
  restart_reason?: string
  schema_version?: number
}

export interface Capabilities {
  platform: string
  policy_routing: boolean
  fwmark: boolean
  per_app_routing: boolean
  proto_tag: boolean
  ipv6: boolean
  kill_switch: boolean
  iface_scoping: boolean
  backend?: string // native traffic-steering backend: pf | nftables | fake
}

export interface VPNStatus {
  active: boolean
  interfaces: string[]
}

export interface Iface {
  name: string
  up: boolean
  kind: string
  addrs: string[] | null // real interfaces with no address marshal as null
  mtu?: number
  is_vpn: boolean
}

export interface DefaultRoute {
  family: Family
  present: boolean
  gateway?: string
  iface?: string
  owner: Owner
  via_vpn: boolean
}

export interface DNSState {
  servers: string[] | null
  search_domains?: string[] | null
  iface?: string
}

export interface ProfileStatus {
  id: string
  name: string
  enabled: boolean
  mode: string
  rule_count: number
  applied: boolean
}

export interface DriftStatus {
  pending: boolean
  adds: number
  dels: number
  reason?: string // set when desired state can't be computed (attention needed)
}

export interface State {
  health: Health
  capabilities: Capabilities
  vpn: VPNStatus
  interfaces: Iface[] | null // null on a degraded/partial provider read
  defaults: DefaultRoute[] | null
  dns: DNSState
  profiles: ProfileStatus[]
  drift: DriftStatus
  managed_route_count: number
  managed_rule_count: number
  auto_apply: boolean
  kill_switch: boolean
  // Why the daemon turned the kill switch off by itself (it was cutting the
  // VPN's own connection); cleared by the next explicit on/off.
  kill_switch_notice?: string
  // Absent from daemons that predate update/telemetry preferences.
  preferences?: Preferences
  // The daemon's updater (absent from daemons without one).
  update?: UpdateStatus
  // VPN connections RiftRoute runs itself; absent when there are none.
  tunnels?: TunnelStatus[]
  generated_at: string
}

// BugReport mirrors domain.BugReport: redacted text for the user to review.
export interface BugReport {
  text: string
  redactions: number
  generated_at: string
}

export type UpdateMode = 'auto' | 'notify' | 'off'
export type TelemetryLevel = 'full' | 'basic' | 'off'

// Preferences mirrors internal/domain/prefs.go.
export interface Preferences {
  updates: UpdateMode
  telemetry: TelemetryLevel
}

export interface SystemUser {
  uid: string
  username: string
  full_name?: string
}

export interface SystemApp {
  value: string // the rule value (Linux cgroup v2 path)
  name: string
}

export interface PolicyRule {
  priority: number
  selector: string
  table: string
  family: Family
  proto?: string
  // macOS PF route-to target (the Darwin analogue of a Linux table default).
  route_to_iface?: string
  route_to_gw?: string
}

export interface Route {
  dst_cidr: string
  gateway?: string
  iface: string
  metric: number
  family: Family
  owner: Owner
  proto?: string
  table?: string // non-main Linux routing table (Model B); absent on macOS
  profile?: string
  // Refuses its destination (no gateway, no interface): a down tunnel's,
  // while it's set to block.
  reject?: boolean
}

export interface RouteDecision {
  target: string
  source: string
  matched_cidr?: string
  gateway?: string
  iface: string
  family: Family
  owner?: Owner
  profile?: string
  via_vpn: boolean
  // The RiftRoute tunnel the traffic goes into, and its protocol (absent
  // from daemons before 0.4.1): not the main VPN, though its interface is a
  // VPN's too.
  tunnel?: string
  tunnel_type?: string
  reachable: boolean
  // A reject route refuses it. With tunnel set: that tunnel is down and set
  // to block (absent from daemons before 0.5.0).
  rejected?: boolean
}

export interface RouteExplain {
  target: string
  resolved?: string[]
  kernel: RouteDecision
  simulated?: RouteDecision
  drift: boolean
  note?: string
}

export interface Rule {
  type: string
  value: string
  comment?: string
}

export interface Profile {
  id: string
  name: string
  description?: string
  enabled: boolean
  mode: string
  gateway: string
  priority: number
  rules?: Rule[]
  lists?: string[]
  // With mode "tunnel": the tunnel its destinations go into.
  tunnel?: string
}

export interface PlanOp {
  kind: string
  route?: Route
  command: string[]
  human: string
}

export interface Plan {
  ops: PlanOp[]
  inverse: PlanOp[]
}

export interface DiffEntry {
  action: string
  route: Route
}

export interface Diff {
  entries?: DiffEntry[]
  adds: number
  dels: number
  changes: number
  in_sync: boolean
}

export interface Violation {
  rule: string
  detail: string
}

export interface ApplyResult {
  tx_id?: string
  plan: Plan
  diff: Diff
  violations?: Violation[]
  status: string // pending | committed | rolled_back | failed
  needs_confirm: boolean
  error?: string
}

export interface AuditEvent {
  id: number
  ts: string
  actor: string
  action: string
  profile?: string
  result: string
  rollback?: boolean
  reason?: string
  plan?: Plan
}

export interface Snapshot {
  id: string
  created_at: string
  reason: string
  // Whether the snapshot captured the profile set (older ones didn't) — only
  // those can be restored.
  restorable?: boolean
}

export interface DoctorCheck {
  name: string
  status: 'pass' | 'warn' | 'fail'
  detail: string
  fix?: string
}

export interface DoctorReport {
  checks: DoctorCheck[]
  pass: number
  warn: number
  fail: number
  ok: boolean
  generated_at: string
}

export interface Leak {
  kind: string
  severity: string
  detail: string
}

// Flow mirrors domain.Flow — an active connection correlated to the route that
// carries it (the flow monitor).
export interface Flow {
  proto: string
  local: string
  remote: string
  state?: string
  process?: string
  pid?: string
  iface?: string
  via_vpn: boolean
}

// List mirrors domain.List — a reusable static or remote (subscribable) rule set.
export interface List {
  name: string
  static?: string[] | null
  source?: string
  refresh?: string
  last_fetched?: string | null
  checksum?: string
  resolved?: string[] | null
}

// SplitDNSRoute mirrors domain.SplitDNSRoute — a per-domain resolver selection.
export interface SplitDNSRoute {
  domain: string
  resolver: string
  port?: number // non-standard resolver port (wildcard DNS learner entries)
}

// UpdateStatus mirrors domain.UpdateStatus — what the daemon's updater knows.
export interface UpdateStatus {
  mode: UpdateMode
  current: string
  // idle | checking | downloading | waiting (staged, for a quiet moment) | installing | error
  state: string
  last_check?: string
  latest?: string
  source?: 'server' | 'github'
  action?: 'none' | 'hold' | 'notify' | 'install'
  reason?: string
  notes_url?: string
  error?: string
  staged?: string
  rolled_back_from?: string
  rolled_back_by?: 'health' | 'you'
  installed_at?: string
  can_roll_back: boolean
  self_updatable: boolean
}

// ConfigFile mirrors desktop/config.go — a config the user picked in the native
// dialog. An empty path means the picker was cancelled.
export interface ConfigFile {
  path: string
  name: string
  format: string // yaml | toml
  content: string
}

export interface ConfigIssue {
  severity: string // error | warning
  line?: number
  field?: string
  msg: string
}

// ConfigImportResult mirrors apiclient.ConfigResult: validation issues plus either
// a dry-run plan/diff (preview) or an applied result (with a pending tx to confirm).
export interface ConfigImportResult {
  // apply_error = partial success: the change persisted but the follow-up
  // reconcile failed (e.g. include mode with no live tunnel).
  apply_error?: string
  issues?: ConfigIssue[]
  plan?: Plan
  diff?: Diff
  result?: ApplyResult
}

export type TunnelState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'failed'
// direct: reach the server around the main VPN; default: through it.
export type TunnelVia = 'direct' | 'default'
// What happens to a tunnel's destinations while it's down: they take the
// usual path, or they're refused until it's back.
export type TunnelWhenDown = 'fallback' | 'block'

// TunnelStatus mirrors domain.TunnelStatus (never carries the profile or password).
export interface TunnelStatus {
  name: string
  type: string
  via: TunnelVia
  routes: string[] | null
  auto_connect: boolean
  // Absent from daemons before 0.5.0 (fallback).
  when_down?: TunnelWhenDown
  // Its destinations are refused right now: set to block, and down while
  // it should be up.
  blocking?: boolean
  username?: string
  has_password: boolean
  needs_auth: boolean
  servers: string[] | null
  ignored?: string[] | null
  // Routes left out on this network, and why (contains its router, or
  // another VPN/the system already routes that exact destination).
  blocked?: TunnelBlocked[] | null
  // Installed, but an app rule of an include profile still sends that app's
  // traffic for them elsewhere (another VPN).
  captured?: TunnelBlocked[] | null
  // The tunnel-mode profiles that send their destinations into it.
  profiles?: TunnelProfileRef[] | null
  // The daemon can't read this tunnel's saved definition: it can only be
  // deleted (and added again). last_error says why; the other fields are
  // placeholders (via "direct", no routes or servers).
  unreadable?: boolean
  state: TunnelState
  detail?: string
  iface?: string
  local_ip?: string
  server?: string
  since?: string
  last_error?: string
  bytes_in: number
  bytes_out: number
}

export interface TunnelBlocked {
  route: string
  reason: string
}

// TunnelSpec mirrors domain.TunnelSpec. Empty config/password on an update
// keep the saved ones.
export interface TunnelSpec {
  name: string
  type: string
  config?: string
  username?: string
  password?: string
  via: TunnelVia
  routes: string[]
  auto_connect: boolean
  when_down?: TunnelWhenDown
}

// TunnelProfileRef is a tunnel-mode profile routed into a tunnel: its toggle
// state, and how many destinations it sends in (0 while off).
export interface TunnelProfileRef {
  id: string
  name: string
  enabled: boolean
  routes: number
}

// TunnelProfileFile is a .ovpn (inlined) or a WireGuard .conf picked in the
// native dialog, and parsed. An empty path means the picker was cancelled;
// error means unusable.
export interface TunnelProfileFile {
  path: string
  name: string
  // openvpn | wireguard; absent from builds before WireGuard (openvpn).
  type?: string
  config: string
  servers: string[] | null
  needs_auth: boolean
  ignored: string[] | null
  username: string
  password: string
  error: string
  // Local files the profile referenced and the picker inlined (ca, cert,
  // key, auth-user-pass, …). Absent from builds that don't report them.
  files?: string[] | null
}

export interface TunnelResult {
  tunnel?: TunnelStatus
  issues?: ConfigIssue[]
}

// TunnelEngine mirrors domain.TunnelEngine: whether tunnels can run on this
// machine and, if not, how the user installs openvpn here.
export interface TunnelEngine {
  available: boolean
  path?: string
  version?: string
  problem?: string
  install?: TunnelInstall
}

// What fixes openvpn here (absent from daemons that predate it):
// update — RiftRoute's own openvpn (macOS) is missing, and the daemon's
//   update check installs the one the newest release ships;
// reinstall — RiftRoute's own openvpn is there but unusable: reinstall the
//   daemon from a current release;
// install — the system's openvpn package (Linux): commands/note/url say how.
export type TunnelInstallAction = 'update' | 'reinstall' | 'install'

export interface TunnelInstall {
  system: string
  action?: TunnelInstallAction
  commands?: string[] | null
  note?: string
  url?: string
}

// The desktop app's own update (it follows the daemon to the same release).
export interface AppUpdateStatus {
  state: 'idle' | 'available' | 'downloading' | 'installing' | 'ready' | 'error' | 'unsupported'
  current: string
  target?: string
  why?: string
  error?: string
}
