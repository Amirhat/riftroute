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

export interface Health {
  daemon: 'ok' | 'degraded'
  reason?: string
  version: string
  provider: string
  uptime_seconds: number
  pid: number
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
  generated_at: string
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
  reachable: boolean
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

// UpdateResult mirrors update.Result — the GitHub Releases check.
export interface UpdateResult {
  current: string
  latest: string
  available: boolean
  url?: string
  notes?: string
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
