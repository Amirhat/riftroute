// Hand-mirrored TypeScript views of the Go domain JSON. The CALL surface goes
// through the generated Wails bindings (see lib/api.ts); these interfaces are
// the component-facing shapes so the UI is insulated from binding-model codegen
// quirks (e.g. time.Time). Keep field names in sync with internal/domain/*.go.

export type Family = 'v4' | 'v6'
export type Owner = 'system' | 'riftroute' | 'vpn' | 'unknown'

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
}

export interface VPNStatus {
  active: boolean
  interfaces: string[]
}

export interface Iface {
  name: string
  up: boolean
  kind: string
  addrs: string[]
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
  servers: string[]
  search_domains?: string[]
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
  changes: number
}

export interface State {
  health: Health
  capabilities: Capabilities
  vpn: VPNStatus
  interfaces: Iface[]
  defaults: DefaultRoute[]
  dns: DNSState
  profiles: ProfileStatus[]
  drift: DriftStatus
  managed_route_count: number
  auto_apply: boolean
  kill_switch: boolean
  generated_at: string
}

export interface Route {
  dst_cidr: string
  gateway?: string
  iface: string
  metric: number
  family: Family
  owner: Owner
  proto?: string
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
