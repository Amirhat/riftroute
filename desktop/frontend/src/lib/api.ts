// The ONLY way the UI calls the backend: the generated Wails bindings. These
// thin wrappers re-type the results to our component-facing interfaces (types.ts)
// and centralize the call surface so views never import bindings directly.
import {
  GetState,
  GetRoutes,
  GetInterfaces,
  Explain,
  GetProfiles,
  GetAudit,
  GetSnapshots,
  PlanPreview,
  Apply,
  Confirm,
  Rollback,
  PanicFlush,
  SetProfileEnabled,
  Reachable,
  Version,
} from '../../wailsjs/go/main/App'
import type {
  State,
  Route,
  Iface,
  RouteExplain,
  Profile,
  Plan,
  ApplyResult,
  AuditEvent,
  Snapshot,
} from '../types'

export const api = {
  state: () => GetState() as unknown as Promise<State>,
  routes: (family = '', owner = '') => GetRoutes(family, owner) as unknown as Promise<Route[]>,
  interfaces: () => GetInterfaces() as unknown as Promise<Iface[]>,
  explain: (target: string) => Explain(target) as unknown as Promise<RouteExplain>,
  profiles: () => GetProfiles() as unknown as Promise<Profile[]>,
  audit: () => GetAudit() as unknown as Promise<AuditEvent[]>,
  snapshots: () => GetSnapshots() as unknown as Promise<Snapshot[]>,
  plan: () => PlanPreview() as unknown as Promise<Plan>,
  apply: (yes: boolean, confirmTimeoutSec: number) => Apply(yes, confirmTimeoutSec) as unknown as Promise<ApplyResult>,
  confirm: (txID: string) => Confirm(txID) as unknown as Promise<string>,
  rollback: (txID: string) => Rollback(txID) as unknown as Promise<string>,
  panic: () => PanicFlush() as Promise<void>,
  setProfileEnabled: (name: string, enable: boolean) =>
    SetProfileEnabled(name, enable) as unknown as Promise<ApplyResult>,
  reachable: () => Reachable() as Promise<boolean>,
  version: () => Version() as Promise<string>,
}
