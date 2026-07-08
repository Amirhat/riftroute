// The ONLY way the UI calls the backend: the generated Wails bindings. These
// thin wrappers re-type the results to our component-facing interfaces (types.ts)
// and centralize the call surface so views never import bindings directly.
import {
  GetState,
  GetRoutes,
  GetRules,
  GetInterfaces,
  Explain,
  GetProfiles,
  GetAudit,
  GetSnapshots,
  RestoreSnapshot,
  GetDoctor,
  GetLeaks,
  SetKillSwitch,
  SetAutoApply,
  PlanPreview,
  Apply,
  Confirm,
  Rollback,
  RouteOp,
  PanicFlush,
  SetProfileEnabled,
  Reachable,
  Version,
  GetDaemonInfo,
  InstallDaemon,
  StartDaemon,
  StopDaemon,
  RestartDaemon,
  UninstallDaemon,
  OpenConfigDialog,
  ApplyConfigContent,
  SaveProfile,
  DeleteProfile,
  GetFlows,
  GetLists,
  SaveList,
  DeleteList,
  RefreshList,
  GetSplitDNS,
  SetSplitDNS,
  GetSystemApps,
  GetSystemUsers,
  ExportConfigDialog,
  CheckUpdate,
} from '../../wailsjs/go/main/App'
import type {
  State,
  Route,
  PolicyRule,
  Iface,
  RouteExplain,
  Profile,
  Plan,
  ApplyResult,
  AuditEvent,
  Snapshot,
  DoctorReport,
  Leak,
  DaemonInfo,
  ConfigFile,
  ConfigImportResult,
  Flow,
  List,
  SplitDNSRoute,
  SystemApp,
  SystemUser,
  UpdateResult,
} from '../types'

export const api = {
  state: () => GetState() as unknown as Promise<State>,
  routes: (family = '', owner = '') => GetRoutes(family, owner) as unknown as Promise<Route[]>,
  rules: () => GetRules() as unknown as Promise<PolicyRule[]>,
  // Single-route delete/edit of EXTERNAL routes (plan-level Apply Protocol,
  // commit-confirm guarded). newRoute is ignored for 'delete'.
  routeOp: (action: 'delete' | 'replace', route: Route, newRoute?: Route) =>
    RouteOp(
      action,
      route as unknown as Parameters<typeof RouteOp>[1],
      (newRoute ?? route) as unknown as Parameters<typeof RouteOp>[2],
    ) as unknown as Promise<ConfigImportResult>,
  interfaces: () => GetInterfaces() as unknown as Promise<Iface[]>,
  explain: (target: string) => Explain(target) as unknown as Promise<RouteExplain>,
  profiles: () => GetProfiles() as unknown as Promise<Profile[]>,
  audit: () => GetAudit() as unknown as Promise<AuditEvent[]>,
  snapshots: () => GetSnapshots() as unknown as Promise<Snapshot[]>,
  restoreSnapshot: (id: string) => RestoreSnapshot(id) as unknown as Promise<ConfigImportResult>,
  doctor: () => GetDoctor() as unknown as Promise<DoctorReport>,
  leaks: () => GetLeaks() as unknown as Promise<Leak[]>,
  setKillSwitch: (enabled: boolean) => SetKillSwitch(enabled) as Promise<boolean>,
  setAutoApply: (enabled: boolean) => SetAutoApply(enabled) as Promise<boolean>,
  plan: () => PlanPreview() as unknown as Promise<Plan>,
  apply: (yes: boolean, confirmTimeoutSec: number) => Apply(yes, confirmTimeoutSec) as unknown as Promise<ApplyResult>,
  confirm: (txID: string) => Confirm(txID) as unknown as Promise<string>,
  rollback: (txID: string) => Rollback(txID) as unknown as Promise<string>,
  panic: () => PanicFlush() as Promise<void>,
  setProfileEnabled: (name: string, enable: boolean) =>
    SetProfileEnabled(name, enable) as unknown as Promise<ApplyResult>,
  // Interactive builder: upsert one profile (dry-run previews the plan) / delete one.
  // Plain objects are what Wails serializes; the casts adapt to whatever argument
  // classes the binding generator emits (they're structurally identical).
  saveProfile: (p: Profile, dryRun: boolean) =>
    SaveProfile(p as unknown as Parameters<typeof SaveProfile>[0], dryRun) as unknown as Promise<ConfigImportResult>,
  deleteProfile: (name: string) => DeleteProfile(name) as unknown as Promise<ConfigImportResult>,
  reachable: () => Reachable() as Promise<boolean>,
  version: () => Version() as Promise<string>,
  // Declarative config import/export (native dialogs).
  openConfigDialog: () => OpenConfigDialog() as unknown as Promise<ConfigFile>,
  applyConfigContent: (content: string, format: string, dryRun: boolean, yes: boolean) =>
    ApplyConfigContent(content, format, dryRun, yes) as unknown as Promise<ConfigImportResult>,
  exportConfig: () => ExportConfigDialog() as Promise<string>,
  // Observability: live flow monitor.
  flows: () => GetFlows() as unknown as Promise<Flow[]>,
  // Reusable lists (visual manager; staging only — drift drives the apply).
  lists: () => GetLists() as unknown as Promise<List[]>,
  saveList: (l: List) => SaveList(l as unknown as Parameters<typeof SaveList>[0]) as unknown as Promise<List>,
  deleteList: (name: string) => DeleteList(name) as Promise<void>,
  refreshList: (name: string) => RefreshList(name) as unknown as Promise<List>,
  // Split-DNS (persisted per-domain resolver selection).
  splitDNS: () => GetSplitDNS() as unknown as Promise<SplitDNSRoute[]>,
  setSplitDNS: (routes: SplitDNSRoute[]) =>
    SetSplitDNS(routes as unknown as Parameters<typeof SetSplitDNS>[0]) as unknown as Promise<SplitDNSRoute[]>,
  // Local catalogs feeding the per-app searchable pickers.
  systemUsers: () => GetSystemUsers() as unknown as Promise<SystemUser[]>,
  systemApps: () => GetSystemApps() as unknown as Promise<SystemApp[]>,
  // Update check (never self-installs).
  checkUpdate: () => CheckUpdate() as unknown as Promise<UpdateResult>,
  // Daemon lifecycle (privileged ops prompt for admin via the OS).
  daemonInfo: () => GetDaemonInfo() as unknown as Promise<DaemonInfo>,
  installDaemon: () => InstallDaemon() as Promise<void>,
  startDaemon: () => StartDaemon() as Promise<void>,
  stopDaemon: () => StopDaemon() as Promise<void>,
  restartDaemon: () => RestartDaemon() as Promise<void>,
  uninstallDaemon: () => UninstallDaemon() as Promise<void>,
}
