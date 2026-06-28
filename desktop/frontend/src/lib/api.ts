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
  Reachable,
  Version,
} from '../../wailsjs/go/main/App'
import type { State, Route, Iface, RouteExplain, Profile } from '../types'

export const api = {
  state: () => GetState() as unknown as Promise<State>,
  routes: (family = '', owner = '') => GetRoutes(family, owner) as unknown as Promise<Route[]>,
  interfaces: () => GetInterfaces() as unknown as Promise<Iface[]>,
  explain: (target: string) => Explain(target) as unknown as Promise<RouteExplain>,
  profiles: () => GetProfiles() as unknown as Promise<Profile[]>,
  audit: () => GetAudit() as unknown as Promise<unknown[]>,
  reachable: () => Reachable() as Promise<boolean>,
  version: () => Version() as Promise<string>,
}
