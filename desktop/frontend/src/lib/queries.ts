import { useQuery } from '@tanstack/react-query'
import { api } from './api'

// TanStack Query wraps the generated bindings so loading/error/stale/refetch are
// managed for us (spec §3.5). Live events keep these caches fresh via
// setQueryData/invalidate in App.

export const stateKey = ['state'] as const
export const routesKey = (family: string) => ['routes', family] as const

export function useStateQuery() {
  return useQuery({ queryKey: stateKey, queryFn: api.state })
}

// Build warnings are cheap (one /healthz read) and change only on install or
// restart, so a slow poll is plenty.
export function useBuildNotesQuery() {
  return useQuery({ queryKey: ['buildNotes'], queryFn: api.buildNotes, refetchInterval: 15_000 })
}

export function useRoutesQuery(family: string) {
  return useQuery({ queryKey: routesKey(family), queryFn: () => api.routes(family) })
}
