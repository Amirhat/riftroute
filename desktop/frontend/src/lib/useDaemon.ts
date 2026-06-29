import { useCallback, useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import type { DaemonInfo } from '../types'

// useDaemon centralizes the daemon lifecycle (status + install/start/stop/
// restart/uninstall). Privileged actions prompt for admin via the OS; a user
// cancellation surfaces as the error 'cancelled' and is treated as a no-op.
export function useDaemon() {
  const qc = useQueryClient()
  const [info, setInfo] = useState<DaemonInfo | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      setInfo(await api.daemonInfo())
    } catch {
      /* leave previous info */
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const run = useCallback(
    (label: string, fn: () => Promise<void>) => async () => {
      setBusy(label)
      setError(null)
      try {
        await fn()
        await refresh()
        qc.invalidateQueries()
      } catch (e) {
        const msg = (e as Error)?.message ?? String(e)
        if (msg && msg !== 'cancelled') setError(msg)
      } finally {
        setBusy(null)
      }
    },
    [qc, refresh],
  )

  return {
    info,
    busy,
    error,
    refresh,
    install: run('install', api.installDaemon),
    start: run('start', api.startDaemon),
    stop: run('stop', api.stopDaemon),
    restart: run('restart', api.restartDaemon),
    uninstall: run('uninstall', api.uninstallDaemon),
  }
}
