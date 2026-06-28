import { useCallback, useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Sidebar } from './components/Sidebar'
import type { View } from './components/Sidebar'
import { Dashboard } from './views/Dashboard'
import { RoutesView } from './views/RoutesView'
import { ExplainView } from './views/ExplainView'
import { Profiles } from './views/Profiles'
import { History } from './views/History'
import { Placeholder } from './views/Placeholder'
import { Badge, Dot } from './components/ui'
import { onConnection, onMenu, onState } from './lib/events'
import { api } from './lib/api'
import { stateKey } from './lib/queries'

type Theme = 'dark' | 'light'

const titles: Record<View, string> = {
  dashboard: 'Dashboard',
  routes: 'Routing Table',
  explain: 'Route Explain',
  profiles: 'Profiles',
  history: 'History',
  settings: 'Settings',
}

export default function App() {
  const qc = useQueryClient()
  const [view, setView] = useState<View>('dashboard')
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem('rr-theme') as Theme) || 'dark')
  const [reachable, setReachable] = useState(true)
  const [version, setVersion] = useState('')

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('rr-theme', theme)
  }, [theme])

  const toggleTheme = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), [])

  useEffect(() => {
    api.version().then(setVersion).catch(() => {})
    api.reachable().then(setReachable).catch(() => setReachable(false))
  }, [])

  // Wire live Wails events into TanStack Query (spec §3.5).
  useEffect(() => {
    const offState = onState((s) => {
      qc.setQueryData(stateKey, s)
      // Keep secondary views in sync whether the change came from this GUI, the
      // CLI, or the daemon's auto-apply.
      qc.invalidateQueries({ queryKey: ['routes'] })
      qc.invalidateQueries({ queryKey: ['profiles'] })
      setReachable(true)
    })
    const offConn = onConnection((r) => {
      setReachable(r)
      if (r) qc.invalidateQueries({ queryKey: stateKey })
    })
    const offMenu = onMenu((action) => {
      if (action === 'toggle-theme') toggleTheme()
      else if (action === 'refresh') qc.invalidateQueries()
      else if (action.startsWith('nav:')) setView(action.slice(4) as View)
    })
    return () => {
      offState()
      offConn()
      offMenu()
    }
  }, [qc, toggleTheme])

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-base text-default">
      <Sidebar current={view} onNavigate={setView} version={version || '…'} />
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex items-center justify-between border-b border-line bg-surface px-5 py-3">
          <h1 className="text-base font-semibold text-default">{titles[view]}</h1>
          <div className="flex items-center gap-3">
            <Badge tone={reachable ? 'success' : 'danger'}>
              <Dot tone={reachable ? 'success' : 'danger'} />
              {reachable ? 'daemon connected' : 'daemon offline'}
            </Badge>
            <button
              onClick={async () => {
                if (!confirm('Flush ALL RiftRoute-managed routes and restore baseline?')) return
                try {
                  await api.panic()
                } finally {
                  qc.invalidateQueries()
                }
              }}
              title="Remove all managed routes, restore baseline"
              className="rounded-lg border border-danger/50 px-3 py-1.5 text-sm font-medium text-danger hover:bg-danger/10"
            >
              Panic
            </button>
            <button
              onClick={toggleTheme}
              title="Toggle theme (⇧⌘T)"
              className="rounded-lg border border-line px-2.5 py-1.5 text-sm text-muted hover:text-default"
            >
              {theme === 'dark' ? '☾' : '☀'}
            </button>
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-auto p-5">
          <ViewRouter view={view} />
        </main>
      </div>
    </div>
  )
}

function ViewRouter({ view }: { view: View }) {
  switch (view) {
    case 'dashboard':
      return <Dashboard />
    case 'routes':
      return <RoutesView />
    case 'explain':
      return <ExplainView />
    case 'profiles':
      return <Profiles />
    case 'history':
      return <History />
    case 'settings':
      return <Placeholder title="Settings" milestone="M7" />
  }
}
