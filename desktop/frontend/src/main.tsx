import React from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import './index.css'

// Live updates arrive as Wails events (SSE re-emitted by the Go side), so we
// don't poll aggressively; queries refetch on demand and are kept fresh by
// setQueryData on incoming events.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 1000,
    },
  },
})

async function boot() {
  // Browser dev mode: outside the Wails webview there are no bindings, so a
  // DEV-only shim proxies them to a live daemon (see src/dev/shim.ts). The
  // dynamic import is dead-code-eliminated from production builds.
  if (import.meta.env.DEV && !(window as unknown as Record<string, unknown>).go) {
    await import('./dev/shim')
  }
  createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </React.StrictMode>,
  )
}

void boot()
