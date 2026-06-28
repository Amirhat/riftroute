// Live updates from riftrouted arrive as Wails runtime events: the desktop Go
// side holds the SSE stream and re-emits (spec §3.5). We read them off
// window.runtime so the app degrades gracefully when run outside the webview
// (e.g. a plain browser during UI development) instead of throwing.
import type { State } from '../types'

type Unsub = () => void
const noop: Unsub = () => {}

interface WailsRuntime {
  EventsOn(name: string, cb: (...data: unknown[]) => void): Unsub
}

function runtime(): WailsRuntime | null {
  const w = window as unknown as { runtime?: WailsRuntime }
  return w.runtime ?? null
}

/** Subscribe to fresh State snapshots. Returns an unsubscribe function. */
export function onState(cb: (s: State) => void): Unsub {
  return runtime()?.EventsOn('rr:state', (s) => cb(s as State)) ?? noop
}

/** Subscribe to daemon reachability changes. */
export function onConnection(cb: (reachable: boolean) => void): Unsub {
  return runtime()?.EventsOn('rr:connection', (d) => cb(Boolean((d as { reachable?: boolean })?.reachable))) ?? noop
}

/** Subscribe to native-menu actions bridged from the Go side. */
export function onMenu(cb: (action: string) => void): Unsub {
  return runtime()?.EventsOn('rr:menu', (a) => cb(String(a))) ?? noop
}
