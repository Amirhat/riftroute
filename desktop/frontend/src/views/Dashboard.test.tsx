import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { State } from '../types'

// The real macOS provider emits interfaces with addrs:null, and a degraded read
// marshals interfaces/defaults/servers as null — shapes the fake provider never
// produces. This regression test renders the Dashboard with those exact shapes;
// before the fixes, `addrs[0]` / `defaults.find` threw and blanked the app.
const base: State = {
  health: { daemon: 'ok', version: '1.0.0', provider: 'macos', uptime_seconds: 42, pid: 1 },
  capabilities: {
    platform: 'darwin', policy_routing: true, fwmark: false, per_app_routing: true,
    proto_tag: false, ipv6: true, kill_switch: true, iface_scoping: true, backend: 'pf',
  },
  vpn: { active: true, interfaces: ['utun8'] },
  interfaces: [
    { name: 'lo0', up: true, kind: 'loopback', addrs: ['127.0.0.1/8'], mtu: 16384, is_vpn: false },
    { name: 'gif0', up: false, kind: 'other', addrs: null, mtu: 1280, is_vpn: false }, // ← null addrs
    { name: 'utun8', up: true, kind: 'tunnel', addrs: null, mtu: 1400, is_vpn: true },
  ],
  defaults: [{ family: 'v4', present: true, gateway: '', iface: 'utun8', owner: 'vpn', via_vpn: true }],
  dns: { servers: null, search_domains: null },
  profiles: [],
  drift: { pending: false, adds: 0, dels: 0 },
  managed_rule_count: 0,
  managed_route_count: 0,
  auto_apply: false,
  kill_switch: false,
  generated_at: new Date(0).toISOString(),
}

let current: State = base
vi.mock('../lib/queries', () => ({
  useStateQuery: () => ({ data: current, isLoading: false, isError: false, error: null, refetch: () => {} }),
}))

describe('Dashboard with real-provider (null-bearing) data', () => {
  it('renders with null addrs / null servers', async () => {
    current = base
    const { Dashboard } = await import('./Dashboard')
    expect(() => render(<Dashboard />)).not.toThrow()
    expect(screen.getByText('Interfaces')).toBeInTheDocument()
    expect(screen.getByText('gif0')).toBeInTheDocument()
    expect(screen.getByText('No resolvers reported.')).toBeInTheDocument()
  })

  it('renders a fully degraded State (interfaces/defaults null) without crashing', async () => {
    current = { ...base, interfaces: null, defaults: null }
    const { Dashboard } = await import('./Dashboard')
    expect(() => render(<Dashboard />)).not.toThrow()
    expect(screen.getByText('Interfaces')).toBeInTheDocument() // header still renders (0/0 up)
  })
})
