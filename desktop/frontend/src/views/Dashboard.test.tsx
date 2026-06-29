import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { State } from '../types'

// The real macOS provider emits interfaces with addrs:null and can report
// servers:null — shapes the fake provider never produces. This regression test
// renders the Dashboard with that exact shape; before the fix, `addrs[0]` threw
// and blanked the whole app.
const realish: State = {
  health: { daemon: 'ok', version: '1.0.0', provider: 'macos', uptime_seconds: 42, pid: 1 },
  capabilities: {
    platform: 'darwin', policy_routing: false, fwmark: false, per_app_routing: false,
    proto_tag: false, ipv6: true, kill_switch: true, iface_scoping: true,
  },
  vpn: { active: true, interfaces: ['utun8'] },
  interfaces: [
    { name: 'lo0', up: true, kind: 'loopback', addrs: ['127.0.0.1/8'], mtu: 16384, is_vpn: false },
    { name: 'gif0', up: false, kind: 'other', addrs: null, mtu: 1280, is_vpn: false }, // ← the crasher
    { name: 'utun8', up: true, kind: 'tunnel', addrs: null, mtu: 1400, is_vpn: true },
  ],
  defaults: [{ family: 'v4', present: true, gateway: '', iface: 'utun8', owner: 'vpn', via_vpn: true }],
  dns: { servers: null, search_domains: null }, // ← also previously crashed
  profiles: [],
  drift: { pending: false, adds: 0, dels: 0, changes: 0 },
  managed_route_count: 0,
  auto_apply: false,
  kill_switch: false,
  generated_at: new Date(0).toISOString(),
}

vi.mock('../lib/queries', () => ({
  useStateQuery: () => ({ data: realish, isLoading: false, isError: false, error: null, refetch: () => {} }),
}))

describe('Dashboard with real-provider (null-bearing) data', () => {
  it('renders without crashing on null addrs / null servers', async () => {
    const { Dashboard } = await import('./Dashboard')
    expect(() => render(<Dashboard />)).not.toThrow()
    expect(screen.getByText('Interfaces')).toBeInTheDocument()
    expect(screen.getByText('gif0')).toBeInTheDocument() // the null-addrs row rendered
    expect(screen.getByText('No resolvers reported.')).toBeInTheDocument() // null servers handled
  })
})
