import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RoutesView, filterRoutes } from './RoutesView'
import { api } from '../lib/api'
import type { Profile, Route, State } from '../types'

// jsdom reports zero dimensions, so @tanstack/react-virtual renders no rows.
// Give the scroll container a real height so virtualized rows (and their
// action buttons) mount, matching the browser.
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 600 })
  Object.defineProperty(HTMLElement.prototype, 'offsetWidth', { configurable: true, value: 800 })
  Element.prototype.getBoundingClientRect = function () {
    return { width: 800, height: 600, top: 0, left: 0, right: 800, bottom: 600, x: 0, y: 0, toJSON() {} } as DOMRect
  }
})

vi.mock('../lib/api', () => ({
  api: {
    routes: vi.fn(),
    rules: vi.fn(),
    profiles: vi.fn(),
    explain: vi.fn(),
    saveProfile: vi.fn(),
    deleteProfile: vi.fn(),
    routeOp: vi.fn(),
    interfaces: vi.fn(),
    state: vi.fn(),
    confirm: vi.fn(),
    rollback: vi.fn(),
  },
}))
const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>

const routes: Route[] = [
  { dst_cidr: '198.51.100.0/24', gateway: '10.8.0.1', iface: 'utun4', metric: 0, family: 'v4', owner: 'riftroute', profile: 'manual-vpn' },
  { dst_cidr: '0.0.0.0/0', gateway: '192.168.1.1', iface: 'en0', metric: 0, family: 'v4', owner: 'system' },
]

const state = {
  vpn: { active: true, interfaces: ['utun4'] },
  capabilities: { platform: 'darwin' },
  drift: { pending: false, adds: 0, dels: 0 },
} as unknown as State

const manualProfile: Profile = {
  id: 'manual-vpn',
  name: 'Manual routes (via VPN)',
  enabled: true,
  mode: 'include',
  gateway: 'auto',
  priority: 0,
  rules: [{ type: 'cidr', value: '198.51.100.0/24' }],
}

function renderView() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <RoutesView />
    </QueryClientProvider>,
  )
}

describe('filterRoutes', () => {
  it('matches substrings across destination, gateway, iface, and profile', () => {
    expect(filterRoutes(routes, '198.51', '')).toHaveLength(1)
    expect(filterRoutes(routes, 'en0', '')).toHaveLength(1)
    expect(filterRoutes(routes, 'manual', '')).toHaveLength(1)
    expect(filterRoutes(routes, 'nomatch', '')).toHaveLength(0)
    expect(filterRoutes(routes, '', '')).toHaveLength(2)
  })

  it('narrows by owner', () => {
    expect(filterRoutes(routes, '', 'riftroute')).toHaveLength(1)
    expect(filterRoutes(routes, '198.51', 'system')).toHaveLength(0)
  })
})

describe('RoutesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.routes.mockResolvedValue(routes)
    mockApi.rules.mockResolvedValue([
      { priority: 5252, selector: 'from any to any user 501', table: '', family: 'v4', proto: 'riftroute', route_to_iface: 'utun4' },
    ])
    mockApi.profiles.mockResolvedValue([manualProfile])
    mockApi.state.mockResolvedValue(state)
    mockApi.interfaces.mockResolvedValue([{ name: 'en0', kind: 'phys', up: true, is_vpn: false }])
  })

  it('shows the route count footer sorted by precedence', async () => {
    renderView()
    expect(await screen.findByText(/showing 2 of 2 routes/)).toBeInTheDocument()
  })

  it('filters routes from the search box', async () => {
    renderView()
    await screen.findByText(/showing 2 of 2 routes/)
    fireEvent.change(screen.getByLabelText('Filter routes'), { target: { value: 'en0' } })
    expect(await screen.findByText(/showing 1 of 2 routes/)).toBeInTheDocument()
  })

  it('looks up a target and renders both decisions', async () => {
    mockApi.explain.mockResolvedValue({
      target: 'netflix.com',
      resolved: ['198.51.100.7'],
      kernel: { target: '198.51.100.7', source: 'kernel', matched_cidr: '198.51.100.0/24', gateway: '10.8.0.1', iface: 'utun4', family: 'v4', via_vpn: true, reachable: true },
      simulated: { target: '198.51.100.7', source: 'simulated', matched_cidr: '198.51.100.0/24', gateway: '10.8.0.1', iface: 'utun4', family: 'v4', via_vpn: true, reachable: true },
      drift: false,
    })
    renderView()
    fireEvent.change(screen.getByLabelText('Lookup target'), { target: { value: 'netflix.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Look up' }))
    expect(await screen.findByText('Now (kernel)')).toBeInTheDocument()
    expect(screen.getByText('After apply (desired)')).toBeInTheDocument()
    expect(mockApi.explain).toHaveBeenCalledWith('netflix.com')
  })

  it('lists manual routes and adds a new one through the manual profile', async () => {
    mockApi.saveProfile.mockResolvedValue({ result: { applied: true } })
    renderView()
    // existing manual rule listed with its path
    expect(await screen.findByRole('button', { name: 'Remove manual route 198.51.100.0/24' })).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Manual route destination'), { target: { value: '203.0.113.9' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add route' }))
    await waitFor(() => expect(mockApi.saveProfile).toHaveBeenCalled())
    const [saved, dryRun] = mockApi.saveProfile.mock.calls[0]
    expect(dryRun).toBe(false)
    expect(saved.id).toBe('manual-bypass') // default path is bypass
    expect(saved.mode).toBe('exclude')
    expect(saved.rules).toEqual([{ type: 'ip', value: '203.0.113.9' }])
  })

  it('refuses duplicate manual destinations with a clear error', async () => {
    renderView()
    await screen.findByRole('button', { name: 'Remove manual route 198.51.100.0/24' })
    fireEvent.change(screen.getByLabelText('Manual route destination'), { target: { value: '198.51.100.0/24' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add route' }))
    expect(await screen.findByText(/already a manual route/)).toBeInTheDocument()
    expect(mockApi.saveProfile).not.toHaveBeenCalled()
  })

  it('removes the manual profile entirely when its last route is deleted', async () => {
    mockApi.deleteProfile.mockResolvedValue({})
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Remove manual route 198.51.100.0/24' }))
    await waitFor(() => expect(mockApi.deleteProfile).toHaveBeenCalledWith('Manual routes (via VPN)'))
    expect(mockApi.saveProfile).not.toHaveBeenCalled()
  })

  it('rejects invalid destinations inline without calling the daemon', async () => {
    renderView()
    await screen.findByText(/showing 2 of 2 routes/)
    fireEvent.change(screen.getByLabelText('Manual route destination'), { target: { value: '999.999.999' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add route' }))
    expect(await screen.findByText('not a valid IP or CIDR')).toBeInTheDocument()
    expect(mockApi.saveProfile).not.toHaveBeenCalled()
  })

  it('renders policy rules with their steering target', async () => {
    renderView()
    expect(await screen.findByText('from any to any user 501')).toBeInTheDocument()
    expect(screen.getByText('route-to utun4')).toBeInTheDocument()
  })

  it('deletes an external route through the plan-level protocol', async () => {
    mockApi.routeOp.mockResolvedValue({ result: { needs_confirm: false } })
    // A deletable (non-default) external route.
    mockApi.routes.mockResolvedValue([
      ...routes,
      { dst_cidr: '10.0.8.0/24', gateway: '192.168.1.1', iface: 'en0', metric: 0, family: 'v4', owner: 'system' },
    ])
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete route 10.0.8.0/24' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Delete route' }))
    await waitFor(() => expect(mockApi.routeOp).toHaveBeenCalled())
    const [action, route] = mockApi.routeOp.mock.calls[0]
    expect(action).toBe('delete')
    expect(route.dst_cidr).toBe('10.0.8.0/24')
    expect(route.owner).toBe('system')
  })

  it('does not offer delete/edit on riftroute-managed routes', async () => {
    renderView()
    await screen.findByText(/showing 2 of 2 routes/)
    // The managed row (198.51.100.0/24) shows "via profile" instead of actions.
    expect(screen.getByText('via profile')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete route 198.51.100.0/24' })).not.toBeInTheDocument()
  })

  it('disables deleting the default route (guarded)', async () => {
    renderView()
    const btn = (await screen.findByRole('button', { name: 'Delete route 0.0.0.0/0' })) as HTMLButtonElement
    expect(btn.disabled).toBe(true)
  })

  it('edits an external route via the edit dialog', async () => {
    mockApi.routeOp.mockResolvedValue({ result: { needs_confirm: false } })
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit route 0.0.0.0/0' }))
    const gw = await screen.findByLabelText('Route gateway')
    fireEvent.change(gw, { target: { value: '192.168.1.254' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply change' }))
    await waitFor(() => expect(mockApi.routeOp).toHaveBeenCalled())
    const [action, , updated] = mockApi.routeOp.mock.calls[0]
    expect(action).toBe('replace')
    expect(updated.gateway).toBe('192.168.1.254')
  })
})
