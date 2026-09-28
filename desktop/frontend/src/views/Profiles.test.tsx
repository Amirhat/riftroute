import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Profiles } from './Profiles'
import { api } from '../lib/api'
import type { Profile, State } from '../types'

vi.mock('../lib/api', () => ({
  api: {
    profiles: vi.fn(),
    state: vi.fn(),
    lists: vi.fn(),
    plan: vi.fn(),
    apply: vi.fn(),
    confirm: vi.fn(),
    rollback: vi.fn(),
    setProfileEnabled: vi.fn(),
    deleteProfile: vi.fn(),
    saveList: vi.fn(),
    deleteList: vi.fn(),
    refreshList: vi.fn(),
    openConfigDialog: vi.fn(),
    applyConfigContent: vi.fn(),
  },
}))
const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>

const viaCon3: Profile = {
  id: 'via-con3',
  name: 'via con3',
  enabled: true,
  mode: 'tunnel',
  tunnel: 'con3',
  gateway: 'auto',
  priority: 0,
  rules: [{ type: 'ip', value: '9.9.9.9' }],
}

function renderView() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <Profiles />
    </QueryClientProvider>,
  )
}

describe('Profiles view — through a tunnel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.lists.mockResolvedValue([])
  })

  it('shows the tunnel a profile goes into, and says when it is down', async () => {
    mockApi.profiles.mockResolvedValue([viaCon3])
    mockApi.state.mockResolvedValue({
      tunnels: [{ name: 'con3', type: 'wireguard', state: 'disconnected' }],
      capabilities: { platform: 'darwin' },
    } as unknown as State)
    renderView()
    expect(await screen.findByText('→ tunnel con3 · WireGuard')).toBeInTheDocument()
    expect(await screen.findByText(/con3 isn't connected — its targets take their usual path/)).toBeInTheDocument()
    expect(screen.queryByText(/gateway auto/)).not.toBeInTheDocument()
  })

  it('says its targets are blocked while a block-mode tunnel is down', async () => {
    mockApi.profiles.mockResolvedValue([viaCon3])
    mockApi.state.mockResolvedValue({
      tunnels: [{ name: 'con3', type: 'wireguard', state: 'reconnecting', when_down: 'block', blocking: true }],
      capabilities: { platform: 'darwin' },
    } as unknown as State)
    renderView()
    expect(await screen.findByText(/con3 is down — its targets are blocked until it's back/)).toBeInTheDocument()
  })

  it('says a reconnecting tunnel carries nothing, so its targets take their usual path', async () => {
    mockApi.profiles.mockResolvedValue([viaCon3])
    mockApi.state.mockResolvedValue({
      tunnels: [{ name: 'con3', type: 'wireguard', state: 'reconnecting' }],
      capabilities: { platform: 'darwin' },
    } as unknown as State)
    renderView()
    expect(await screen.findByText(/con3 isn't connected — its targets take their usual path/)).toBeInTheDocument()
  })

  it('says when the tunnel it names does not exist', async () => {
    mockApi.profiles.mockResolvedValue([viaCon3])
    mockApi.state.mockResolvedValue({ tunnels: [], capabilities: { platform: 'darwin' } } as unknown as State)
    renderView()
    expect(await screen.findByText(/there's no tunnel named con3 — this profile routes nothing/)).toBeInTheDocument()
  })
})
