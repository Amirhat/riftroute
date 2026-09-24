import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Tunnels } from './Tunnels'
import { api } from '../lib/api'
import type { State, TunnelStatus } from '../types'

vi.mock('../lib/api', () => ({
  api: {
    state: vi.fn(),
    connectTunnel: vi.fn(),
    disconnectTunnel: vi.fn(),
    deleteTunnel: vi.fn(),
    saveTunnel: vi.fn(),
    openTunnelProfile: vi.fn(),
  },
}))
const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>

const connected: TunnelStatus = {
  name: 'infra',
  type: 'openvpn',
  via: 'direct',
  routes: ['192.168.70.0/24', '192.168.72.11'],
  auto_connect: true,
  username: 'alice',
  has_password: true,
  needs_auth: true,
  servers: ['198.51.100.7:1194/tcp'],
  ignored: ['redirect-gateway', 'user'],
  state: 'connected',
  iface: 'utun6',
  local_ip: '10.20.20.15',
  server: '198.51.100.7:1194',
  since: new Date(Date.now() - 65_000).toISOString(),
  bytes_in: 2048,
  bytes_out: 512,
}

function withTunnels(tunnels: TunnelStatus[]) {
  mockApi.state.mockResolvedValue({ tunnels } as unknown as State)
}

function renderView() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Tunnels />
    </QueryClientProvider>,
  )
}

describe('Tunnels view', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows a connected tunnel with where its traffic goes', async () => {
    withTunnels([connected])
    renderView()
    expect(await screen.findByText('infra')).toBeInTheDocument()
    expect(screen.getByText('192.168.70.0/24')).toBeInTheDocument()
    expect(screen.getByText('192.168.72.11')).toBeInTheDocument()
    expect(screen.getByText(/utun6 · 10\.20\.20\.15/)).toBeInTheDocument()
    expect(screen.getByText('auto-connect')).toBeInTheDocument()
    expect(screen.getByText(/redirect-gateway, user/)).toBeInTheDocument()
    mockApi.disconnectTunnel.mockResolvedValue({
      ...connected,
      state: 'disconnected',
    })
    fireEvent.click(screen.getByText('Disconnect'))
    await waitFor(() => expect(mockApi.disconnectTunnel).toHaveBeenCalledWith('infra'))
  })

  it('shows why a tunnel failed and offers to connect', async () => {
    withTunnels([
      {
        ...connected,
        state: 'failed',
        iface: '',
        since: undefined,
        last_error: 'the server rejected the username or password',
      },
    ])
    renderView()
    expect(await screen.findByText('the server rejected the username or password')).toBeInTheDocument()
    mockApi.connectTunnel.mockResolvedValue(connected)
    fireEvent.click(screen.getByText('Connect'))
    await waitFor(() => expect(mockApi.connectTunnel).toHaveBeenCalledWith('infra'))
  })

  it('adds a tunnel from a profile and connects it', async () => {
    withTunnels([])
    mockApi.openTunnelProfile.mockResolvedValue({
      path: '/Users/me/office.ovpn',
      name: 'office.ovpn',
      config: 'client\nremote 198.51.100.7\nauth-user-pass\n',
      servers: ['198.51.100.7:1194/udp'],
      needs_auth: true,
      ignored: ['redirect-gateway'],
      username: '',
      password: '',
      error: '',
    })
    mockApi.saveTunnel.mockResolvedValue({
      tunnel: { ...connected, name: 'office', state: 'disconnected' },
    })
    mockApi.connectTunnel.mockResolvedValue(connected)
    renderView()
    fireEvent.click(await screen.findByText('+ Add Tunnel'))
    fireEvent.click(screen.getByText('Choose .ovpn…'))
    expect(await screen.findByText('office.ovpn')).toBeInTheDocument()
    expect(screen.getByDisplayValue('office')).toBeInTheDocument() // name from the file
    const inputs = screen.getAllByRole('textbox')
    fireEvent.change(inputs[1], { target: { value: 'alice' } }) // username
    fireEvent.change(document.querySelector('input[type=password]')!, {
      target: { value: 'pw' },
    })
    fireEvent.change(screen.getByPlaceholderText(/192\.168\.70\.0\/24/), {
      target: { value: '192.168.70.0/24\n192.168.72.11' },
    })
    fireEvent.click(screen.getByText('Save & connect'))
    await waitFor(() =>
      expect(mockApi.saveTunnel).toHaveBeenCalledWith({
        name: 'office',
        type: 'openvpn',
        config: 'client\nremote 198.51.100.7\nauth-user-pass\n',
        username: 'alice',
        password: 'pw',
        via: 'direct',
        routes: ['192.168.70.0/24', '192.168.72.11'],
        auto_connect: false,
      }),
    )
    await waitFor(() => expect(mockApi.connectTunnel).toHaveBeenCalledWith('office'))
  })

  it('renders the daemon’s field errors inline', async () => {
    withTunnels([])
    mockApi.openTunnelProfile.mockResolvedValue({
      path: '/p.ovpn',
      name: 'p.ovpn',
      config: 'x',
      servers: [],
      needs_auth: false,
      ignored: [],
      username: '',
      password: '',
      error: '',
    })
    mockApi.saveTunnel.mockResolvedValue({
      issues: [
        {
          severity: 'error',
          field: 'routes',
          msg: '0.0.0.0/0 would send ALL traffic into the tunnel',
        },
      ],
    })
    renderView()
    fireEvent.click(await screen.findByText('+ Add Tunnel'))
    fireEvent.click(screen.getByText('Choose .ovpn…'))
    await screen.findByText('p.ovpn')
    fireEvent.click(screen.getByText('Save'))
    expect(await screen.findByText(/would send ALL traffic/)).toBeInTheDocument()
    expect(mockApi.connectTunnel).not.toHaveBeenCalled()
  })
})

describe('Tunnels view — routes left out', () => {
  it('shows which routes are not installed on this network, and why', async () => {
    mockApi.state.mockResolvedValue({
      tunnels: [
        {
          ...connected,
          routes: ['192.168.0.0/16', '192.168.70.0/24'],
          blocked: [
            { route: '192.168.0.0/16', reason: 'contains your router 192.168.1.1 — it would cut your connection' },
          ],
        },
      ],
    } as unknown as State)
    renderView()
    expect(
      await screen.findByText(/isn't installed on this network: contains your router 192\.168\.1\.1/),
    ).toBeInTheDocument()
    expect(screen.getByText('192.168.70.0/24')).toBeInTheDocument()
  })
})
