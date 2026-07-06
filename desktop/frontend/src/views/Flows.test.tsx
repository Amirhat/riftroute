import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Flows } from './Flows'
import { api } from '../lib/api'
import type { Flow } from '../types'

vi.mock('../lib/api', () => ({ api: { flows: vi.fn() } }))
const mockApi = api as unknown as { flows: ReturnType<typeof vi.fn> }

const sample: Flow[] = [
  { proto: 'tcp', local: '10.8.0.2:50000', remote: '1.1.1.1:443', state: 'ESTABLISHED', process: 'firefox', iface: 'utun3', via_vpn: true },
  { proto: 'udp', local: '192.168.1.50:5353', remote: '224.0.0.251:5353', process: 'mDNSResponder', iface: 'en0', via_vpn: false },
]

function renderFlows() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Flows />
    </QueryClientProvider>,
  )
}

describe('Flows view', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.flows.mockResolvedValue(sample)
  })

  it('renders live connections with their VPN/direct path', async () => {
    renderFlows()
    expect(await screen.findByText('firefox')).toBeInTheDocument()
    expect(screen.getByText('mDNSResponder')).toBeInTheDocument()
    expect(screen.getByText('1 via VPN')).toBeInTheDocument()
    expect(screen.getByText('1 direct')).toBeInTheDocument()
  })

  it('filters to via-VPN flows only', async () => {
    renderFlows()
    await screen.findByText('firefox')
    fireEvent.click(screen.getByRole('button', { name: 'via VPN' }))
    expect(screen.getByText('firefox')).toBeInTheDocument()
    expect(screen.queryByText('mDNSResponder')).not.toBeInTheDocument()
  })

  it('handles an empty flow set without crashing', async () => {
    mockApi.flows.mockResolvedValue([])
    renderFlows()
    expect(await screen.findByText('No matching connections right now.')).toBeInTheDocument()
  })
})
