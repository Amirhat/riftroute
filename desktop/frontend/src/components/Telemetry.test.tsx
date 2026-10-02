import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { State } from '../types'
import { TelemetryNoticeBanner } from './Telemetry'

let current: Partial<State> | undefined
vi.mock('../lib/queries', () => ({
  stateKey: ['state'],
  useStateQuery: () => ({ data: current }),
}))
vi.mock('../lib/api', () => ({
  api: {
    setPreferences: vi.fn(),
    telemetryPreview: vi.fn(),
    telemetryNoticeSeen: vi.fn(),
  },
}))
const mockApi = api as unknown as Record<
  'setPreferences' | 'telemetryPreview' | 'telemetryNoticeSeen',
  ReturnType<typeof vi.fn>
>

function renderBanner() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <TelemetryNoticeBanner />
    </QueryClientProvider>,
  )
}

describe('TelemetryNoticeBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.setPreferences.mockResolvedValue({ updates: 'auto', telemetry: 'off' })
    mockApi.telemetryNoticeSeen.mockResolvedValue(undefined)
    mockApi.telemetryPreview.mockResolvedValue({
      level: 'full',
      next: { schema: 1, level: 'full' },
      waiting: 'until you’ve been told about telemetry',
      notice_seen: false,
    })
  })

  it('shows only while the user is yet to be told', () => {
    current = { telemetry_notice: false }
    const { container } = renderBanner()
    expect(container).toBeEmptyDOMElement()
  })

  it('OK marks the notice seen, and goes', async () => {
    current = { telemetry_notice: true }
    renderBanner()
    expect(screen.getByRole('status', { name: 'Telemetry notice' })).toHaveTextContent(
      /Never addresses, domains or names/,
    )
    fireEvent.click(screen.getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(mockApi.telemetryNoticeSeen).toHaveBeenCalled())
    expect(mockApi.setPreferences).not.toHaveBeenCalled()
    await waitFor(() => expect(screen.queryByRole('status', { name: 'Telemetry notice' })).not.toBeInTheDocument())
  })

  it('Turn off is one click: off, and seen', async () => {
    current = { telemetry_notice: true }
    renderBanner()
    fireEvent.click(screen.getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(mockApi.setPreferences).toHaveBeenCalledWith({ telemetry: 'off' }))
    await waitFor(() => expect(mockApi.telemetryNoticeSeen).toHaveBeenCalled())
  })

  it('See what’s sent shows the exact next report', async () => {
    current = { telemetry_notice: true }
    renderBanner()
    fireEvent.click(screen.getByRole('button', { name: 'See what’s sent' }))
    expect(await screen.findByLabelText('Next report')).toHaveTextContent('"level": "full"')
    expect(screen.getByText(/Next report: waiting until/)).toBeInTheDocument()
    expect(mockApi.telemetryNoticeSeen).toHaveBeenCalled()
  })
})
