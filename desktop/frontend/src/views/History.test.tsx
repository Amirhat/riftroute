import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { History } from './History'
import { api } from '../lib/api'
import type { AuditEvent } from '../types'

vi.mock('../lib/api', () => ({
  api: { audit: vi.fn(), snapshots: vi.fn(), confirm: vi.fn(), rollback: vi.fn(), restoreSnapshot: vi.fn() },
}))
const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>

function renderView() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <History />
    </QueryClientProvider>,
  )
}

describe('History — how long a change took, and why one was reverted', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.snapshots.mockResolvedValue([])
  })

  it('says how long an applied change took, and where a slow one spent it', async () => {
    const evs: AuditEvent[] = [
      { id: 2, ts: '2026-09-30T10:00:05Z', actor: 'ui', action: 'apply', result: 'applied',
        timing: { total_ms: 5600, wait_ms: 900, build_ms: 4600, check_ms: 40, exec_ms: 60 } },
      { id: 1, ts: '2026-09-30T10:00:00Z', actor: 'ui', action: 'apply', result: 'applied',
        timing: { total_ms: 180, wait_ms: 0, build_ms: 120, check_ms: 20, exec_ms: 40 } },
      { id: 3, ts: '2026-09-30T10:01:00Z', actor: 'daemon-auto', action: 'rollback', result: 'rolled_back', rollback: true,
        reason: 'the connection was lost: no connectivity check answered, several times in a row' },
    ]
    mockApi.audit.mockResolvedValue(evs)
    renderView()
    const line = (re: RegExp) => (_: string, el: Element | null) => el?.tagName === 'DIV' && re.test(el.textContent ?? '')
    const slow = await screen.findByText(line(/^took 5\.6s/))
    expect(slow).toHaveTextContent('waiting for another change 0.9s, working out the routes 4.6s')
    expect(slow).not.toHaveTextContent('checking')
    expect(screen.getByText(line(/^took 0\.2s/))).not.toHaveTextContent('—')
    expect(screen.getByText(/the connection was lost/)).toBeInTheDocument()
  })
})
