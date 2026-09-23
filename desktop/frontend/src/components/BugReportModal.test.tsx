import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { BugReportModal } from './BugReportModal'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { createBugReport: vi.fn(), saveBugReport: vi.fn(), openIssuePage: vi.fn() },
}))
const mockApi = api as unknown as Record<'createBugReport' | 'saveBugReport' | 'openIssuePage', ReturnType<typeof vi.fn>>

const text = 'RiftRoute bug report\n## Daemon\ndefault via <ip4-lan-1> dev en0\n'

describe('BugReportModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.createBugReport.mockResolvedValue({ text, redactions: 12, generated_at: '2026-09-23T03:00:00Z' })
    mockApi.saveBugReport.mockResolvedValue('/tmp/report.txt')
  })

  // The full redacted text is on screen before any action is possible, and
  // building it sends nothing anywhere (only the local build call).
  it('shows the whole redacted report for review', async () => {
    render(<BugReportModal onClose={() => {}} />)
    expect(screen.getByText('Collecting diagnostics…')).toBeInTheDocument()
    const pre = await screen.findByLabelText('Report preview')
    expect(pre.textContent).toBe(text)
    expect(screen.getByText('12 values redacted')).toBeInTheDocument()
    expect(mockApi.saveBugReport).not.toHaveBeenCalled()
    expect(mockApi.openIssuePage).not.toHaveBeenCalled()
  })

  it('saves exactly the previewed text', async () => {
    render(<BugReportModal onClose={() => {}} />)
    await screen.findByLabelText('Report preview')
    fireEvent.click(screen.getByText('Save…'))
    await waitFor(() => expect(mockApi.saveBugReport).toHaveBeenCalledWith(text))
    expect(await screen.findByText('Saved to /tmp/report.txt')).toBeInTheDocument()
  })

  it('copies through the Wails clipboard and shows a refusal as an error', async () => {
    const set = vi.fn().mockResolvedValue(false)
    ;(window as unknown as { runtime: unknown }).runtime = { ClipboardSetText: set }
    render(<BugReportModal onClose={() => {}} />)
    await screen.findByLabelText('Report preview')
    fireEvent.click(screen.getByText('Copy'))
    const msg = await screen.findByText(/clipboard refused/)
    expect(set).toHaveBeenCalledWith(text)
    expect(msg.className).toContain('text-danger')
    delete (window as unknown as { runtime?: unknown }).runtime
  })

  it('reports a failure instead of an empty preview', async () => {
    mockApi.createBugReport.mockRejectedValue(new Error('boom'))
    render(<BugReportModal onClose={() => {}} />)
    expect(await screen.findByText(/boom/)).toBeInTheDocument()
    expect(screen.getByText('Save…')).toBeDisabled()
  })
})
