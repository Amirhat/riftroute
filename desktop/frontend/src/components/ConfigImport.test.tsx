import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ConfigImport } from './ConfigImport'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: {
    openConfigDialog: vi.fn(),
    applyConfigContent: vi.fn(),
  },
}))

const mockApi = api as unknown as {
  openConfigDialog: ReturnType<typeof vi.fn>
  applyConfigContent: ReturnType<typeof vi.fn>
}

const yamlFile = { path: '/x/riftroute.yaml', name: 'riftroute.yaml', format: 'yaml', content: 'version: 1' }

describe('ConfigImport', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows a visual plan preview for a valid config', async () => {
    mockApi.openConfigDialog.mockResolvedValue(yamlFile)
    mockApi.applyConfigContent.mockResolvedValue({
      issues: [],
      plan: { ops: [{ kind: 'add_route', command: ['ip', 'route', 'add', '10.0.0.0/8'], human: '' }], inverse: [] },
    })

    render(<ConfigImport onPending={() => {}} onApplied={() => {}} />)
    fireEvent.click(screen.getByText('Import / Apply Config File'))

    expect(await screen.findByText('riftroute.yaml')).toBeInTheDocument()
    expect(await screen.findByText('1 change(s) to apply:')).toBeInTheDocument()
    expect(screen.getByText('ip route add 10.0.0.0/8')).toBeInTheDocument()
    // dry-run only: nothing applied yet.
    expect(mockApi.applyConfigContent).toHaveBeenCalledWith('version: 1', 'yaml', true, false)
    expect((screen.getByText('Apply to daemon') as HTMLButtonElement).disabled).toBe(false)
  })

  it('renders line-referenced validation errors and blocks apply (no crash)', async () => {
    mockApi.openConfigDialog.mockResolvedValue(yamlFile)
    mockApi.applyConfigContent.mockResolvedValue({
      issues: [{ severity: 'error', line: 3, msg: 'invalid CIDR "nope"' }],
    })

    render(<ConfigImport onPending={() => {}} onApplied={() => {}} />)
    fireEvent.click(screen.getByText('Import / Apply Config File'))

    expect(await screen.findByText(/errors and can/)).toBeInTheDocument()
    expect(screen.getByText(/invalid CIDR "nope"/)).toBeInTheDocument()
    expect((screen.getByText('Apply to daemon') as HTMLButtonElement).disabled).toBe(true)
  })

  it('does nothing when the file dialog is cancelled', async () => {
    mockApi.openConfigDialog.mockResolvedValue({ path: '', name: '', format: '', content: '' })
    render(<ConfigImport onPending={() => {}} onApplied={() => {}} />)
    fireEvent.click(screen.getByText('Import / Apply Config File'))
    // let the promise settle
    await Promise.resolve()
    expect(screen.queryByText('Import config')).not.toBeInTheDocument()
    expect(mockApi.applyConfigContent).not.toHaveBeenCalled()
  })

  it('surfaces a friendly error if reading the file fails', async () => {
    mockApi.openConfigDialog.mockRejectedValue(new Error('could not read riftroute.yaml: permission denied'))
    render(<ConfigImport onPending={() => {}} onApplied={() => {}} />)
    fireEvent.click(screen.getByText('Import / Apply Config File'))
    expect(await screen.findByText(/permission denied/)).toBeInTheDocument()
  })
})
