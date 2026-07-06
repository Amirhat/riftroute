import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ListsManager, ListEditor } from './ListsManager'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: {
    lists: vi.fn(),
    saveList: vi.fn(),
    deleteList: vi.fn(),
    refreshList: vi.fn(),
  },
}))
const mockApi = api as unknown as Record<'lists' | 'saveList' | 'deleteList' | 'refreshList', ReturnType<typeof vi.fn>>

function withQC(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

describe('ListEditor', () => {
  beforeEach(() => vi.clearAllMocks())

  it('validates static entries inline and blocks save until fixed', () => {
    withQC(<ListEditor existingNames={[]} onSaved={() => {}} onClose={() => {}} />)
    fireEvent.change(screen.getByPlaceholderText('e.g. corp-nets'), { target: { value: 'corp' } })
    const entry = screen.getByPlaceholderText('10.0.0.0/8')
    fireEvent.change(entry, { target: { value: '999.999.999' } })
    expect(screen.getByText('not a valid IP or CIDR')).toBeInTheDocument()
    expect((screen.getByText('Save list') as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(entry, { target: { value: '10.0.0.0/8' } })
    expect((screen.getByText('Save list') as HTMLButtonElement).disabled).toBe(false)
  })

  it('requires an https source for remote lists', () => {
    withQC(<ListEditor existingNames={[]} onSaved={() => {}} onClose={() => {}} />)
    fireEvent.change(screen.getByPlaceholderText('e.g. corp-nets'), { target: { value: 'ads' } })
    fireEvent.click(screen.getByText('Remote (subscribable)'))
    const src = screen.getByPlaceholderText('https://example.com/ranges.txt')
    fireEvent.change(src, { target: { value: 'http://insecure.example/x' } })
    expect(screen.getByText('must be an https:// URL')).toBeInTheDocument()
    fireEvent.change(src, { target: { value: 'https://example.com/x' } })
    expect(screen.queryByText('must be an https:// URL')).not.toBeInTheDocument()
  })

  it('serializes and saves a valid static list', async () => {
    mockApi.saveList.mockResolvedValue({ name: 'corp', static: ['10.0.0.0/8'] })
    const onSaved = vi.fn()
    withQC(<ListEditor existingNames={[]} onSaved={onSaved} onClose={() => {}} />)
    fireEvent.change(screen.getByPlaceholderText('e.g. corp-nets'), { target: { value: 'corp' } })
    fireEvent.change(screen.getByPlaceholderText('10.0.0.0/8'), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByText('Save list'))
    await vi.waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(mockApi.saveList).toHaveBeenCalledWith({ name: 'corp', static: ['10.0.0.0/8'] })
  })

  it('rejects a duplicate list name', () => {
    withQC(<ListEditor existingNames={['corp']} onSaved={() => {}} onClose={() => {}} />)
    fireEvent.change(screen.getByPlaceholderText('e.g. corp-nets'), { target: { value: 'corp' } })
    expect(screen.getByText('a list with this name already exists')).toBeInTheDocument()
  })
})

describe('ListsManager', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders lists and surfaces a delete refusal as a friendly error', async () => {
    mockApi.lists.mockResolvedValue([{ name: 'corp', static: ['10.0.0.0/8'] }])
    mockApi.deleteList.mockRejectedValue(new Error('list "corp" is used by profile "work" — remove it from the profile first'))
    withQC(<ListsManager />)
    expect(await screen.findByText('corp')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Delete'))
    fireEvent.click(await screen.findByText('Delete list')) // confirm modal
    expect(await screen.findByText(/used by profile "work"/)).toBeInTheDocument()
  })
})
