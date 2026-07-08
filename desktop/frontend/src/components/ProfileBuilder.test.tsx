import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ProfileBuilder } from './ProfileBuilder'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { saveProfile: vi.fn(), lists: vi.fn(), systemUsers: vi.fn(), systemApps: vi.fn() },
}))
const mockApi = api as unknown as {
  saveProfile: ReturnType<typeof vi.fn>
  lists: ReturnType<typeof vi.fn>
  systemUsers: ReturnType<typeof vi.fn>
  systemApps: ReturnType<typeof vi.fn>
}

const ROUTE_PH = '10.0.0.0/8 or 1.1.1.1'
const NAME_PH = 'e.g. work-vpn'
const DOMAIN_PH = '*.corp.example.com'

function renderBuilder(overrides: Record<string, unknown> = {}) {
  const onPending = vi.fn()
  const onApplied = vi.fn()
  const onClose = vi.fn()
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <ProfileBuilder
        existingNames={[]}
        platform="darwin"
        onPending={onPending}
        onApplied={onApplied}
        onClose={onClose}
        {...overrides}
      />
    </QueryClientProvider>,
  )
  return { onPending, onApplied, onClose }
}

const applyBtn = () => screen.getByText('Apply Changes Safely') as HTMLButtonElement

describe('ProfileBuilder', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.lists.mockResolvedValue([])
    mockApi.systemUsers.mockResolvedValue([{ uid: '501', username: 'amir', full_name: 'Amir H' }])
    mockApi.systemApps.mockResolvedValue([{ value: 'system.slice/nginx.service', name: 'nginx' }])
  })

  it('sets honest, actionable expectations for wildcard subdomain coverage', () => {
    renderBuilder()
    const hint = screen.getByText(/Wildcards/i)
    const text = hint.textContent || ''
    // Names concrete examples of what IS discovered proactively.
    expect(text).toMatch(/\b(app|api|www)\b/)
    // Is honest that coverage is not exhaustive…
    expect(text).toMatch(/not (all|every)|rare|custom|aren'?t guaranteed|may not/i)
    // …and gives the actionable escape hatch (add an exact rule).
    expect(text).toMatch(/add .*(rule|domain)/i)
    // Must not over-promise that everything routes automatically.
    expect(text).not.toMatch(/routes? (them )?all automatically/i)
  })

  it('offers known lists as toggleable references and serializes the selection', async () => {
    mockApi.lists.mockResolvedValue([{ name: 'corp-nets', static: ['10.0.0.0/8'] }])
    mockApi.saveProfile.mockResolvedValue({ result: { status: 'pending', needs_confirm: false } })
    renderBuilder()
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(await screen.findByText('corp-nets'))
    fireEvent.click(applyBtn())
    await vi.waitFor(() => expect(mockApi.saveProfile).toHaveBeenCalled())
    expect(mockApi.saveProfile.mock.calls[0][0]).toMatchObject({ lists: ['corp-nets'] })
  })

  it('validates a route target inline and blocks apply until fixed', () => {
    renderBuilder()
    fireEvent.click(screen.getByText('+ Add route target'))
    const input = screen.getByPlaceholderText(ROUTE_PH)
    fireEvent.change(input, { target: { value: '999.999.999' } })
    expect(screen.getByText('not a valid IP or CIDR')).toBeInTheDocument()
    expect(applyBtn().disabled).toBe(true)
    fireEvent.change(input, { target: { value: '10.0.0.0/8' } })
    expect(screen.queryByText('not a valid IP or CIDR')).not.toBeInTheDocument()
  })

  it('requires a name before applying', () => {
    renderBuilder()
    fireEvent.click(screen.getByText('+ Add route target'))
    fireEvent.change(screen.getByPlaceholderText(ROUTE_PH), { target: { value: '1.1.1.1' } })
    expect(applyBtn().disabled).toBe(true) // name missing
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    expect(applyBtn().disabled).toBe(false)
  })

  it('tracks a live staged banner as rows are added and removed', () => {
    renderBuilder()
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(screen.getByText('+ Add route target'))
    fireEvent.change(screen.getByPlaceholderText(ROUTE_PH), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByText('+ Add domain'))
    fireEvent.change(screen.getByPlaceholderText(DOMAIN_PH), { target: { value: '*.corp.example.com' } })

    const banner = screen.getByText('Staged configuration').parentElement as HTMLElement
    expect(banner.textContent).toContain('+1 route')
    expect(banner.textContent).toContain('+1 domain')

    // remove the route row → count drops
    fireEvent.click(screen.getAllByLabelText('Remove')[0])
    expect(banner.textContent).toContain('+0 routes')
    expect(banner.textContent).toContain('+1 domain')
  })

  it('validates a per-app uid rule on macOS via the user picker', async () => {
    renderBuilder()
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(screen.getByText('Include')) // app rules need include mode
    fireEvent.click(screen.getByText('+ Add app rule'))
    const input = screen.getByLabelText('App rule value')
    fireEvent.change(input, { target: { value: '/Applications/Firefox.app' } })
    expect(screen.getByText(/uid or username/)).toBeInTheDocument()
    fireEvent.change(input, { target: { value: '501' } })
    expect(screen.queryByText(/uid or username/)).not.toBeInTheDocument()
  })

  it('suggests local users in the macOS per-app picker and selects one', async () => {
    renderBuilder()
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(screen.getByText('Include'))
    fireEvent.click(screen.getByText('+ Add app rule'))
    const input = screen.getByLabelText('App rule value')
    fireEvent.focus(input)
    fireEvent.mouseDown(await screen.findByText('amir (uid 501)'))
    expect((input as HTMLInputElement).value).toBe('amir')
  })

  it('blocks apply when app rules are used in exclude mode', () => {
    renderBuilder()
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(screen.getByText('Include'))
    fireEvent.click(screen.getByText('+ Add app rule'))
    fireEvent.change(screen.getByLabelText('App rule value'), { target: { value: '501' } })
    expect(applyBtn().disabled).toBe(false)
    fireEvent.click(screen.getByText('Exclude'))
    expect(screen.getByText(/only take effect in Include mode/)).toBeInTheDocument()
    expect(applyBtn().disabled).toBe(true)
  })

  it('shows the review diff after preview and clears it when the form changes', async () => {
    mockApi.saveProfile.mockResolvedValue({
      plan: { ops: [{ kind: 'add_route', command: ['route', 'add', '1.1.1.1'] }], inverse: [] },
      diff: { adds: 1, dels: 0, entries: [], in_sync: false },
    })
    renderBuilder()
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(screen.getByText('+ Add route target'))
    fireEvent.change(screen.getByPlaceholderText(ROUTE_PH), { target: { value: '1.1.1.1' } })
    fireEvent.click(screen.getByText('Preview'))
    expect(await screen.findByText(/what applying will change/)).toBeInTheDocument()
    expect(screen.getByText('+1 to add')).toBeInTheDocument()
    // editing any field invalidates the shown preview
    fireEvent.change(screen.getByPlaceholderText(ROUTE_PH), { target: { value: '2.2.2.2' } })
    expect(screen.queryByText(/what applying will change/)).not.toBeInTheDocument()
  })

  it('reports a partial success (saved but not applied) as a warning and closes', async () => {
    mockApi.saveProfile.mockResolvedValue({ apply_error: 'include mode: no active VPN tunnel for v4 to route into' })
    const onWarning = vi.fn()
    const { onApplied, onClose, onPending } = renderBuilder({ onWarning })
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(screen.getByText('+ Add route target'))
    fireEvent.change(screen.getByPlaceholderText(ROUTE_PH), { target: { value: '1.1.1.1' } })
    fireEvent.click(applyBtn())
    await vi.waitFor(() => expect(onWarning).toHaveBeenCalled())
    expect(onWarning.mock.calls[0][0]).toMatch(/saved — not applied yet/i)
    expect(onApplied).toHaveBeenCalled()
    expect(onClose).toHaveBeenCalled()
    expect(onPending).not.toHaveBeenCalled()
  })

  it('serializes the form and hands a pending tx to commit-confirm on apply', async () => {
    mockApi.saveProfile.mockResolvedValue({
      result: { tx_id: 'tx-9', needs_confirm: true, status: 'pending', plan: { ops: [], inverse: [] }, diff: { adds: 1, dels: 0, changes: 0, in_sync: false } },
    })
    const { onPending, onApplied, onClose } = renderBuilder()
    fireEvent.change(screen.getByPlaceholderText(NAME_PH), { target: { value: 'work' } })
    fireEvent.click(screen.getByText('+ Add route target'))
    fireEvent.change(screen.getByPlaceholderText(ROUTE_PH), { target: { value: '1.1.1.1' } })
    fireEvent.click(applyBtn())

    await vi.waitFor(() => expect(mockApi.saveProfile).toHaveBeenCalled())
    const [profileArg, dryRunArg] = mockApi.saveProfile.mock.calls[0]
    expect(dryRunArg).toBe(false)
    expect(profileArg).toMatchObject({ name: 'work', mode: 'exclude', enabled: true, rules: [{ type: 'ip', value: '1.1.1.1' }] })

    await vi.waitFor(() => expect(onApplied).toHaveBeenCalled())
    expect(onClose).toHaveBeenCalled()
    expect(onPending).toHaveBeenCalledWith(expect.objectContaining({ tx_id: 'tx-9' }))
  })

  it('preserves rule types it has no editor for (asn/country) when editing', async () => {
    mockApi.saveProfile.mockResolvedValue({ result: { status: 'pending', needs_confirm: false } })
    renderBuilder({
      initial: {
        id: 'gui:geo', name: 'geo', enabled: true, mode: 'exclude', gateway: 'auto', priority: 0,
        rules: [
          { type: 'cidr', value: '10.0.0.0/8' },
          { type: 'asn', value: 'AS13335' },
          { type: 'country', value: 'DE' },
        ],
      },
    })
    expect(screen.getByText(/2 advanced rules \(asn\/country\) kept as-is/)).toBeInTheDocument()
    fireEvent.click(applyBtn())
    await vi.waitFor(() => expect(mockApi.saveProfile).toHaveBeenCalled())
    const rules = mockApi.saveProfile.mock.calls[0][0].rules
    expect(rules).toEqual(
      expect.arrayContaining([
        { type: 'cidr', value: '10.0.0.0/8' },
        { type: 'asn', value: 'AS13335' },
        { type: 'country', value: 'DE' },
      ]),
    )
  })

  it('pre-fills fields when editing an existing profile', () => {
    renderBuilder({
      initial: {
        id: 'gui:work', name: 'work', description: 'corp', enabled: true, mode: 'include', gateway: 'auto', priority: 0,
        rules: [{ type: 'cidr', value: '10.0.0.0/8' }, { type: 'domain', value: 'corp.example.com' }],
      },
    })
    expect((screen.getByPlaceholderText(NAME_PH) as HTMLInputElement).value).toBe('work')
    expect((screen.getByDisplayValue('10.0.0.0/8') as HTMLInputElement)).toBeInTheDocument()
    expect((screen.getByDisplayValue('corp.example.com') as HTMLInputElement)).toBeInTheDocument()
    expect(screen.getByText('Edit profile')).toBeInTheDocument()
  })
})
