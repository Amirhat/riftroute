import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Tunnels } from './Tunnels'
import { api } from '../lib/api'
import type { State, TunnelProfileFile, TunnelStatus, UpdateStatus } from '../types'

vi.mock('../lib/api', () => ({
  api: {
    state: vi.fn(),
    connectTunnel: vi.fn(),
    disconnectTunnel: vi.fn(),
    deleteTunnel: vi.fn(),
    saveTunnel: vi.fn(),
    openTunnelProfile: vi.fn(),
    tunnelEngine: vi.fn(),
    checkUpdate: vi.fn(),
    setProfileEnabled: vi.fn(),
    apply: vi.fn(),
    confirm: vi.fn(),
    rollback: vi.fn(),
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

const officeProfile: TunnelProfileFile = {
  path: '/Users/me/office.ovpn',
  name: 'office.ovpn',
  config: 'client\nremote 198.51.100.7\nauth-user-pass\n',
  servers: ['198.51.100.7:1194/udp'],
  needs_auth: true,
  ignored: ['redirect-gateway'],
  username: 'alice',
  password: 'pw',
  error: '',
}

function withTunnels(tunnels: TunnelStatus[]) {
  mockApi.state.mockResolvedValue({ tunnels } as unknown as State)
}

function renderView(onOpenUpdates?: () => void) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Tunnels onOpenUpdates={onOpenUpdates} />
    </QueryClientProvider>,
  )
}

describe('Tunnels view', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.tunnelEngine.mockResolvedValue({ available: true, path: '/usr/sbin/openvpn', version: '2.6.14' })
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

  it('says when an app rule still sends some traffic past a tunnel route', async () => {
    withTunnels([{ ...connected, captured: [{ route: '192.168.70.0/24', reason: 'Firefox is sent into utun4 by the profile “work apps”' }] }])
    renderView()
    expect(await screen.findByText(/still goes past it/)).toHaveTextContent('Firefox is sent into utun4')
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
    fireEvent.click(screen.getByText('Choose a file…'))
    expect(await screen.findByText('office.ovpn')).toBeInTheDocument()
    expect(screen.getByDisplayValue('office')).toBeInTheDocument() // name from the file
    expect(screen.queryByText(/Also read/)).not.toBeInTheDocument() // the picker reported no files
    fireEvent.change(screen.getByRole('textbox', { name: 'Username' }), { target: { value: 'alice' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Networks through this tunnel' }), {
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
    fireEvent.click(screen.getByText('Choose a file…'))
    await screen.findByText('p.ovpn')
    fireEvent.click(screen.getByText('Save'))
    expect(await screen.findByText(/would send ALL traffic/)).toBeInTheDocument()
    expect(mockApi.connectTunnel).not.toHaveBeenCalled()
  })

  it('keeps the editor’s warnings when saving and connecting in one go', async () => {
    withTunnels([])
    mockApi.openTunnelProfile.mockResolvedValue(officeProfile)
    const warning = '192.168.0.0/16 contains your router (192.168.1.1), so it isn’t installed while you’re on this network'
    mockApi.saveTunnel.mockResolvedValue({
      tunnel: { ...connected, name: 'office', state: 'disconnected' },
      issues: [{ severity: 'warning', field: 'routes', msg: warning }],
    })
    mockApi.connectTunnel.mockResolvedValue(connected)
    renderView()
    fireEvent.click(await screen.findByText('+ Add Tunnel'))
    fireEvent.click(screen.getByText('Choose a file…'))
    await screen.findByText('office.ovpn')
    fireEvent.change(screen.getByRole('textbox', { name: 'Networks through this tunnel' }), {
      target: { value: '192.168.0.0/16' },
    })
    fireEvent.click(screen.getByText('Save & connect'))
    await waitFor(() => expect(mockApi.connectTunnel).toHaveBeenCalledWith('office'))
    // The connect finished and the notice is still up; ✕ dismisses it.
    await waitFor(() => expect(screen.getByText(warning)).toBeInTheDocument())
    expect(screen.getByText(warning)).toHaveClass('text-warning')
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByText(warning)).not.toBeInTheDocument()
  })

  it('checks each route line before Save, and styles the daemon’s warnings apart from its errors', async () => {
    withTunnels([])
    mockApi.openTunnelProfile.mockResolvedValue({ ...officeProfile, needs_auth: false })
    renderView()
    fireEvent.click(await screen.findByText('+ Add Tunnel'))
    fireEvent.click(screen.getByText('Choose a file…'))
    await screen.findByText('office.ovpn')
    const routes = screen.getByRole('textbox', { name: 'Networks through this tunnel' })
    fireEvent.change(routes, { target: { value: '192.168.70.0/24\n999.1.1.1\n\n10.0.0.0/33' } })
    const lineError = (text: string) => (_: string, el: Element | null) =>
      el?.tagName === 'P' && el.textContent === text
    expect(screen.getByText(lineError('Line 2: 999.1.1.1 — not a valid IP or CIDR'))).toHaveClass('text-danger')
    expect(screen.getByText(lineError('Line 4: 10.0.0.0/33 — prefix must be 0–32'))).toBeInTheDocument()
    expect(routes).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save & connect' })).toBeDisabled()

    // Fixed: the daemon's own verdict shows, errors red and warnings amber;
    // an issue for a field the form doesn't show still surfaces.
    fireEvent.change(routes, { target: { value: '0.0.0.0/0\n192.168.0.0/16' } })
    expect(screen.queryByText(/^Line \d/)).not.toBeInTheDocument()
    mockApi.saveTunnel.mockResolvedValue({
      issues: [
        { severity: 'error', field: 'routes', msg: '0.0.0.0/0 would send ALL traffic into the tunnel' },
        { severity: 'warning', field: 'routes', msg: '192.168.0.0/16 contains your router (192.168.1.1)' },
        { severity: 'error', field: 'via', msg: 'via must be "direct" or "default"' },
      ],
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/would send ALL traffic/)).toHaveClass('text-danger')
    expect(screen.getByText(/contains your router/)).toHaveClass('text-warning')
    expect(screen.getByText(/via must be/)).toHaveClass('text-danger')
    expect(mockApi.saveTunnel).toHaveBeenCalledWith(
      expect.objectContaining({ routes: ['0.0.0.0/0', '192.168.0.0/16'] }),
    )
  })

  it('lists the local files a profile pulled in', async () => {
    withTunnels([])
    mockApi.openTunnelProfile.mockResolvedValue({
      ...officeProfile,
      files: ['/Users/me/vpn/ca.crt', '/Users/me/vpn/auth.txt'],
    })
    renderView()
    fireEvent.click(await screen.findByText('+ Add Tunnel'))
    fireEvent.click(screen.getByText('Choose a file…'))
    const files = await screen.findByText('/Users/me/vpn/ca.crt, /Users/me/vpn/auth.txt')
    expect(files).toHaveClass('ltr', 'font-mono')
    expect(files.parentElement).toHaveTextContent(/^Also read:/)
    expect(files.parentElement).toHaveClass('text-muted')
  })

  it('deletes a tunnel after confirming in the app’s own dialog', async () => {
    withTunnels([connected])
    mockApi.deleteTunnel.mockResolvedValue(undefined)
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete infra' }))
    expect(screen.getByText('Delete tunnel infra')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(mockApi.deleteTunnel).toHaveBeenCalledWith('infra'))
  })

  it('runs no per-second timer while no tunnel is connected', async () => {
    const setIntervalSpy = vi.spyOn(globalThis, 'setInterval')
    try {
      withTunnels([{ ...connected, state: 'disconnected', since: undefined, iface: undefined }])
      renderView()
      expect(await screen.findByText('infra')).toBeInTheDocument()
      expect(screen.getByText('Reaches server')).toBeInTheDocument()
      expect(setIntervalSpy.mock.calls.filter(([, ms]) => ms === 1000)).toHaveLength(0)
    } finally {
      setIntervalSpy.mockRestore()
    }
  })

  it('ticks how long a connected tunnel has been up', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      withTunnels([{ ...connected, since: new Date(Date.now() - 65_500).toISOString() }])
      renderView()
      expect(await screen.findByText('1m 5s')).toBeInTheDocument()
      expect(screen.getByText('Connected for')).toBeInTheDocument()
      act(() => {
        vi.advanceTimersByTime(2000)
      })
      expect(screen.getByText('1m 7s')).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
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

  it('explains up front how to install openvpn on this system, and holds Connect until it is', async () => {
    const failed: TunnelStatus = { ...connected, state: 'disconnected', iface: undefined, since: undefined }
    withTunnels([failed])
    mockApi.tunnelEngine.mockResolvedValue({
      available: false,
      problem: "OpenVPN isn't installed",
      install: {
        system: 'Ubuntu 24.04.1 LTS',
        commands: ['sudo apt install openvpn'],
      },
    })
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    renderView()

    expect(await screen.findByText("OpenVPN isn't installed")).toBeInTheDocument()
    expect(screen.getByText(/On Ubuntu 24\.04\.1 LTS, run this in a terminal/)).toBeInTheDocument()
    expect(screen.getByText('sudo apt install openvpn')).toBeInTheDocument()
    const connect = screen.getByRole('button', { name: 'Connect infra' })
    expect(connect).toBeDisabled()
    expect(connect).toHaveAttribute('title', "OpenVPN isn't usable yet (see above)")
    // Why it's off is in its accessible description too, not only a tooltip.
    expect(connect).toHaveAccessibleDescription("OpenVPN isn't installed")
    expect(screen.getByText(/from your system's packages/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Check for updates' })).not.toBeInTheDocument()
    expect(screen.getByText('disconnected')).toBeInTheDocument() // state in words, not just a color

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('sudo apt install openvpn'))

    // Installed meanwhile: checking again clears the banner and frees Connect.
    mockApi.tunnelEngine.mockResolvedValue({ available: true, path: '/usr/sbin/openvpn', version: '2.6.14' })
    fireEvent.click(screen.getByRole('button', { name: 'Check again' }))
    await waitFor(() => expect(screen.queryByText("OpenVPN isn't installed")).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Connect infra' })).toBeEnabled()
  })

  it('offers only Save in the editor while openvpn is missing', async () => {
    withTunnels([])
    mockApi.tunnelEngine.mockResolvedValue({ available: false, problem: "OpenVPN isn't installed" })
    mockApi.openTunnelProfile.mockResolvedValue(officeProfile)
    mockApi.saveTunnel.mockResolvedValue({ tunnel: { ...connected, name: 'office', state: 'disconnected' } })
    renderView()
    await screen.findByText("OpenVPN isn't installed")
    fireEvent.click(screen.getByText('+ Add Tunnel'))
    fireEvent.click(screen.getByText('Choose a file…'))
    await screen.findByText('office.ovpn')

    const saveConnect = screen.getByRole('button', { name: 'Save & connect' })
    expect(saveConnect).toBeDisabled()
    expect(saveConnect).toHaveAttribute('title', "OpenVPN isn't usable yet (see the Tunnels page)")
    expect(saveConnect).toHaveAccessibleDescription(/OpenVPN isn't usable yet/)
    fireEvent.click(saveConnect)
    expect(mockApi.saveTunnel).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mockApi.saveTunnel).toHaveBeenCalled())
    expect(mockApi.connectTunnel).not.toHaveBeenCalled()
  })
})

describe('Tunnels view — a definition the daemon can’t read', () => {
  const broken: TunnelStatus = {
    name: 'office',
    type: 'openvpn',
    via: 'direct', // a placeholder, not its setting
    routes: [],
    auto_connect: false,
    has_password: false,
    needs_auth: false,
    servers: [],
    unreadable: true,
    state: 'failed',
    last_error: "its saved definition can't be read (unexpected end of JSON input); delete it and add it again",
    bytes_in: 0,
    bytes_out: 0,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.tunnelEngine.mockResolvedValue({ available: true, path: '/usr/sbin/openvpn', version: '2.6.14' })
  })

  it('shows why, offers only Delete, and deletes after the app’s own dialog', async () => {
    withTunnels([broken, connected])
    mockApi.deleteTunnel.mockResolvedValue(undefined)
    renderView()
    expect(await screen.findByText(/its saved definition can't be read \(unexpected end of JSON input\)/)).toBeInTheDocument()
    expect(screen.getByText("can't be read")).toBeInTheDocument()
    // Nothing that would act on (or pass for) its settings.
    expect(screen.queryByRole('button', { name: 'Connect office' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit office' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Disconnect office/ })).not.toBeInTheDocument()
    expect(screen.queryByText('directly')).not.toBeInTheDocument()
    expect(screen.queryByText(/Nothing yet — edit the tunnel/)).not.toBeInTheDocument()
    // The readable tunnel beside it is unaffected.
    expect(screen.getByRole('button', { name: 'Edit infra' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete office' }))
    expect(screen.getByText('Delete tunnel office')).toBeInTheDocument()
    expect(screen.getByText(/which RiftRoute can’t read/)).toBeInTheDocument()
    expect(mockApi.deleteTunnel).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(mockApi.deleteTunnel).toHaveBeenCalledWith('office'))
  })

  it('opens the editor as a named dialog: focus inside, the via choice a group, Escape closes', async () => {
    withTunnels([{ ...connected, state: 'disconnected' }])
    renderView()
    const edit = await screen.findByRole('button', { name: 'Edit infra' })
    edit.focus()
    fireEvent.click(edit)
    const dialog = screen.getByRole('dialog', { name: 'Edit tunnel infra' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toContainElement(document.activeElement as HTMLElement)
    const via = screen.getByRole('group', { name: 'Reach the server' })
    expect(via.tagName).toBe('FIELDSET')
    expect(within(via).getAllByRole('radio')).toHaveLength(2)
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(edit).toHaveFocus()
  })

  it('edits a tunnel saved without a via as direct', async () => {
    withTunnels([{ ...connected, state: 'disconnected', via: '' as TunnelStatus['via'] }])
    mockApi.saveTunnel.mockResolvedValue({ tunnel: { ...connected, state: 'disconnected' } })
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit infra' }))
    expect(screen.getByRole('radio', { name: /Directly/ })).toBeChecked()
    expect(screen.getByRole('radio', { name: /Through the main VPN/ })).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mockApi.saveTunnel).toHaveBeenCalledWith(expect.objectContaining({ via: 'direct' })))
  })
})

// On macOS openvpn ships with RiftRoute: a missing one comes back with the
// daemon's update check (its repair), which the page offers as the fix.
describe('Tunnels view — macOS openvpn', () => {
  const macMissing = {
    available: false,
    problem: "OpenVPN isn't installed",
    install: {
      system: 'macOS',
      action: 'update',
      note: 'Tunnels use the openvpn that ships with RiftRoute. Checking for updates installs it: `riftroute update check`…',
      url: 'https://github.com/Amirhat/riftroute/releases/latest',
    },
  }
  const disconnected: TunnelStatus = { ...connected, state: 'disconnected', iface: undefined, since: undefined }
  const update = (over: Partial<UpdateStatus> = {}): UpdateStatus => ({
    mode: 'auto',
    current: '0.3.0',
    state: 'idle',
    can_roll_back: false,
    self_updatable: true,
    ...over,
  })
  function withMac(u: UpdateStatus | undefined) {
    mockApi.state.mockResolvedValue({ tunnels: [disconnected], update: u } as unknown as State)
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.tunnelEngine.mockResolvedValue(macMissing)
  })

  it('offers Check for updates, and frees Connect once the check brought openvpn', async () => {
    withMac(update())
    mockApi.checkUpdate.mockResolvedValue(update({ last_check: new Date().toISOString(), action: 'none' }))
    renderView()
    expect(await screen.findByText("OpenVPN isn't installed")).toBeInTheDocument()
    expect(screen.getByText(/that ships with RiftRoute\./)).toBeInTheDocument()
    expect(screen.getByText(/installs it from RiftRoute's newest signed release/)).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/install(s)? (it )?yourself/)
    expect(screen.queryByText(/Updates are off/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Check again' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Connect infra' })).toBeDisabled()

    // The daemon's check installs openvpn before it answers.
    mockApi.tunnelEngine.mockResolvedValue({ available: true, path: '/Library/PrivilegedHelperTools/riftroute-openvpn' })
    fireEvent.click(await screen.findByRole('button', { name: 'Check for updates' }))
    await waitFor(() => expect(mockApi.checkUpdate).toHaveBeenCalledOnce())
    await waitFor(() => expect(screen.queryByText("OpenVPN isn't installed")).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Connect infra' })).toBeEnabled()
  })

  it('says when updates are off, links to Settings → Updates, and still checks', async () => {
    withMac(update({ mode: 'off' }))
    mockApi.checkUpdate.mockResolvedValue(update({ mode: 'off' }))
    const onOpenUpdates = vi.fn()
    renderView(onOpenUpdates)
    expect(await screen.findByText(/Updates are off, so RiftRoute doesn't check on its own/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Settings → Updates' }))
    expect(onOpenUpdates).toHaveBeenCalledOnce()

    // Still missing after the check: say what's left to do.
    fireEvent.click(screen.getByRole('button', { name: 'Check for updates' }))
    expect(
      await screen.findByText(/If openvpn is still missing in a minute, reinstall the daemon from a current release/),
    ).toBeInTheDocument()
  })

  it('says so when the check is installing an update, which brings openvpn itself', async () => {
    withMac(update())
    mockApi.checkUpdate.mockResolvedValue(update({ action: 'install', latest: '0.3.1', state: 'downloading' }))
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Check for updates' }))
    expect(await screen.findByText(/RiftRoute is installing 0\.3\.1, which brings openvpn with it/)).toBeInTheDocument()
    expect(screen.queryByText(/If openvpn is still missing/)).not.toBeInTheDocument()
  })

  it('shows why the check failed', async () => {
    withMac(update())
    mockApi.checkUpdate.mockResolvedValue(update({ state: 'error', error: 'no route to host' }))
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Check for updates' }))
    expect(await screen.findByText('The update check failed: no route to host')).toHaveClass('text-danger')
  })

  it('asks for the installed daemon where the check can’t fetch openvpn', async () => {
    withMac(update({ self_updatable: false }))
    renderView()
    expect(await screen.findByText(/isn't running as the installed service/)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Check for updates' })).not.toBeInTheDocument())
    expect(screen.getByText('sudo riftroute daemon install')).toHaveClass('ltr', 'font-mono')
    expect(screen.getByRole('button', { name: 'Check again' })).toBeInTheDocument()
  })

  it('shows the reinstall steps for an openvpn that is there but unusable', async () => {
    withMac(update())
    mockApi.tunnelEngine.mockResolvedValue({
      available: false,
      path: '/Library/PrivilegedHelperTools/riftroute-openvpn',
      problem: "/Library/PrivilegedHelperTools/riftroute-openvpn doesn't run: dyld: Library not loaded",
      install: {
        system: 'macOS',
        action: 'reinstall',
        note: 'Reinstall the daemon from a current release to put back the openvpn that ships with RiftRoute.',
        url: 'https://github.com/Amirhat/riftroute/releases/latest',
      },
    })
    renderView()
    expect(await screen.findByText(/but can't use it/)).toBeInTheDocument()
    expect(screen.getByText(/Reinstall the daemon from a current release/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Check for updates' })).not.toBeInTheDocument()
  })

  it('never tells macOS users to install openvpn themselves when there are no tunnels', async () => {
    mockApi.state.mockResolvedValue({ tunnels: [], update: update() } as unknown as State)
    mockApi.tunnelEngine.mockResolvedValue({ available: true, path: '/usr/sbin/openvpn' })
    renderView()
    expect(await screen.findByText('No tunnels yet')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/yourself/)
    expect(screen.getByText(/On\s+macOS it comes with RiftRoute/)).toBeInTheDocument()
  })
})

describe('Tunnels view — WireGuard', () => {
  const wgFile: TunnelProfileFile = {
    path: '/Users/me/lab-wg0.conf',
    name: 'lab-wg0.conf',
    type: 'wireguard',
    config: '[Interface]\nPrivateKey = …\n',
    servers: ['vpn.example.com:51820/udp'],
    needs_auth: false,
    ignored: ['DNS', 'PostUp'],
    username: '',
    password: '',
    error: '',
  }
  const wgTunnel: TunnelStatus = {
    name: 'lab',
    type: 'wireguard',
    via: 'direct',
    routes: ['10.20.0.0/16'],
    auto_connect: false,
    has_password: false,
    needs_auth: false,
    servers: ['vpn.example.com:51820/udp'],
    ignored: ['DNS'],
    state: 'disconnected',
    bytes_in: 0,
    bytes_out: 0,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    // openvpn is missing: WireGuard doesn't need it.
    mockApi.tunnelEngine.mockResolvedValue({ available: false, problem: "OpenVPN isn't installed" })
  })

  it('adds one from a .conf — no login, AllowedIPs never routes — and connects without openvpn', async () => {
    withTunnels([])
    mockApi.openTunnelProfile.mockResolvedValue(wgFile)
    mockApi.saveTunnel.mockResolvedValue({ tunnel: wgTunnel })
    mockApi.connectTunnel.mockResolvedValue({ ...wgTunnel, state: 'connecting' })
    renderView()
    fireEvent.click(await screen.findByText('+ Add Tunnel'))
    fireEvent.click(screen.getByText('Choose a file…'))
    await screen.findByText('lab-wg0.conf')

    expect(screen.getByRole('heading', { name: 'Add a WireGuard tunnel' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Username')).not.toBeInTheDocument()
    expect(screen.getByText(/Ignored from the configuration/)).toHaveTextContent('DNS, PostUp')
    expect(screen.getByText(/they never\s+become routes/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Networks through this tunnel'), { target: { value: '10.20.0.0/16' } })

    const saveConnect = screen.getByRole('button', { name: 'Save & connect' })
    expect(saveConnect).toBeEnabled()
    fireEvent.click(saveConnect)
    await waitFor(() => expect(mockApi.connectTunnel).toHaveBeenCalledWith('lab'))
    const spec = mockApi.saveTunnel.mock.calls[0][0]
    expect(spec).toMatchObject({ name: 'lab-wg0', type: 'wireguard', routes: ['10.20.0.0/16'] })
    expect(spec.username).toBeUndefined()
    expect(spec.password).toBeUndefined()
  })

  it('connects while openvpn is missing, with no openvpn banner', async () => {
    withTunnels([wgTunnel])
    renderView()
    expect(await screen.findByText('WireGuard')).toBeInTheDocument()
    await waitFor(() => expect(mockApi.tunnelEngine).toHaveBeenCalled())
    expect(screen.queryByText("OpenVPN isn't installed")).not.toBeInTheDocument()
    mockApi.connectTunnel.mockResolvedValue({ ...wgTunnel, state: 'connecting' })
    const connect = screen.getByRole('button', { name: 'Connect lab' })
    expect(connect).toBeEnabled()
    fireEvent.click(connect)
    await waitFor(() => expect(mockApi.connectTunnel).toHaveBeenCalledWith('lab'))
  })

  it('takes only a .conf when editing one', async () => {
    withTunnels([wgTunnel])
    mockApi.openTunnelProfile.mockResolvedValue(officeProfile)
    renderView()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit lab' }))
    expect(screen.getByText('keeping the saved configuration')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Replace .conf…'))
    expect(await screen.findByText(/This is a WireGuard tunnel; choose a \.conf file/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })
})

describe('Tunnels view — profiles through a tunnel', () => {
  const con3: TunnelStatus = {
    name: 'con3',
    type: 'wireguard',
    via: 'direct',
    routes: [],
    auto_connect: false,
    has_password: false,
    needs_auth: false,
    servers: ['vpn.example.com:51820/udp'],
    state: 'connected',
    iface: 'utun8',
    bytes_in: 0,
    bytes_out: 0,
    profiles: [
      { id: 'a', name: 'dns', enabled: true, routes: 2 },
      { id: 'b', name: 'corp', enabled: false, routes: 0 },
    ],
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.tunnelEngine.mockResolvedValue({ available: true, path: '/usr/sbin/openvpn', version: '2.6.14' })
  })

  it('lists the profiles sent into a tunnel, and turns one off from its card', async () => {
    withTunnels([con3])
    mockApi.setProfileEnabled.mockResolvedValue({ status: 'committed' })
    renderView()
    expect(await screen.findByText('Profiles through this tunnel')).toBeInTheDocument()
    expect(screen.getByText('2 destinations')).toBeInTheDocument()
    expect(screen.getByText('off')).toBeInTheDocument()
    // With profiles sending routes in, an empty own list isn't a warning.
    expect(screen.queryByText(/Nothing yet/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('switch', { name: 'Send profile dns through con3' }))
    await waitFor(() => expect(mockApi.setProfileEnabled).toHaveBeenCalledWith('dns', false))
  })

  it('applies pending changes from the page, confirmed like any other', async () => {
    mockApi.state.mockResolvedValue({ tunnels: [con3], drift: { pending: true, adds: 0, dels: 2 } } as unknown as State)
    mockApi.apply.mockResolvedValue({
      tx_id: 'tx-7',
      needs_confirm: true,
      status: 'pending',
      plan: { ops: [], inverse: [] },
      diff: { adds: 0, dels: 2, changes: 0, in_sync: false, entries: [] },
    })
    mockApi.confirm.mockResolvedValue({})
    renderView()
    expect(await screen.findByText('Pending changes')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Apply changes' }))
    await waitFor(() => expect(mockApi.apply).toHaveBeenCalledWith(false, 60))
    fireEvent.click(await screen.findByRole('button', { name: /Keep/ }))
    await waitFor(() => expect(mockApi.confirm).toHaveBeenCalledWith('tx-7'))
  })
})
