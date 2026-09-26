import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { State } from '../types'

let current: State | undefined
vi.mock('../lib/queries', () => ({
  stateKey: ['state'],
  useStateQuery: () => ({ data: current }),
  useBuildNotesQuery: () => ({ data: [] }),
}))
vi.mock('../lib/api', () => ({
  api: {
    setPreferences: vi.fn(),
    checkUpdate: vi.fn(),
    installUpdate: vi.fn(),
    rollbackUpdate: vi.fn(),
    openReleaseNotes: vi.fn(),
    appUpdate: vi.fn().mockResolvedValue({ state: 'idle', current: '0.2.8' }),
    installAppUpdate: vi.fn(),
    restartApp: vi.fn(),
  },
}))
vi.mock('../lib/useDaemon', () => ({ useDaemon: () => ({ info: null }) }))
vi.mock('../components/SplitDNSEditor', () => ({ SplitDNSEditor: () => null }))
const mockApi = api as unknown as {
  setPreferences: ReturnType<typeof vi.fn>
  installUpdate: ReturnType<typeof vi.fn>
  rollbackUpdate: ReturnType<typeof vi.fn>
}

const base = {
  health: { daemon: 'ok', version: '0.2.4', provider: 'fake', uptime_seconds: 1, pid: 1 },
  capabilities: {
    platform: 'darwin', policy_routing: true, fwmark: false, per_app_routing: true,
    proto_tag: false, ipv6: true, kill_switch: true, iface_scoping: true,
  },
  vpn: { active: false, interfaces: [] },
  interfaces: [],
  defaults: [],
  dns: { servers: [] },
  profiles: [],
  drift: { pending: false, adds: 0, dels: 0 },
  managed_route_count: 0,
  managed_rule_count: 0,
  auto_apply: true,
  kill_switch: false,
  generated_at: new Date(0).toISOString(),
} as State

async function renderSettings() {
  const { Settings } = await import('./Settings')
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Settings theme="dark" onToggleTheme={() => {}} />
    </QueryClientProvider>,
  )
}

describe('Settings — updates & telemetry preferences', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.setPreferences.mockResolvedValue({ updates: 'auto', telemetry: 'off' })
  })

  it('shows the current choices and changes only the one clicked', async () => {
    current = { ...base, preferences: { updates: 'auto', telemetry: 'full' } }
    await renderSettings()
    const updates = screen.getByRole('radiogroup', { name: 'Update mode' })
    const telemetry = screen.getByRole('radiogroup', { name: 'Telemetry level' })
    expect(updates.querySelector('input[value="auto"]')).toBeChecked()
    expect(telemetry.querySelector('input[value="full"]')).toBeChecked()

    fireEvent.click(telemetry.querySelector('input[value="off"]')!)
    await waitFor(() => expect(mockApi.setPreferences).toHaveBeenCalledWith({ telemetry: 'off' }))
  })

  // The hard privacy limits and "nothing is sent yet" must be stated plainly.
  it('states what is never sent and that nothing is sent yet', async () => {
    current = { ...base, preferences: { updates: 'notify', telemetry: 'basic' } }
    await renderSettings()
    expect(screen.getByText(/Never sent, at any level:/)).toBeInTheDocument()
    expect(screen.getByText(/IP addresses, domains/)).toBeInTheDocument()
    expect(screen.getByText(/doesn’t send telemetry yet/)).toBeInTheDocument()
  })

  it('disables the choices against a daemon that predates preferences', async () => {
    current = { ...base }
    await renderSettings()
    const telemetry = screen.getByRole('radiogroup', { name: 'Telemetry level' })
    expect(telemetry.querySelector('input[value="off"]')).toBeDisabled()
    expect(screen.getAllByText(/too old to store/).length).toBe(2)
  })

  // The old copy promised "a reconnect path stays open" — false: the VPN's
  // own server was blocked. The description must say what it really does.
  it('describes the kill switch accurately', async () => {
    current = { ...base, preferences: { updates: 'auto', telemetry: 'full' } }
    await renderSettings()
    expect(screen.getByText(/Your apps reach the internet only through the VPN tunnel/)).toBeInTheDocument()
    expect(screen.getByText(/VPN clients can still reconnect/)).toBeInTheDocument()
    expect(screen.queryByText(/reconnect path stays open/)).toBeNull()
  })

  // When the daemon had to turn the kill switch off (it was cutting the VPN's
  // own connection), Settings says so next to the toggle.
  it('shows why the kill switch turned itself off', async () => {
    current = {
      ...base,
      preferences: { updates: 'auto', telemetry: 'full' },
      kill_switch_notice: "Turned the kill switch off: your VPN's own connection runs as your user account",
    }
    await renderSettings()
    expect(screen.getByText(/Turned the kill switch off/)).toBeInTheDocument()
  })

  // The updater's own status shows, with the right buttons for it.
  it('offers an available update and a way back', async () => {
    current = {
      ...base,
      preferences: { updates: 'notify', telemetry: 'full' },
      update: {
        mode: 'notify', current: '0.2.6', state: 'idle', latest: '0.2.7', action: 'notify', reason: '0.2.7 is available',
        notes_url: 'https://github.com/Amirhat/riftroute/releases/tag/v0.2.7', can_roll_back: true, self_updatable: true,
        last_check: new Date(1000).toISOString(),
      },
    }
    mockApi.installUpdate.mockResolvedValue({ ...current.update, state: 'installing', staged: '0.2.7' })
    mockApi.rollbackUpdate.mockResolvedValue(undefined)
    await renderSettings()
    expect(screen.getByText(/0.2.7 is available\./)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Install 0.2.7' }))
    await waitFor(() => expect(mockApi.installUpdate).toHaveBeenCalled())
    // Going back asks first (no window.confirm in the app's webview).
    fireEvent.click(screen.getByRole('button', { name: 'Go back to the previous version' }))
    expect(mockApi.rollbackUpdate).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Go back' }))
    await waitFor(() => expect(mockApi.rollbackUpdate).toHaveBeenCalled())
  })

  it('says when an update was rolled back, and never offers to install on a managed install', async () => {
    current = {
      ...base,
      preferences: { updates: 'auto', telemetry: 'full' },
      update: {
        mode: 'auto', current: '0.2.6', state: 'idle', latest: '0.2.8', action: 'notify', rolled_back_from: '0.2.7',
        can_roll_back: false, self_updatable: false,
      },
    }
    await renderSettings()
    expect(screen.getByText(/0.2.7 didn’t start properly on this computer/)).toBeInTheDocument()
    expect(screen.getByText(/update it the way you installed it/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Install/ })).toBeNull()
  })

  it('shows an update that is ready and waiting for a quiet moment', async () => {
    current = {
      ...base,
      preferences: { updates: 'auto', telemetry: 'full' },
      update: {
        mode: 'auto', current: '0.2.6', state: 'waiting', staged: '0.2.7', action: 'install',
        reason: '0.2.7 is ready; installing at a quiet moment (a change awaits confirmation)', can_roll_back: false, self_updatable: true,
      },
    }
    await renderSettings()
    expect(screen.getByText(/0.2.7 is verified and ready/)).toBeInTheDocument()
  })
})
