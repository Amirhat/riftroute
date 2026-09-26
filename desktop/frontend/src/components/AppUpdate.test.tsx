import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AppUpdateBanner, AppUpdateSection } from './AppUpdate'
import { api } from '../lib/api'
import type { AppUpdateStatus } from '../types'

vi.mock('../lib/api', () => ({
  api: { appUpdate: vi.fn(), installAppUpdate: vi.fn(), restartApp: vi.fn() },
}))
const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>

const st = (s: Partial<AppUpdateStatus>): AppUpdateStatus => ({ state: 'idle', current: '0.2.7', ...s })

describe('app update', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.restartApp.mockResolvedValue(undefined)
  })

  it('asks for a restart only once the new app is in place', () => {
    const { rerender } = render(<AppUpdateBanner st={st({ state: 'downloading', target: '0.2.8' })} />)
    expect(screen.queryByRole('status')).toBeNull()
    rerender(<AppUpdateBanner st={st({ state: 'ready', target: '0.2.8' })} />)
    expect(screen.getByRole('status')).toHaveTextContent('RiftRoute 0.2.8 is installed')
    fireEvent.click(screen.getByRole('button', { name: 'Restart RiftRoute' }))
    expect(mockApi.restartApp).toHaveBeenCalled()
  })

  it('offers the update in notify mode and installs it on click', async () => {
    mockApi.installAppUpdate.mockResolvedValue(st({ state: 'ready', target: '0.2.8' }))
    render(<AppUpdateSection st={st({ state: 'available', target: '0.2.8' })} />)
    fireEvent.click(screen.getByRole('button', { name: 'Update the app to 0.2.8' }))
    await waitFor(() => expect(mockApi.installAppUpdate).toHaveBeenCalled())
  })

  it('says why an app can’t update itself, and offers nothing', () => {
    render(<AppUpdateSection st={st({ state: 'unsupported', why: 'the app is installed where this user can’t change it' })} />)
    expect(screen.getByText(/doesn’t update itself here/)).toHaveTextContent('can’t change it')
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('shows a failed attempt with a retry', () => {
    render(<AppUpdateSection st={st({ state: 'error', target: '0.2.8', error: 'download doesn’t match the signed checksum' })} />)
    expect(screen.getByText(/couldn’t update to 0.2.8/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Update the app to 0.2.8' })).toBeEnabled()
  })
})
