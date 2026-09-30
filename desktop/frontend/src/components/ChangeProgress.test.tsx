import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { ChangeProgress, SHOW_AFTER_MS } from './ChangeProgress'
import type { ApplyProgress } from '../types'

// The Go side's rr:apply-progress events, fired by hand.
let emit: (p: ApplyProgress) => void = () => {}

beforeEach(() => {
  vi.useFakeTimers()
  ;(window as unknown as { runtime: unknown }).runtime = {
    EventsOn: (name: string, cb: (p: unknown) => void) => {
      if (name === 'rr:apply-progress') emit = (p) => act(() => cb(p))
      return () => {}
    },
  }
})

afterEach(() => {
  vi.useRealTimers()
  delete (window as unknown as { runtime?: unknown }).runtime
})

const pass = (ms: number) => act(() => vi.advanceTimersByTime(ms))

describe('ChangeProgress', () => {
  it('shows each step of a slow change as it comes, and closes when it returns', () => {
    render(<ChangeProgress />)
    emit({ id: 'c1', step: 'started' })
    expect(screen.queryByRole('status')).not.toBeInTheDocument() // not before it's slow
    pass(SHOW_AFTER_MS + 50)
    expect(screen.getByRole('status', { name: 'Applying your change' })).toHaveTextContent('Starting…')

    emit({ id: 'c1', step: 'waiting' })
    expect(screen.getByText('Waiting for another change to finish')).toBeInTheDocument()
    emit({ id: 'c1', step: 'resolving', done: 3, total: 15 })
    expect(screen.getByText('Looking up domain addresses').closest('li')).toHaveTextContent('3/15')
    expect(screen.getByText('Waiting for another change to finish').closest('li')).toHaveTextContent('✓')
    emit({ id: 'c1', step: 'checking' })
    emit({ id: 'c1', step: 'applying', done: 40, total: 64 })
    const applying = screen.getByText('Changing routes').closest('li')!
    expect(applying).toHaveTextContent('40/64')
    expect(applying).toHaveAttribute('aria-current', 'step')

    pass(16_000)
    expect(screen.getByText(/Still working/)).toBeInTheDocument()
    expect(screen.getByText('16s')).toBeInTheDocument()

    emit({ id: 'c1', step: 'finished' })
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    // A step the stream delivers after the call returned doesn't bring it back.
    emit({ id: 'c1', step: 'applying', done: 64, total: 64 })
    pass(SHOW_AFTER_MS + 50)
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('never flashes for a change that returns quickly', () => {
    render(<ChangeProgress />)
    emit({ id: 'c2', step: 'started' })
    emit({ id: 'c2', step: 'checking' })
    pass(100)
    emit({ id: 'c2', step: 'finished' })
    pass(SHOW_AFTER_MS)
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
