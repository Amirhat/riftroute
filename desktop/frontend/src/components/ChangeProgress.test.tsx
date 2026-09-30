import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { ChangeProgress, SHOW_AFTER_MS } from './ChangeProgress'
import { Modal } from './Modal'
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

  it('takes the app behind it out of reach while it shows, and names a dry run for what it is', () => {
    const root = document.createElement('div')
    root.id = 'root'
    document.body.appendChild(root)
    render(<ChangeProgress />, { container: root })
    emit({ id: 'p1', step: 'started', preview: true })
    pass(SHOW_AFTER_MS + 50)
    expect(screen.getByRole('status', { name: 'Working out your change' })).toBeInTheDocument()
    expect(root.inert).toBe(true)
    emit({ id: 'p1', step: 'finished' })
    expect(root.inert).toBe(false)
    root.remove()
  })

  // jsdom has no inert: what a browser does to focus under it, by hand —
  // focus() does nothing inside an inert #root, and going inert moves focus
  // off the element that had it.
  function inertRoot() {
    const root = document.createElement('div')
    root.id = 'root'
    document.body.appendChild(root)
    const focus = HTMLElement.prototype.focus
    vi.spyOn(HTMLElement.prototype, 'focus').mockImplementation(function (this: HTMLElement) {
      if (!(root.inert && root.contains(this))) focus.call(this)
    })
    return root
  }

  it('gives focus back to the button that started the change', () => {
    const root = inertRoot()
    render(
      <>
        <button>Save</button>
        <ChangeProgress />
      </>,
      { container: root },
    )
    const save = screen.getByRole('button', { name: 'Save' })
    save.focus()
    emit({ id: 'c1', step: 'started' })
    pass(SHOW_AFTER_MS + 50)
    expect(root.inert).toBe(true)
    save.blur() // the browser's focus fixup
    emit({ id: 'c1', step: 'finished' })
    expect(save).toHaveFocus()
    root.remove()
    vi.restoreAllMocks()
  })

  it('gives focus to a dialog that opened while the app was out of reach', () => {
    const root = inertRoot()
    const { rerender } = render(
      <>
        <button>Save</button>
        <ChangeProgress />
      </>,
      { container: root },
    )
    screen.getByRole('button', { name: 'Save' }).focus()
    emit({ id: 'c1', step: 'started' })
    pass(SHOW_AFTER_MS + 50)
    screen.getByRole('button', { name: 'Save' }).blur()
    // The change needs confirming: its dialog opens under the panel.
    rerender(
      <>
        <button>Save</button>
        <ChangeProgress />
        <Modal>
          <h2>Keep these changes?</h2>
          <button>Keep</button>
        </Modal>
      </>,
    )
    expect(screen.getByRole('button', { name: 'Keep' })).not.toHaveFocus()
    emit({ id: 'c1', step: 'finished' })
    expect(screen.getByRole('button', { name: 'Keep' })).toHaveFocus()
    root.remove()
    vi.restoreAllMocks()
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
