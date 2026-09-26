import { describe, it, expect, vi } from 'vitest'
import { useState } from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { Modal } from './Modal'
import { ConfirmModal } from './ConfirmModal'

// A page with a button that opens a modal, as the app's views do.
function Opener({ closeable = true, nested = false }: { closeable?: boolean; nested?: boolean }) {
  const [open, setOpen] = useState(false)
  const [inner, setInner] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)}>Open</button>
      <button>Elsewhere</button>
      {open && (
        <Modal onBackdrop={closeable ? () => setOpen(false) : undefined}>
          <h2>Edit tunnel infra</h2>
          <input aria-label="Name" />
          <input type="password" aria-label="Password" />
          {nested && <button onClick={() => setInner(true)}>Delete</button>}
          <button onClick={() => setOpen(false)}>Close</button>
          <ConfirmModal
            open={inner}
            title="Delete tunnel infra"
            message="Disconnects it."
            onConfirm={() => setInner(false)}
            onCancel={() => setInner(false)}
          />
        </Modal>
      )}
    </>
  )
}

const escape = () => fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' })
const tab = (shiftKey = false) => fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Tab', shiftKey })

describe('Modal', () => {
  it('is a modal dialog named by its title', () => {
    render(<Opener />)
    fireEvent.click(screen.getByText('Open'))
    const dialog = screen.getByRole('dialog', { name: 'Edit tunnel infra' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
  })

  it('takes an explicit label and description', () => {
    render(
      <Modal labelledBy="t" describedBy="d">
        <h2>Not this</h2>
        <h3 id="t">The title</h3>
        <p id="d">What it does</p>
      </Modal>,
    )
    const dialog = screen.getByRole('dialog', { name: 'The title' })
    expect(dialog).toHaveAccessibleDescription('What it does')
  })

  it('moves focus in when it opens and back to the opener when it closes', () => {
    render(<Opener />)
    const open = screen.getByText('Open')
    open.focus()
    fireEvent.click(open)
    expect(screen.getByRole('textbox', { name: 'Name' })).toHaveFocus()
    fireEvent.click(screen.getByText('Close'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(open).toHaveFocus()
  })

  it('closes on Escape when it can be closed, and not otherwise', () => {
    const { unmount } = render(<Opener />)
    const open = screen.getByText('Open')
    open.focus()
    fireEvent.click(open)
    escape()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(open).toHaveFocus()
    unmount()

    render(<Opener closeable={false} />)
    fireEvent.click(screen.getByText('Open'))
    escape()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('keeps Tab inside the dialog', () => {
    render(<Opener />)
    fireEvent.click(screen.getByText('Open'))
    const name = screen.getByRole('textbox', { name: 'Name' })
    const close = screen.getByText('Close')
    close.focus()
    tab()
    expect(name).toHaveFocus()
    tab(true)
    expect(close).toHaveFocus()
    // Focus that escaped (a click on the backdrop) comes back in.
    screen.getByText('Elsewhere').focus()
    tab()
    expect(name).toHaveFocus()
  })

  it('focuses the dialog itself when it has nothing to focus', () => {
    render(
      <Modal>
        <h2>Working…</h2>
      </Modal>,
    )
    expect(screen.getByRole('dialog', { name: 'Working…' })).toHaveFocus()
    tab()
    expect(screen.getByRole('dialog')).toHaveFocus()
  })

  it('lets only the innermost dialog answer Escape', () => {
    render(<Opener nested />)
    fireEvent.click(screen.getByText('Open'))
    const del = screen.getByText('Delete')
    del.focus()
    fireEvent.click(del)
    expect(screen.getByRole('dialog', { name: 'Delete tunnel infra' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus()
    escape()
    expect(screen.queryByRole('dialog', { name: 'Delete tunnel infra' })).not.toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: 'Edit tunnel infra' })).toBeInTheDocument()
    expect(del).toHaveFocus() // back to the button that opened the confirmation
    escape()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('leaves focus alone when its opener is gone', () => {
    const onBackdrop = vi.fn()
    function Card() {
      const [shown, setShown] = useState(true)
      const [open, setOpen] = useState(false)
      return (
        <>
          {shown && <button onClick={() => setOpen(true)}>Delete infra</button>}
          {open && (
            <Modal onBackdrop={onBackdrop}>
              <h2>Delete</h2>
              <button
                onClick={() => {
                  setShown(false)
                  setOpen(false)
                }}
              >
                Confirm
              </button>
            </Modal>
          )}
        </>
      )
    }
    render(<Card />)
    const del = screen.getByText('Delete infra')
    del.focus()
    fireEvent.click(del)
    fireEvent.click(screen.getByText('Confirm'))
    expect(screen.queryByText('Delete infra')).not.toBeInTheDocument()
    expect(document.body).toHaveFocus()
  })
})
