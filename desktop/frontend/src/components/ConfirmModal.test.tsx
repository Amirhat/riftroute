import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ConfirmModal } from './ConfirmModal'

describe('ConfirmModal', () => {
  it('renders nothing when closed', () => {
    const { container } = render(
      <ConfirmModal open={false} title="t" message="m" onConfirm={() => {}} onCancel={() => {}} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows title/message and fires onConfirm (the Wails-safe replacement for window.confirm)', () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    render(
      <ConfirmModal
        open
        title="Enable kill switch"
        message="blocks egress"
        confirmLabel="Enable"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    )
    expect(screen.getByText('Enable kill switch')).toBeInTheDocument()
    expect(screen.getByText('blocks egress')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Enable'))
    expect(onConfirm).toHaveBeenCalledOnce()
    expect(onCancel).not.toHaveBeenCalled()
  })

  it('fires onCancel from the Cancel button', () => {
    const onCancel = vi.fn()
    render(<ConfirmModal open title="t" message="m" onConfirm={() => {}} onCancel={onCancel} />)
    fireEvent.click(screen.getByText('Cancel'))
    expect(onCancel).toHaveBeenCalledOnce()
  })
})
