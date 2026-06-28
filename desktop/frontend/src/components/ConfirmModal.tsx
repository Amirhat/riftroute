import type { ReactNode } from 'react'
import { Modal } from './Modal'

// ConfirmModal is an in-app confirmation dialog. We use it instead of the
// browser's window.confirm(), which is a no-op in the Wails WKWebView (the JS
// confirm panel isn't implemented, so confirm() returns false and the guarded
// action silently never runs). All destructive confirmations route through here.
export function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = false,
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  message: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  if (!open) return null
  return (
    <Modal onBackdrop={onCancel}>
      <div className="space-y-4 p-5">
        <h2 className="text-base font-semibold text-default">{title}</h2>
        <p className="text-sm text-muted">{message}</p>
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            className={`rounded-lg px-3 py-1.5 text-sm font-medium ${
              danger ? 'bg-danger text-white hover:opacity-90' : 'bg-accent text-accent-contrast hover:opacity-90'
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  )
}
