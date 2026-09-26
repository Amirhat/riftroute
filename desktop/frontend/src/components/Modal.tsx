import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react'

// What Tab can reach inside a dialog.
const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

function focusables(el: HTMLElement): HTMLElement[] {
  return Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (f) => !f.closest('[aria-hidden="true"], [hidden]'),
  )
}

// The open dialogs, innermost last: only that one answers Escape and Tab
// (a ConfirmModal opened from inside another modal closes by itself).
const open: HTMLElement[] = []

// Modal uses the explicit z-index scale (z-modal) so it always sits above
// runtime overlays and never opens "behind" something (AGENTS §6 / spec §8.3).
//
// It is a real dialog: role="dialog" and aria-modal, named by its title —
// labelledBy, or else the first heading inside it. Focus moves into it when
// it opens (a field marked data-autofocus, else the first control) and back
// to whatever had it when it closes; Tab and Shift+Tab stay inside it; and
// Escape closes it when it can be closed (onBackdrop is set — callers leave
// it unset while busy).
export function Modal({
  children,
  onBackdrop,
  className = 'max-w-lg',
  labelledBy,
  describedBy,
}: {
  children: ReactNode
  onBackdrop?: () => void
  className?: string
  labelledBy?: string
  describedBy?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  // The latest close handler, so the listener below is added once.
  const close = useRef(onBackdrop)
  close.current = onBackdrop
  // Whatever had focus before the dialog rendered (read before any child
  // autofocuses): focus goes back there when it closes.
  const [opener] = useState(() => (typeof document === 'undefined' ? null : (document.activeElement as HTMLElement | null)))
  const headingId = useId()
  const [titleId, setTitleId] = useState<string | undefined>(undefined)

  // No labelledBy: the first heading names the dialog (given an id if it
  // has none). Checked after every render, as the heading may come later.
  useLayoutEffect(() => {
    if (labelledBy) return
    const h = ref.current?.querySelector<HTMLElement>('h1, h2, h3')
    if (!h) return
    if (!h.id) h.id = headingId
    if (h.id !== titleId) setTitleId(h.id)
  })

  useEffect(() => {
    const el = ref.current
    if (!el) return
    open.push(el)
    if (!el.contains(document.activeElement)) {
      const first = el.querySelector<HTMLElement>('[data-autofocus]') ?? focusables(el)[0] ?? el
      first.focus()
    }
    function onKey(e: KeyboardEvent) {
      if (!el || open[open.length - 1] !== el || e.isComposing) return
      if (e.key === 'Escape') {
        if (close.current && !e.defaultPrevented) {
          e.preventDefault()
          close.current()
        }
        return
      }
      if (e.key !== 'Tab') return
      const f = focusables(el)
      const active = document.activeElement
      if (f.length === 0) {
        e.preventDefault()
        el.focus()
      } else if (e.shiftKey && (active === f[0] || active === el || !el.contains(active))) {
        e.preventDefault()
        f[f.length - 1].focus()
      } else if (!e.shiftKey && (active === f[f.length - 1] || !el.contains(active))) {
        e.preventDefault()
        f[0].focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      const i = open.indexOf(el)
      if (i >= 0) open.splice(i, 1)
      // Back to the opener — unless something else has taken focus since,
      // or the opener is gone (a card's Delete button, with its card).
      const active = document.activeElement
      if (opener?.isConnected && (!active || active === document.body || el.contains(active))) {
        opener.focus()
      }
    }
    // Once per open: the close handler is read through its ref.
  }, [opener])

  return (
    <div className="fixed inset-0 z-modal flex items-center justify-center p-6">
      <div className="absolute inset-0 bg-black/50" onClick={onBackdrop} />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy ?? titleId}
        aria-describedby={describedBy}
        tabIndex={-1}
        className={`relative max-h-[86vh] w-full overflow-y-auto rounded-xl border border-line bg-surface shadow-2xl outline-none ${className}`}
      >
        {children}
      </div>
    </div>
  )
}
