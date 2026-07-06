import type { ReactNode } from 'react'

// Modal uses the explicit z-index scale (z-modal) so it always sits above
// runtime overlays and never opens "behind" something (AGENTS §6 / spec §8.3).
export function Modal({
  children,
  onBackdrop,
  className = 'max-w-lg',
}: {
  children: ReactNode
  onBackdrop?: () => void
  className?: string
}) {
  return (
    <div className="fixed inset-0 z-modal flex items-center justify-center p-6">
      <div className="absolute inset-0 bg-black/50" onClick={onBackdrop} />
      <div className={`relative max-h-[86vh] w-full overflow-y-auto rounded-xl border border-line bg-surface shadow-2xl ${className}`}>
        {children}
      </div>
    </div>
  )
}
