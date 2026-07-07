import { useEffect, useMemo, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'

export type ComboOption = {
  value: string // what gets stored (uid/username, cgroup path…)
  label: string // primary display text
  sub?: string // secondary line (full name, unit path…)
}

// Combobox is a searchable dropdown over a plain text input: typing filters the
// option list, arrows navigate, Enter/click selects, Escape closes. Free text
// stays valid (options are suggestions, not a closed set) so power users can
// enter values the catalog doesn't know — the daemon re-validates anyway.
export function Combobox({
  value,
  onChange,
  options,
  placeholder,
  ariaLabel,
  invalid,
  loading,
  emptyHint,
}: {
  value: string
  onChange: (v: string) => void
  options: ComboOption[]
  placeholder?: string
  ariaLabel?: string
  invalid?: boolean
  loading?: boolean
  emptyHint?: string
}) {
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const rootRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLUListElement>(null)

  const q = value.trim().toLowerCase()
  const filtered = useMemo(() => {
    if (!q) return options
    return options.filter(
      (o) =>
        o.value.toLowerCase().includes(q) ||
        o.label.toLowerCase().includes(q) ||
        (o.sub ?? '').toLowerCase().includes(q),
    )
  }, [options, q])

  // Close on outside click (Wails webview has no native blur ordering quirks,
  // but mousedown-before-blur keeps option clicks reliable).
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  useEffect(() => {
    if (active >= filtered.length) setActive(0)
  }, [filtered.length, active])

  // Keep the active option scrolled into view during keyboard navigation.
  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView?.({ block: 'nearest' })
  }, [active, open])

  const select = (v: string) => {
    onChange(v)
    setOpen(false)
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (!open) setOpen(true)
      else setActive((a) => Math.min(a + 1, filtered.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => Math.max(a - 1, 0))
    } else if (e.key === 'Enter') {
      if (open && filtered[active]) {
        e.preventDefault()
        select(filtered[active].value)
      }
    } else if (e.key === 'Escape' && open) {
      e.stopPropagation()
      setOpen(false)
    }
  }

  return (
    <div ref={rootRef} className="relative min-w-0 flex-1">
      <input
        value={value}
        onChange={(e) => {
          onChange(e.target.value)
          setOpen(true)
          setActive(0)
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
        placeholder={placeholder}
        aria-label={ariaLabel}
        role="combobox"
        aria-expanded={open}
        aria-autocomplete="list"
        spellCheck={false}
        className={[
          'ltr w-full rounded-lg border bg-base px-3 py-2 font-mono text-sm text-default outline-none placeholder:text-muted focus:border-accent',
          invalid ? 'border-danger/60' : 'border-line',
        ].join(' ')}
      />
      {open && (
        <ul
          ref={listRef}
          role="listbox"
          className="absolute z-modal mt-1 max-h-56 w-full overflow-auto rounded-lg border border-line bg-surface py-1 shadow-lg"
        >
          {loading && <li className="px-3 py-2 text-xs text-muted">Loading…</li>}
          {!loading && filtered.length === 0 && (
            <li className="px-3 py-2 text-xs text-muted">{emptyHint ?? 'No matches — free text is allowed.'}</li>
          )}
          {!loading &&
            filtered.map((o, i) => (
              <li
                key={o.value}
                role="option"
                aria-selected={o.value === value}
                data-active={i === active}
                onMouseDown={(e) => {
                  e.preventDefault() // don't blur the input before we set the value
                  select(o.value)
                }}
                onMouseEnter={() => setActive(i)}
                className={[
                  'ltr cursor-pointer px-3 py-1.5 text-sm',
                  i === active ? 'bg-accent/15 text-accent' : 'text-default',
                ].join(' ')}
              >
                <div className="truncate font-mono">{o.label}</div>
                {o.sub && <div className="truncate text-xs text-muted">{o.sub}</div>}
              </li>
            ))}
        </ul>
      )}
    </div>
  )
}
