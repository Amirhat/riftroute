import { useEffect, useReducer, useState } from 'react'
import { onApplyProgress } from '../lib/events'
import type { ApplyProgress, ApplyStep } from '../types'

// The daemon's steps, in the order a change goes through them. A change
// shows only the ones it reached: most don't wait, and one without domains
// looks nothing up.
const ORDER: ApplyStep[] = ['waiting', 'resolving', 'checking', 'applying']

const LABEL: Record<string, string> = {
  waiting: 'Waiting for another change to finish',
  resolving: 'Looking up domain addresses',
  checking: 'Checking the change is safe',
  applying: 'Changing routes',
}

// How long a change runs before the panel shows: a quick one never flashes it.
export const SHOW_AFTER_MS = 300

type Seen = Partial<Record<ApplyStep, { done?: number; total?: number }>>
interface Change {
  id: string
  at: number
  current?: ApplyStep
  seen: Seen
}

type Action = { p: ApplyProgress; now: number }

// running holds this app's changes in flight, newest last. A step for a
// change that has finished (the stream is behind the call) is dropped.
function reduce(running: Change[], { p, now }: Action): Change[] {
  if (p.step === 'started') return [...running.filter((c) => c.id !== p.id), { id: p.id, at: now, seen: {} }]
  if (p.step === 'finished') return running.filter((c) => c.id !== p.id)
  return running.map((c) =>
    c.id === p.id ? { ...c, current: p.step, seen: { ...c.seen, [p.step]: { done: p.done, total: p.total } } } : c,
  )
}

// ChangeProgress is the one panel every change the app makes shows while it
// runs — a profile toggled and applied, a route added, a config imported —
// step by step, so a slow change is visibly working rather than stuck:
// waiting behind another change, looking up the profiles' domains,
// checking, changing routes (counted). It closes when the change returns;
// what comes next (Keep these changes?) is the page's.
export function ChangeProgress() {
  const [running, dispatch] = useReducer(reduce, [])
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => onApplyProgress((p) => dispatch({ p, now: Date.now() })), [])

  const change = running[running.length - 1]
  // Tick while a change runs: to show it once SHOW_AFTER_MS has passed, and
  // its elapsed time.
  useEffect(() => {
    if (!change) return
    setNow(Date.now())
    const t = setInterval(() => setNow(Date.now()), 100)
    return () => clearInterval(t)
  }, [change?.id])

  if (!change || now - change.at < SHOW_AFTER_MS) return null
  const elapsed = Math.floor((now - change.at) / 1000)
  const reached = ORDER.filter((s) => change.seen[s] || s === change.current)
  const currentAt = change.current ? ORDER.indexOf(change.current) : -1

  return (
    <div className="fixed inset-0 z-dialog flex items-center justify-center bg-base/60 p-4 backdrop-blur-[1px]">
      <div
        role="status"
        aria-live="polite"
        aria-busy="true"
        aria-label="Applying your change"
        className="w-full max-w-sm rounded-xl border border-line bg-surface p-5 shadow-xl"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-default">Applying your change</h2>
          {elapsed >= 2 && <span className="ltr text-xs tabular-nums text-muted">{elapsed}s</span>}
        </div>
        <ol className="mt-4 space-y-2.5">
          {reached.length === 0 && <StepRow state="current" label="Starting…" />}
          {reached.map((s) => {
            const at = ORDER.indexOf(s)
            const state = at < currentAt ? 'done' : at === currentAt ? 'current' : 'upcoming'
            return <StepRow key={s} state={state} label={LABEL[s]} count={change.seen[s]} />
          })}
        </ol>
        {elapsed >= 15 && (
          <p className="mt-4 text-xs text-muted">
            Still working — a slow network or a large list can take a while. Nothing is lost if you wait.
          </p>
        )}
      </div>
    </div>
  )
}

function StepRow({
  state,
  label,
  count,
}: {
  state: 'done' | 'current' | 'upcoming'
  label: string
  count?: { done?: number; total?: number }
}) {
  const total = count?.total ?? 0
  const done = Math.min(count?.done ?? 0, total)
  return (
    <li className="flex items-start gap-2.5" aria-current={state === 'current' ? 'step' : undefined}>
      <span className="relative mt-0.5 h-4 w-4 shrink-0">
        {state === 'done' && (
          <span className="absolute inset-0 flex items-center justify-center rounded-full bg-success/15 text-[10px] text-success">
            ✓
          </span>
        )}
        {state === 'current' && (
          <span className="absolute inset-0 animate-spin rounded-full border-2 border-accent/30 border-t-accent" />
        )}
        {state === 'upcoming' && <span className="absolute left-1/2 top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-muted/50" />}
      </span>
      <span className="min-w-0 flex-1">
        <span className={`text-sm ${state === 'upcoming' ? 'text-muted' : 'text-default'}`}>
          {label}
          {total > 0 && (
            <span className="ltr ms-1.5 tabular-nums text-muted">
              {done}/{total}
            </span>
          )}
        </span>
        {state === 'current' && total > 1 && (
          <span className="mt-1.5 block h-1 w-full overflow-hidden rounded-full bg-elevated">
            <span
              className="block h-full rounded-full bg-accent transition-[width] duration-150"
              style={{ width: `${(done / total) * 100}%` }}
            />
          </span>
        )}
      </span>
    </li>
  )
}
