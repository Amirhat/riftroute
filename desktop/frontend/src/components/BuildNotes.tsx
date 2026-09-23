import { useBuildNotesQuery } from '../lib/queries'

// BuildNotes surfaces "a newer daemon is installed but not running" and
// app/daemon version mismatches — the trap where an update looks like it
// didn't fix anything because the old binary is still serving.
export function BuildNotes() {
  const { data } = useBuildNotesQuery()
  if (!data || data.length === 0) return null
  return (
    <div className="space-y-2 px-4 pb-4">
      {data.map((n) => (
        <p key={n} role="status" className="break-words rounded-lg bg-warning/10 px-3 py-2 text-xs text-warning">
          {n}
        </p>
      ))}
    </div>
  )
}
