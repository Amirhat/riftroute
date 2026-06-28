import { Card } from '../components/ui'

export function Placeholder({ title, milestone }: { title: string; milestone: string }) {
  return (
    <div className="flex h-full items-center justify-center">
      <Card className="max-w-md p-8 text-center">
        <div className="text-lg font-semibold text-default">{title}</div>
        <p className="mt-2 text-sm text-muted">
          This screen lands in <span className="font-mono text-accent">{milestone}</span>. The read-only core (M1)
          ships first so nothing here can ever change your routing.
        </p>
      </Card>
    </div>
  )
}
