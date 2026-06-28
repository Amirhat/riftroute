import { Card } from '../components/ui'

export function Placeholder({ title, milestone }: { title: string; milestone: string }) {
  return (
    <div className="flex h-full items-center justify-center">
      <Card className="max-w-md p-8 text-center">
        <div className="text-lg font-semibold text-default">{title}</div>
        <p className="mt-2 text-sm text-muted">
          Settings are managed declaratively in the config file
          (<span className="font-mono text-accent">riftroute.yaml</span>) and via the
          <span className="font-mono text-accent"> riftroute</span> CLI. An in-app editor is
          planned for <span className="font-mono text-accent">{milestone}</span>.
        </p>
      </Card>
    </div>
  )
}
