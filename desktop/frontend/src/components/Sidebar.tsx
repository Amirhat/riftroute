import type { ComponentType, SVGProps } from 'react'
import {
  DashboardIcon,
  TableIcon,
  ExplainIcon,
  ProfilesIcon,
  FlowsIcon,
  HistoryIcon,
  SettingsIcon,
  DiagnosticsIcon,
  ShieldIcon,
} from './icons'

export type View = 'dashboard' | 'routes' | 'explain' | 'profiles' | 'flows' | 'diagnostics' | 'history' | 'settings'

type Item = {
  view: View
  label: string
  icon: ComponentType<SVGProps<SVGSVGElement>>
  soon?: string // milestone label when not yet implemented
}

const items: Item[] = [
  { view: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
  { view: 'routes', label: 'Routing Table', icon: TableIcon },
  { view: 'explain', label: 'Explain', icon: ExplainIcon },
  { view: 'profiles', label: 'Profiles', icon: ProfilesIcon },
  { view: 'flows', label: 'Flows', icon: FlowsIcon },
  { view: 'diagnostics', label: 'Diagnostics', icon: DiagnosticsIcon },
  { view: 'history', label: 'History', icon: HistoryIcon },
  { view: 'settings', label: 'Settings', icon: SettingsIcon },
]

export function Sidebar({
  current,
  onNavigate,
  version,
}: {
  current: View
  onNavigate: (v: View) => void
  version: string
}) {
  return (
    <aside className="no-select flex h-full w-56 shrink-0 flex-col border-e border-line bg-surface">
      <div className="flex items-center gap-2 px-4 py-4">
        <span className="text-accent">
          <ShieldIcon width={22} height={22} />
        </span>
        <div>
          <div className="text-sm font-semibold leading-none text-default">RiftRoute</div>
          <div className="mt-0.5 text-[10px] uppercase tracking-wider text-muted">split-tunnel control</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-2 py-2">
        {items.map((it) => {
          const active = current === it.view
          const Icon = it.icon
          return (
            <button
              key={it.view}
              onClick={() => onNavigate(it.view)}
              className={[
                'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                active
                  ? 'bg-accent/15 text-accent'
                  : 'text-muted hover:bg-elevated hover:text-default',
              ].join(' ')}
            >
              <Icon />
              <span className="flex-1 text-start">{it.label}</span>
              {it.soon && (
                <span className="rounded bg-elevated px-1.5 py-0.5 text-[10px] font-medium text-muted">{it.soon}</span>
              )}
            </button>
          )
        })}
      </nav>

      <div className="border-t border-line px-4 py-3 text-[11px] text-muted">
        <div>version {version}</div>
        <div className="mt-0.5">split-tunnel controller</div>
      </div>
    </aside>
  )
}
