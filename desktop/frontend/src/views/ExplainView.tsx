import { useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { useMutation } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardHeader, Badge, Label, Addr } from '../components/ui'
import type { RouteDecision, RouteExplain } from '../types'

export function ExplainView() {
  const [target, setTarget] = useState('')
  const mutation = useMutation({ mutationFn: (t: string) => api.explain(t) })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const t = target.trim()
    if (t) mutation.mutate(t)
  }

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <Card>
        <CardHeader title="Route explain" hint="where does traffic to X go, and why?" />
        <form onSubmit={submit} className="flex gap-2 p-4">
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g. 8.8.8.8 or 192.168.1.10"
            spellCheck={false}
            className="ltr flex-1 rounded-lg border border-line bg-base px-3 py-2 font-mono text-sm text-default outline-none placeholder:text-muted focus:border-accent"
          />
          <button
            type="submit"
            disabled={mutation.isPending}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
          >
            {mutation.isPending ? 'Resolving…' : 'Explain'}
          </button>
        </form>
      </Card>

      {mutation.isError && (
        <Card className="p-4 text-sm text-danger">{(mutation.error as Error)?.message}</Card>
      )}

      {mutation.data && <ExplainResult result={mutation.data} />}
    </div>
  )
}

function ExplainResult({ result }: { result: RouteExplain }) {
  return (
    <div className="space-y-4">
      {result.note && (
        <Card className="p-4 text-sm text-muted">{result.note}</Card>
      )}
      <DecisionCard title="Kernel decision" decision={result.kernel} />
      {result.simulated ? (
        <DecisionCard title="Simulated (desired)" decision={result.simulated} drift={result.drift} />
      ) : (
        <Card className="p-4 text-xs text-muted">
          Simulated decision &amp; drift detection arrive with the routing engine (M1+).
        </Card>
      )}
    </div>
  )
}

function DecisionCard({ title, decision, drift }: { title: string; decision: RouteDecision; drift?: boolean }) {
  if (!decision.iface && !decision.reachable) {
    return (
      <Card>
        <CardHeader title={title} />
        <div className="p-4 text-sm text-muted">No answer.</div>
      </Card>
    )
  }
  return (
    <Card>
      <CardHeader
        title={title}
        hint={
          drift ? (
            <Badge tone="warning">drift</Badge>
          ) : decision.reachable ? (
            <Badge tone={decision.via_vpn ? 'vpn' : 'success'}>{decision.via_vpn ? 'via VPN' : 'direct'}</Badge>
          ) : (
            <Badge tone="danger">unreachable</Badge>
          )
        }
      />
      <div className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
        <Cell label="Target"><Addr>{decision.target}</Addr></Cell>
        <Cell label="Matched"><Addr>{decision.matched_cidr || '—'}</Addr></Cell>
        <Cell label="Gateway"><Addr>{decision.gateway || 'on-link'}</Addr></Cell>
        <Cell label="Interface"><Addr>{decision.iface || '—'}</Addr></Cell>
      </div>
      <div className="flex flex-wrap items-center gap-2 px-4 pb-4">
        <Badge tone="muted">{decision.family}</Badge>
        {decision.owner && <Badge tone="muted">owner: {decision.owner}</Badge>}
        {decision.profile && <Badge tone="accent">profile: {decision.profile}</Badge>}
      </div>
    </Card>
  )
}

function Cell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <Label>{label}</Label>
      <div className="mt-1">{children}</div>
    </div>
  )
}
