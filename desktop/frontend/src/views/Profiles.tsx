import { useCallback, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { stateKey, useStateQuery } from '../lib/queries'
import { Card, CardHeader, Badge, Addr, Skeleton, Toggle } from '../components/ui'
import { CommitConfirm } from '../components/CommitConfirm'
import { ConfigImport } from '../components/ConfigImport'
import { ProfileBuilder } from '../components/ProfileBuilder'
import { ListsManager } from '../components/ListsManager'
import { ConfirmModal } from '../components/ConfirmModal'
import type { ApplyResult, Plan, Profile } from '../types'

const CONFIRM_SECONDS = 15
const DAEMON_BACKSTOP_SEC = 60

type BuilderState = { mode: 'new' } | { mode: 'edit'; profile: Profile } | null

export function Profiles() {
  const qc = useQueryClient()
  const profilesQ = useQuery({ queryKey: ['profiles'], queryFn: api.profiles })
  const stateQ = useStateQuery()
  const [pending, setPending] = useState<ApplyResult | null>(null)
  const [preview, setPreview] = useState<Plan | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [builder, setBuilder] = useState<BuilderState>(null)
  const [deleting, setDeleting] = useState<Profile | null>(null)

  const refresh = useCallback(() => {
    qc.invalidateQueries({ queryKey: ['profiles'] })
    qc.invalidateQueries({ queryKey: stateKey })
    qc.invalidateQueries({ queryKey: ['routes'] })
  }, [qc])

  const onKeep = useCallback(async () => {
    if (!pending?.tx_id) return setPending(null)
    try {
      await api.confirm(pending.tx_id)
    } finally {
      setPending(null)
      refresh()
    }
  }, [pending, refresh])

  const onRevert = useCallback(async () => {
    if (!pending?.tx_id) return setPending(null)
    try {
      await api.rollback(pending.tx_id)
    } finally {
      setPending(null)
      refresh()
    }
  }, [pending, refresh])

  async function toggle(p: Profile) {
    setError(null)
    setPreview(null)
    try {
      await api.setProfileEnabled(p.name, !p.enabled)
      refresh()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  async function doPreview() {
    setError(null)
    try {
      setPreview(await api.plan())
    } catch (e) {
      setError((e as Error).message)
    }
  }

  async function doApply() {
    setError(null)
    setBusy(true)
    try {
      const res = await api.apply(false /* interactive */, DAEMON_BACKSTOP_SEC)
      if (res.violations && res.violations.length > 0) {
        setError('Refused by guardrails: ' + res.violations.map((v) => v.rule).join(', '))
      } else if (res.needs_confirm) {
        setPending(res)
      }
      setPreview(null)
      refresh()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function doDelete() {
    const p = deleting
    setDeleting(null)
    if (!p) return
    setError(null)
    try {
      const res = await api.deleteProfile(p.name)
      if (res.result?.needs_confirm && res.result.tx_id) setPending(res.result)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      // The profile may be deleted even when the follow-up reconcile errored —
      // always re-read so the list never shows a ghost profile.
      refresh()
    }
  }

  const drift = stateQ.data?.drift
  const hasDrift = !!drift?.pending
  const profiles = profilesQ.data ?? []
  const platform = stateQ.data?.capabilities.platform
  const profileNames = profiles.map((p) => p.name)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted">
          Build a profile visually, toggle one, or import a declarative <span className="font-mono text-default">.yaml</span> — no terminal needed.
        </p>
        <div className="flex items-center gap-2">
          <ConfigImport onPending={setPending} onApplied={refresh} />
          <button
            onClick={() => setBuilder({ mode: 'new' })}
            className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
          >
            + New Profile
          </button>
        </div>
      </div>

      {hasDrift && (
        <Card className="flex items-center justify-between border-warning/40 bg-warning/5 p-4">
          <div className="text-sm">
            <span className="font-semibold text-warning">Pending changes</span>
            <span className="ml-2 text-muted">
              +{drift?.adds ?? 0} −{drift?.dels ?? 0} ~{drift?.changes ?? 0} managed route(s)
            </span>
          </div>
          <div className="flex gap-2">
            <button onClick={doPreview} className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default">
              Preview
            </button>
            <button
              onClick={doApply}
              disabled={busy}
              className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
            >
              {busy ? 'Applying…' : 'Apply changes'}
            </button>
          </div>
        </Card>
      )}

      {error && <Card className="border-danger/40 p-3 text-sm text-danger">{error}</Card>}

      {preview && (
        <Card>
          <CardHeader title="Dry-run plan" hint={`${preview.ops.length} op(s)`} />
          <div className="divide-y divide-line">
            {preview.ops.length === 0 && <div className="p-3 text-sm text-muted">No changes — in sync.</div>}
            {preview.ops.map((op, i) => (
              <div key={i} className="ltr flex items-center gap-2 px-4 py-2 text-sm">
                <span className={op.kind === 'add_route' ? 'text-success' : 'text-danger'}>{op.kind === 'add_route' ? '+' : '−'}</span>
                <span className="font-mono text-muted">{op.command.join(' ')}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {profilesQ.isLoading && <Skeleton className="h-40 w-full" />}

      {!profilesQ.isLoading && profiles.length === 0 && (
        <Card className="p-8 text-center">
          <div className="text-base font-semibold text-default">No profiles yet</div>
          <p className="mt-2 text-sm text-muted">
            Click <span className="font-medium text-accent">+ New Profile</span> to build one visually, or import a{' '}
            <span className="font-mono text-default">.yaml</span> config.
          </p>
          <button
            onClick={() => setBuilder({ mode: 'new' })}
            className="mt-4 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90"
          >
            + New Profile
          </button>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {profiles.map((p) => (
          <Card key={p.id}>
            <div className="flex items-center justify-between border-b border-line px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <span className="truncate font-semibold text-default">{p.name}</span>
                <Badge tone={p.mode === 'include' ? 'vpn' : 'muted'}>{p.mode}</Badge>
              </div>
              <Toggle on={p.enabled} onClick={() => toggle(p)} />
            </div>
            <div className="space-y-1.5 p-4">
              {p.description && <div className="text-sm text-default">{p.description}</div>}
              <div className="text-xs text-muted">
                gateway {p.gateway} · priority {p.priority}
              </div>
              {(p.rules ?? []).length === 0 && <div className="text-sm text-muted">no rules</div>}
              {(p.rules ?? []).map((r, i) => (
                <div key={i} className="ltr flex items-center gap-2 text-sm">
                  <Badge tone="muted">{r.type}</Badge>
                  <Addr>{r.value}</Addr>
                  {r.comment && <span className="text-muted">— {r.comment}</span>}
                </div>
              ))}
              {(p.lists ?? []).length > 0 && (
                <div className="pt-1 text-xs text-muted">lists: {(p.lists ?? []).join(', ')}</div>
              )}
            </div>
            <div className="flex justify-end gap-2 border-t border-line px-4 py-2.5">
              <button onClick={() => setBuilder({ mode: 'edit', profile: p })} className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default">
                Edit
              </button>
              <button onClick={() => setDeleting(p)} className="rounded-lg border border-danger/40 px-3 py-1.5 text-sm text-danger hover:bg-danger/10">
                Delete
              </button>
            </div>
          </Card>
        ))}
      </div>

      <ListsManager />

      {builder && (
        <ProfileBuilder
          initial={builder.mode === 'edit' ? builder.profile : undefined}
          existingNames={profileNames}
          platform={platform}
          onPending={setPending}
          onApplied={refresh}
          onClose={() => setBuilder(null)}
        />
      )}

      <ConfirmModal
        open={deleting !== null}
        danger
        title={`Delete profile "${deleting?.name ?? ''}"`}
        message="This removes the profile and reconciles its routes out of the table (guarded by commit-confirm)."
        confirmLabel="Delete profile"
        onConfirm={doDelete}
        onCancel={() => setDeleting(null)}
      />

      {pending && <CommitConfirm result={pending} seconds={CONFIRM_SECONDS} onKeep={onKeep} onRevert={onRevert} />}
    </div>
  )
}
