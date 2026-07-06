import { useState } from 'react'
import { Modal } from './Modal'
import { api } from '../lib/api'
import { friendly } from '../lib/format'
import type { ApplyResult, ConfigFile, ConfigImportResult } from '../types'

// ConfigImport brings `riftroute apply file.yaml` into the window: a native file
// picker → strict daemon-side validation → a visual "+X / −Y" preview → an atomic,
// commit-confirmed apply to the live root daemon. Corrupt YAML, invalid values,
// and blocked ranges come back as line-referenced issues rendered inline — every
// failure path is caught and shown, so the frontend never crashes on a bad file.
export function ConfigImport({
  onPending,
  onApplied,
}: {
  onPending: (r: ApplyResult) => void
  onApplied: () => void
}) {
  const [file, setFile] = useState<ConfigFile | null>(null)
  const [preview, setPreview] = useState<ConfigImportResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function reset() {
    setFile(null)
    setPreview(null)
    setError(null)
    setBusy(false)
  }

  async function pick() {
    setError(null)
    setPreview(null)
    try {
      const f = await api.openConfigDialog()
      if (!f || !f.path) return // user cancelled the dialog
      setFile(f)
      setBusy(true)
      // dry-run: validate + build the plan without changing anything.
      setPreview(await api.applyConfigContent(f.content, f.format, true, false))
    } catch (e) {
      setError(friendly(e))
      setFile((f) => f) // keep the modal open to show the error
    } finally {
      setBusy(false)
    }
  }

  async function apply() {
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      const res = await api.applyConfigContent(file.content, file.format, false, false)
      if ((res.issues ?? []).some((i) => i.severity === 'error')) {
        setPreview(res) // config changed under us / still invalid — show why
        return
      }
      const r = res.result
      if (r?.violations && r.violations.length > 0) {
        setError('Refused by guardrails: ' + r.violations.map((v) => v.rule).join(', '))
        return
      }
      reset()
      onApplied()
      if (r?.needs_confirm && r.tx_id) onPending(r) // hand off to commit-confirm
    } catch (e) {
      setError(friendly(e))
    } finally {
      setBusy(false)
    }
  }

  const issues = preview?.issues ?? []
  const errors = issues.filter((i) => i.severity === 'error')
  const warnings = issues.filter((i) => i.severity === 'warning')
  const ops = preview?.plan?.ops ?? []
  const open = file !== null || error !== null
  const canApply = !busy && file !== null && errors.length === 0

  return (
    <>
      <button
        onClick={pick}
        disabled={busy}
        className="rounded-lg border border-accent/50 px-3 py-1.5 text-sm font-medium text-accent hover:bg-accent/10 disabled:opacity-50"
      >
        Import / Apply Config File
      </button>

      {open && (
        <Modal onBackdrop={busy ? undefined : reset}>
          <div className="p-5">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-default">Import config</h2>
              {file && <span className="font-mono text-xs text-muted">{file.name}</span>}
            </div>

            {error && (
              <div className="mt-3 rounded-lg border border-danger/40 bg-danger/5 p-3 text-sm text-danger">{error}</div>
            )}

            {busy && !preview && <p className="mt-4 text-sm text-muted">Validating…</p>}

            {errors.length > 0 && (
              <div className="mt-3">
                <div className="text-sm font-medium text-danger">This config has errors and can’t be applied:</div>
                <ul className="mt-1 max-h-40 overflow-auto rounded-lg border border-danger/30">
                  {errors.map((i, k) => (
                    <li key={k} className="ltr border-b border-danger/20 px-3 py-1.5 text-sm text-danger last:border-0">
                      {i.line ? <span className="text-muted">line {i.line}: </span> : null}
                      {i.msg}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {warnings.length > 0 && (
              <ul className="mt-3 max-h-28 overflow-auto rounded-lg border border-warning/30">
                {warnings.map((i, k) => (
                  <li key={k} className="ltr border-b border-warning/20 px-3 py-1.5 text-sm text-warning last:border-0">
                    {i.line ? <span className="text-muted">line {i.line}: </span> : null}
                    {i.msg}
                  </li>
                ))}
              </ul>
            )}

            {preview && errors.length === 0 && (
              <div className="mt-3">
                <div className="text-sm text-muted">
                  {ops.length === 0 ? 'No changes — already in sync.' : `${ops.length} change(s) to apply:`}
                </div>
                {ops.length > 0 && (
                  <div className="mt-1 max-h-52 overflow-auto rounded-lg border border-line">
                    {ops.map((op, i) => (
                      <div key={i} className="ltr flex items-center gap-2 border-b border-line/60 px-3 py-1.5 text-sm last:border-0">
                        <span className={op.kind.startsWith('add') ? 'text-success' : 'text-danger'}>
                          {op.kind.startsWith('add') ? '+' : '−'}
                        </span>
                        <span className="font-mono text-muted">{op.command.join(' ')}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={reset}
                disabled={busy}
                className="rounded-lg border border-line px-4 py-2 text-sm text-muted hover:text-default disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={apply}
                disabled={!canApply}
                className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
              >
                {busy ? 'Applying…' : 'Apply to daemon'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </>
  )
}

