import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { friendly } from '../lib/format'
import type { BugReport } from '../types'
import { Modal } from './Modal'

// copyText uses the Wails runtime clipboard inside the app (the webview's
// navigator.clipboard isn't reliable on a wails:// origin), and the browser
// API elsewhere (dev harness).
async function copyText(text: string): Promise<boolean> {
  const rt = (window as unknown as { runtime?: { ClipboardSetText?: (t: string) => Promise<boolean> } }).runtime
  if (rt?.ClipboardSetText) return rt.ClipboardSetText(text)
  await navigator.clipboard.writeText(text)
  return true
}

// BugReportModal builds the redacted diagnostics report and shows it in full
// BEFORE anything else can happen: the user reads it, then copies or saves it
// and attaches it to an issue themselves. Nothing is uploaded from here.
export function BugReportModal({ onClose }: { onClose: () => void }) {
  const [rep, setRep] = useState<BugReport | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [note, setNote] = useState<{ text: string; ok: boolean } | null>(null)

  useEffect(() => {
    let live = true
    api
      .createBugReport()
      .then((r) => live && setRep(r))
      .catch((e) => live && setErr(friendly(e, 'could not build the report')))
    return () => {
      live = false
    }
  }, [])

  async function copy() {
    if (!rep) return
    try {
      if (!(await copyText(rep.text))) throw new Error('the clipboard refused the text')
      setNote({ text: 'Copied to the clipboard.', ok: true })
    } catch (e) {
      setNote({ text: friendly(e, 'copy failed'), ok: false })
    }
  }

  async function save() {
    if (!rep) return
    try {
      const path = await api.saveBugReport(rep.text)
      if (path) setNote({ text: `Saved to ${path}`, ok: true })
    } catch (e) {
      setNote({ text: friendly(e, 'save failed'), ok: false })
    }
  }

  return (
    <Modal onBackdrop={onClose} className="max-w-3xl">
      <div className="flex items-center justify-between border-b border-line px-4 py-3">
        <h2 className="text-sm font-semibold text-default">Bug report</h2>
        <button onClick={onClose} aria-label="Close" className="text-muted hover:text-default">
          ✕
        </button>
      </div>
      <div className="space-y-3 p-4">
        <p className="text-xs text-muted">
          Addresses, domains, names and home paths are replaced with placeholders, and nothing is sent anywhere. Read it
          through before sharing; then save or copy it and attach it to a GitHub issue.
        </p>
        {!rep && !err && <p className="text-sm text-muted">Collecting diagnostics…</p>}
        {err && <p className="text-sm text-danger">{err}</p>}
        {rep && (
          <>
            <p className="text-xs text-muted">{rep.redactions} values redacted</p>
            <pre
              aria-label="Report preview"
              className="ltr max-h-[50vh] overflow-auto whitespace-pre rounded-lg border border-line bg-base p-3 font-mono text-[11px] leading-relaxed text-default"
            >
              {rep.text}
            </pre>
          </>
        )}
        {note && <p className={`ltr break-all text-xs ${note.ok ? 'text-success' : 'text-danger'}`}>{note.text}</p>}
      </div>
      <div className="flex flex-wrap justify-end gap-2 border-t border-line px-4 py-3">
        <button
          onClick={() => void api.openIssuePage()}
          className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default"
        >
          Open GitHub issues
        </button>
        <button
          onClick={() => void copy()}
          disabled={!rep}
          className="rounded-lg border border-line px-3 py-1.5 text-sm text-muted hover:text-default disabled:opacity-50"
        >
          Copy
        </button>
        <button
          onClick={() => void save()}
          disabled={!rep}
          className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
        >
          Save…
        </button>
      </div>
    </Modal>
  )
}
