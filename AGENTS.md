# AGENTS.md — Building Cross-Platform Desktop Apps (web-UI + native shell)

**Audience:** a coding agent (or engineer) about to build a desktop app whose UI is
**web technology rendered in a native window**, backed by a local process. This is the
most productive architecture for a solo dev / small team: web tech for the UI, a real
language for the backend, one shippable binary.

**Scope:** *desktop-specific* decisions only — shell/stack choice, the native window +
menu, process lifecycle, native dialogs, the dev loop, cross-compilation with cgo,
code-signing/notarization, distribution, webview-specific UI traps, and how to verify.
It deliberately does **not** re-teach generic web/backend best practices.

**How to read this:** every item is a rule — `ALWAYS` / `NEVER` / `PREFER` / `VERIFY`.
Work top-to-bottom; early decisions constrain later ones. Each rule is followed by a
one-line *why* only where it prevents misapplication.

---

## 0. Decision gate — run this before writing any code

1. **Classify the app in one sentence.** Is it (a) *"a local tool I'm fine opening in a
   browser tab,"* or (b) *"a desktop app with its own window, Dock/taskbar icon, and menu"*?
2. **If (a):** a plain local HTTP server + `open http://localhost:PORT` is enough. Skip
   most of this guide; still read §2 (dev loop), §4 (lifecycle), §11 (privacy).
3. **If (b): default to a webview framework — Wails (Go) or Tauri (Rust).** Do **not**
   build the native shell yourself.
4. **NEVER hand-roll a native webview window + menu + lifecycle layer unless you have a
   hard, specific reason.** You will reimplement — worse — what Wails/Tauri give for free:
   native window, native menu bar, native file dialogs, single-instance handling, app
   lifecycle, asset bundling, and signing/notarization helpers. *Why: a project that
   started with "just open the browser in app mode" ended up hand-writing ~400 lines of
   Objective-C + lifecycle code to get a real window — i.e. a worse Wails.*

**One-line stack matrix:**

| Option | Use when |
|---|---|
| **Wails** | Backend is Go; want a native window + the smallest sane footprint. **Default.** |
| **Tauri** | Backend is Rust; want the smallest binary + a tight security model. |
| **Electron** | You need pixel-identical rendering across OSes and a deep ecosystem, and can accept ~100 MB+ with a bundled Chromium. |
| **Server + system browser** | Internal tool; "desktop feel" not required; zero native code. |
| **Fully native (Fyne, Gio, SwiftUI, …)** | No web UI at all; native widgets. Different paradigm — not covered here. |

**Internalize this consequence:** outside Electron, the UI does **not** run in Chrome. It
runs in the OS webview — **WKWebView on macOS, WebView2 (Chromium) on Windows, WebKitGTK
on Linux.** Your CSS/JS must work on **WebKit**, not just Chrome.

---

## 1. Stack & shell rules

- **PREFER Wails/Tauri** (per §0). They own the window, menu, dialogs, tray, single-instance,
  update hooks, and packaging.
- **VERIFY rendering on the real target engine, not Chrome.** A layout that's perfect in
  Chrome can break in WKWebView/WebKitGTK. Test in the actual webview (or at least Safari).
- **Keep the backend and UI decoupled** behind a small RPC/IPC or HTTP boundary. This keeps
  the shell swappable (browser ↔ native) and the backend testable headless.
- **NEVER bind business logic to the shell.** The window/menu must call the *same* actions
  the UI already exposes; the backend must not know how it is being displayed.

---

## 2. Dev loop — the #1 source of wasted time

- **KNOW your reload tiers.** A UI served from disk hot-reloads on save. **Compiled backend
  code does NOT** — it keeps running the old binary until you rebuild *and* restart. *Why:
  the classic trap is "my new endpoint isn't working" — it was; the old binary was still up.*
- **ALWAYS use a watch mode that rebuilds AND restarts the backend** (`wails dev`,
  `tauri dev`, or a Go watcher like `air`/`reflex`). Never hand-restart per backend edit.
- **In dev, serve the UI from disk** (a `-dev <dir>` flag); embed assets only for release
  builds (`go:embed` / the framework bundler).
- **Use a different port in dev than prod, and NEVER assume the port is free.** Acquire the
  listener up front; if it's taken, probe whether it's *your own* already-running instance
  (a known health endpoint) and hand off to it, otherwise fail with a clear message.
- **VERIFY in the actual rendered UI after a change** (screenshot + read computed styles),
  not by reasoning about the code. If "eval in page" hangs, suspect a blocked UI thread
  (§6), not a flaky tool.

---

## 3. Native shell: window, Dock/taskbar, menu

With Wails/Tauri this is mostly config. **If you hand-roll it (discouraged), these traps
each cost about a day:**

- **Run all UI on the main OS thread.** On macOS, lock to the main thread at startup
  (`runtime.LockOSThread()` in `init`) and run the native loop there; serve HTTP on a
  background goroutine.
- **Keep strong references to delegates/handlers.** Cocoa's `NSApplication.delegate` is a
  *weak* reference — if your delegate isn't held by a long-lived (file-scope/static)
  variable, ARC frees it and your "quit on last window closed" hook silently never fires.
- **Bridge the menu to the UI; don't reimplement actions.** Make each native menu item run
  a tiny snippet against the webview (`webview.eval("app.doThing()")`) so menus reuse the
  UI's existing actions.
- **Provide the standard Edit menu** (Undo/Cut/Copy/Paste/Select-All) — without it, ⌘C/⌘V
  don't work in text inputs inside a webview.
- **Set the app icon explicitly** so it appears in the Dock/taskbar even when launched from
  a terminal (no bundle to supply one).

---

## 4. App lifecycle — make it behave like a real app

- **Closing the window must quit the process** (single-window app) **and free the port** so
  the next launch is clean. Users should never have to Force-Quit.
- **Tie process lifetime to the UI being present.** Robust pattern for the server+webview
  model: the UI holds a live connection (SSE/WebSocket) while open and sends an explicit
  "closing" beacon on unload; the backend exits when no UI is connected.
- **Use grace periods, not instant exit:**
  - **short** (~2 s) on an explicit "window closing" beacon → exit promptly;
  - **long** (~15–30 s) if the connection merely *drops* → a reload, laptop sleep/wake, or a
    throttled background tab can reconnect and cancel the quit;
  - **startup backstop** (~60–90 s) so a failed window-open never leaves the process holding
    the port forever; cancel it on the first request.
- **Handle the timer race:** when the quit timer fires, re-check that no UI reconnected in
  the meantime before calling exit.
- **Install signal handlers** (SIGINT/SIGTERM) for graceful shutdown from Ctrl-C / `kill` /
  Activity Monitor.
- **VERIFY:** open → close → relaunch immediately (port is free); reload the window (app
  stays up); sleep/wake (app stays up).

---

## 5. Native dialogs & OS integration

- **NEVER ship a file/folder picker implemented for one OS only.** *Why: a macOS-only
  AppleScript (`osascript`) picker leaves Linux/Windows with no native dialog.* Use the
  framework's cross-platform dialog API, or implement per-OS with a tested fallback.
- **"Open in editor / terminal / file manager / browser" is per-OS:** macOS `open`, Windows
  `start`/`explorer`, Linux `xdg-open` (+ terminal-emulator detection). Centralize these and
  degrade gracefully when a tool is absent.
- **Reveal-in-file-manager, open-on-web, copy-to-clipboard** are table stakes for a desktop
  app — wire them early.

---

## 6. Webview UI traps (the desktop-specific ones)

Generic CSS/JS practices are out of scope; these specifically bite in a single-window webview.

- **NEVER block the UI thread with an unbounded synchronous render.** A webview has one main
  thread; rendering a 50k-line diff or an infinite list synchronously freezes the whole
  window — no spinner, no input. **Cap or virtualize** large renders and show a "too large —
  N items" affordance. *Symptom in automation: screenshot/eval calls hang.*
- **Define an explicit z-index layer scale up front** (e.g. base 0, dropdown 40, drawer 60,
  sheet 70, modal 90, dialog 100, toast 110). *Why: dynamically-appended overlays sit
  **above** static ones at equal z-index because of DOM order — so a statically-placed modal
  can open **behind** a runtime sheet and look like a freeze.* Assign layers deliberately.
- **Theme with CSS variables from line one.** Every color goes in `:root` custom properties;
  a theme is then a variable swap (`[data-theme="light"]`). **NEVER hardcode hex colors in
  component rules** — they'll be unreadable in the other theme (e.g. dark text on a
  hardcoded-dark hover). Design light and dark in parallel.
- **Use CSS Grid for tabular/diff/data layouts, not nested flexboxes with empty placeholder
  cells.** *Why: an empty `display:flex` cell inside a `white-space:pre` context can stretch
  to many times its line height — a subtle, hard-to-find bug. Grid cells collapse predictably.*
- **Gate ALL interactive styling on a mode flag when a component is reused read-only.** A
  diff/list component used both for "editable selection" and "read-only view" must not leak
  its selection styling (dimming, strike-through, checkboxes) into the read-only view.
- **Center glyphs with transforms, not magic pixel offsets** (`left:50%;
  transform:translate(-50%,-50%)`), so they stay centered across font sizes and engines.
- **Study the reference app before inventing an affordance.** *Why: a hand-invented
  per-line-checkbox selection was noisy; the established pattern (a colored gutter on
  selected lines, à la GitHub Desktop) was cleaner. Copy the proven UX first.*
- **VERIFY exact styling by reading computed values**, not by eyeballing a screenshot —
  screenshots lie about sub-pixel position and color.

---

## 7. i18n / RTL

- **Don't ship localization until it's asked for — but build i18n-ready.** Route every
  user-facing string through a `t()` lookup, use CSS logical properties
  (`margin-inline-start`, not `margin-left`), and keep layouts direction-agnostic. Adding a
  language later is then cheap.
- **Keep the language switch behind a flag** so you can develop/retain the machinery without
  exposing an unfinished translation.
- **Force `direction: ltr` on code/diff/terminal containers** even in an RTL UI — a CSS Grid
  or pre-formatted block otherwise mirrors its columns and reads backwards.

---

## 8. Build & cross-compile

- **cgo for a native window means per-OS toolchains.** A native macOS window (WKWebView via
  cgo) **cannot** be produced by a pure-Go cross-compile from Linux. Split the build:
  - **macOS slice:** `CGO_ENABLED=1`, built on a macOS runner; cross the two arches with
    clang `-arch` (`CC=clang -arch x86_64|arm64`).
  - **Other platforms:** `CGO_ENABLED=0` with a build-tagged stub
    (`//go:build !darwin || !cgo`) that falls back to browser mode, so *every* configuration
    still compiles.
- **ALWAYS keep a no-native fallback path** so the app still builds and runs (browser mode)
  where the native shell isn't available.
- **Build the matrix in CI on the right runners;** don't rely on a single host. (Wails/Tauri
  ship cross-build tooling that handles much of this.)
- **Use `-trimpath` and `-ldflags "-s -w -X main.version=…"`** for clean, smaller,
  version-stamped release binaries.

---

## 9. Signing, notarization & packaging (macOS is the hard one)

- **Know the macOS spectrum and pick deliberately:**
  1. **Unsigned** → Gatekeeper shows *"app is damaged / can't be opened."* Bad first impression.
  2. **Ad-hoc signed** (`codesign --sign -`) → runs on Apple Silicon without the "damaged"
     error, but the **first launch still needs right-click → Open** (or clearing the
     quarantine attribute). Free, no account.
  3. **Developer ID signed + notarized** → zero prompts. Requires a paid **Apple Developer
     account**, a Developer ID certificate (hardened runtime + timestamp), and notarization
     (`xcrun notarytool submit … --wait`, then `xcrun stapler staple`).
- **Document the install step that matches your signing level** (e.g. the right-click→Open
  dance for ad-hoc) in the README.
- **Gate signing/notarization CI steps on secrets being present**, so a contributor without
  Apple credentials still gets a working (ad-hoc) build.
- **Distribution channels:** `.dmg` and/or a Homebrew tap (macOS); AppImage/`.deb` (Linux);
  installer/MSIX (Windows). Frameworks generate most of these.
- **Auto-update:** at minimum, check the latest release (e.g. the GitHub Releases API) and
  notify with a download link; full self-update needs a signed feed (Sparkle / Tauri updater).

---

## 10. Verify like a user (and review before shipping)

- **Run the real app and observe the real window** — don't ship on unit tests alone.
  Screenshot the actual UI; click through the actual flows.
- **For a CLI-wrapping app, integration-test against throwaway real state, not mocks.** Spin
  up the real backend over an in-process test server, create temporary repos/files/DBs, use
  local fixtures as "remotes," and assert the real resulting state. This runs offline, is
  fast, and catches real bugs.
- **Shell out to the underlying CLI (git/docker/…) instead of reimplementing it** when
  wrapping a tool — fidelity beats purity, and the user's existing credentials/config just
  work. Parse **machine-readable output** (`--porcelain`, `-z`, `--format` with explicit
  field separators), set non-interactive env (`GIT_TERMINAL_PROMPT=0`), and add a timeout to
  every external call.
- **Run one adversarial review pass before shipping a large change** — a reviewer whose job
  is to *refute* each change. It reliably catches the subtle, plausible-looking bugs a
  feature pass introduces.
- **Don't defer frontend tests forever** — at least a smoke test (Playwright/WebDriver) of
  the critical flows.

---

## 11. Privacy & safety before you ship / open-source

- **Bind the local server to `127.0.0.1` only**, never `0.0.0.0`. A desktop app's backend
  must not be reachable from the network.
- **Scrub internal hostnames, tokens, usernames, and sample data before pushing to a public
  repo** — placeholders, fixtures, screenshots, *and commit history*. If something leaked,
  rewrite history and force-push; don't just delete it in a follow-up commit.
- **Be deliberate about powerful features.** "Run an arbitrary command in every project" is
  fine for a local tool, but it is remote code execution if the server is ever exposed —
  another reason for the 127.0.0.1 bind and for not trusting any non-local request.
- **Escape untrusted content when building HTML.** Anything from disk (file contents, paths,
  branch names) injected into the DOM must be escaped — repo/file content is untrusted input.

---

## Appendix A — If you keep the "server + system browser" approach (no native window)

- Open the UI in the browser's app mode for a window-like feel (`chrome --app=URL`), with
  flags to suppress first-run / keychain / default-browser prompts and a dedicated
  `--user-data-dir` profile.
- Accept the limitations: depends on a Chromium browser being installed; no native menu; no
  native dialogs (you'll shell out per-OS); window state isn't persisted natively; it's a
  separate browser process you don't control.
- Still apply §4 — tie the server to the page via SSE so closing the tab quits the app.

## Appendix B — One-time checklist for a new desktop app

1. Decide web-tool vs desktop-app (§0). If desktop → `wails init` (or `tauri init`).
2. Wire the backend↔UI boundary; serve UI from disk in dev, embed for release.
3. Watch-mode dev loop + distinct dev port + single-instance handoff.
4. Native window + Dock/taskbar icon + menu (bridged to UI actions) + standard Edit menu.
5. Lifecycle: close-to-quit, grace periods, signal handlers, port freed on exit.
6. Cross-platform dialogs (no single-OS pickers).
7. Theme via CSS vars (light + dark); explicit z-index scale; cap large renders.
8. CI build matrix (cgo split if hand-rolled); `-trimpath` + version stamp; always-compiles fallback.
9. Signing/notarization per target level; packaging (.dmg / AppImage / MSIX); README install steps.
10. Verify in the real window; adversarial review; scrub secrets; bind 127.0.0.1.