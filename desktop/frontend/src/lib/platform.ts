// Host-OS detection for the native window chrome. On macOS the window uses a
// hidden inset title bar (desktop/main.go: mac.TitleBarHiddenInset), so the web
// content runs edge-to-edge underneath the traffic-light buttons. Tagging <html>
// with data-platform lets CSS reserve that space (the `mac:` Tailwind variant)
// and turn the top chrome into the window's drag region (index.css .app-drag).

interface WailsRuntime {
  Environment(): Promise<{ platform: string }>
}

/**
 * Resolve the host OS from the Wails runtime and set `data-platform` on `root`
 * (e.g. "darwin"). Outside the webview (browser dev mode, tests) there is no
 * runtime and nothing is tagged. Never rejects and never waits longer than
 * `timeoutMs`, so boot can await it before the first render — no layout jump
 * when the macOS inset kicks in, and no blank window if the runtime stalls.
 */
export async function tagPlatform(
  root: HTMLElement = document.documentElement,
  timeoutMs = 300,
): Promise<string | undefined> {
  const rt = (window as unknown as { runtime?: Partial<WailsRuntime> }).runtime
  if (!rt?.Environment) return undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    const env = await Promise.race([
      rt.Environment(),
      new Promise<undefined>((resolve) => {
        timer = setTimeout(resolve, timeoutMs)
      }),
    ])
    if (env?.platform) root.dataset.platform = env.platform
    return env?.platform
  } catch {
    return undefined
  } finally {
    clearTimeout(timer)
  }
}
