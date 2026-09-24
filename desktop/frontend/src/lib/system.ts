// Clipboard and browser helpers. Inside the app they go through the Wails
// runtime (the webview's navigator.clipboard isn't reliable on a wails://
// origin, and a plain link would navigate the app window itself); elsewhere
// (dev harness, tests) they fall back to the browser APIs.

type WailsRuntime = {
  ClipboardSetText?: (t: string) => Promise<boolean>
  BrowserOpenURL?: (url: string) => void
}

const wailsRuntime = () => (window as unknown as { runtime?: WailsRuntime }).runtime

export async function copyText(text: string): Promise<boolean> {
  const rt = wailsRuntime()
  if (rt?.ClipboardSetText) return rt.ClipboardSetText(text)
  await navigator.clipboard.writeText(text)
  return true
}

// openURL opens an https link in the user's browser.
export function openURL(url: string) {
  if (!/^https:\/\//.test(url)) return
  const rt = wailsRuntime()
  if (rt?.BrowserOpenURL) rt.BrowserOpenURL(url)
  else window.open(url, '_blank', 'noopener')
}
