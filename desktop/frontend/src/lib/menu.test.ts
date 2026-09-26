import { describe, it, expect } from 'vitest'
import { menuNav } from './menu'
import { VIEWS } from '../components/Sidebar'

describe('menuNav', () => {
  it('opens every view by name', () => {
    for (const v of VIEWS) expect(menuNav(`nav:${v}`)).toEqual({ view: v })
  })

  it('sends Explain to the Routing Table lookup', () => {
    expect(menuNav('nav:explain')).toEqual({ view: 'routes', focusLookup: true })
  })

  it('ignores unknown targets instead of opening a blank page', () => {
    for (const a of ['nav:', 'nav:nope', 'nav:Routes', 'nav:constructor', 'nav:__proto__', 'refresh', 'toggle-theme', 'dashboard']) {
      expect(menuNav(a)).toBeNull()
    }
  })

  // The native menu lives in Go (desktop/main.go); read its source so a menu
  // item added there without a destination here fails this test.
  it('has a destination for every nav item in the native menu', async () => {
    // @ts-expect-error -- Node's types aren't installed for the frontend
    const { readFileSync } = await import('node:fs')
    // A plain path (Vite rewrites `new URL(file, import.meta.url)` into an
    // asset URL, and jsdom's URL isn't one Node's fs accepts).
    const here = decodeURIComponent(new URL(import.meta.url).pathname)
    const mainGo: string = readFileSync(here.replace(/src\/lib\/menu\.test\.ts$/, '../main.go'), 'utf8')
    const actions = [...mainGo.matchAll(/"(nav:[^"]*)"/g)].map((m) => m[1])
    expect(actions.length).toBeGreaterThan(0)
    for (const a of actions) expect(menuNav(a), a).not.toBeNull()
  })
})
