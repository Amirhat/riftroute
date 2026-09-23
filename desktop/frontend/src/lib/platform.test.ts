import { afterEach, describe, it, expect } from 'vitest'
import { tagPlatform } from './platform'

const w = window as unknown as { runtime?: unknown }

afterEach(() => {
  delete w.runtime
})

describe('tagPlatform', () => {
  it('tags the host OS from the Wails runtime', async () => {
    w.runtime = { Environment: () => Promise.resolve({ platform: 'darwin' }) }
    const el = document.createElement('div')
    expect(await tagPlatform(el)).toBe('darwin')
    expect(el.dataset.platform).toBe('darwin')
  })
  it('leaves the page untagged outside the webview', async () => {
    const el = document.createElement('div')
    expect(await tagPlatform(el)).toBeUndefined()
    expect(el.dataset.platform).toBeUndefined()
  })
  it('never rejects or blocks boot when the runtime fails or stalls', async () => {
    const el = document.createElement('div')
    w.runtime = { Environment: () => Promise.reject(new Error('ipc down')) }
    expect(await tagPlatform(el)).toBeUndefined()
    w.runtime = { Environment: () => new Promise(() => {}) }
    expect(await tagPlatform(el, 10)).toBeUndefined()
    expect(el.dataset.platform).toBeUndefined()
  })
})
