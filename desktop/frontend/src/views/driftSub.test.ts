import { describe, expect, it } from 'vitest'
import { driftSub } from './Dashboard'

describe('driftSub', () => {
  it('says how many of the adds another program removed', () => {
    expect(driftSub({ pending: true, adds: 2, dels: 0, missing: 1 })).toBe('+2 to add (1 removed by another program) · −0 to remove')
  })
  it('says what RiftRoute stopped putting back', () => {
    const until = new Date(2026, 9, 3, 1, 30).toISOString()
    const text = driftSub({ pending: false, adds: 0, dels: 0, held: [{ route: { dst_cidr: '9.9.9.0/24', iface: 'en0' } as never, until }] })
    expect(text).toMatch(/^another program keeps removing 1 route; not put back until /)
  })
  it('is in sync otherwise', () => {
    expect(driftSub({ pending: false, adds: 0, dels: 0 })).toBe('desired = actual')
  })
})
