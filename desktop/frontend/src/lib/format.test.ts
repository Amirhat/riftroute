import { describe, it, expect } from 'vitest'
import { fmtUptime, ownerTone } from './format'

describe('fmtUptime', () => {
  it('formats sub-minute as seconds', () => {
    expect(fmtUptime(45)).toBe('45s')
  })
  it('formats compound durations', () => {
    expect(fmtUptime(3661)).toBe('1h 1m 1s')
    expect(fmtUptime(90061)).toBe('1d 1h 1m 1s')
  })
  it('guards against bad input', () => {
    expect(fmtUptime(-1)).toBe('—')
    expect(fmtUptime(Number.NaN)).toBe('—')
  })
})

describe('ownerTone', () => {
  it('maps owners to tones', () => {
    expect(ownerTone('riftroute')).toBe('accent')
    expect(ownerTone('vpn')).toBe('vpn')
    expect(ownerTone('system')).toBe('muted')
  })
})
