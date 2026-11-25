import { describe, expect, it } from 'vitest'
import { l2tpProfile } from './tunnels'

describe('l2tpProfile', () => {
  it('writes the [L2TP] file the daemon reads', () => {
    const { profile, ready } = l2tpProfile({ server: ' vpn.example.com ', psk: 'k=1', noIPsec: false })
    expect(ready).toBe(true)
    expect(profile.error).toBe('')
    expect(profile.type).toBe('l2tp')
    expect(profile.config).toBe('[L2TP]\nServer = vpn.example.com\nPreSharedKey = k=1\n')
    expect(profile.servers).toEqual(['vpn.example.com (L2TP/IPsec)'])
  })

  it('writes IPsec = none, and needs no key then', () => {
    const { profile, ready } = l2tpProfile({ server: '192.0.2.7', psk: '', noIPsec: true })
    expect(ready).toBe(true)
    expect(profile.config).toContain('IPsec = none')
    expect(profile.servers).toEqual(['192.0.2.7 (L2TP, unencrypted)'])
  })

  it("refuses what the file can't carry, and isn't ready without its fields", () => {
    const twoLines = l2tpProfile({ server: 'vpn.example.com', psk: 'a\nIPsec = none', noIPsec: false })
    expect(twoLines.profile.error).not.toBe('')
    expect(l2tpProfile({ server: 'vpn example', psk: 'k', noIPsec: false }).profile.error).not.toBe('')
    expect(l2tpProfile({ server: '', psk: 'k', noIPsec: false }).ready).toBe(false)
    expect(l2tpProfile({ server: 'vpn.example.com', psk: '', noIPsec: false }).ready).toBe(false)
  })
})
