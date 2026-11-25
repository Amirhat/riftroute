import { describe, expect, it } from 'vitest'
import { ikev2Profile, l2tpProfile } from './tunnels'

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

describe('ikev2Profile', () => {
  const base = { server: 'vpn.example.com', remoteId: '', auth: 'eap' as const, psk: '', localId: '' }

  it('writes an IKEv2 .mobileconfig with the EAP username, escaped', () => {
    const { profile, ready } = ikev2Profile(base, 'alice & <bob>')
    expect(ready).toBe(true)
    expect(profile.type).toBe('ikev2')
    expect(profile.needs_auth).toBe(true)
    expect(profile.config).toContain('<key>VPNType</key><string>IKEv2</string>')
    expect(profile.config).toContain('<key>RemoteIdentifier</key><string>vpn.example.com</string>')
    expect(profile.config).toContain('<key>ExtendedAuthEnabled</key><true/>')
    expect(profile.config).toContain('<key>AuthName</key><string>alice &amp; &lt;bob&gt;</string>')
  })

  it('writes a pre-shared key, and needs it', () => {
    const psk = { ...base, auth: 'psk' as const, psk: 'k', localId: 'me@example.com', remoteId: 'vpn' }
    const { profile, ready } = ikev2Profile(psk)
    expect(ready).toBe(true)
    expect(profile.needs_auth).toBe(false)
    expect(profile.config).toContain('<key>SharedSecret</key><string>k</string>')
    expect(profile.config).toContain('<key>LocalIdentifier</key><string>me@example.com</string>')
    expect(profile.config).toContain('<key>RemoteIdentifier</key><string>vpn</string>')
    expect(ikev2Profile({ ...psk, psk: '' }).ready).toBe(false)
  })
})
