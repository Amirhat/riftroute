// What each tunnel type is called, and the file it's configured from.

import type { TunnelProfileFile } from '../types'

export type TunnelKind = 'openvpn' | 'wireguard' | 'ikev2' | 'l2tp'

export interface KindInfo {
  name: string // OpenVPN
  a: string // "an OpenVPN" — the name with its article
  file: string // what the file is: "OpenVPN profile"
  ext: string // .ovpn
  word: string // how the text refers to it: "profile" / "configuration"
}

export const KINDS: Record<TunnelKind, KindInfo> = {
  openvpn: { name: 'OpenVPN', a: 'an OpenVPN', file: 'OpenVPN profile', ext: '.ovpn', word: 'profile' },
  wireguard: { name: 'WireGuard', a: 'a WireGuard', file: 'WireGuard configuration', ext: '.conf', word: 'configuration' },
  ikev2: { name: 'IKEv2', a: 'an IKEv2', file: 'IKEv2 profile', ext: '.mobileconfig', word: 'profile' },
  l2tp: {
    name: 'L2TP/IPsec',
    a: 'an L2TP/IPsec',
    file: 'L2TP configuration',
    ext: '[L2TP] or .mobileconfig',
    word: 'configuration',
  },
}

/** kindOf reads a tunnel's type; empty or unknown (a daemon from before types) is OpenVPN. */
export function kindOf(t?: string): TunnelKind {
  return t === 'wireguard' || t === 'ikev2' || t === 'l2tp' ? t : 'openvpn'
}

/** tunnelTypeName is how a tunnel's protocol reads. */
export function tunnelTypeName(t: string): string {
  return t === 'wireguard' || t === 'ikev2' || t === 'l2tp' || t === 'openvpn' ? KINDS[t].name : t
}

/** certExpiry says when a tunnel's login certificate stops working, and whether that's soon (14 days). */
export function certExpiry(iso?: string, now = Date.now()): { days: number; soon: boolean } | null {
  if (!iso) return null
  const at = Date.parse(iso)
  if (!Number.isFinite(at)) return null
  const days = Math.floor((at - now) / 86_400_000)
  return { days, soon: days < 14 }
}

/** L2TPFields are an L2TP/IPsec connection typed into the app instead of a file. */
export interface L2TPFields {
  server: string
  psk: string
  noIPsec: boolean
}

/**
 * l2tpProfile turns typed fields into RiftRoute's [L2TP] file, as if it had been
 * chosen: the daemon parses and checks it the same way. error is set for a value
 * the file can't carry (a line break); missing fields leave ready false.
 */
export function l2tpProfile(f: L2TPFields): { profile: TunnelProfileFile; ready: boolean } {
  const server = f.server.trim()
  const error = /\s/.test(server)
    ? 'The server is a host name or address, without spaces.'
    : /[\r\n]/.test(f.psk)
      ? 'The pre-shared key is a single line.'
      : ''
  const config = ['[L2TP]', `Server = ${server}`, f.noIPsec ? 'IPsec = none' : `PreSharedKey = ${f.psk}`, ''].join('\n')
  const what = f.noIPsec ? 'L2TP, unencrypted' : 'L2TP/IPsec'
  return {
    profile: {
      path: '',
      name: 'typed in',
      type: 'l2tp',
      config,
      servers: server ? [`${server} (${what})`] : [],
      needs_auth: true,
      ignored: [],
      username: '',
      password: '',
      error,
    },
    ready: server !== '' && (f.noIPsec || f.psk.trim() !== ''),
  }
}
