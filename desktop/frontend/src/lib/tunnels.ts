// What each tunnel type is called, and the file it's configured from.

export type TunnelKind = 'openvpn' | 'wireguard' | 'ikev2'

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
}

/** kindOf reads a tunnel's type; empty or unknown (a daemon from before types) is OpenVPN. */
export function kindOf(t?: string): TunnelKind {
  return t === 'wireguard' || t === 'ikev2' ? t : 'openvpn'
}

/** tunnelTypeName is how a tunnel's protocol reads. */
export function tunnelTypeName(t: string): string {
  return t === 'wireguard' || t === 'ikev2' || t === 'openvpn' ? KINDS[t].name : t
}

/** certExpiry says when a tunnel's login certificate stops working, and whether that's soon (14 days). */
export function certExpiry(iso?: string, now = Date.now()): { days: number; soon: boolean } | null {
  if (!iso) return null
  const at = Date.parse(iso)
  if (!Number.isFinite(at)) return null
  const days = Math.floor((at - now) / 86_400_000)
  return { days, soon: days < 14 }
}
