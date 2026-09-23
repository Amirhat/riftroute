// One accurate description of the kill switch, shared by Settings and
// Diagnostics (see internal/killswitch for the rules it describes).

export const KILL_SWITCH_SHORT =
  'Your apps reach the internet only through the VPN tunnel — if it drops, they are cut off instead of leaking. VPN clients can still reconnect.'

export function KillSwitchConfirmMessage() {
  return (
    <>
      <span className="block">
        While on, apps you run reach the internet only through a VPN tunnel, your local network, or destinations your
        profiles send around the VPN. If the VPN drops, they are cut off until it reconnects.
      </span>
      <span className="mt-2 block">
        Never blocked: VPN helpers running as administrator (most desktop VPNs, macOS IKEv2), standard VPN ports, and
        system services — so the system resolver’s DNS lookups can still leave outside the tunnel. A VPN app that runs
        without admin rights on a non-standard port (such as 443) may not reconnect until you turn this off. Panic also
        turns it off.
      </span>
    </>
  )
}
