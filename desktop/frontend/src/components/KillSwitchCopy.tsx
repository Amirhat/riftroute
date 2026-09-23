// One accurate description of the kill switch, shared by Settings and
// Diagnostics (see internal/killswitch for the rules it describes).

export const KILL_SWITCH_SHORT =
  'Your apps reach the internet only through the VPN tunnel — if it drops, they are cut off instead of leaking. VPN clients can still reconnect.'

export function KillSwitchConfirmMessage() {
  return (
    <>
      <span className="block">
        While on, apps you run reach the internet only through a VPN tunnel, your local network, or destinations your
        profiles send around the VPN. If the VPN drops, they are cut off until it reconnects. It stays on across restarts
        and while the RiftRoute service is stopped; Panic turns it off.
      </span>
      <span className="mt-2 block">
        Never blocked: VPN helpers running as administrator (most desktop VPNs, macOS IKEv2), standard VPN ports, system
        services — so the system resolver’s DNS lookups can still leave outside the tunnel — and bridged virtual machines
        or Internet Sharing. Apps that share your Mac’s connection (Docker Desktop, most VMs using NAT) count as your
        apps. A network extension running as administrator (such as a corporate proxy) can carry apps’ traffic around it.
      </span>
      <span className="mt-2 block">
        Out of reach while on: a VPN app that runs without admin rights on a non-standard port (such as 443), and
        hotel or café login pages. Turn it off to get through those.
      </span>
    </>
  )
}
