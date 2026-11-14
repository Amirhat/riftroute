package ipsec

import "fmt"

// plugins charon loads: exactly these, so nothing from a system strongSwan
// applies. kernel-pfkey on macOS (its kernel IPsec), kernel-netlink on
// Linux. socket-default and vici are critical: without either it can do
// nothing, and it stops at once, naming the plugin, rather than run on with
// no socket to drive it.
func plugins(goos string) string {
	kernel := "kernel-netlink"
	if goos == "darwin" {
		kernel = "kernel-pfkey kernel-pfroute"
	}
	return "random nonce openssl kdf x509 pem pkcs1 pkcs8 pubkey constraints " + kernel + " socket-default! vici!"
}

// Conf is charon's strongswan.conf (under charon, which charon-systemd
// falls back to).
//
//   - Random IKE ports: no clash with anything else on 500/4500, and with
//     encap the ESP goes in UDP to the server's 4500 from the start.
//   - No routes and no virtual IPs: transport mode carries one UDP flow; the
//     tunnel's interface is L2TP's own.
//   - Retransmissions give up within the initiate's 30 s.
//   - Its log on stderr (the daemon's), not syslog.
func Conf(goos, socket string) string {
	return fmt.Sprintf(`# written by riftrouted for L2TP/IPsec tunnels; not read by anything else
charon {
    load = %s
    port = 0
    port_nat_t = 0
    install_routes = no
    install_virtual_ip = no
    retransmit_tries = 3
    retransmit_timeout = 2.0
    filelog {
        stderr {
            default = 1
            lib = 2
        }
    }
    plugins {
        vici {
            socket = unix://%s
        }
    }
}
`, plugins(goos), socket)
}
