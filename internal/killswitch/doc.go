// Package killswitch implements egress blocking when the tunnel drops, via pf on
// macOS (pfctl + dedicated anchor) and nftables on Linux (dedicated table/chain)
// — spec §6/§7. Built in M6.
package killswitch
