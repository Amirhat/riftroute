// Package netmon is the per-OS network event monitor (spec §4.5). It emits
// debounced events (VPNUp/Down, DefaultRouteChanged, LinkChanged, AddrChanged,
// DNSChanged, Wake, DHCPLeaseChanged) that the reconciler subscribes to for the
// auto-apply path. macOS: route socket / SCDynamicStore. Linux: netlink
// (`ip monitor`). Built in M3.
package netmon
