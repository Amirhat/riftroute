//go:build !linux

package tunnel

// requireESP: no per-socket policy outside Linux. shortcut: on macOS
// IP_IPSEC_POLICY (both ways, then outbound alone) cut the owner's live
// session (2026-11-24: SA up, no L2TP reply), so a session there relies on
// charon's trap policies and Lost (a window of milliseconds if charon is
// stopped from outside); revisit with a way to see why the SA didn't match.
func requireESP(uintptr, uint32) error { return nil }
