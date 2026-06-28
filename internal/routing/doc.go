// Package routing is the engine: reconcile (desired↔actual diff), plan/inverse
// generation, the longest-prefix-match simulator (powering route-explain and
// conflict detection), and CIDR aggregation (spec §5.2). Pure logic, tested
// against the fake provider. Built out from M2.
package routing
