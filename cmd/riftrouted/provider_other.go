//go:build !darwin && !linux

package main

import "github.com/Amirhat/riftroute/internal/provider"

// realProvider on unsupported platforms (e.g. a future Windows target) returns
// the fail-safe stub so the daemon always builds and runs (spec §8).
func realProvider() provider.RouteProvider { return provider.NewUnsupported() }
