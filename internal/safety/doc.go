// Package safety implements the heart of RiftRoute (spec §2): snapshot,
// atomic transaction with precomputed inverse, the connectivity watchdog /
// deadman switch, commit-confirm, and panic/flush. Built in M2; the entire
// §2.5 failure-and-recovery matrix must be green on the fake provider AND a
// Linux netns before any real route mutation ships.
package safety
