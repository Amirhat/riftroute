package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestWatchViewRenders(t *testing.T) {
	m := watchModel{
		updated: time.Unix(0, 0),
		state: domain.State{
			Health: domain.Health{Daemon: domain.DaemonOK, Version: "1.2.3", Provider: "fake", UptimeSeconds: 125},
			VPN:    domain.VPNStatus{Active: true, Interfaces: []string{"utun3"}},
			Drift:  domain.DriftStatus{Pending: true, Adds: 2, Dels: 1},
			Profiles: []domain.ProfileStatus{
				{Name: "work", Mode: domain.ModeExclude, Enabled: true, RuleCount: 3, Applied: false},
			},
			ManagedRouteCount: 5,
		},
		audit: []domain.AuditEvent{
			{TS: time.Unix(100, 0), Actor: domain.ActorUI, Action: "apply", Result: "committed"},
		},
	}
	out := m.View()
	for _, want := range []string{"RiftRoute", "utun3", "PENDING", "work", "apply", "refresh"} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q:\n%s", want, out)
		}
	}
}

func TestWatchViewError(t *testing.T) {
	m := watchModel{err: errString("connection refused")}
	out := m.View()
	if !strings.Contains(out, "unreachable") {
		t.Fatalf("expected unreachable banner, got:\n%s", out)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
