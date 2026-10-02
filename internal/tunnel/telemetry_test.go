package tunnel

import (
	"slices"
	"sync"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/telemetry"
)

type countRec struct {
	mu   sync.Mutex
	keys []string
}

func (c *countRec) add(k string) { c.mu.Lock(); c.keys = append(c.keys, k); c.mu.Unlock() }
func (c *countRec) n(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, x := range c.keys {
		if x == k {
			n++
		}
	}
	return n
}

// What the report counts of a tunnel's sessions, read off its state: a
// connection, a drop and the reconnection, failed attempts by cause, a
// give-up, a missing engine.
func TestTunnelSessionsAreCounted(t *testing.T) {
	h, fi := newIKEHarness(t)
	rec := &countRec{}
	h.m.o.Count = rec.add
	if _, err := h.m.Save(t.Context(), ikeSpec(t, newTestPKI(t))); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("office"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "office", domain.TunnelConnected)
	fi.Drop()
	waitFor(t, "a second charon-cmd", func() bool { return len(fi.Started()) == 2 })
	waitState(t, h.m, "office", domain.TunnelConnected)
	waitFor(t, "counted", func() bool { return rec.n("tunnel.ikev2.connected") == 2 })
	if rec.n("tunnel.ikev2.drops") != 1 || rec.n("tunnel.ikev2.failed.other") != 0 {
		t.Fatalf("counted %v", rec.keys)
	}
	if err := h.m.Disconnect(t.Context(), "office"); err != nil {
		t.Fatal(err)
	}
	if rec.n("tunnel.ikev2.drops") != 1 {
		t.Fatal("a disconnect counted as a drop")
	}

	fi.Fail = []string{"received AUTHENTICATION_FAILED notify error"}
	if err := h.m.Connect("office"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "office", domain.TunnelFailed)
	waitFor(t, "give-up counted", func() bool { return rec.n("tunnel.ikev2.gave_up") == 1 })
	if n := rec.n("tunnel.ikev2.failed.auth"); n != maxFailedAttempts {
		t.Fatalf("%d failed attempts counted, want %d: %v", n, maxFailedAttempts, rec.keys)
	}

	fi.Fail, fi.Missing = nil, true
	_ = h.m.Connect("office")
	if rec.n("tunnel.ikev2.failed.engine") != 1 {
		t.Fatalf("missing engine not counted: %v", rec.keys)
	}
	for _, k := range rec.keys {
		if !telemetry.ValidKey(k) {
			t.Errorf("%s isn't a report key", k)
		}
	}
}

// Every diagnosis maps to a code (the message itself never goes anywhere).
func TestFailureCodesFromDiagnoses(t *testing.T) {
	cases := map[string]string{
		diagnose("x", "connection-reset", []string{"VERIFY OK"}):                                                                    "auth",
		diagnose("x", "tls-error", nil):                                                                                             "tls",
		diagnose("x", "", []string{"VERIFY EKU ERROR"}):                                                                             "eku",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2EAP, []string{"received EAP_FAILURE"}):                                        "auth",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2PSK, []string{"received AUTHENTICATION_FAILED notify error"}):                 "auth",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"AUTHENTICATION_FAILED"}):                               "auth",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"NO_PROPOSAL_CHOSEN"}):                                  "proposal",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"IDr 'a' does not match to 'b'"}):                       "identity",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"constraint check failed"}):                             "identity",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"no trusted ECDSA public key found"}):                   "cert",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"certificate has expired"}):                             "cert",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"giving up after 5 retransmits"}):                       "unreachable",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"00[LIB] plugin 'vici': failed to load - x not found"}): "plugin",
		diagnoseIKE("x", domain.TunnelViaDirect, IKEv2Certificate, []string{"something odd"}):                                       "other",
		"the server gave the tunnel the network 10.0.0.0/8, which holds your router; refusing":                                      "addressing",
		"gave up after 6 attempts: something":                                                                                       "other",
	}
	for msg, want := range cases {
		if got := failureCode(msg); got != want {
			t.Errorf("%q → %s, want %s", msg, got, want)
		}
	}
	for _, f := range failureCodes {
		if !slices.Contains(telemetry.FailureCodes, f.code) {
			t.Errorf("%s isn't a report failure code", f.code)
		}
	}
}
