package l2tp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func fastTimers(t *testing.T) {
	t.Helper()
	f, m, tr, tk := ctlFirst, ctlMax, ctlTries, tick
	ctlFirst, ctlMax, ctlTries, tick = 20*time.Millisecond, 40*time.Millisecond, 3, 5*time.Millisecond
	t.Cleanup(func() { ctlFirst, ctlMax, ctlTries, tick = f, m, tr, tk })
}

func dialFake(t *testing.T, f *FakeServer, user, pass string, encrypted bool) (*Session, error) {
	t.Helper()
	ap, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := Dial(ctx, Config{Conn: c, Username: user, Password: pass, Encrypted: encrypted})
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

func TestSessionLogsInEachWay(t *testing.T) {
	for _, auth := range []string{"mschapv2", "chap", "pap", "none"} {
		t.Run(auth, func(t *testing.T) {
			f := &FakeServer{Users: map[string]string{`CORP\alice`: "s3cret"}, Auth: auth,
				DNS: []netip.Addr{netip.MustParseAddr("10.77.0.53"), netip.MustParseAddr("10.77.0.54")}}
			s, err := dialFake(t, f, `CORP\alice`, "s3cret", true)
			if err != nil {
				t.Fatal(err)
			}
			if s.LocalIP().String() != "10.77.0.2" || s.PeerIP().String() != "10.77.0.1" {
				t.Errorf("addresses %s %s", s.LocalIP(), s.PeerIP())
			}
			if len(s.DNS()) != 2 || s.DNS()[0].String() != "10.77.0.53" {
				t.Errorf("dns %v", s.DNS())
			}
			if s.MTU() != 1400 {
				t.Errorf("mtu %d", s.MTU())
			}
			// Both ways.
			pkt := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			if err := s.WritePacket(pkt); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-f.Received():
				if !bytes.Equal(got, pkt) {
					t.Fatalf("server got %x", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the server got nothing")
			}
			back := append([]byte{}, pkt...)
			back[4] = 0x99
			if err := f.Send(back); err != nil {
				t.Fatal(err)
			}
			got, err := s.ReadPacket()
			if err != nil || !bytes.Equal(got, back) {
				t.Fatalf("client got %x, %v", got, err)
			}
			if rx, tx := s.Counters(); rx != 20 || tx != 20 {
				t.Errorf("counters %d %d", rx, tx)
			}
			if err := s.Close(); err != nil || s.Err() != nil {
				t.Errorf("close: %v %v", err, s.Err())
			}
		})
	}
}

func TestSessionRejectedLogin(t *testing.T) {
	for _, auth := range []string{"mschapv2", "chap", "pap"} {
		t.Run(auth, func(t *testing.T) {
			f := &FakeServer{Users: map[string]string{"alice": "right"}, Auth: auth}
			_, err := dialFake(t, f, "alice", "wrong", true)
			if !errors.Is(err, errRejected) || !strings.Contains(err.Error(), "rejected the username or password") {
				t.Fatalf("%v", err)
			}
			if f.Logins() != 1 {
				t.Errorf("%d login attempts", f.Logins())
			}
		})
	}
}

// A server that accepts any login without proving it knows the password
// isn't trusted.
func TestSessionChecksTheServersProof(t *testing.T) {
	f := &FakeServer{Users: map[string]string{"alice": "pw"}, BadAuthenticator: true}
	_, err := dialFake(t, f, "alice", "pw", true)
	if err == nil || !strings.Contains(err.Error(), "couldn't prove it knows the password") {
		t.Fatalf("%v", err)
	}
}

// Without IPsec, PAP (the password in the clear) is refused: the client asks
// for MS-CHAPv2 instead.
func TestSessionNoPAPInTheClear(t *testing.T) {
	f := &FakeServer{Users: map[string]string{"alice": "pw"}, Auth: "pap"}
	s, err := dialFake(t, f, "alice", "pw", false)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	auth := f.Auth
	f.mu.Unlock()
	if auth != "mschapv2" || !s.LocalIP().IsValid() {
		t.Fatalf("logged in by %s", auth)
	}
}

// A server that takes only PAP, without IPsec: refused, saying why.
func TestSessionPAPOnlyInTheClear(t *testing.T) {
	f := &FakeServer{Users: map[string]string{"alice": "pw"}, Auth: "pap", Insist: true}
	_, err := dialFake(t, f, "alice", "pw", false)
	if !errors.Is(err, errPAPInClear) {
		t.Fatalf("%v", err)
	}
	if f.Logins() != 0 {
		t.Error("the password was sent")
	}
}

func TestSessionFailures(t *testing.T) {
	fastTimers(t)
	for name, c := range map[string]struct {
		f    *FakeServer
		want string
	}{
		"silent":     {&FakeServer{Silent: true}, "the server didn't answer: nothing came back"},
		"secret":     {&FakeServer{TunnelSecret: true}, "tunnel secret"},
		"no address": {&FakeServer{Users: map[string]string{"a": "b"}, NoAddress: true}, "assigned no address"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := dialFake(t, c.f, "a", "b", true)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestSessionServerHangsUp(t *testing.T) {
	f := &FakeServer{Users: map[string]string{"a": "b"}}
	s, err := dialFake(t, f, "a", "b", true)
	if err != nil {
		t.Fatal(err)
	}
	f.HangUp()
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("still up")
	}
	if err := s.Err(); err == nil || !strings.Contains(err.Error(), "closed the L2TP tunnel (result 6: going away)") {
		t.Fatalf("%v", err)
	}
	if _, err := s.ReadPacket(); err == nil {
		t.Error("read after the end")
	}
}

func TestSessionNothingListens(t *testing.T) {
	fastTimers(t)
	l, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	addr := l.LocalAddr().(*net.UDPAddr)
	_ = l.Close()
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Dial(context.Background(), Config{Conn: c, Username: "a", Password: "b"})
	if err == nil || !(strings.Contains(err.Error(), "can't reach the server") || strings.Contains(err.Error(), "didn't answer")) {
		t.Fatalf("%v", err)
	}
}

func TestSessionDialCancelled(t *testing.T) {
	f := &FakeServer{Silent: true}
	ap, _ := f.Start()
	defer f.Close()
	c, _ := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Dial(ctx, Config{Conn: c}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}
