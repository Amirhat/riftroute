package flow

import "testing"

func TestParseSS(t *testing.T) {
	out := `tcp ESTAB 0 0 192.168.1.50:54321 1.2.3.4:443 users:(("firefox",pid=1,fd=4))
udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*
tcp ESTAB 0 0 [2001:db8::1]:22 [2001:db8::2]:5555 users:(("sshd",pid=9,fd=3))`
	conns := ParseSS(out)
	if len(conns) != 3 {
		t.Fatalf("want 3 conns, got %d", len(conns))
	}
	if conns[0].Proto != "tcp" || conns[0].Remote != "1.2.3.4:443" || conns[0].Process != "firefox" {
		t.Fatalf("conn0 = %+v", conns[0])
	}
	if conns[2].Process != "sshd" || conns[2].Remote != "[2001:db8::2]:5555" {
		t.Fatalf("conn2 = %+v", conns[2])
	}
}

func TestParseLsof(t *testing.T) {
	out := `COMMAND   PID USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
firefox   1 amir   4u  IPv4 0x1      0t0  TCP 192.168.1.50:54321->1.2.3.4:443 (ESTABLISHED)
Spotify   2 amir   7u  IPv4 0x2      0t0  UDP 192.168.1.50:5353->8.8.8.8:53
sshd      9 amir   3u  IPv4 0x3      0t0  TCP *:22 (LISTEN)`
	conns := ParseLsof(out)
	if len(conns) != 2 { // the LISTEN socket (no ->) is skipped
		t.Fatalf("want 2 conns, got %d: %+v", len(conns), conns)
	}
	if conns[0].Process != "firefox" || conns[0].Remote != "1.2.3.4:443" || conns[0].State != "ESTABLISHED" {
		t.Fatalf("conn0 = %+v", conns[0])
	}
	if conns[1].Proto != "udp" || conns[1].Remote != "8.8.8.8:53" {
		t.Fatalf("conn1 = %+v", conns[1])
	}
}

func TestRemoteIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:443":        "1.2.3.4",
		"[2001:db8::2]:5555": "2001:db8::2",
		"8.8.8.8:53":         "8.8.8.8",
	}
	for in, want := range cases {
		if got := RemoteIP(in); got != want {
			t.Errorf("RemoteIP(%q)=%q want %q", in, got, want)
		}
	}
}
