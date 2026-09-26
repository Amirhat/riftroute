package tunnel

import (
	"strings"
	"testing"
)

// Session tokens a server pushes never reach the log, whatever their case or
// quoting.
func TestRedactLineHidesAuthTokens(t *testing.T) {
	for _, line := range []string{
		`PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,auth-token SESS_ID_abc123,peer-id 0'`,
		`PUSH_REPLY,auth-token-user dXNlcg==,auth-token SESS_ID_abc123`,
		`Auth-Token SESS_ID_abc123`,
		`AUTH_TOKEN=SESS_ID_abc123`,
		`auth-token "SESS_ID_abc123, still secret"`,
	} {
		got := redactLine(line)
		if strings.Contains(got, "abc123") || strings.Contains(got, "dXNlcg") {
			t.Errorf("redactLine(%q) = %q", line, got)
		}
	}
	if got := redactLine("Initialization Sequence Completed"); got != "Initialization Sequence Completed" {
		t.Errorf("an ordinary line changed: %q", got)
	}
}
