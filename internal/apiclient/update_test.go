package apiclient

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

type stubUpdater struct {
	st          domain.UpdateStatus
	installErr  error
	rolledBack  bool
	checkedHand bool
}

func (s *stubUpdater) Status() domain.UpdateStatus { return s.st }
func (s *stubUpdater) CheckNow() domain.UpdateStatus {
	s.checkedHand = true
	s.st.Latest = "0.2.7"
	return s.st
}
func (s *stubUpdater) InstallNow() (domain.UpdateStatus, error) {
	return s.st, s.installErr
}
func (s *stubUpdater) RequestRollback() error { s.rolledBack = true; return nil }

func TestClientUpdateEndpoints(t *testing.T) {
	c, srv, _ := serveTest(t)
	ctx := context.Background()

	// No updater wired: 503, which the CLI treats as "old daemon".
	_, err := c.UpdateStatus(ctx)
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no updater: %v", err)
	}

	u := &stubUpdater{st: domain.UpdateStatus{Current: "0.2.6", Mode: domain.UpdateNotify, State: "idle"}}
	srv.SetUpdater(u)
	if st, err := c.UpdateStatus(ctx); err != nil || st.Current != "0.2.6" {
		t.Fatalf("status: %+v %v", st, err)
	}
	if st, err := c.UpdateCheck(ctx); err != nil || st.Latest != "0.2.7" || !u.checkedHand {
		t.Fatalf("check: %+v %v manual=%v", st, err, u.checkedHand)
	}
	u.installErr = errors.New("this is a development build; install the release yourself")
	if _, err := c.UpdateInstall(ctx); !errors.As(err, &ae) || ae.StatusCode != http.StatusConflict || ae.Message != u.installErr.Error() {
		t.Fatalf("install refusal: %v", err)
	}
	if err := c.UpdateRollback(ctx); err != nil || !u.rolledBack {
		t.Fatalf("rollback: %v %v", err, u.rolledBack)
	}
	// State carries nothing unless the daemon wires it (svc.SetUpdateStatus).
}
