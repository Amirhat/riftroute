package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// Panic must fire the teardown hook so the daemon restores side state the
// protocol doesn't own — the wildcard DNS learner and its resolver files.
// Without it a panic leaves /etc/resolver pointing at a stopped proxy.
func TestPanicFiresTeardownHook(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prov := fake.New()
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{},
		func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	srv := NewServer(svc, st, proto, uint32(0), "test", nil)

	fired := false
	srv.SetOnPanic(func(context.Context) { fired = true })

	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/panic", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("panic status %d", resp.StatusCode)
	}
	if !fired {
		t.Fatal("onPanic teardown hook did not fire — resolver files would dangle at a stopped proxy")
	}
}
