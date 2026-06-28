package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

var errStreamingUnsupported = errors.New("response writer does not support streaming")

// peerKey is the context key under which peer credentials are stored.
type peerKey struct{}

// peerInfo carries the connecting peer's uid/gid (from SO_PEERCRED /
// LOCAL_PEERCRED). err is set if credentials could not be read.
type peerInfo struct {
	uid uint32
	gid uint32
	err error
}

func peerFrom(ctx context.Context) (peerInfo, bool) {
	pi, ok := ctx.Value(peerKey{}).(peerInfo)
	return pi, ok
}

// credListener wraps a Unix listener so each accepted connection captures the
// peer's OS credentials at accept time (spec §11 peer-cred authz).
type credListener struct {
	net.Listener
}

func (l credListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return c, nil
	}
	uid, gid, cerr := peerCredFromConn(uc)
	return &credConn{Conn: c, uid: uid, gid: gid, credErr: cerr}, nil
}

// credConn is a net.Conn annotated with its peer's credentials.
type credConn struct {
	net.Conn
	uid     uint32
	gid     uint32
	credErr error
}

func peerCredFromConn(uc *net.UnixConn) (uint32, uint32, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var (
		uid, gid uint32
		credErr  error
	)
	if err := raw.Control(func(fd uintptr) {
		uid, gid, credErr = peerCred(fd)
	}); err != nil {
		return 0, 0, err
	}
	return uid, gid, credErr
}

// requireWrite gates mutating endpoints: only root or the installing user may
// call them (spec §12). Wired now; applied to mutation routes from M2.
func (s *Server) requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pi, ok := peerFrom(r.Context())
		if !ok || pi.err != nil {
			writeErr(w, http.StatusForbidden, errors.New("peer credentials unavailable; refusing mutation"))
			return
		}
		if pi.uid != 0 && pi.uid != s.allowUID {
			writeErr(w, http.StatusForbidden, fmt.Errorf("uid %d is not authorized to mutate routing", pi.uid))
			return
		}
		next(w, r)
	}
}
