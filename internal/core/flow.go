package core

import (
	"context"
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/flow"
)

// Flows lists active connections and correlates each with the route that carries
// it — labeling whether it egresses the VPN or goes direct (spec §7.4).
func (s *Service) Flows(ctx context.Context) ([]domain.Flow, error) {
	conns, err := flow.Collect(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Flow, 0, len(conns))
	cache := map[string]domain.RouteDecision{}
	for _, c := range conns {
		f := domain.Flow{Proto: c.Proto, Local: c.Local, Remote: c.Remote, State: c.State, Process: c.Process, PID: c.PID}
		ipStr := flow.RemoteIP(c.Remote)
		if addr, perr := netip.ParseAddr(ipStr); perr == nil {
			dec, ok := cache[ipStr]
			if !ok {
				dec, _ = s.prov.LookupRoute(ctx, addr)
				cache[ipStr] = dec
			}
			f.Iface = dec.Iface
			f.ViaVPN = dec.ViaVPN
		}
		out = append(out, f)
	}
	return out, nil
}
