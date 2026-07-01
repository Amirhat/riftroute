package linux

import (
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Captured `ip -j route show` (new iproute2), incl. a VPN default on wg0 and a
// RiftRoute-owned route (proto riftroute).
const routesJSONv4 = `[
  {"dst":"default","gateway":"192.168.1.1","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]},
  {"dst":"default","dev":"wg0","protocol":"static","metric":50,"flags":[]},
  {"dst":"10.0.0.0/8","gateway":"192.168.1.1","dev":"eth0","protocol":"riftroute","metric":0,"flags":[]},
  {"dst":"192.168.1.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.168.1.50","flags":[]},
  {"dst":"8.8.8.8","gateway":"192.168.1.1","dev":"eth0","protocol":"riftroute","flags":[]}
]`

func TestParseRoutesJSON(t *testing.T) {
	routes, err := parseRoutesJSON([]byte(routesJSONv4), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 5 {
		t.Fatalf("want 5 routes, got %d", len(routes))
	}
	// default via physical -> system
	if routes[0].DstCIDR != "0.0.0.0/0" || routes[0].Owner != domain.OwnerSystem {
		t.Errorf("route0 = %+v", routes[0])
	}
	// default via wg0 (tunnel) -> vpn
	if routes[1].Owner != domain.OwnerVPN || routes[1].Iface != "wg0" {
		t.Errorf("route1 (wg default) = %+v", routes[1])
	}
	// proto riftroute -> riftroute owner, regardless of device
	if routes[2].Owner != domain.OwnerRiftRoute || routes[2].Proto != "riftroute" {
		t.Errorf("route2 (owned) = %+v", routes[2])
	}
	// bare host IP normalized to /32
	if routes[4].DstCIDR != "8.8.8.8/32" {
		t.Errorf("route4 host = %+v", routes[4])
	}
}

// On a host that hasn't registered the "riftroute" name in rt_protos, `ip` shows
// our routes by their NUMERIC proto tag. They must still be recognized as owned
// and normalized to the canonical "riftroute" — this is what makes the provider
// portable across iproute2 setups (the CI-failure fix).
func TestParseRoutesJSON_NumericProtoRecognized(t *testing.T) {
	const j = `[{"dst":"10.0.0.0/8","gateway":"192.168.1.1","dev":"eth0","protocol":"152","metric":0,"flags":[]}]`
	routes, err := parseRoutesJSON([]byte(j), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	if routes[0].Owner != domain.OwnerRiftRoute {
		t.Errorf("numeric proto %q should be owned by riftroute: %+v", routeProtoNum, routes[0])
	}
	if routes[0].Proto != "riftroute" {
		t.Errorf("numeric proto should normalize to canonical name, got %q", routes[0].Proto)
	}
	if !isOurProto("152") || !isOurProto("riftroute") || isOurProto("dhcp") {
		t.Error("isOurProto should match both the number and the name, not others")
	}
}

func TestParseRoutesJSONv6Default(t *testing.T) {
	const j = `[{"dst":"default","gateway":"fe80::1","dev":"eth0","protocol":"ra","flags":[]}]`
	routes, err := parseRoutesJSON([]byte(j), domain.FamilyV6)
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].DstCIDR != "::/0" || routes[0].Family != domain.FamilyV6 {
		t.Fatalf("v6 default = %+v", routes[0])
	}
}

func TestParseRulesJSON(t *testing.T) {
	const j = `[
	  {"priority":0,"src":"all","table":"local"},
	  {"priority":100,"dst":"10.0.0.0/8","table":"50","protocol":"riftroute"},
	  {"priority":32766,"src":"all","table":"main"}
	]`
	rules, err := parseRulesJSON([]byte(j), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(rules))
	}
	if rules[0].Selector != "from all" || rules[0].Table != "local" {
		t.Errorf("rule0 = %+v", rules[0])
	}
	if rules[1].Selector != "to 10.0.0.0/8" || rules[1].Table != "50" || rules[1].Proto != "riftroute" {
		t.Errorf("rule1 = %+v", rules[1])
	}
}

// Real `ip -j rule show` reports the selector address WITHOUT its prefix length,
// carrying the length in a separate dstlen/srclen. We must reconstruct the CIDR
// so "to 1.1.1.0/24" round-trips (else teardown can't match the rule to delete).
func TestParseRulesJSON_ReconstructsPrefixLen(t *testing.T) {
	const j = `[
	  {"priority":5252,"dst":"1.1.1.0","dstlen":24,"table":"5252","protocol":"152"},
	  {"priority":100,"src":"10.0.0.0","srclen":8,"table":"50"}
	]`
	rules, err := parseRulesJSON([]byte(j), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Selector != "to 1.1.1.0/24" || rules[0].Proto != "riftroute" {
		t.Errorf("rule0 selector should reconstruct the /24 + normalize proto: %+v", rules[0])
	}
	if rules[1].Selector != "from 10.0.0.0/8" {
		t.Errorf("rule1 selector should reconstruct the /8: %+v", rules[1])
	}
}

func TestParseRouteGetJSON(t *testing.T) {
	const j = `[{"dst":"8.8.8.8","gateway":"10.6.0.1","dev":"wg0","prefsrc":"10.6.0.2","flags":[],"uid":1000,"cache":[]}]`
	dec, err := parseRouteGetJSON([]byte(j), "8.8.8.8", domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Iface != "wg0" || dec.Gateway != "10.6.0.1" || !dec.ViaVPN || !dec.Reachable {
		t.Fatalf("decision = %+v", dec)
	}
}

func TestParseRoutesText(t *testing.T) {
	const text = `default via 192.168.1.1 dev eth0 proto dhcp metric 100
10.0.0.0/8 via 192.168.1.1 dev eth0 proto riftroute
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50`
	routes := parseRoutesText(text, domain.FamilyV4)
	if len(routes) != 3 {
		t.Fatalf("want 3, got %d", len(routes))
	}
	if routes[0].DstCIDR != "0.0.0.0/0" || routes[0].Gateway != "192.168.1.1" || routes[0].Metric != 100 {
		t.Errorf("text route0 = %+v", routes[0])
	}
	if routes[1].Owner != domain.OwnerRiftRoute {
		t.Errorf("text route1 owner = %+v", routes[1])
	}
}

func TestParseRouteGetText(t *testing.T) {
	const text = `8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 1000`
	dec := parseRouteGetText(text, "8.8.8.8", domain.FamilyV4)
	if dec.Gateway != "192.168.1.1" || dec.Iface != "eth0" || dec.ViaVPN || !dec.Reachable {
		t.Fatalf("text decision = %+v", dec)
	}
}

func TestClassifyIface(t *testing.T) {
	cases := map[string]struct {
		kind  domain.IfaceKind
		isVPN bool
	}{
		"lo":      {domain.IfaceKindLoopback, false},
		"eth0":    {domain.IfaceKindPhysical, false},
		"wlan0":   {domain.IfaceKindPhysical, false},
		"wg0":     {domain.IfaceKindWG, true},
		"tun0":    {domain.IfaceKindTun, true},
		"docker0": {domain.IfaceKindBridge, false},
	}
	for name, want := range cases {
		k, v := classifyIface(name)
		if k != want.kind || v != want.isVPN {
			t.Errorf("%s: got (%s,%v) want (%s,%v)", name, k, v, want.kind, want.isVPN)
		}
	}
}
