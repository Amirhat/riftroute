package telemetry

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fullReport() *Report {
	return &Report{
		Schema: Schema, Install: strings.Repeat("ab", 16), Level: "full", Day: "2026-10-02",
		App:     App{Version: "0.7.0", Channel: "stable", OS: "darwin", OSMajor: 15, Arch: "arm64", Service: true},
		Daemon:  Daemon{Starts: 2, Unclean: 1},
		Updates: Updates{Installed: 1, HelpersRepaired: 1},
		Usage: &Usage{
			Profiles: 4, ProfilesEnabled: 3, ProfileModes: map[string]int{"exclude": 2, "tunnel": 1},
			Rules: map[string]int{"cidr": 12, "wildcard": 2}, Tunnels: map[string]int{"ikev2": 1},
			KillSwitch: true, AutoApply: true,
		},
		Applies: &Applies{
			Applied: 31, Auto: 20, Failed: 1, Refused: map[string]int{"gateway-capture": 1},
			RolledBack: map[string]int{"requested": 1}, Slow: 2, MS: map[string]int{"lt250": 20, "lt5000": 11},
		},
		Tunnels: map[string]TunnelSessions{"ikev2": {Connected: 3, Drops: 1, Failed: map[string]int{"cert": 1}}},
		Events:  &Events{DNSFailures: 4},
	}
}

func TestValidReportsRoundTrip(t *testing.T) {
	for _, r := range []*Report{fullReport(), {
		Schema: Schema, Install: strings.Repeat("0", 32), Level: "basic", Day: "2026-10-02",
		App: App{Version: "dev", Channel: "stable", OS: "linux", Distro: "ubuntu", OSMajor: 24, Arch: "amd64"},
	}} {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatalf("%s: %v", b, err)
		}
		if !reflect.DeepEqual(got, r) {
			t.Fatalf("round trip:\n%+v\n%+v", got, r)
		}
	}
}

// Anything outside the schema is refused, so nothing but counts and fixed
// values can reach the server.
func TestDecodeRefusesWhatsNotInTheSchema(t *testing.T) {
	good, _ := json.Marshal(fullReport())
	for name, mutate := range map[string]func(m map[string]any){
		"unknown field":      func(m map[string]any) { m["hostname"] = "amirs-mac" },
		"unknown app field":  func(m map[string]any) { m["app"].(map[string]any)["ip"] = "192.0.2.1" },
		"free-text version":  func(m map[string]any) { m["app"].(map[string]any)["version"] = "0.7.0 (my build)" },
		"unknown os":         func(m map[string]any) { m["app"].(map[string]any)["os"] = "plan9" },
		"distro on macOS":    func(m map[string]any) { m["app"].(map[string]any)["distro"] = "ubuntu" },
		"unlisted rule kind": func(m map[string]any) { m["usage"].(map[string]any)["rules"] = map[string]any{"example.com": 1} },
		"unlisted tunnel": func(m map[string]any) {
			m["tunnel_sessions"] = map[string]any{"office": map[string]any{"connected": 1}}
		},
		"unlisted failure": func(m map[string]any) {
			m["tunnel_sessions"].(map[string]any)["ikev2"].(map[string]any)["failed"] = map[string]any{"vpn.example.com": 1}
		},
		"negative count":       func(m map[string]any) { m["daemon"].(map[string]any)["starts"] = -1 },
		"huge count":           func(m map[string]any) { m["applies"].(map[string]any)["applied"] = 1e9 },
		"bad install":          func(m map[string]any) { m["install"] = "not-hex" },
		"bad day":              func(m map[string]any) { m["day"] = "yesterday" },
		"wrong schema":         func(m map[string]any) { m["schema"] = 2 },
		"full fields at basic": func(m map[string]any) { m["level"] = "basic" },
		"string count":         func(m map[string]any) { m["daemon"].(map[string]any)["starts"] = "2" },
	} {
		var m map[string]any
		_ = json.Unmarshal(good, &m)
		mutate(m)
		b, _ := json.Marshal(m)
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: accepted %s", name, b)
		}
	}
	if _, err := Decode(append(append([]byte{}, good...), []byte(`{}`)...)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := Decode(make([]byte, MaxReportBytes+1)); err == nil {
		t.Error("oversized report accepted")
	}
}

// The only strings a report may carry are the ones Validate checks against a
// format or a fixed list. A new string field (or map keyed by something
// new) fails here until it's added to Validate — so free text can't slip in
// by accident.
func TestEveryStringIsChecked(t *testing.T) {
	checked := map[string]bool{
		"Report.Install": true, "Report.Level": true, "Report.Day": true,
		"App.Version": true, "App.Channel": true, "App.OS": true, "App.Distro": true, "App.Arch": true,
		// maps keyed by a fixed list
		"Report.Tunnels": true, "Usage.ProfileModes": true, "Usage.Rules": true, "Usage.Tunnels": true,
		"Applies.Refused": true, "Applies.RolledBack": true, "Applies.MS": true, "TunnelSessions.Failed": true,
	}
	var walk func(t reflect.Type)
	seen := map[reflect.Type]bool{}
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := range typ.NumField() {
			f := typ.Field(i)
			name := typ.Name() + "." + f.Name
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			switch ft.Kind() {
			case reflect.String:
				if !checked[name] {
					t.Errorf("%s is a string Validate doesn't check", name)
				}
			case reflect.Map:
				if !checked[name] {
					t.Errorf("%s is a map Validate doesn't check", name)
				}
				walk(ft.Elem())
			case reflect.Struct:
				walk(ft)
			case reflect.Int, reflect.Bool:
			default:
				t.Errorf("%s has kind %s", name, ft.Kind())
			}
		}
	}
	walk(reflect.TypeOf(Report{}))
}

func TestDurationBucketAndKnown(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "lt250", 249 * time.Millisecond: "lt250", time.Second - 1: "lt1000", 4 * time.Second: "lt5000", time.Minute: "ge5000",
	} {
		if got := DurationBucket(d); got != want {
			t.Errorf("%v → %s, want %s", d, got, want)
		}
	}
	if Known(Distros, "ubuntu") != "ubuntu" || Known(Distros, "mydistro") != "other" || Known(Levels, "x") != "" {
		t.Error("Known")
	}
}
