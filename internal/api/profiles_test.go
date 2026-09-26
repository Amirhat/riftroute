package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// "tunnel:" tags the routes RiftRoute's tunnels own: a profile with such an
// id would have its routes withdrawn by every tunnel apply. The id is refused.
func TestProfileSaveRefusesATunnelID(t *testing.T) {
	ts, st := newMutableServer(t)
	b, _ := json.Marshal(domain.Profile{
		ID: "tunnel:infra", Name: "sneaky", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}},
	})
	resp, err := http.Post(ts.URL+"/profiles?yes=1", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out ConfigResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusBadRequest || len(out.Issues) == 0 || out.Issues[0].Field != "id" || !strings.Contains(out.Issues[0].Msg, "tunnel:") {
		t.Fatalf("status %d, issues %+v", resp.StatusCode, out.Issues)
	}
	if profs, _ := st.ListProfiles(); len(profs) != 0 {
		t.Fatalf("saved anyway: %+v", profs)
	}
}
