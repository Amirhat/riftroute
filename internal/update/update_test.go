package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
	}{
		{"1.2.3", "1.2.4", true},
		{"v1.2.3", "v1.3.0", true},
		{"1.2.3", "1.2.3", false},
		{"1.2.3", "1.2.2", false},
		{"2.0.0", "1.9.9", false},
		{"1.2.3", "v2.0.0-rc1", true},
		{"dev", "1.0.0", false}, // non-semver current → fail-closed
		{"1.0.0", "garbage", false},
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.cand); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.cur, c.cand, got, c.want)
		}
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.5.0","html_url":"https://example/r","body":"notes","assets":[{"name":"riftroute_darwin_arm64.tar.gz","browser_download_url":"https://example/a"}]}`))
	}))
	defer srv.Close()

	res, err := Check(context.Background(), srv.Client(), srv.URL, "1.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Available || res.Latest != "v1.5.0" || len(res.Assets) != 1 {
		t.Fatalf("result = %+v", res)
	}

	res2, _ := Check(context.Background(), srv.Client(), srv.URL, "1.5.0")
	if res2.Available {
		t.Fatalf("should not be available at same version: %+v", res2)
	}
}

func TestVerifyAndChecksums(t *testing.T) {
	data := []byte("hello")
	// sha256("hello")
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if !VerifySHA256(data, want) {
		t.Fatal("VerifySHA256 should match")
	}
	if VerifySHA256(data, "deadbeef") {
		t.Fatal("VerifySHA256 should reject wrong digest")
	}
	cs := ParseChecksums(want + "  riftroute.tar.gz\nabc123 *other.zip\n")
	if cs["riftroute.tar.gz"] != want || cs["other.zip"] != "abc123" {
		t.Fatalf("checksums = %+v", cs)
	}
}
