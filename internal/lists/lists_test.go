package lists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseEntries(t *testing.T) {
	data := []byte("# a comment\n" +
		"10.0.0.0/8\n" +
		"  192.168.0.0/16   # inline comment\n" +
		"\n" +
		"1.1.1.1\n" +
		"; semicolon comment\n" +
		"not-an-ip\n" +
		"2001:db8::/32\n")
	got := ParseEntries(data)
	want := []string{"10.0.0.0/8", "192.168.0.0/16", "1.1.1.1", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: want %q got %q", i, want[i], got[i])
		}
	}
}

func TestFetchRejectsNonHTTPS(t *testing.T) {
	if _, _, err := Fetch(context.Background(), "http://example.com/list"); err == nil {
		t.Fatal("expected non-https source to be rejected")
	}
}

func TestFetchTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# cloudflare-ish\n1.1.1.0/24\n1.0.0.0/24\n"))
	}))
	defer ts.Close()

	orig := httpClient
	httpClient = ts.Client()
	defer func() { httpClient = orig }()

	entries, checksum, err := Fetch(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0] != "1.1.1.0/24" || entries[1] != "1.0.0.0/24" {
		t.Fatalf("entries = %v", entries)
	}
	if len(checksum) != 64 {
		t.Fatalf("expected sha256 hex checksum, got %q", checksum)
	}
}
