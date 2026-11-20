package engine

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReadmeVersionFromLocalFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wp-content/plugins/sample/readme.txt" {
			t.Errorf("unexpected readme path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("=== Sample ===\nStable tag: 2026.1.4\n"))
	}))
	defer srv.Close()

	if got := GetPluginVersionFromReadme(srv.URL, "sample"); got != "2026.1.4" {
		t.Fatalf("got version %q, want 2026.1.4", got)
	}
}

func TestReadmeVersionDoesNotTrustOversizedFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxReadmeBytes+1))
	}))
	defer srv.Close()

	if got := GetPluginVersionFromReadme(srv.URL, "sample"); got != "" {
		t.Fatalf("oversized readme returned a version: %q", got)
	}
}

func TestMetadataHTTPClientKeepsToOriginalOrigin(t *testing.T) {
	var reached atomic.Bool
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	defer dest.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/other", http.StatusFound)
	}))
	defer origin.Close()

	resp, err := httpClient.Get(origin.URL)
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	_ = resp.Body.Close()
	if reached.Load() {
		t.Fatal("enumeration metadata client followed cross-origin redirect")
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, expected redirect", resp.StatusCode)
	}
}

func TestMetadataReadmeOnUntrustedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Stable tag: 1.2.3"))
	}))
	defer srv.Close()

	if got := GetPluginVersionFromReadme(strings.TrimSuffix(srv.URL, "/"), "sample"); got != "" {
		t.Fatalf("untrusted TLS fixture returned version %q", got)
	}
}
