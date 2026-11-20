package engine

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDoRequestRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("WordPress"))
	}))
	defer server.Close()

	if _, _, err := doRequest(server.URL, ""); err == nil {
		t.Fatal("expected an untrusted TLS certificate to be rejected")
	}
}

func TestDoRequestRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), int(maxFingerprintBodyBytes)+1))
	}))
	defer server.Close()

	if _, _, err := doRequest(server.URL, ""); err == nil {
		t.Fatal("expected an oversized response to be rejected")
	}
}

func TestDoRequestDoesNotFollowCrossHostRedirect(t *testing.T) {
	var followed atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Store(true)
	}))
	defer destination.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/elsewhere", http.StatusFound)
	}))
	defer origin.Close()

	_, _, err := doRequest(origin.URL, "")
	if err != nil {
		t.Fatalf("request to redirecting origin failed: %v", err)
	}
	if followed.Load() {
		t.Fatal("a redirect to another host must not be followed")
	}
}
