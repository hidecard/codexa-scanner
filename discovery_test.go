package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateDiscoveryDomain(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		bad      bool
	}{
		{"Example.COM.", "example.com", false},
		{"a-b.example", "a-b.example", false},
		{"", "", true}, {"https://example.com", "", true},
		{"-bad.example", "", true}, {"bad..example", "", true},
		{"127.0.0.1", "", true}, {"example.com/path", "", true},
		{"bad_label.example", "", true},
	} {
		got, err := validateDiscoveryDomain(tc.in)
		if (err != nil) != tc.bad || got != tc.want {
			t.Errorf("validateDiscoveryDomain(%q)=(%q,%v), want (%q,bad=%v)", tc.in, got, err, tc.want, tc.bad)
		}
	}
}

func TestValidateDiscoveryURL(t *testing.T) {
	for _, tc := range []struct {
		in  string
		bad bool
	}{
		{"https://example.test/base", false}, {"HTTP://localhost:8080", false}, {"http://localhost:8080", false},
		{"ftp://example.test", true}, {"//example.test", true}, {"https://user:pass@example.test", true},
		{"https:///no-host", true}, {"https://example.test\\@evil.test", true},
	} {
		_, err := validateDiscoveryURL(tc.in)
		if (err != nil) != tc.bad {
			t.Errorf("validateDiscoveryURL(%q) error=%v; bad=%v", tc.in, err, tc.bad)
		}
	}
}

func TestInspectTLSPresentsSelfSignedCertificateAsUntrusted(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	address := strings.TrimPrefix(server.URL, "https://")
	result := (&App{}).InspectTLS(address)
	if result.Trusted {
		t.Fatal("test server's self-signed certificate must not be trusted")
	}
	if !result.SelfSigned {
		t.Fatalf("expected self-signed certificate classification: %+v", result)
	}
	if result.TLSVersion == "" || len(result.SANs) == 0 {
		t.Fatalf("expected negotiated protocol and certificate SANs, got %+v", result)
	}
}

func TestGenericNotFoundBaselineUsesStatusAndSize(t *testing.T) {
	if !isGenericNotFound(http.StatusNotFound, 120, http.StatusNotFound, 120) {
		t.Fatal("same status and size should match catch-all baseline")
	}
	if isGenericNotFound(http.StatusNotFound, 240, http.StatusNotFound, 120) {
		t.Fatal("different content length should remain a candidate")
	}
	if isGenericNotFound(http.StatusOK, 120, http.StatusNotFound, 120) {
		t.Fatal("different status should remain a candidate")
	}
}

func TestFuzzPathValidation(t *testing.T) {
	for _, p := range []string{"admin", "/robots.txt", "v1/items.json"} {
		if !validFuzzPath(p) {
			t.Errorf("expected safe path %q", p)
		}
	}
	for _, p := range []string{"", "../secret", "a/../b", "%2e%2e/secret", "//evil.test/path", "http://evil.test", "a\\b", "a?x=1", "a#frag", "a\r\nX: y"} {
		if validFuzzPath(p) {
			t.Errorf("accepted unsafe path %q", p)
		}
	}
}

func TestFuzzPathsFiltersCustomNotFoundAndUsesHEADOnly(t *testing.T) {
	var nonHead atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			nonHead.Add(1)
		}
		if strings.HasSuffix(r.URL.Path, "/found") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("must never be returned"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("custom not-found body"))
	}))
	defer server.Close()
	result := (&App{}).FuzzPaths(server.URL, []string{"found", "missing", "../private", "//attacker.test/x", "found"}, 4)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if nonHead.Load() != 0 {
		t.Fatalf("sent %d non-HEAD requests", nonHead.Load())
	}
	if len(result.Paths) != 1 || result.Paths[0].StatusCode != http.StatusOK || !strings.HasSuffix(result.Paths[0].URL, "/found") {
		t.Fatalf("unexpected filtered findings: %+v", result.Paths)
	}
	// The public result type cannot contain response text, and serialized output must not leak it.
	encoded := result.Paths[0].URL
	if strings.Contains(encoded, "must never") || strings.Contains(encoded, "custom not-found") {
		t.Fatalf("response body leaked: %q", encoded)
	}
}
