package main

import (
	"crypto/tls"
	"errors"
	"net"
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
	for _, probe := range []struct {
		name   string
		status TLSProbeStatus
		detail string
	}{
		{name: "TLS 1.0", status: result.TLS10Status, detail: result.TLS10Error},
		{name: "TLS 1.1", status: result.TLS11Status, detail: result.TLS11Error},
	} {
		if probe.status != TLSProbeSupported && probe.status != TLSProbeNotSupported && probe.status != TLSProbeInconclusive {
			t.Errorf("%s probe has invalid status %q", probe.name, probe.status)
		}
		if probe.status != TLSProbeSupported && probe.detail == "" {
			t.Errorf("%s non-supported/inconclusive probe should include a useful explanation", probe.name)
		}
	}
}

func TestClassifyLegacyTLSProbe(t *testing.T) {
	tests := []struct {
		name              string
		negotiatedVersion uint16
		err               error
		wantStatus        TLSProbeStatus
		wantDetail        string
	}{
		{
			name:              "exact version handshake means supported",
			negotiatedVersion: tls.VersionTLS10,
			wantStatus:        TLSProbeSupported,
		},
		{
			name:              "unexpected negotiated version is inconclusive",
			negotiatedVersion: tls.VersionTLS12,
			wantStatus:        TLSProbeInconclusive,
			wantDetail:        "instead of the requested TLS 1.0",
		},
		{
			name:       "explicit protocol version alert means not supported",
			err:        tls.AlertError(tlsAlertProtocolVersion),
			wantStatus: TLSProbeNotSupported,
			wantDetail: "explicitly rejected TLS 1.0",
		},
		{
			name:       "handshake failure alert is inconclusive",
			err:        tls.AlertError(40),
			wantStatus: TLSProbeInconclusive,
			wantDetail: "handshake failure",
		},
		{
			name:       "network error is inconclusive",
			err:        errors.New("dial tcp: i/o timeout"),
			wantStatus: TLSProbeInconclusive,
			wantDetail: "i/o timeout",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, detail := classifyLegacyTLSProbe(tls.VersionTLS10, test.negotiatedVersion, test.err)
			if status != test.wantStatus {
				t.Fatalf("expected status %q, got %q (detail %q)", test.wantStatus, status, detail)
			}
			if test.wantDetail != "" && !strings.Contains(detail, test.wantDetail) {
				t.Fatalf("expected detail to contain %q, got %q", test.wantDetail, detail)
			}
			if status == TLSProbeSupported && detail != "" {
				t.Fatalf("supported probe should not have an error, got %q", detail)
			}
			if status != TLSProbeSupported && detail == "" {
				t.Fatal("non-supported/inconclusive result should include an explanation")
			}
		})
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

func TestClassifyIPAddressDoesNotTreatPrivateOrSpecialAddressesAsPublic(t *testing.T) {
	tests := []struct {
		address string
		class   string
	}{
		{"8.8.8.8", "public"},
		{"2001:4860:4860::8888", "public"},
		{"192.168.1.10", "private"},
		{"fd00::10", "private"},
		{"127.0.0.1", "loopback"},
		{"169.254.1.1", "link-local"},
		{"224.0.0.1", "special-use"},
	}
	for _, test := range tests {
		if got := classifyIPAddress(net.ParseIP(test.address)); got != test.class {
			t.Errorf("classifyIPAddress(%q) = %q, want %q", test.address, got, test.class)
		}
	}
}
