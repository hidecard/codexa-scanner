package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuditHTTPResponseFindsPassiveIssues(t *testing.T) {
	target, _ := url.Parse("https://site.example")
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"sid=abc; Path=/"},
			"Server":     []string{"example-server/1.0"},
		},
		Request: &http.Request{URL: target},
	}
	findings := auditHTTPResponse(resp, []byte(`<html><img src="http://cdn.example/img.png"></html>`))
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.ID] = true
		if finding.Title == "" || finding.Recommendation == "" {
			t.Errorf("finding %q has no explanatory text or remediation", finding.ID)
		}
	}
	for _, id := range []string{
		"hsts-missing", "csp-missing", "clickjacking-protection-missing",
		"nosniff-missing", "referrer-policy-missing", "mixed-content-reference",
		"technology-disclosure",
	} {
		if !seen[id] {
			t.Errorf("expected finding %q; got %v", id, seen)
		}
	}
	for _, prefix := range []string{"cookie-secure-missing", "cookie-httponly-missing", "cookie-samesite-missing"} {
		found := false
		for id := range seen {
			if strings.HasPrefix(id, prefix+"-") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a finding with ID prefix %q; got %v", prefix, seen)
		}
	}
}

func TestAuditHTTPResponseAcceptsConfiguredHeadersAndCookies(t *testing.T) {
	target, _ := url.Parse("https://site.example")
	resp := &http.Response{
		Header: http.Header{
			"Strict-Transport-Security": []string{"max-age=31536000"},
			"Content-Security-Policy":   []string{"default-src 'self'; frame-ancestors 'none'"},
			"X-Content-Type-Options":    []string{"nosniff"},
			"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
			"Permissions-Policy":        []string{"camera=()"},
			"Set-Cookie":                []string{"sid=abc; Secure; HttpOnly; SameSite=Lax"},
		},
		Request: &http.Request{URL: target},
	}
	findings := auditHTTPResponse(resp, []byte("<html></html>"))
	if len(findings) != 0 {
		t.Fatalf("expected no findings for configured response, got: %+v", findings)
	}
	score, grade := gradeFindings(findings)
	if score != 0 || grade != "A+" {
		t.Fatalf("expected 0/A+, got %d/%s", score, grade)
	}
}

func TestGradeFindingsUsesSeverityAndCapsScore(t *testing.T) {
	findings := []SecurityFinding{
		{Severity: "high"}, {Severity: "medium"}, {Severity: "low"},
	}
	score, grade := gradeFindings(findings)
	if score != 45 || grade != "C" {
		t.Fatalf("expected 45/C, got %d/%s", score, grade)
	}
	many := strings.Repeat("x", 101)
	lots := make([]SecurityFinding, len(many))
	for i := range lots {
		lots[i].Severity = "critical"
	}
	score, grade = gradeFindings(lots)
	if score != 100 || grade != "F" {
		t.Fatalf("expected capped 100/F, got %d/%s", score, grade)
	}
}

func TestAnalyzeURLRejectsUntrustedTLSCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second}
	result := analyzeURL(server.URL, client, nil)
	if result.Error == "" {
		t.Fatal("expected self-signed test certificate to fail normal TLS verification")
	}
	found := false
	for _, finding := range result.Findings {
		if finding.ID == "tls-untrusted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an untrusted-certificate finding, got %+v", result)
	}
}

func TestAnalyzeURLReportsPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := analyzeURL(server.URL, &http.Client{Timeout: time.Second}, nil)
	if result.Error != "" {
		t.Fatalf("unexpected analysis error: %s", result.Error)
	}
	for _, finding := range result.Findings {
		if finding.ID == "https-not-enforced" && finding.Severity == "high" {
			return
		}
	}
	t.Fatalf("expected high-severity cleartext-transport finding, got %+v", result.Findings)
}
