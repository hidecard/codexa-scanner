package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

func TestNormalizePortScanLimits(t *testing.T) {
	workers, timeout := normalizePortScanLimits(1000, 10_000, 90_000)
	if workers != maxScanWorkers {
		t.Errorf("workers should be capped at %d, got %d", maxScanWorkers, workers)
	}
	if timeout != 30*time.Second {
		t.Errorf("timeout should be capped at 30 seconds, got %s", timeout)
	}

	workers, _ = normalizePortScanLimits(8, 10, 1000)
	if workers != 8 {
		t.Errorf("workers should be capped to port count, got %d", workers)
	}

	workers, timeout = normalizePortScanLimits(1000, 0, 0)
	if workers != defaultScanWorkers || timeout != time.Duration(defaultScanTimeout)*time.Millisecond {
		t.Errorf("non-positive values should use defaults, got %d workers and %s", workers, timeout)
	}
}

func TestStopPortScanCancelsBannerReadAndIsConcurrencySafe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for scan fixture: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	address := listener.Addr().(*net.TCPAddr)
	app := &App{}
	if status := app.StartPortScan("127.0.0.1", address.Port, address.Port, 1, 30_000); status != "STARTED" {
		t.Fatalf("start scan: %s", status)
	}

	var scan *portScan
	deadline := time.After(2 * time.Second)
	for scan == nil {
		app.scanMu.Lock()
		scan = app.activeScan
		app.scanMu.Unlock()
		if scan != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("scan did not become active")
		case <-time.After(time.Millisecond):
		}
	}
	if scan.status != scanStatusRunning {
		t.Fatalf("active scan should report running, got %q", scan.status)
	}
	if status := app.StartPortScan("127.0.0.1", address.Port, address.Port, 1, 100); status != "A scan is already running or stopping" {
		t.Fatalf("second scan should be rejected while one is active, got %q", status)
	}

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("scanner did not connect to the fixture listener")
	}
	defer serverConn.Close()

	var stops sync.WaitGroup
	for i := 0; i < 8; i++ {
		stops.Add(1)
		go func() {
			defer stops.Done()
			app.StopPortScan()
		}()
	}
	stops.Wait()

	select {
	case <-scan.done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not interrupt the active banner read")
	}
	if scan.status != scanStatusCancelled {
		t.Fatalf("stopped scan should report cancelled, got %q", scan.status)
	}
	app.scanMu.Lock()
	active := app.activeScan
	app.scanMu.Unlock()
	if active != nil {
		t.Fatal("completed scan should be removed from active state")
	}
}

func TestPortScanReportsCompletedStatus(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a closed local port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scan := &portScan{ctx: ctx, cancel: cancel, done: make(chan struct{}), status: scanStatusRunning}
	app := &App{activeScan: scan}
	go app.runPortScan(scan, "127.0.0.1", port, port, 1, 100*time.Millisecond)

	select {
	case <-scan.done:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not finish")
	}
	if scan.status != scanStatusCompleted {
		t.Fatalf("finished scan should report completed, got %q", scan.status)
	}
}
