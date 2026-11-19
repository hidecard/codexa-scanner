package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAuditArgsValidationAndDefaults(t *testing.T) {
	var stderr bytes.Buffer
	got, err := parseAuditArgs([]string{"--url", "https://example.test"}, &stderr)
	if err != nil {
		t.Fatalf("parseAuditArgs returned error: %v", err)
	}
	if got.FailOn != "high" || got.Timeout != 10 || got.AllowPrivate {
		t.Fatalf("unexpected defaults: %+v", got)
	}
	for _, args := range [][]string{
		{}, {"--url", "https://example.test", "--fail-on", "urgent"},
		{"--url", "https://example.test", "--timeout", "61"},
	} {
		if _, err := parseAuditArgs(args, &stderr); err == nil {
			t.Errorf("parseAuditArgs(%v) unexpectedly succeeded", args)
		}
	}
}

func TestResultsMeetFailureThreshold(t *testing.T) {
	results := []BulkHeaderResult{{Findings: []SecurityFinding{{Severity: "medium"}, {Severity: "high"}}}}
	if resultsMeetFailureThreshold(results, "critical") {
		t.Fatal("medium/high findings must not meet critical threshold")
	}
	if !resultsMeetFailureThreshold(results, "high") {
		t.Fatal("high finding should meet high threshold")
	}
}

func TestWriteCLIAuditReportRedactsSensitiveDataAndRestrictsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	results := []BulkHeaderResult{{URL: "https://example.test/?token=supersecret", Findings: []SecurityFinding{}}}
	if _, err := writeCLIAuditReport(path, results); err != nil {
		t.Fatalf("writeCLIAuditReport: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "supersecret") {
		t.Fatalf("report contains sensitive query value: %s", body)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("report mode=%o, want 600", info.Mode().Perm())
	}
}

func TestRunCLIUsesScopedAuditAndWritesReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "audit.json")
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"audit", "--url", server.URL, "--allow-private", "--json", path}, &stdout, &stderr)
	if code == 2 {
		t.Fatalf("audit returned execution/usage error: %s", stderr.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected JSON report: %v", err)
	}
}
