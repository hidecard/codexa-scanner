package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
		{"--url", "https://example.test", "--json", "-", "--sarif", "-"},
	} {
		if _, err := parseAuditArgs(args, &stderr); err == nil {
			t.Errorf("parseAuditArgs(%v) unexpectedly succeeded", args)
		}
	}
}

func TestParseAuditArgsWithRulesFlag(t *testing.T) {
	var stderr bytes.Buffer
	got, err := parseAuditArgs([]string{"--url", "https://example.test", "--rules", "rules.yaml"}, &stderr)
	if err != nil {
		t.Fatalf("parseAuditArgs returned error: %v", err)
	}
	if got.RulesPath != "rules.yaml" {
		t.Fatalf("expected RulesPath=rules.yaml, got %q", got.RulesPath)
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
	// File permissions are enforced where supported (Unix). On Windows, os.Chmod
	// is a no-op and the file inherits directory permissions; accept any mode there.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
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
	sarifPath := filepath.Join(t.TempDir(), "audit.sarif")
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"audit", "--url", server.URL, "--allow-private", "--json", path, "--sarif", sarifPath}, &stdout, &stderr)
	if code == 2 {
		t.Fatalf("audit returned execution/usage error: %s", stderr.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected JSON report: %v", err)
	}
	if _, err := os.Stat(sarifPath); err != nil {
		t.Fatalf("expected SARIF report: %v", err)
	}
	var sarifStdout, sarifStderr bytes.Buffer
	code = runCLI([]string{"audit", "--url", server.URL, "--allow-private", "--sarif", "-"}, &sarifStdout, &sarifStderr)
	if code == 2 {
		t.Fatalf("stdout SARIF audit returned error: %s", sarifStderr.String())
	}
	if !strings.Contains(sarifStdout.String(), `"version": "2.1.0"`) || strings.Contains(sarifStdout.String(), "Grade ") {
		t.Fatalf("stdout must contain only SARIF JSON: %s", sarifStdout.String())
	}
}

func TestLoadCustomRulesFromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "test-rules.yaml")
	yamlContent := `
secretPatterns:
  - id: "test-pattern"
    name: "Test Pattern"
    pattern: "test_secret_[A-Za-z0-9]{16}"
    severity: "high"
    description: "Test secret pattern"
headerRules:
  - id: "test-header"
    name: "Test Header Rule"
    header: "X-Test-Header"
    match: "enabled"
    severity: "medium"
    description: "Test header rule"
pathWordlists:
  - id: "test-wordlist"
    name: "Test Wordlist"
    paths:
      - "/test-path"
      - "/admin/test"
`
	if err := os.WriteFile(rulesPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	rules, err := loadCustomRules(rulesPath)
	if err != nil {
		t.Fatalf("loadCustomRules: %v", err)
	}
	if rules == nil {
		t.Fatal("expected rules, got nil")
	}
	if len(rules.SecretPatterns) != 1 {
		t.Fatalf("expected 1 secret pattern, got %d", len(rules.SecretPatterns))
	}
	if rules.SecretPatterns[0].ID != "test-pattern" {
		t.Fatalf("expected secret pattern ID 'test-pattern', got %q", rules.SecretPatterns[0].ID)
	}
	if len(rules.HeaderRules) != 1 {
		t.Fatalf("expected 1 header rule, got %d", len(rules.HeaderRules))
	}
	if rules.HeaderRules[0].Header != "X-Test-Header" {
		t.Fatalf("expected header 'X-Test-Header', got %q", rules.HeaderRules[0].Header)
	}
	if len(rules.PathWordlists) != 1 {
		t.Fatalf("expected 1 path wordlist, got %d", len(rules.PathWordlists))
	}
	if len(rules.PathWordlists[0].Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(rules.PathWordlists[0].Paths))
	}
}

func TestLoadCustomRulesFromJSON(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "test-rules.json")
	jsonContent := `{
  "secretPatterns": [
    {"id": "json-pattern", "name": "JSON Pattern", "pattern": "json_key_[A-Za-z0-9]{16}", "severity": "critical", "description": "JSON secret pattern"}
  ],
  "headerRules": [],
  "pathWordlists": []
}`
	if err := os.WriteFile(rulesPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	rules, err := loadCustomRules(rulesPath)
	if err != nil {
		t.Fatalf("loadCustomRules: %v", err)
	}
	if rules == nil {
		t.Fatal("expected rules, got nil")
	}
	if len(rules.SecretPatterns) != 1 {
		t.Fatalf("expected 1 secret pattern, got %d", len(rules.SecretPatterns))
	}
	if rules.SecretPatterns[0].ID != "json-pattern" {
		t.Fatalf("expected secret pattern ID 'json-pattern', got %q", rules.SecretPatterns[0].ID)
	}
}

func TestLoadCustomRulesInvalidFile(t *testing.T) {
	_, err := loadCustomRules("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "cannot find the file") && !strings.Contains(err.Error(), "cannot find the file specified") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(rulesPath, []byte("invalid: yaml: ["), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "failed to parse YAML") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesUnsupportedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "rules.txt")
	if err := os.WriteFile(rulesPath, []byte("test"), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported custom rules file format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesFileSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "large.yaml")
	// Create a file > 100KB
	largeContent := strings.Repeat("x", 101*1024)
	if err := os.WriteFile(rulesPath, []byte(largeContent), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for file too large")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesSecretPatternCountLimit(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "patterns.yaml")
	// Create 51 secret patterns (max 50)
	var patterns strings.Builder
	patterns.WriteString("secretPatterns:\n")
	for i := 0; i < 51; i++ {
		patterns.WriteString(fmt.Sprintf("  - id: \"pattern-%d\"\n", i))
		patterns.WriteString(fmt.Sprintf("    name: \"Pattern %d\"\n", i))
		patterns.WriteString("    pattern: \"test_[A-Za-z0-9]{16}\"\n")
		patterns.WriteString("    severity: \"high\"\n")
		patterns.WriteString("    description: \"Test pattern\"\n")
	}
	if err := os.WriteFile(rulesPath, []byte(patterns.String()), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for too many secret patterns")
	}
	if !strings.Contains(err.Error(), "too many secret patterns") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesHeaderRuleCountLimit(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "headers.yaml")
	var rules strings.Builder
	rules.WriteString("headerRules:\n")
	for i := 0; i < 51; i++ {
		rules.WriteString(fmt.Sprintf("  - id: \"header-%d\"\n", i))
		rules.WriteString(fmt.Sprintf("    name: \"Header %d\"\n", i))
		rules.WriteString("    header: \"X-Test-Header\"\n")
		rules.WriteString("    match: \"enabled\"\n")
		rules.WriteString("    severity: \"medium\"\n")
		rules.WriteString("    description: \"Test header\"\n")
	}
	if err := os.WriteFile(rulesPath, []byte(rules.String()), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for too many header rules")
	}
	if !strings.Contains(err.Error(), "too many header rules") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesPathWordlistCountLimit(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "wordlists.yaml")
	var rules strings.Builder
	rules.WriteString("pathWordlists:\n")
	for i := 0; i < 21; i++ {
		rules.WriteString(fmt.Sprintf("  - id: \"wordlist-%d\"\n", i))
		rules.WriteString(fmt.Sprintf("    name: \"Wordlist %d\"\n", i))
		rules.WriteString("    paths:\n")
		rules.WriteString("      - \"/test\"\n")
	}
	if err := os.WriteFile(rulesPath, []byte(rules.String()), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for too many path wordlists")
	}
	if !strings.Contains(err.Error(), "too many path wordlists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesPatternSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "pattern-size.yaml")
	// Pattern > 500 chars
	longPattern := strings.Repeat("a", 501)
	yamlContent := fmt.Sprintf(`
secretPatterns:
  - id: "long-pattern"
    name: "Long Pattern"
    pattern: "%s"
    severity: "high"
    description: "Test pattern"
`, longPattern)
	if err := os.WriteFile(rulesPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for pattern too long")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesDangerousPatternRejected(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "dangerous.yaml")
	// Nested quantifier pattern that could cause ReDoS in backtracking engines
	dangerousPatterns := []string{
		"(a+)+",
		"(a*)*",
		"(.+)+",
		"(?:a+)+",
	}
	for _, dp := range dangerousPatterns {
		yamlContent := fmt.Sprintf(`
secretPatterns:
  - id: "dangerous"
    name: "Dangerous Pattern"
    pattern: "%s"
    severity: "high"
    description: "Test pattern"
`, dp)
		if err := os.WriteFile(rulesPath, []byte(yamlContent), 0644); err != nil {
			t.Fatalf("write rules file: %v", err)
		}

		_, err := loadCustomRules(rulesPath)
		if err == nil {
			t.Fatalf("expected error for dangerous pattern: %s", dp)
		}
		if !strings.Contains(err.Error(), "catastrophic") && !strings.Contains(err.Error(), "nested quantifier") {
			t.Fatalf("unexpected error for %s: %v", dp, err)
		}
	}
}

func TestLoadCustomRulesExcessiveAlternationRejected(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "alternation.yaml")
	// Pattern with > 20 alternations
	pattern := strings.Repeat("a|", 21) + "b"
	yamlContent := fmt.Sprintf(`
secretPatterns:
  - id: "excessive-alternation"
    name: "Excessive Alternation"
    pattern: "%s"
    severity: "high"
    description: "Test pattern"
`, pattern)
	if err := os.WriteFile(rulesPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for excessive alternation")
	}
	if !strings.Contains(err.Error(), "too many alternations") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesExcessiveGroupsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "groups.yaml")
	// Pattern with > 30 capture groups
	pattern := strings.Repeat("(a)", 31)
	yamlContent := fmt.Sprintf(`
secretPatterns:
  - id: "excessive-groups"
    name: "Excessive Groups"
    pattern: "%s"
    severity: "high"
    description: "Test pattern"
`, pattern)
	if err := os.WriteFile(rulesPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, err := loadCustomRules(rulesPath)
	if err == nil {
		t.Fatal("expected error for excessive groups")
	}
	if !strings.Contains(err.Error(), "too many capture groups") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCustomRulesValidPatternsAccepted(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "valid.yaml")
	yamlContent := `
secretPatterns:
  - id: "valid-pattern"
    name: "Valid Pattern"
    pattern: "test_[A-Za-z0-9]{16}"
    severity: "high"
    description: "Test pattern"
headerRules:
  - id: "valid-header"
    name: "Valid Header"
    header: "X-Custom-Header"
    match: "enabled|disabled"
    severity: "medium"
    description: "Test header"
pathWordlists:
  - id: "valid-wordlist"
    name: "Valid Wordlist"
    paths:
      - "/admin"
      - "/api/v1"
`
	if err := os.WriteFile(rulesPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	rules, err := loadCustomRules(rulesPath)
	if err != nil {
		t.Fatalf("unexpected error for valid rules: %v", err)
	}
	if rules == nil {
		t.Fatal("expected rules, got nil")
	}
	if len(rules.SecretPatterns) != 1 {
		t.Fatalf("expected 1 secret pattern, got %d", len(rules.SecretPatterns))
	}
	if len(rules.HeaderRules) != 1 {
		t.Fatalf("expected 1 header rule, got %d", len(rules.HeaderRules))
	}
	if len(rules.PathWordlists) != 1 {
		t.Fatalf("expected 1 path wordlist, got %d", len(rules.PathWordlists))
	}
}

func TestImportNmapXML(t *testing.T) {
	nmapXML := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="test.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
</nmaprun>`

	app := NewApp()
	result := app.ImportNmapXML(nmapXML)
	if result.HostsProcessed != 1 {
		t.Fatalf("expected 1 host processed, got %d", result.HostsProcessed)
	}
	if result.HostsUp != 1 {
		t.Fatalf("expected 1 host up, got %d", result.HostsUp)
	}
	if result.PortsFound != 2 {
		t.Fatalf("expected 2 ports found, got %d", result.PortsFound)
	}
	if result.WebEndpointsFound != 1 {
		t.Fatalf("expected 1 web endpoint, got %d", result.WebEndpointsFound)
	}
}

func TestImportNmapXMLFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.xml")
	nmapXML := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.20.0"/>
      </port>
    </ports>
  </host>
</nmaprun>`
	if err := os.WriteFile(filePath, []byte(nmapXML), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	app := NewApp()
	result, err := app.ImportNmapXMLFile(filePath)
	if err != nil {
		t.Fatalf("ImportNmapXMLFile: %v", err)
	}
	if result.HostsProcessed != 1 || result.WebEndpointsFound != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestImportNmapXMLFileTooLarge(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "large.xml")
	// Create file > 10MB
	largeContent := strings.Repeat("x", 11*1024*1024)
	if err := os.WriteFile(filePath, []byte(largeContent), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	app := NewApp()
	_, err := app.ImportNmapXMLFile(filePath)
	if err == nil {
		t.Fatal("expected error for file too large")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImportSubdomains(t *testing.T) {
	subdomains := `sub1.example.com
sub2.example.com
# comment
sub2.example.com
invalid..domain
sub3.example.com
`
	app := NewApp()
	result := app.ImportSubdomains(subdomains)
	if result.SubdomainsLoaded != 3 {
		t.Fatalf("expected 3 subdomains loaded, got %d", result.SubdomainsLoaded)
	}
	if result.DuplicatesRemoved != 1 {
		t.Fatalf("expected 1 duplicate removed, got %d", result.DuplicatesRemoved)
	}
	if result.InvalidEntries != 1 {
		t.Fatalf("expected 1 invalid entry, got %d", result.InvalidEntries)
	}
}

func TestImportSubdomainsFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "subs.txt")
	content := `api.example.com
www.example.com
admin.example.com
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	app := NewApp()
	result, err := app.ImportSubdomainsFile(filePath)
	if err != nil {
		t.Fatalf("ImportSubdomainsFile: %v", err)
	}
	if result.SubdomainsLoaded != 3 {
		t.Fatalf("expected 3 subdomains loaded, got %d", result.SubdomainsLoaded)
	}
}

func TestImportSubdomainsFileTooLarge(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "large.txt")
	// Create file > 1MB
	largeContent := strings.Repeat("x\n", 1024*1024)
	if err := os.WriteFile(filePath, []byte(largeContent), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	app := NewApp()
	_, err := app.ImportSubdomainsFile(filePath)
	if err == nil {
		t.Fatal("expected error for file too large")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunImportNmapXMLCommand(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.xml")
	nmapXML := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache"/>
      </port>
    </ports>
  </host>
</nmaprun>`
	if err := os.WriteFile(filePath, []byte(nmapXML), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	jsonPath := filepath.Join(tmpDir, "result.json")
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"import", "nmap-xml", filePath, "--json", jsonPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("import nmap-xml failed: %s", stderr.String())
	}
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("expected JSON output file: %v", err)
	}
}

func TestRunImportSubdomainsCommand(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "subs.txt")
	content := `test1.example.com
test2.example.com
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	jsonPath := filepath.Join(tmpDir, "result.json")
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"import", "subdomains", filePath, "--json", jsonPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("import subdomains failed: %s", stderr.String())
	}
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("expected JSON output file: %v", err)
	}
}
