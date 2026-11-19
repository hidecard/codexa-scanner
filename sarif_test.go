package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalSARIFReportCreatesSARIF21WithRedactedFindings(t *testing.T) {
	results := []BulkHeaderResult{{
		URL: "https://example.test/a?token=supersecret",
		Findings: []SecurityFinding{
			{ID: "header-high", Severity: "high", Title: "Missing security header", Description: "A header is missing.", Recommendation: "Add the header.", Evidence: "observed at https://example.test/a?token=supersecret"},
			{ID: "csp-medium", Severity: "medium", Title: "CSP clue", Description: "Policy clue."},
			{ID: "info-clue", Severity: "info", Title: "Informational clue"},
		},
	}}
	encoded, err := marshalSARIFReport(results)
	if err != nil {
		t.Fatalf("marshalSARIFReport: %v", err)
	}
	if strings.Contains(string(encoded), "supersecret") {
		t.Fatalf("SARIF output leaked sensitive query value: %s", encoded)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("version=%v, want 2.1.0", document["version"])
	}
	runs := document["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)["driver"].(map[string]any)
	if tool["name"] != "Codexa Scanner" {
		t.Fatalf("unexpected tool driver: %+v", tool)
	}
	findings := run["results"].([]any)
	wantLevels := []string{"error", "warning", "note"}
	for i, finding := range findings {
		if got := finding.(map[string]any)["level"]; got != wantLevels[i] {
			t.Errorf("finding %d level=%v, want %s", i, got, wantLevels[i])
		}
	}
	location := findings[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)
	if strings.Contains(location["uri"].(string), "supersecret") {
		t.Fatalf("SARIF location leaked sensitive query value: %+v", location)
	}
	if len(tool["rules"].([]any)) != 3 {
		t.Fatalf("expected 3 rule descriptors, got %d", len(tool["rules"].([]any)))
	}
}

func TestSARIFRuleIDFallback(t *testing.T) {
	if got := sarifRuleID(SecurityFinding{Title: "Unsafe CSP policy!"}); got != "unsafe-csp-policy" {
		t.Fatalf("sarifRuleID fallback=%q", got)
	}
}
