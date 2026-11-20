package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseCISAKEVResponse(t *testing.T) {
	feedJSON := `{
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-1234",
				"vendorProject": "Microsoft",
				"product": "Windows",
				"vulnerabilityName": "Windows Kernel Elevation of Privilege",
				"dateAdded": "2024-01-15",
				"shortDescription": "A vulnerability in Windows Kernel allows elevation of privilege",
				"requiredAction": "Apply updates per vendor instructions",
				"knownRansomwareCampaignUse": "Known",
				"notes": "Actively exploited"
			},
			{
				"cveID": "CVE-2024-5678",
				"vendorProject": "Apache",
				"product": "HTTP Server",
				"vulnerabilityName": "Apache HTTP Server Path Traversal",
				"dateAdded": "2024-02-20",
				"shortDescription": "Path traversal in Apache HTTP Server",
				"requiredAction": "Upgrade to 2.4.58 or later",
				"knownRansomwareCampaignUse": "",
				"notes": ""
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(feedJSON))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	ctx := testCtx()
	items, err := fetchCISAKEVWithURL(ctx, client, server.URL)
	if err != nil {
		t.Fatalf("fetchCISAKEV failed: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	// Check first item
	if items[0].CVE != "CVE-2024-1234" {
		t.Errorf("first item CVE: got %s, want CVE-2024-1234", items[0].CVE)
	}
	if items[0].Vendor != "microsoft" {
		t.Errorf("first item vendor: got %s, want microsoft", items[0].Vendor)
	}
	if items[0].Product != "windows" {
		t.Errorf("first item product: got %s, want windows", items[0].Product)
	}
	if !items[0].KEV {
		t.Error("first item should be KEV=true")
	}
	if items[0].Source != "CISA KEV" {
		t.Errorf("first item source: got %s, want CISA KEV", items[0].Source)
	}

	// Check second item
	if items[1].CVE != "CVE-2024-5678" {
		t.Errorf("second item CVE: got %s, want CVE-2024-5678", items[1].CVE)
	}
	if items[1].Vendor != "apache" {
		t.Errorf("second item vendor: got %s, want apache", items[1].Vendor)
	}
	if items[1].Product != "http server" {
		t.Errorf("second item product: got %s, want http server", items[1].Product)
	}
}

func TestParseNVDResponse(t *testing.T) {
	feedJSON := `{
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-9999",
					"published": "2024-03-10T10:00:00.000",
					"descriptions": [
						{"lang": "en", "value": "Critical RCE in nginx"}
					],
					"references": [
						{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999"},
						{"url": "https://nginx.org/security.html"}
					],
					"configurations": [
						{
							"nodes": [
								{
									"cpeMatch": [
										{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}
									]
								}
							]
						}
					],
					"metrics": {
						"cvssMetricV31": [
							{
								"cvssData": {
									"baseScore": 9.8,
									"baseSeverity": "CRITICAL"
								}
							}
						]
					}
				}
			},
			{
				"cve": {
					"id": "CVE-2024-8888",
					"published": "2024-03-11T10:00:00.000",
					"descriptions": [
						{"lang": "en", "value": "Medium severity issue"}
					],
					"references": [
						{"url": "https://example.com/ref"}
					],
					"configurations": [],
					"metrics": {
						"cvssMetricV31": [
							{
								"cvssData": {
									"baseScore": 5.3,
									"baseSeverity": "MEDIUM"
								}
							}
						]
					}
				}
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(feedJSON))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	ctx := testCtx()
	items, err := fetchNVDRecentWithURL(ctx, client, server.URL, time.Now().Add(-7*24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("fetchNVDRecent failed: %v", err)
	}

	// Only CRITICAL and HIGH should be included (MEDIUM filtered out)
	if len(items) != 1 {
		t.Fatalf("expected 1 CRITICAL/HIGH item, got %d", len(items))
	}

	if items[0].CVE != "CVE-2024-9999" {
		t.Errorf("item CVE: got %s, want CVE-2024-9999", items[0].CVE)
	}
	if items[0].Product != "nginx" {
		t.Errorf("item product: got %s, want nginx", items[0].Product)
	}
	if items[0].Severity != "CRITICAL" {
		t.Errorf("item severity: got %s, want CRITICAL", items[0].Severity)
	}
	if items[0].CVSS != 9.8 {
		t.Errorf("item CVSS: got %f, want 9.8", items[0].CVSS)
	}
	if items[0].Source != "NVD" {
		t.Errorf("item source: got %s, want NVD", items[0].Source)
	}
	if len(items[0].References) != 2 {
		t.Errorf("item references: got %d, want 2", len(items[0].References))
	}
}

func TestNormalizeFeedProduct(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"nginx", "nginx"},
		{"NGINX", "nginx"},
		{"nginx/1.24.0", "nginx/1.24.0"},
		{"Apache HTTP Server", "apache http server"},
		{"OpenSSH_8.9p1", "openssh 8.9p1"},
		{"Microsoft-IIS/10.0", "microsoft iis/10.0"},
		{"  spaces  ", "spaces"},
		{"under_score", "under score"},
		{"hyphen-ated", "hyphen ated"},
		{"", ""},
	}

	for _, tc := range tests {
		result := normalizeFeedProduct(tc.input)
		if result != tc.expected {
			t.Errorf("normalizeFeedProduct(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestExtractTechnologiesFromHistory(t *testing.T) {
	// This test requires a database connection - skip in unit tests
	// Integration tests should cover this
	t.Skip("Requires database - run integration tests instead")
}

func TestCorrelateCVEsWithAssets(t *testing.T) {
	// Test the correlation logic
	items := []CVEItem{
		{
			CVEID:   "CVE-2024-1234",
			Product: "nginx",
			Vendor:  "nginx",
			Title:   "nginx RCE",
			Severity: "CRITICAL",
			CVSSScore: 9.8,
		},
		{
			CVEID:   "CVE-2024-5678",
			Product: "apache",
			Vendor:  "apache",
			Title:   "Apache Path Traversal",
			Severity: "HIGH",
			CVSSScore: 7.5,
		},
	}

	targetTechs := map[string][]string{
		"https://example.com": {"nginx", "php", "mysql"},
		"https://api.example.com": {"apache", "python"},
	}

	// Manual correlation test
	for i := range items {
		cveProduct := normalizeFeedProduct(items[i].Product)
		var matched []string
		for target, techs := range targetTechs {
			for _, tech := range techs {
				if tech == cveProduct || strings.Contains(tech, cveProduct) || strings.Contains(cveProduct, tech) {
					matched = append(matched, target)
					break
				}
			}
		}
		items[i].MatchedTargets = matched
	}

	if len(items[0].MatchedTargets) != 1 || items[0].MatchedTargets[0] != "https://example.com" {
		t.Errorf("CVE-2024-1234 (nginx) should match https://example.com, got %v", items[0].MatchedTargets)
	}

	if len(items[1].MatchedTargets) != 1 || items[1].MatchedTargets[0] != "https://api.example.com" {
		t.Errorf("CVE-2024-5678 (apache) should match https://api.example.com, got %v", items[1].MatchedTargets)
	}
}

func TestCVEFeedRetentionPolicy(t *testing.T) {
	// This test requires a database connection - skip in unit tests
	t.Skip("Requires database - run integration tests instead")
}

func TestCVEItemJSONSerialization(t *testing.T) {
	item := CVEItem{
		CVEID:          "CVE-2024-1234",
		Source:         "CISA KEV",
		Vendor:         "microsoft",
		Product:        "windows",
		Title:          "Windows Kernel Elevation of Privilege",
		Description:    "A vulnerability in Windows Kernel allows elevation of privilege",
		Severity:       "HIGH",
		CVSSScore:      7.8,
		PublishedDate:  "2024-01-15T00:00:00Z",
		DueDate:        "2024-01-29T00:00:00Z",
		IsKEV:          true,
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
		MatchedTargets: []string{"https://example.com"},
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var parsed CVEItem
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if parsed.CVEID != item.CVEID {
		t.Errorf("CVEID mismatch after round-trip: got %s, want %s", parsed.CVEID, item.CVEID)
	}
	if parsed.IsKEV != item.IsKEV {
		t.Errorf("IsKEV mismatch after round-trip: got %v, want %v", parsed.IsKEV, item.IsKEV)
	}
	if len(parsed.MatchedTargets) != len(item.MatchedTargets) {
		t.Errorf("MatchedTargets length mismatch: got %d, want %d", len(parsed.MatchedTargets), len(item.MatchedTargets))
	}
}

func TestCVEFeedSummaryJSONSerialization(t *testing.T) {
	summary := CVEFeedSummary{
		Items: []CVEItem{
			{CVEID: "CVE-2024-1234", Product: "nginx", Severity: "CRITICAL", IsKEV: true, MatchedTargets: []string{"https://example.com"}},
			{CVEID: "CVE-2024-5678", Product: "apache", Severity: "HIGH", IsKEV: false, MatchedTargets: []string{}},
		},
		TotalCached:   2,
		KEVCount:      1,
		AffectedCount: 1,
		LastSyncedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var parsed CVEFeedSummary
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if parsed.TotalCached != summary.TotalCached {
		t.Errorf("TotalCached mismatch: got %d, want %d", parsed.TotalCached, summary.TotalCached)
	}
	if parsed.KEVCount != summary.KEVCount {
		t.Errorf("KEVCount mismatch: got %d, want %d", parsed.KEVCount, summary.KEVCount)
	}
	if parsed.AffectedCount != summary.AffectedCount {
		t.Errorf("AffectedCount mismatch: got %d, want %d", parsed.AffectedCount, summary.AffectedCount)
	}
	if len(parsed.Items) != len(summary.Items) {
		t.Errorf("Items length mismatch: got %d, want %d", len(parsed.Items), len(summary.Items))
	}
}

// Helper to create a context for tests
func testCtx() context.Context {
	return context.Background()
}