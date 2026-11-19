package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

var sarifEmbeddedURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  *sarifMessage       `json:"fullDescription,omitempty"`
	Help             *sarifMessage       `json:"help,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       map[string][]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Kind         string            `json:"kind,omitempty"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func sarifLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sarifRuleID(finding SecurityFinding) string {
	id := strings.TrimSpace(finding.ID)
	if id != "" {
		return id
	}
	name := strings.ToLower(strings.TrimSpace(finding.Title))
	var b strings.Builder
	separator := false
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if separator && b.Len() > 0 {
				b.WriteByte('-')
			}
			separator = false
			b.WriteRune(r)
		} else {
			separator = true
		}
	}
	if b.Len() == 0 {
		return "codexa-finding"
	}
	return b.String()
}

func redactSARIFText(text string) string {
	return sarifEmbeddedURLPattern.ReplaceAllStringFunc(text, func(candidate string) string {
		if safeURL, ok := redactSensitiveURL(candidate); ok {
			return safeURL
		}
		return candidate
	})
}

func buildSARIFReport(results []BulkHeaderResult) (sarifReport, error) {
	// Reuse the history/report redaction policy before embedding URL or evidence text.
	encoded, err := json.Marshal(results)
	if err != nil {
		return sarifReport{}, err
	}
	redacted := redactHistoryResult(json.RawMessage(encoded))
	redactedJSON, err := json.Marshal(redacted)
	if err != nil {
		return sarifReport{}, err
	}
	var safeResults []BulkHeaderResult
	if err := json.Unmarshal(redactedJSON, &safeResults); err != nil {
		return sarifReport{}, err
	}

	rulesByID := map[string]sarifRule{}
	var sarifResults []sarifResult
	for _, target := range safeResults {
		locationURL := target.URL
		if locationURL == "" {
			locationURL = target.FinalURL
		}
		for _, finding := range target.Findings {
			finding.Title = redactSARIFText(finding.Title)
			finding.Description = redactSARIFText(finding.Description)
			finding.Recommendation = redactSARIFText(finding.Recommendation)
			finding.Evidence = redactSARIFText(finding.Evidence)
			ruleID := sarifRuleID(finding)
			if _, exists := rulesByID[ruleID]; !exists {
				rule := sarifRule{
					ID:               ruleID,
					Name:             finding.Title,
					ShortDescription: sarifMessage{Text: finding.Title},
					HelpURI:          "https://github.com/hidecard/codexa-scanner/blob/main/docs/web-audit.md",
					Properties:       map[string][]string{"tags": {"security"}},
				}
				if strings.TrimSpace(finding.Description) != "" {
					rule.FullDescription = &sarifMessage{Text: finding.Description}
				}
				if strings.TrimSpace(finding.Recommendation) != "" {
					rule.Help = &sarifMessage{Markdown: finding.Recommendation}
				}
				rulesByID[ruleID] = rule
			}
			message := strings.TrimSpace(finding.Description)
			if evidence := strings.TrimSpace(finding.Evidence); evidence != "" {
				if message != "" {
					message += "\n\n"
				}
				message += "Evidence: " + evidence
			}
			if message == "" {
				message = finding.Title
			}
			result := sarifResult{
				RuleID:  ruleID,
				Level:   sarifLevel(finding.Severity),
				Kind:    "fail",
				Message: sarifMessage{Text: message},
				Properties: map[string]any{
					"codexaSeverity": strings.ToLower(strings.TrimSpace(finding.Severity)),
				},
			}
			if locationURL != "" {
				result.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: locationURL}}}}
			}
			fingerprintInput := ruleID + "\x00" + locationURL + "\x00" + finding.Title + "\x00" + finding.Evidence
			sum := sha256.Sum256([]byte(fingerprintInput))
			result.Fingerprints = map[string]string{"codexa/v1": hex.EncodeToString(sum[:])}
			sarifResults = append(sarifResults, result)
		}
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, rulesByID[id])
	}
	if sarifResults == nil {
		sarifResults = []sarifResult{}
	}
	return sarifReport{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Codexa Scanner",
				InformationURI: "https://github.com/hidecard/codexa-scanner",
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}, nil
}

func marshalSARIFReport(results []BulkHeaderResult) ([]byte, error) {
	report, err := buildSARIFReport(results)
	if err != nil {
		return nil, fmt.Errorf("build SARIF report: %w", err)
	}
	return json.MarshalIndent(report, "", "  ")
}
