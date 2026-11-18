package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed knowledge/remediation.json
var remediationFS embed.FS

type BilingualText struct {
	En string `json:"en"`
	My string `json:"my"`
}

type StackFix struct {
	File   string `json:"file"`
	Before string `json:"before"`
	After  string `json:"after"`
	Deploy string `json:"deploy"`
	Verify string `json:"verify"`
}

// UnmarshalJSON keeps the embedded knowledge base backward-compatible with
// the compact [file, before, after, deploy, verify] form used by older entries.
func (s *StackFix) UnmarshalJSON(data []byte) error {
	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		if len(values) != 5 {
			return fmt.Errorf("stack fix array must contain 5 strings, got %d", len(values))
		}
		*s = StackFix{File: values[0], Before: values[1], After: values[2], Deploy: values[3], Verify: values[4]}
		return nil
	}
	var object struct {
		File   json.RawMessage `json:"file"`
		Before json.RawMessage `json:"before"`
		After  json.RawMessage `json:"after"`
		Deploy json.RawMessage `json:"deploy"`
		Verify json.RawMessage `json:"verify"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	var fileValues []string
	if err := json.Unmarshal(object.File, &fileValues); err == nil {
		if len(fileValues) != 5 {
			return fmt.Errorf("stack fix file array must contain 5 strings, got %d", len(fileValues))
		}
		*s = StackFix{File: fileValues[0], Before: fileValues[1], After: fileValues[2], Deploy: fileValues[3], Verify: fileValues[4]}
		return nil
	}
	decode := func(raw json.RawMessage) string {
		var value string
		_ = json.Unmarshal(raw, &value)
		return value
	}
	*s = StackFix{File: decode(object.File), Before: decode(object.Before), After: decode(object.After), Deploy: decode(object.Deploy), Verify: decode(object.Verify)}
	return nil
}

type RemediationEntry struct {
	ID             string              `json:"id"`
	Title          BilingualText       `json:"title"`
	Mechanism      BilingualText       `json:"mechanism"`
	CommonMistakes BilingualTextList   `json:"commonMistakes"`
	AttackScenario BilingualText       `json:"attackScenario"`
	WhereToFix     BilingualText       `json:"whereToFix"`
	Stacks         map[string]StackFix `json:"stacks"`
}

type BilingualTextList struct {
	En []string `json:"en"`
	My []string `json:"my"`
}

type RemediationKnowledge struct {
	Version string             `json:"version"`
	Stacks  []string           `json:"stacks"`
	Entries []RemediationEntry `json:"entries"`
}

var remediationIndex = loadRemediationKnowledge()

func loadRemediationKnowledge() map[string]RemediationEntry {
	b, err := remediationFS.ReadFile("knowledge/remediation.json")
	if err != nil {
		return map[string]RemediationEntry{}
	}
	var kb RemediationKnowledge
	if err := json.Unmarshal(b, &kb); err != nil {
		return map[string]RemediationEntry{}
	}
	idx := make(map[string]RemediationEntry, len(kb.Entries))
	for _, e := range kb.Entries {
		if e.ID != "" {
			idx[e.ID] = e
		}
	}
	return idx
}

func (a *App) GetRemediationKnowledge() RemediationKnowledge {
	b, err := remediationFS.ReadFile("knowledge/remediation.json")
	if err != nil {
		return RemediationKnowledge{Version: "1.0", Stacks: []string{"Next.js", "Laravel", "Express", "Nginx", "Apache", "Supabase"}, Entries: []RemediationEntry{}}
	}
	var kb RemediationKnowledge
	if err := json.Unmarshal(b, &kb); err != nil {
		return RemediationKnowledge{Version: "1.0", Stacks: []string{"Next.js", "Laravel", "Express", "Nginx", "Apache", "Supabase"}, Entries: []RemediationEntry{}}
	}
	// ensure stable order for UI
	sort.Slice(kb.Entries, func(i, j int) bool { return kb.Entries[i].ID < kb.Entries[j].ID })
	return kb
}

func lookupRemediation(id string) (RemediationEntry, bool) {
	if e, ok := remediationIndex[id]; ok {
		return e, true
	}
	// dynamic/prefixed IDs
	prefixes := []string{"client-secret-pattern-", "cookie-secure-missing", "cookie-httponly-missing", "cookie-samesite-missing", "db-error-"}
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			if e, ok := remediationIndex[p]; ok {
				e.ID = id
				return e, true
			}
		}
	}
	// fallback: generic
	if e, ok := remediationIndex["generic-finding"]; ok {
		e.ID = id
		return e, true
	}
	return RemediationEntry{ID: id}, false
}
