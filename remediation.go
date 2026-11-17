package main

import (
	"embed"
	"encoding/json"
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

type RemediationEntry struct {
	ID               string              `json:"id"`
	Title            BilingualText       `json:"title"`
	Mechanism        BilingualText       `json:"mechanism"`
	CommonMistakes   BilingualTextList   `json:"commonMistakes"`
	AttackScenario   BilingualText       `json:"attackScenario"`
	WhereToFix       BilingualText       `json:"whereToFix"`
	Stacks           map[string]StackFix `json:"stacks"`
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