package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestScanRateControlNormalizesBounds(t *testing.T) {
	got := (ScanRateControl{RPS: -1, JitterMs: -1}).normalized()
	if got.RPS != 0 || got.JitterMs != 0 {
		t.Fatalf("negative rate controls should normalize to zero, got %+v", got)
	}
	got = (ScanRateControl{RPS: 999, JitterMs: 999999}).normalized()
	if got.RPS != 50 || got.JitterMs != 5000 {
		t.Fatalf("rate controls should be capped, got %+v", got)
	}
}

func TestPauseResumeRateSlotLifecycle(t *testing.T) {
	a := NewApp()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.PauseScans()
	ready := make(chan bool, 1)
	go func() {
		_, ok := a.waitForRateSlot(ctx, time.Time{}, ScanRateControl{})
		ready <- ok
	}()
	select {
	case <-ready:
		t.Fatal("rate slot should wait while paused")
	case <-time.After(40 * time.Millisecond):
	}
	a.ResumeScans()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("rate slot should resume")
		}
	case <-time.After(time.Second):
		t.Fatal("rate slot did not resume")
	}
}

func TestEmbeddedRemediationKnowledgeCoverage(t *testing.T) {
	b, err := remediationFS.ReadFile("knowledge/remediation.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		t.Fatal(err)
	}
	for i, entry := range envelope.Entries {
		var check RemediationEntry
		if err := json.Unmarshal(entry, &check); err != nil {
			t.Fatalf("remediation entry %d does not match Go model: %v", i, err)
		}
	}
	var raw RemediationKnowledge
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("embedded remediation JSON does not match Go model: %v", err)
	}
	kb := NewApp().GetRemediationKnowledge()
	if len(kb.Entries) == 0 {
		t.Fatal("embedded remediation knowledge is empty")
	}
	for _, stack := range []string{"Next.js", "Laravel", "Express", "Nginx", "Apache", "Supabase"} {
		found := false
		for _, available := range kb.Stacks {
			if available == stack {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing required stack %q", stack)
		}
	}
	for _, entry := range kb.Entries {
		if entry.ID == "" || entry.Title.En == "" || entry.Title.My == "" || entry.Mechanism.En == "" || entry.Mechanism.My == "" || entry.RootCause.En == "" || entry.RootCause.My == "" || entry.Impact.En == "" || entry.Impact.My == "" || entry.Severity == "" || entry.Priority == "" || entry.ChangeRisk == "" || len(entry.Prerequisites.En) == 0 || len(entry.Prerequisites.My) == 0 || len(entry.ImplementationNotes.En) == 0 || len(entry.ImplementationNotes.My) == 0 || len(entry.References) == 0 || len(entry.CommonMistakes.En) < 4 || len(entry.CommonMistakes.My) < 4 || entry.AttackScenario.En == "" || entry.AttackScenario.My == "" || len(entry.AttackSteps.En) < 4 || len(entry.AttackSteps.My) < 4 || entry.WhereToFix.En == "" || entry.WhereToFix.My == "" || len(entry.VerificationSteps.En) < 4 || len(entry.VerificationSteps.My) < 4 || entry.FalsePositiveNotes.En == "" || entry.FalsePositiveNotes.My == "" {
			t.Fatalf("incomplete bilingual remediation entry %q", entry.ID)
		}
		for _, stack := range kb.Stacks {
			fix, ok := entry.Stacks[stack]
			if !ok || fix.File == "" || fix.Location == "" || fix.Before == "" || fix.After == "" || fix.Deploy == "" || fix.Verify == "" || fix.Rollback == "" {
				t.Fatalf("incomplete %q remediation for stack %q", entry.ID, stack)
			}
		}
	}
	if got, ok := lookupRemediation("cookie-secure-missing-extra"); !ok || got.ID != "cookie-secure-missing-extra" {
		t.Fatalf("dynamic remediation lookup failed: %+v, %v", got, ok)
	}
}
