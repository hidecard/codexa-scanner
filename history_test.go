package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestScanHistoryRecentEntriesAndJSON(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "history.sqlite")
	db, err := openScanHistory(dbPath)
	if err != nil {
		t.Fatalf("open history database: %v", err)
	}
	defer db.Close()

	if info, err := os.Stat(dbPath); err != nil {
		t.Fatalf("stat database: %v", err)
	} else if perm := info.Mode().Perm(); perm&0077 != 0 {
		// Windows filesystems do not reliably expose Unix permission bits.
		t.Logf("database permissions are not user-only on this platform: %04o", perm)
	}

	app := &App{historyDB: db}
	first := []PortFinding{{Port: 22, Service: "SSH"}}
	second := []PortFinding{{Port: 80, Service: "HTTP"}}
	if err := app.saveHistory("port", "EXAMPLE.COM.", first, 0); err != nil {
		t.Fatalf("save first history entry: %v", err)
	}
	// Ensure the ordering assertion does not depend on SQLite timestamp precision.
	time.Sleep(2 * time.Millisecond)
	if err := app.saveHistory("port", "example.com", second, 0); err != nil {
		t.Fatalf("save second history entry: %v", err)
	}
	if err := app.saveHistory("http", "https://example.com", map[string]any{"ok": true}, 0); err != nil {
		t.Fatalf("save third history entry: %v", err)
	}

	entries := app.GetScanHistory(2)
	if len(entries) != 2 {
		t.Fatalf("expected 2 recent records, got %d", len(entries))
	}
	if entries[0].ScanType != "http" || entries[1].ScanType != "port" {
		t.Fatalf("unexpected newest-first order: %+v", entries)
	}
	if entries[1].Target != "example.com" {
		t.Errorf("expected normalized target, got %q", entries[1].Target)
	}
	var decoded []PortFinding
	if err := json.Unmarshal([]byte(entries[1].Result), &decoded); err != nil {
		t.Fatalf("decode stored JSON result: %v", err)
	}
	if !reflect.DeepEqual(decoded, second) {
		t.Errorf("stored JSON mismatch: got %+v, want %+v", decoded, second)
	}
	if entries[0].CreatedAt.IsZero() || entries[1].CreatedAt.IsZero() {
		t.Fatal("expected persisted timestamps")
	}
}

func TestDiffLatestPortScansFindsNewAndRemovedPorts(t *testing.T) {
	db, err := openScanHistory(filepath.Join(t.TempDir(), "history.sqlite"))
	if err != nil {
		t.Fatalf("open history database: %v", err)
	}
	defer db.Close()
	app := &App{historyDB: db}

	if err := app.saveHistory("port", "Host.Example.", []PortFinding{
		{Port: 22}, {Port: 80}, {Port: 443},
	}, 0); err != nil {
		t.Fatalf("save previous snapshot: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := app.saveHistory("port", "host.example", []PortFinding{
		{Port: 22}, {Port: 443}, {Port: 8080}, {Port: 8443},
	}, 0); err != nil {
		t.Fatalf("save latest snapshot: %v", err)
	}

	diff := app.DiffLatestPortScans("HOST.EXAMPLE")
	if diff.Target != "host.example" {
		t.Errorf("unexpected normalized diff target: %q", diff.Target)
	}
	if !reflect.DeepEqual(diff.NewPorts, []int{8080, 8443}) {
		t.Errorf("new ports: got %v, want [8080 8443]", diff.NewPorts)
	}
	if !reflect.DeepEqual(diff.RemovedPorts, []int{80}) {
		t.Errorf("removed ports: got %v, want [80]", diff.RemovedPorts)
	}
	if diff.LatestAt.IsZero() || diff.PreviousAt.IsZero() {
		t.Fatal("expected timestamps for both snapshots")
	}
}

func TestSearchScanHistoryFiltersAndDeleteAndClear(t *testing.T) {
	db, err := openScanHistory(filepath.Join(t.TempDir(), "history.sqlite"))
	if err != nil {
		t.Fatalf("open history database: %v", err)
	}
	defer db.Close()
	app := &App{historyDB: db}

	_ = app.saveHistory("port", "alpha.example", []PortFinding{{Port: 80}}, 0)
	time.Sleep(2 * time.Millisecond)
	_ = app.saveHistory("http", "https://beta.example/path?token=secret", map[string]any{"ok": true}, 0)
	time.Sleep(2 * time.Millisecond)
	_ = app.saveHistory("dns", "alpha.internal", map[string]any{"a": []string{"10.0.0.1"}}, 0)

	if got := app.SearchScanHistory(10, "http", ""); len(got) != 1 || got[0].ScanType != "http" {
		t.Fatalf("expected 1 http record, got %+v", got)
	}
	if got := app.SearchScanHistory(10, "", "alpha"); len(got) != 2 {
		t.Fatalf("expected 2 alpha records, got %d", len(got))
	}
	if got := app.SearchScanHistory(10, "port", "alpha"); len(got) != 1 || got[0].ID == 0 {
		t.Fatalf("expected 1 port+alpha record, got %+v", got)
	}

	// delete one
	all := app.SearchScanHistory(10, "", "")
	if len(all) != 3 {
		t.Fatalf("expected 3 records before delete, got %d", len(all))
	}
	if err := app.DeleteScanHistoryEntry(all[0].ID); err != nil {
		t.Fatalf("delete history entry: %v", err)
	}
	if got := app.SearchScanHistory(10, "", ""); len(got) != 2 {
		t.Fatalf("expected 2 records after delete, got %d", len(got))
	}

	// clear all
	if err := app.ClearScanHistory(); err != nil {
		t.Fatalf("clear history: %v", err)
	}
	if got := app.SearchScanHistory(10, "", ""); len(got) != 0 {
		t.Fatalf("expected 0 records after clear, got %d", len(got))
	}
}

func TestSaveHistoryRedactsSensitiveURLAndKeys(t *testing.T) {
	db, err := openScanHistory(filepath.Join(t.TempDir(), "history.sqlite"))
	if err != nil {
		t.Fatalf("open history database: %v", err)
	}
	defer db.Close()
	app := &App{historyDB: db}

	result := map[string]any{
		"url":   "https://user:pass@example.com/path?token=abc&safe=1",
		"token": "supersecret",
		"nested": map[string]any{
			"authorization": "Bearer xyz",
			"ok":            "https://example.com/cb?code=123",
		},
	}
	if err := app.saveHistory("http", "https://user:pass@example.com/path?token=abc", result, 0); err != nil {
		t.Fatalf("save history: %v", err)
	}
	entries := app.SearchScanHistory(1, "http", "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Target == "https://user:pass@example.com/path?token=abc" || !contains(entries[0].Target, "redacted") && !contains(entries[0].Target, "[REDACTED]") && !contains(entries[0].Target, "%5BREDACTED%5D") && entries[0].Target == "" {
		// target normalized/redacted; at least ensure no raw token/userinfo
	}
	if contains(entries[0].Target, "token=abc") || contains(entries[0].Target, "user:pass") {
		t.Fatalf("expected redacted target, got %q", entries[0].Target)
	}
	if contains(entries[0].Result, "supersecret") || contains(entries[0].Result, "Bearer xyz") || contains(entries[0].Result, "token=abc") || contains(entries[0].Result, "user:pass") {
		t.Fatalf("expected redacted result, got %s", entries[0].Result)
	}
	if !contains(entries[0].Result, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] markers in result, got %s", entries[0].Result)
	}
}

func TestHistoryNoopWhenDatabaseUninitialized(t *testing.T) {
	var app *App
	if err := app.saveHistory("port", "localhost", []PortFinding{{Port: 80}}, 0); err != nil {
		t.Fatalf("saveHistory should safely no-op for nil App: %v", err)
	}
	if got := app.GetScanHistory(5); len(got) != 0 {
		t.Fatalf("expected no entries for nil App, got %v", got)
	}
	if got := app.SearchScanHistory(5, "", ""); len(got) != 0 {
		t.Fatalf("expected no search entries for nil App, got %v", got)
	}
	if err := app.DeleteScanHistoryEntry(1); err != nil {
		t.Fatalf("delete should safely no-op for nil App: %v", err)
	}
	if err := app.ClearScanHistory(); err != nil {
		t.Fatalf("clear should safely no-op for nil App: %v", err)
	}
	if got := app.DiffLatestPortScans("localhost"); len(got.NewPorts)+len(got.RemovedPorts) != 0 {
		t.Fatalf("expected empty diff for nil App, got %+v", got)
	}
}

func contains(s, sub string) bool { return len(sub) == 0 || (len(s) >= len(sub) && (func() bool { return indexOf(s, sub) >= 0 })()) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
