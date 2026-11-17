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
	} else if info.Mode().Perm()&0077 != 0 {
		t.Errorf("database permissions are not user-only: %04o", info.Mode().Perm())
	}

	app := &App{historyDB: db}
	first := []PortFinding{{Port: 22, Service: "SSH"}}
	second := []PortFinding{{Port: 80, Service: "HTTP"}}
	if err := app.saveHistory("port", "EXAMPLE.COM.", first); err != nil {
		t.Fatalf("save first history entry: %v", err)
	}
	// Ensure the ordering assertion does not depend on SQLite timestamp precision.
	time.Sleep(2 * time.Millisecond)
	if err := app.saveHistory("port", "example.com", second); err != nil {
		t.Fatalf("save second history entry: %v", err)
	}
	if err := app.saveHistory("http", "https://example.com", map[string]any{"ok": true}); err != nil {
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
	}); err != nil {
		t.Fatalf("save previous snapshot: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := app.saveHistory("port", "host.example", []PortFinding{
		{Port: 22}, {Port: 443}, {Port: 8080}, {Port: 8443},
	}); err != nil {
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

func TestHistoryNoopWhenDatabaseUninitialized(t *testing.T) {
	var app *App
	if err := app.saveHistory("port", "localhost", []PortFinding{{Port: 80}}); err != nil {
		t.Fatalf("saveHistory should safely no-op for nil App: %v", err)
	}
	if got := app.GetScanHistory(5); len(got) != 0 {
		t.Fatalf("expected no entries for nil App, got %v", got)
	}
	if got := app.DiffLatestPortScans("localhost"); len(got.NewPorts)+len(got.RemovedPorts) != 0 {
		t.Fatalf("expected empty diff for nil App, got %+v", got)
	}
}
