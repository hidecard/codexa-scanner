package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// HistoryEntry is one locally persisted scan result.
type HistoryEntry struct {
	ID        int64     `json:"id"`
	ScanType  string    `json:"scanType"`
	Target    string    `json:"target"`
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"createdAt"`
}

// PortScanDiff compares the two most recent port scan snapshots for a target.
type PortScanDiff struct {
	Target       string    `json:"target"`
	LatestAt     time.Time `json:"latestAt,omitempty"`
	PreviousAt   time.Time `json:"previousAt,omitempty"`
	NewPorts     []int     `json:"newPorts"`
	RemovedPorts []int     `json:"removedPorts"`
}

// openScanHistory opens (or creates) a SQLite history database and applies its schema.
// SQLite is restricted to one connection to avoid unsafe concurrent writers and locks.
func openScanHistory(path string) (*sql.DB, error) {
	if path == "" {
		return nil, os.ErrInvalid
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if _, err = db.Exec(`PRAGMA busy_timeout = 5000`); err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS scan_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_type TEXT NOT NULL,
			target TEXT NOT NULL,
			result_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_history_type_target_created
			ON scan_history(scan_type, target, created_at DESC, id DESC)`)
	}
	if err == nil {
		err = db.Ping()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		// Enforce user-only access on platforms that support Unix-style permissions.
		_ = os.Chmod(path, 0600)
	}
	return db, nil
}

// saveHistory serializes and stores a scan result. An uninitialized App/database
// is intentionally a no-op so scans remain usable when local history is disabled.
func (a *App) saveHistory(scanType, target string, result any) error {
	if a == nil || a.historyDB == nil {
		return nil
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = a.historyDB.Exec(`INSERT INTO scan_history(scan_type, target, result_json, created_at)
		VALUES (?, ?, ?, ?)`, strings.ToLower(strings.TrimSpace(scanType)), normalizeHistoryTarget(target), string(encoded), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	_, err = a.historyDB.Exec(`DELETE FROM scan_history WHERE id NOT IN
		(SELECT id FROM scan_history ORDER BY created_at DESC, id DESC LIMIT 2000)`)
	return err
}

// GetScanHistory returns the newest records first. A non-positive limit returns
// no results; database failures are represented as an empty slice for UI callers.
func (a *App) GetScanHistory(limit int) []HistoryEntry {
	if a == nil || a.historyDB == nil || limit <= 0 {
		return []HistoryEntry{}
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := a.historyDB.Query(`SELECT id, scan_type, target, result_json, created_at
		FROM scan_history ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return []HistoryEntry{}
	}
	defer rows.Close()
	entries := make([]HistoryEntry, 0)
	for rows.Next() {
		var entry HistoryEntry
		var raw, created string
		if err := rows.Scan(&entry.ID, &entry.ScanType, &entry.Target, &raw, &created); err != nil {
			return []HistoryEntry{}
		}
		entry.Result = raw
		entry.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return []HistoryEntry{}
		}
		entries = append(entries, entry)
	}
	if rows.Err() != nil {
		return []HistoryEntry{}
	}
	return entries
}

// DiffLatestPortScans compares the latest two port snapshots for a normalized target.
func (a *App) DiffLatestPortScans(target string) PortScanDiff {
	normalized := normalizeHistoryTarget(target)
	diff := PortScanDiff{Target: normalized, NewPorts: []int{}, RemovedPorts: []int{}}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'port' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
	if err != nil {
		return diff
	}
	defer rows.Close()
	var snapshots []map[int]struct{}
	for rows.Next() {
		var raw, created string
		if err := rows.Scan(&raw, &created); err != nil {
			return diff
		}
		ports, err := decodePortSnapshot([]byte(raw))
		if err != nil {
			return diff
		}
		at, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return diff
		}
		if len(snapshots) == 0 {
			diff.LatestAt = at
		} else {
			diff.PreviousAt = at
		}
		snapshots = append(snapshots, ports)
	}
	if rows.Err() != nil || len(snapshots) < 2 {
		return diff
	}
	latest, previous := snapshots[0], snapshots[1]
	for port := range latest {
		if _, exists := previous[port]; !exists {
			diff.NewPorts = append(diff.NewPorts, port)
		}
	}
	for port := range previous {
		if _, exists := latest[port]; !exists {
			diff.RemovedPorts = append(diff.RemovedPorts, port)
		}
	}
	sort.Ints(diff.NewPorts)
	sort.Ints(diff.RemovedPorts)
	return diff
}

func normalizeHistoryTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.TrimSuffix(target, ".")
	return target
}

func decodePortSnapshot(data []byte) (map[int]struct{}, error) {
	var findings []PortFinding
	if err := json.Unmarshal(data, &findings); err == nil && findings != nil {
		ports := make(map[int]struct{}, len(findings))
		for _, finding := range findings {
			ports[finding.Port] = struct{}{}
		}
		return ports, nil
	}
	// Also accept a direct port-number array for callers that store compact snapshots.
	var numbers []int
	if err := json.Unmarshal(data, &numbers); err != nil {
		return nil, err
	}
	ports := make(map[int]struct{}, len(numbers))
	for _, port := range numbers {
		ports[port] = struct{}{}
	}
	return ports, nil
}
