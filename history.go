package main

import (
	"database/sql"
	"encoding/json"
	"net/url"
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

// WebAuditURLDiff compares the two most recent web audit snapshots for a URL target.
type WebAuditURLDiff struct {
	URL                   string    `json:"url"`
	LatestAt              time.Time `json:"latestAt,omitempty"`
	PreviousAt            time.Time `json:"previousAt,omitempty"`
	GradeChanged          bool      `json:"gradeChanged"`
	PreviousGrade         string    `json:"previousGrade,omitempty"`
	LatestGrade           string    `json:"latestGrade,omitempty"`
	RiskScoreDelta        int       `json:"riskScoreDelta"`
	PreviousRiskScore     int       `json:"previousRiskScore"`
	LatestRiskScore       int       `json:"latestRiskScore"`
	StatusChanged         bool      `json:"statusChanged"`
	PreviousStatus        int       `json:"previousStatus"`
	LatestStatus          int       `json:"latestStatus"`
	NewMissingHeaders     []string  `json:"newMissingHeaders"`
	ResolvedMissingHeaders []string `json:"resolvedMissingHeaders"`
	NewFindingIDs         []string  `json:"newFindingIds"`
	ResolvedFindingIDs    []string  `json:"resolvedFindingIds"`
	CertDaysDelta         *int      `json:"certDaysDelta,omitempty"`
	PreviousCertDays      *int      `json:"previousCertDays,omitempty"`
	LatestCertDays        *int      `json:"latestCertDays,omitempty"`
}

// WebAuditDiff is returned for a compared web audit target (single URL snapshot diff).
type WebAuditDiff struct {
	Target   string          `json:"target"`
	LatestAt time.Time       `json:"latestAt,omitempty"`
	PreviousAt time.Time     `json:"previousAt,omitempty"`
	URLDiffs []WebAuditURLDiff `json:"urlDiffs"`
	Note     string          `json:"note,omitempty"`
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
// Targets and URL-bearing result fields are redacted before persistence to avoid
// storing embedded credentials or sensitive query values.
func (a *App) saveHistory(scanType, target string, result any) error {
	if a == nil || a.historyDB == nil {
		return nil
	}
	redactedTarget := redactHistoryTarget(target)
	redactedResult := redactHistoryResult(result)
	encoded, err := json.Marshal(redactedResult)
	if err != nil {
		return err
	}
	_, err = a.historyDB.Exec(`INSERT INTO scan_history(scan_type, target, result_json, created_at)
		VALUES (?, ?, ?, ?)`, strings.ToLower(strings.TrimSpace(scanType)), redactedTarget, string(encoded), time.Now().UTC().Format(time.RFC3339Nano))
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
	return a.SearchScanHistory(limit, "", "")
}

// SearchScanHistory returns newest-first records filtered by scan type and/or a
// case-insensitive target substring. Empty filters are ignored. Database failures
// or invalid limits are represented as an empty slice for UI callers.
func (a *App) SearchScanHistory(limit int, scanType string, query string) []HistoryEntry {
	if a == nil || a.historyDB == nil || limit <= 0 {
		return []HistoryEntry{}
	}
	if limit > 200 {
		limit = 200
	}
	scanType = strings.ToLower(strings.TrimSpace(scanType))
	query = strings.ToLower(strings.TrimSpace(query))

	clauses := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if scanType != "" && scanType != "all" {
		clauses = append(clauses, "scan_type = ?")
		args = append(args, scanType)
	}
	if query != "" {
		clauses = append(clauses, "LOWER(target) LIKE ?")
		args = append(args, "%"+escapeLike(query)+"%")
	}
	sqlQuery := `SELECT id, scan_type, target, result_json, created_at FROM scan_history`
	if len(clauses) > 0 {
		sqlQuery += " WHERE " + strings.Join(clauses, " AND ")
	}
	sqlQuery += " ORDER BY created_at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := a.historyDB.Query(sqlQuery, args...)
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

// DeleteScanHistoryEntry removes one locally stored history record by ID.
func (a *App) DeleteScanHistoryEntry(id int64) error {
	if a == nil || a.historyDB == nil || id <= 0 {
		return nil
	}
	_, err := a.historyDB.Exec(`DELETE FROM scan_history WHERE id = ?`, id)
	return err
}

// ClearScanHistory removes all locally stored history records.
func (a *App) ClearScanHistory() error {
	if a == nil || a.historyDB == nil {
		return nil
	}
	_, err := a.historyDB.Exec(`DELETE FROM scan_history`)
	return err
}

func escapeLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
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

func redactHistoryTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if redacted, ok := redactSensitiveURL(target); ok {
		return normalizeHistoryTarget(redacted)
	}
	return normalizeHistoryTarget(target)
}

func redactHistoryResult(result any) any {
	data, err := json.Marshal(result)
	if err != nil {
		return result
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return result
	}
	return redactJSONValue(decoded)
}

func redactJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			lower := strings.ToLower(key)
			if isSensitiveHistoryKey(lower) {
				out[key] = "[REDACTED]"
				continue
			}
			out[key] = redactJSONValue(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = redactJSONValue(child)
		}
		return out
	case string:
		if redacted, ok := redactSensitiveURL(v); ok {
			return redacted
		}
		return v
	default:
		return value
	}
}

func isSensitiveHistoryKey(key string) bool {
	switch {
	case strings.Contains(key, "password"),
		strings.Contains(key, "passwd"),
		strings.Contains(key, "secret"),
		strings.Contains(key, "token"),
		strings.Contains(key, "apikey"),
		strings.Contains(key, "api_key"),
		strings.Contains(key, "authorization"),
		strings.Contains(key, "cookie"),
		strings.Contains(key, "session"),
		strings.Contains(key, "credential"):
		return true
	}
	return false
}

func redactSensitiveURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return raw, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return raw, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return raw, false
	}
	changed := false
	if parsed.User != nil {
		username := parsed.User.Username()
		if _, hasPassword := parsed.User.Password(); hasPassword || username != "" {
			parsed.User = url.UserPassword("[REDACTED]", "[REDACTED]")
			changed = true
		}
	}
	q := parsed.Query()
	if len(q) > 0 {
		for key, values := range q {
			if !isSensitiveQueryKey(key) {
				continue
			}
			for i := range values {
				values[i] = "[REDACTED]"
			}
			q[key] = values
			changed = true
		}
		parsed.RawQuery = q.Encode()
	}
	if parsed.Fragment != "" && isSensitiveQueryKey(parsed.Fragment) {
		parsed.Fragment = "[REDACTED]"
		changed = true
	}
	if !changed {
		return raw, false
	}
	return parsed.String(), true
}

func isSensitiveQueryKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	for _, marker := range []string{
		"token", "key", "secret", "password", "passwd", "auth", "session", "api_key", "apikey",
		"signature", "sig", "code", "access_token", "id_token", "refresh_token", "jwt", "cookie", "credential",
	} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
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

// DiffLatestWebAuditScans compares the two most recent web audit snapshots for a normalized URL target.
// Targets are compared by the stored (redacted/normalized) history target key for scan_type="http".
func (a *App) DiffLatestWebAuditScans(target string) WebAuditDiff {
	normalized := redactHistoryTarget(target)
	if normalized == "" {
		normalized = normalizeHistoryTarget(target)
	}
	diff := WebAuditDiff{Target: normalized, URLDiffs: []WebAuditURLDiff{}}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'http' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
	if err != nil {
		return diff
	}
	defer rows.Close()
	type snap struct {
		at     time.Time
		result map[string]any
	}
	snaps := make([]snap, 0, 2)
	for rows.Next() {
		var raw, created string
		if err := rows.Scan(&raw, &created); err != nil {
			return diff
		}
		at, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return diff
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(raw), &result); err != nil {
			// Bulk snapshots are not directly comparable here.
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable Web Audit snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at
	u := WebAuditURLDiff{
		URL:                   normalized,
		LatestAt:              latest.at,
		PreviousAt:            previous.at,
		PreviousGrade:         toStringValue(previous.result["grade"]),
		LatestGrade:           toStringValue(latest.result["grade"]),
		PreviousRiskScore:     toIntValue(previous.result["riskScore"]),
		LatestRiskScore:       toIntValue(latest.result["riskScore"]),
		PreviousStatus:        toIntValue(previous.result["statusCode"]),
		LatestStatus:          toIntValue(latest.result["statusCode"]),
		NewMissingHeaders:     []string{},
		ResolvedMissingHeaders: []string{},
		NewFindingIDs:         []string{},
		ResolvedFindingIDs:    []string{},
	}
	u.GradeChanged = u.PreviousGrade != u.LatestGrade
	u.RiskScoreDelta = u.LatestRiskScore - u.PreviousRiskScore
	u.StatusChanged = u.PreviousStatus != u.LatestStatus
	prevMissing := toStringSet(previous.result["missing"])
	latestMissing := toStringSet(latest.result["missing"])
	for v := range latestMissing {
		if _, ok := prevMissing[v]; !ok {
			u.NewMissingHeaders = append(u.NewMissingHeaders, v)
		}
	}
	for v := range prevMissing {
		if _, ok := latestMissing[v]; !ok {
			u.ResolvedMissingHeaders = append(u.ResolvedMissingHeaders, v)
		}
	}
	sort.Strings(u.NewMissingHeaders)
	sort.Strings(u.ResolvedMissingHeaders)
	prevFindings := toStringSetFromFindings(previous.result["findings"])
	latestFindings := toStringSetFromFindings(latest.result["findings"])
	for v := range latestFindings {
		if _, ok := prevFindings[v]; !ok {
			u.NewFindingIDs = append(u.NewFindingIDs, v)
		}
	}
	for v := range prevFindings {
		if _, ok := latestFindings[v]; !ok {
			u.ResolvedFindingIDs = append(u.ResolvedFindingIDs, v)
		}
	}
	sort.Strings(u.NewFindingIDs)
	sort.Strings(u.ResolvedFindingIDs)
	prevDays, prevOK := tlsDaysRemaining(previous.result["tls"])
	latestDays, latestOK := tlsDaysRemaining(latest.result["tls"])
	if prevOK {
		d := prevDays
		u.PreviousCertDays = &d
	}
	if latestOK {
		d := latestDays
		u.LatestCertDays = &d
	}
	if prevOK && latestOK {
		delta := latestDays - prevDays
		u.CertDaysDelta = &delta
	}
	diff.URLDiffs = []WebAuditURLDiff{u}
	return diff
}

func toStringValue(v any) string {
	s, _ := v.(string)
	return s
}

func toIntValue(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	default:
		return 0
	}
}

func toStringSet(v any) map[string]struct{} {
	out := map[string]struct{}{}
	arr, ok := v.([]any)
	if !ok {
		return out
	}
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out[s] = struct{}{}
		}
	}
	return out
}

func toStringSetFromFindings(v any) map[string]struct{} {
	out := map[string]struct{}{}
	arr, ok := v.([]any)
	if !ok {
		return out
	}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := toStringValue(m["id"])
		if id == "" {
			id = toStringValue(m["title"])
		}
		if id != "" {
			out[id] = struct{}{}
		}
	}
	return out
}

func tlsDaysRemaining(v any) (int, bool) {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return 0, false
	}
	days, ok := m["daysRemaining"]
	if !ok {
		return 0, false
	}
	return toIntValue(days), true
}
