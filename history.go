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

// SubdomainDiff compares the two most recent subdomain enumeration snapshots for a target.
type SubdomainDiff struct {
	Target       string   `json:"target"`
	LatestAt     time.Time `json:"latestAt,omitempty"`
	PreviousAt   time.Time `json:"previousAt,omitempty"`
	NewSubdomains     []string `json:"newSubdomains"`
	RemovedSubdomains []string `json:"removedSubdomains"`
	Note         string   `json:"note,omitempty"`
}

// PathFuzzDiff compares the two most recent path fuzzing snapshots for a target.
type PathFuzzDiff struct {
	Target       string   `json:"target"`
	LatestAt     time.Time `json:"latestAt,omitempty"`
	PreviousAt   time.Time `json:"previousAt,omitempty"`
	NewPaths     []string `json:"newPaths"`
	RemovedPaths []string `json:"removedPaths"`
	Note         string   `json:"note,omitempty"`
}

// TLSInspectionDiff compares the two most recent TLS inspection snapshots for a target.
type TLSInspectionDiff struct {
	Target       string    `json:"target"`
	LatestAt     time.Time `json:"latestAt,omitempty"`
	PreviousAt   time.Time `json:"previousAt,omitempty"`
	CertDaysDelta *int     `json:"certDaysDelta,omitempty"`
	PreviousCertDays *int  `json:"previousCertDays,omitempty"`
	LatestCertDays   *int  `json:"latestCertDays,omitempty"`
	VersionChanged    bool `json:"versionChanged"`
	PreviousTLSVersion string `json:"previousTLSVersion,omitempty"`
	LatestTLSVersion   string `json:"latestTLSVersion,omitempty"`
	CipherSuiteChanged bool `json:"cipherSuiteChanged"`
	PreviousCipherSuite string `json:"previousCipherSuite,omitempty"`
	LatestCipherSuite   string `json:"latestCipherSuite,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// DNSIntelligenceDiff compares the two most recent DNS intelligence snapshots for a target.
type DNSIntelligenceDiff struct {
	Target       string   `json:"target"`
	LatestAt     time.Time `json:"latestAt,omitempty"`
	PreviousAt   time.Time `json:"previousAt,omitempty"`
	NewRecords   map[string][]string `json:"newRecords"`
	RemovedRecords map[string][]string `json:"removedRecords"`
	Note         string   `json:"note,omitempty"`
}

// IPInformationDiff compares the two most recent IP information snapshots for a target.
type IPInformationDiff struct {
	Target       string    `json:"target"`
	LatestAt     time.Time `json:"latestAt,omitempty"`
	PreviousAt   time.Time `json:"previousAt,omitempty"`
	ASNChanged   bool      `json:"asnChanged"`
	PreviousASN  string    `json:"previousASN,omitempty"`
	LatestASN    string    `json:"latestASN,omitempty"`
	CountryChanged bool    `json:"countryChanged"`
	PreviousCountry string `json:"previousCountry,omitempty"`
	LatestCountry   string `json:"latestCountry,omitempty"`
	OrgChanged   bool      `json:"orgChanged"`
	PreviousOrg  string    `json:"previousOrg,omitempty"`
	LatestOrg    string    `json:"latestOrg,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// CIDRSweepDiff compares the two most recent CIDR sweep snapshots for a target.
type CIDRSweepDiff struct {
	Target       string    `json:"target"`
	LatestAt     time.Time `json:"latestAt,omitempty"`
	PreviousAt   time.Time `json:"previousAt,omitempty"`
	NewHosts     []string  `json:"newHosts"`
	RemovedHosts []string  `json:"removedHosts"`
	NewPorts     []int     `json:"newPorts"`
	RemovedPorts []int     `json:"removedPorts"`
	Note         string   `json:"note,omitempty"`
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
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS workspaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT,
			created_at TEXT NOT NULL
		)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS workspace_branding (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL UNIQUE REFERENCES workspaces(id) ON DELETE CASCADE,
			company_name TEXT,
			auditor_name TEXT,
			client_name TEXT,
			logo_base64 TEXT,
			logo_mime_type TEXT,
			executive_summary_template TEXT,
			custom_footer TEXT,
			disclaimer TEXT,
			version INTEGER NOT NULL DEFAULT 1,
			updated_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS scheduled_scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scan_types TEXT NOT NULL, -- JSON array: ["port","http","dns","subdomain","tls"]
			targets TEXT NOT NULL, -- JSON array of targets
			schedule_cron TEXT NOT NULL, -- cron expression: "0 2 * * *" (daily 2am)
			webhook_url TEXT,
			webhook_type TEXT, -- "slack", "discord", "email"
			last_run_at TEXT,
			next_run_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_scheduled_scans_workspace ON scheduled_scans(workspace_id)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS scan_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_type TEXT NOT NULL,
			target TEXT NOT NULL,
			result_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			workspace_id INTEGER REFERENCES workspaces(id) ON DELETE SET NULL
		)`)
	}
	if err == nil {
		// Migration: add workspace_id column if it doesn't exist (for existing databases)
		_, err = db.Exec(`ALTER TABLE scan_history ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id) ON DELETE SET NULL`)
		// Ignore "duplicate column name" error
		if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return nil, err
		}
		err = nil
	}
	if err == nil {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_history_type_target_created
			ON scan_history(scan_type, target, created_at DESC, id DESC)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_history_workspace
			ON scan_history(workspace_id)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS finding_tags (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			history_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
			finding_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(history_id, finding_id)
		)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_finding_tags_history
			ON finding_tags(history_id)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS finding_notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			history_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
			finding_id TEXT NOT NULL,
			note TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(history_id, finding_id)
		)`)
	}
	if err == nil {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_finding_notes_history
			ON finding_notes(history_id)`)
	}
	if err == nil {
		err = ensureCVEFeedTable(db)
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
func (a *App) saveHistory(scanType, target string, result any, workspaceID int64) error {
	if a == nil || a.historyDB == nil {
		return nil
	}
	redactedTarget := redactHistoryTarget(target)
	redactedResult := redactHistoryResult(result)
	encoded, err := json.Marshal(redactedResult)
	if err != nil {
		return err
	}
	var wsID any
	if workspaceID > 0 {
		wsID = workspaceID
	}
	_, err = a.historyDB.Exec(`INSERT INTO scan_history(scan_type, target, result_json, created_at, workspace_id)
		VALUES (?, ?, ?, ?, ?)`, strings.ToLower(strings.TrimSpace(scanType)), redactedTarget, string(encoded), time.Now().UTC().Format(time.RFC3339Nano), wsID)
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

// DiffLatestSubdomainScans compares the two most recent subdomain enumeration snapshots for a target.
func (a *App) DiffLatestSubdomainScans(target string) SubdomainDiff {
	normalized := normalizeHistoryTarget(target)
	diff := SubdomainDiff{Target: normalized, NewSubdomains: []string{}, RemovedSubdomains: []string{}}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'subdomain' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable Subdomain snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at
	prevNames := toStringSet(previous.result["names"])
	latestNames := toStringSet(latest.result["names"])
	for v := range latestNames {
		if _, ok := prevNames[v]; !ok {
			diff.NewSubdomains = append(diff.NewSubdomains, v)
		}
	}
	for v := range prevNames {
		if _, ok := latestNames[v]; !ok {
			diff.RemovedSubdomains = append(diff.RemovedSubdomains, v)
		}
	}
	sort.Strings(diff.NewSubdomains)
	sort.Strings(diff.RemovedSubdomains)
	return diff
}

// DiffLatestDNSScans compares the two most recent DNS intelligence snapshots for a target.
func (a *App) DiffLatestDNSScans(target string) DNSIntelligenceDiff {
	normalized := normalizeHistoryTarget(target)
	diff := DNSIntelligenceDiff{Target: normalized, NewRecords: map[string][]string{}, RemovedRecords: map[string][]string{}}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'dns' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable DNS snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at

	recordTypes := []string{"a", "aaaa", "mx", "ns", "txt", "spf", "dmarc"}
	for _, rt := range recordTypes {
		prevVals := toStringSet(previous.result[rt])
		latestVals := toStringSet(latest.result[rt])
		var newRecs, removedRecs []string
		for v := range latestVals {
			if _, ok := prevVals[v]; !ok {
				newRecs = append(newRecs, v)
			}
		}
		for v := range prevVals {
			if _, ok := latestVals[v]; !ok {
				removedRecs = append(removedRecs, v)
			}
		}
		if len(newRecs) > 0 {
			diff.NewRecords[rt] = newRecs
		}
		if len(removedRecs) > 0 {
			diff.RemovedRecords[rt] = removedRecs
		}
	}
	return diff
}

// DiffLatestTLSInspections compares the two most recent TLS inspection snapshots for a target.
func (a *App) DiffLatestTLSInspections(target string) TLSInspectionDiff {
	normalized := normalizeHistoryTarget(target)
	diff := TLSInspectionDiff{Target: normalized}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'tls' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable TLS snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at

	// Compare TLS versions
	prevTLS := toStringValue(previous.result["tlsVersion"])
	latestTLS := toStringValue(latest.result["tlsVersion"])
	diff.PreviousTLSVersion = prevTLS
	diff.LatestTLSVersion = latestTLS
	if prevTLS != latestTLS {
		diff.VersionChanged = true
	}

	// Compare cipher suites
	prevCipher := toStringValue(previous.result["cipherSuite"])
	latestCipher := toStringValue(latest.result["cipherSuite"])
	diff.PreviousCipherSuite = prevCipher
	diff.LatestCipherSuite = latestCipher
	if prevCipher != latestCipher {
		diff.CipherSuiteChanged = true
	}

	// Compare cert days remaining
	prevDays, prevOK := tlsDaysRemaining(previous.result["tls"])
	latestDays, latestOK := tlsDaysRemaining(latest.result["tls"])
	if prevOK {
		diff.PreviousCertDays = &prevDays
	}
	if latestOK {
		diff.LatestCertDays = &latestDays
	}
	if prevOK && latestOK {
		delta := latestDays - prevDays
		diff.CertDaysDelta = &delta
	}

	return diff
}

// DiffLatestPathFuzzScans compares the two most recent path fuzzing snapshots for a target.
func (a *App) DiffLatestPathFuzzScans(target string) PathFuzzDiff {
	normalized := normalizeHistoryTarget(target)
	diff := PathFuzzDiff{Target: normalized, NewPaths: []string{}, RemovedPaths: []string{}}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'fuzzer' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable Path Fuzz snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at
	prevPaths := toStringSetFromPathFindings(previous.result["paths"])
	latestPaths := toStringSetFromPathFindings(latest.result["paths"])
	for v := range latestPaths {
		if _, ok := prevPaths[v]; !ok {
			diff.NewPaths = append(diff.NewPaths, v)
		}
	}
	for v := range prevPaths {
		if _, ok := latestPaths[v]; !ok {
			diff.RemovedPaths = append(diff.RemovedPaths, v)
		}
	}
	sort.Strings(diff.NewPaths)
	sort.Strings(diff.RemovedPaths)
	return diff
}

// DiffLatestTLSInspectionScans compares the two most recent TLS inspection snapshots for a target.
func (a *App) DiffLatestTLSInspectionScans(target string) TLSInspectionDiff {
	normalized := normalizeHistoryTarget(target)
	diff := TLSInspectionDiff{Target: normalized}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'tls' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable TLS Inspection snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at
	prevDays := toIntValuePtr(previous.result["daysRemaining"])
	latestDays := toIntValuePtr(latest.result["daysRemaining"])
	if prevDays != nil && latestDays != nil {
		delta := *latestDays - *prevDays
		diff.CertDaysDelta = &delta
		diff.PreviousCertDays = prevDays
		diff.LatestCertDays = latestDays
	}
	prevVer := toStringValue(previous.result["tlsVersion"])
	latestVer := toStringValue(latest.result["tlsVersion"])
	if prevVer != latestVer {
		diff.VersionChanged = true
		diff.PreviousTLSVersion = prevVer
		diff.LatestTLSVersion = latestVer
	}
	prevCipher := toStringValue(previous.result["cipherSuite"])
	latestCipher := toStringValue(latest.result["cipherSuite"])
	if prevCipher != latestCipher {
		diff.CipherSuiteChanged = true
		diff.PreviousCipherSuite = prevCipher
		diff.LatestCipherSuite = latestCipher
	}
	return diff
}

// DiffLatestDNSIntelligenceScans compares the two most recent DNS intelligence snapshots for a target.
func (a *App) DiffLatestDNSIntelligenceScans(target string) DNSIntelligenceDiff {
	normalized := normalizeHistoryTarget(target)
	diff := DNSIntelligenceDiff{Target: normalized, NewRecords: map[string][]string{}, RemovedRecords: map[string][]string{}}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'dns' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable DNS Intelligence snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at
	recordTypes := []string{"a", "aaaa", "mx", "ns", "txt", "spf", "dmarc", "ptr"}
	for _, rt := range recordTypes {
		prevVals := toStringSet(previous.result[rt])
		latestVals := toStringSet(latest.result[rt])
		for v := range latestVals {
			if _, ok := prevVals[v]; !ok {
				diff.NewRecords[rt] = append(diff.NewRecords[rt], v)
			}
		}
		for v := range prevVals {
			if _, ok := latestVals[v]; !ok {
				diff.RemovedRecords[rt] = append(diff.RemovedRecords[rt], v)
			}
		}
		if len(diff.NewRecords[rt]) > 0 {
			sort.Strings(diff.NewRecords[rt])
		}
		if len(diff.RemovedRecords[rt]) > 0 {
			sort.Strings(diff.RemovedRecords[rt])
		}
	}
	return diff
}

// DiffLatestIPInformationScans compares the two most recent IP information snapshots for a target.
func (a *App) DiffLatestIPInformationScans(target string) IPInformationDiff {
	normalized := normalizeHistoryTarget(target)
	diff := IPInformationDiff{Target: normalized}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'ip' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable IP Information snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at
	prevASN := toStringValue(previous.result["asn"])
	latestASN := toStringValue(latest.result["asn"])
	if prevASN != latestASN {
		diff.ASNChanged = true
		diff.PreviousASN = prevASN
		diff.LatestASN = latestASN
	}
	prevCountry := toStringValue(previous.result["country"])
	latestCountry := toStringValue(latest.result["country"])
	if prevCountry != latestCountry {
		diff.CountryChanged = true
		diff.PreviousCountry = prevCountry
		diff.LatestCountry = latestCountry
	}
	prevOrg := toStringValue(previous.result["org"])
	latestOrg := toStringValue(latest.result["org"])
	if prevOrg != latestOrg {
		diff.OrgChanged = true
		diff.PreviousOrg = prevOrg
		diff.LatestOrg = latestOrg
	}
	return diff
}

// DiffLatestCIDRSweepScans compares the two most recent CIDR sweep snapshots for a target.
func (a *App) DiffLatestCIDRSweepScans(target string) CIDRSweepDiff {
	normalized := normalizeHistoryTarget(target)
	diff := CIDRSweepDiff{Target: normalized, NewHosts: []string{}, RemovedHosts: []string{}, NewPorts: []int{}, RemovedPorts: []int{}}
	if a == nil || a.historyDB == nil || normalized == "" {
		return diff
	}
	rows, err := a.historyDB.Query(`SELECT result_json, created_at FROM scan_history
		WHERE scan_type = 'cidr-sweep' AND target = ? ORDER BY created_at DESC, id DESC LIMIT 2`, normalized)
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
			continue
		}
		snaps = append(snaps, snap{at: at, result: result})
	}
	if rows.Err() != nil || len(snaps) < 2 {
		if len(snaps) == 1 {
			diff.LatestAt = snaps[0].at
			diff.Note = "Only one comparable CIDR Sweep snapshot found for this target."
		}
		return diff
	}
	latest, previous := snaps[0], snaps[1]
	diff.LatestAt = latest.at
	diff.PreviousAt = previous.at
	prevHosts := toStringSet(latest.result["hosts"])
	latestHosts := toStringSet(previous.result["hosts"])
	for v := range latestHosts {
		if _, ok := prevHosts[v]; !ok {
			diff.NewHosts = append(diff.NewHosts, v)
		}
	}
	for v := range prevHosts {
		if _, ok := latestHosts[v]; !ok {
			diff.RemovedHosts = append(diff.RemovedHosts, v)
		}
	}
	sort.Strings(diff.NewHosts)
	sort.Strings(diff.RemovedHosts)
	prevPorts := toIntSet(latest.result["ports"])
	latestPorts := toIntSet(previous.result["ports"])
	for v := range latestPorts {
		if _, ok := prevPorts[v]; !ok {
			diff.NewPorts = append(diff.NewPorts, v)
		}
	}
	for v := range prevPorts {
		if _, ok := latestPorts[v]; !ok {
			diff.RemovedPorts = append(diff.RemovedPorts, v)
		}
	}
	sort.Ints(diff.NewPorts)
	sort.Ints(diff.RemovedPorts)
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

func toIntValuePtr(v any) *int {
	switch n := v.(type) {
	case float64:
		i := int(n)
		return &i
	case int:
		return &n
	case int64:
		i := int(n)
		return &i
	default:
		return nil
	}
}

func toStringSetFromPathFindings(v any) map[string]struct{} {
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
		url := toStringValue(m["url"])
		if url != "" {
			out[url] = struct{}{}
		}
	}
	return out
}

func toIntSet(v any) map[int]struct{} {
	out := map[int]struct{}{}
	arr, ok := v.([]any)
	if !ok {
		return out
	}
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out[int(n)] = struct{}{}
		case int:
			out[n] = struct{}{}
		case int64:
			out[int(n)] = struct{}{}
		}
	}
	return out
}
