package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var dynamicAdvisoryMu sync.RWMutex
var dynamicAdvisories []AdvisoryEntry

const (
	cisaKEVFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	nvdCVEFeedURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	cveFeedTimeout = 15 * time.Second
)

type ThreatFeedItem struct {
	CVE             string    `json:"cve"`
	Product         string    `json:"product"`
	Title           string    `json:"title"`
	Severity        string    `json:"severity"`
	CVSS            float64   `json:"cvss,omitempty"`
	Description     string    `json:"description"`
	PublishedAt     time.Time `json:"publishedAt"`
	Source          string    `json:"source"`
	KEV             bool      `json:"kev"`
	Vendor          string    `json:"vendor,omitempty"`
	AffectedVersion string    `json:"affectedVersion,omitempty"`
	FixedVersion    string    `json:"fixedVersion,omitempty"`
	References      []string  `json:"references,omitempty"`
}

type CVEFeedSyncResult struct {
	Fetched       int       `json:"fetched"`
	Stored        int       `json:"stored"`
	CISAKEV       int       `json:"cisaKev"`
	NVDRecent     int       `json:"nvdRecent"`
	CompletedAt   time.Time `json:"completedAt"`
	Warnings      []string  `json:"warnings,omitempty"`
	UsedCacheOnly bool      `json:"usedCacheOnly"`
}

// CVEItem represents a CVE entry for the frontend feed view.
type CVEItem struct {
	CVEID          string   `json:"cveId"`
	Source         string   `json:"source"`
	Vendor         string   `json:"vendor"`
	Product        string   `json:"product"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	CVSSScore      float64  `json:"cvssScore"`
	PublishedDate  string   `json:"publishedDate"`
	DueDate        string   `json:"dueDate,omitempty"`
	IsKEV          bool     `json:"isKev"`
	References     []string `json:"references"`
	MatchedTargets []string `json:"matchedTargets"`
}

// CVEFeedSummary represents the summary response for the frontend.
type CVEFeedSummary struct {
	Items         []CVEItem `json:"items"`
	TotalCached   int       `json:"totalCached"`
	KEVCount      int       `json:"kevCount"`
	AffectedCount int       `json:"affectedCount"`
	LastSyncedAt  string    `json:"lastSyncedAt"`
	SyncError     string    `json:"syncError,omitempty"`
}

type cisaKEVResponse struct {
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string                         `json:"id"`
			Published    string                         `json:"published"`
			Descriptions []struct{ Lang, Value string } `json:"descriptions"`
			References   []struct {
				URL string `json:"url"`
			} `json:"references"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria string `json:"criteria"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func ensureCVEFeedTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS cve_feed (
		cve_id TEXT PRIMARY KEY,
		source TEXT NOT NULL,
		vendor TEXT,
		product TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		cvss_score REAL NOT NULL DEFAULT 0,
		published_date TEXT NOT NULL,
		due_date TEXT,
		is_kev INTEGER NOT NULL DEFAULT 0,
		references_json TEXT NOT NULL DEFAULT '[]',
		updated_at TEXT NOT NULL
	)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_feed(published_date DESC)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_feed(product)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve_feed(is_kev)`)
	return err
}

func (a *App) SyncLatestCVEs() (CVEFeedSyncResult, error) {
	result := CVEFeedSyncResult{CompletedAt: time.Now().UTC()}
	if a == nil || a.historyDB == nil {
		return result, fmt.Errorf("local SQLite cache is not available")
	}
	if err := ensureCVEFeedTable(a.historyDB); err != nil {
		return result, err
	}
	client := &http.Client{Timeout: cveFeedTimeout}
	items := make(map[string]ThreatFeedItem)
	kevCtx, kevCancel := context.WithTimeout(context.Background(), cveFeedTimeout)
	kevItems, err := fetchCISAKEV(kevCtx, client)
	kevCancel()
	if err != nil {
		result.Warnings = append(result.Warnings, "CISA KEV: "+err.Error())
		log.Printf("CVE Feed: CISA KEV fetch error: %v", err)
	} else {
		result.CISAKEV = len(kevItems)
		log.Printf("CVE Feed: CISA KEV fetched %d items", len(kevItems))
		for _, item := range kevItems {
			items[item.CVE] = item
		}
	}
	if len(items) == 0 {
		result.UsedCacheOnly = true
		log.Println("CVE Feed: No items fetched, using cache only")
		return result, nil
	}
	tx, err := a.historyDB.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO cve_feed (cve_id,source,vendor,product,title,description,severity,cvss_score,published_date,due_date,is_kev,references_json,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET source=excluded.source,vendor=excluded.vendor,product=excluded.product,title=excluded.title,description=excluded.description,severity=excluded.severity,cvss_score=excluded.cvss_score,published_date=excluded.published_date,due_date=excluded.due_date,is_kev=excluded.is_kev,references_json=excluded.references_json,updated_at=excluded.updated_at`)
	if err != nil {
		return result, err
	}
	defer stmt.Close()
	for _, item := range items {
		vendor := ""
		dueDate := ""
		if item.Source == "CISA KEV" {
			vendor = item.Product
			dueDate = item.PublishedAt.Add(14 * 24 * time.Hour).Format(time.RFC3339)
		}
		refs, _ := json.Marshal(item.References)
		if _, err := stmt.Exec(item.CVE, item.Source, vendor, item.Product, item.Title, item.Description, item.Severity, item.CVSS, item.PublishedAt.UTC().Format(time.RFC3339), dueDate, boolInt(item.KEV), string(refs), time.Now().UTC().Format(time.RFC3339)); err != nil {
			return result, err
		}
		result.Stored++
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	result.Fetched = len(items)
	result.CompletedAt = time.Now().UTC()
	mergeFeedItemsIntoAdvisories(items)
	return result, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (a *App) GetLatestThreatFeed(days int) ([]ThreatFeedItem, error) {
	if a == nil || a.historyDB == nil {
		return []ThreatFeedItem{}, nil
	}
	if err := ensureCVEFeedTable(a.historyDB); err != nil {
		return nil, err
	}
	if days != 1 && days != 7 && days != 30 {
		days = 30
	}
	rows, err := a.historyDB.Query(`SELECT cve,product,title,severity,cvss,description,published_at,source,kev,affected_version,fixed_version,references_json FROM cve_feed WHERE published_at >= datetime('now', ?) OR kev=1 ORDER BY kev DESC, published_at DESC LIMIT 100`, "-"+strconv.Itoa(days)+" days")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatFeedItem{}
	for rows.Next() {
		var i ThreatFeedItem
		var published, refs string
		var kev int
		if err := rows.Scan(&i.CVE, &i.Product, &i.Title, &i.Severity, &i.CVSS, &i.Description, &published, &i.Source, &kev, &i.AffectedVersion, &i.FixedVersion, &refs); err != nil {
			return nil, err
		}
		i.KEV = kev == 1
		i.PublishedAt, _ = time.Parse(time.RFC3339, published)
		_ = json.Unmarshal([]byte(refs), &i.References)
		out = append(out, i)
	}
	return out, rows.Err()
}

func fetchJSON(ctx context.Context, client *http.Client, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Codexa-Scanner/1.2 (local-first; no API key)")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(dst)
}

func fetchCISAKEV(ctx context.Context, client *http.Client) ([]ThreatFeedItem, error) {
	return fetchCISAKEVWithURL(ctx, client, cisaKEVFeedURL)
}

func fetchCISAKEVWithURL(ctx context.Context, client *http.Client, url string) ([]ThreatFeedItem, error) {
	var feed cisaKEVResponse
	if err := fetchJSON(ctx, client, url, &feed); err != nil {
		return nil, err
	}
	out := make([]ThreatFeedItem, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		published, _ := time.Parse("2006-01-02", v.DateAdded)
		vendor := normalizeFeedProduct(v.VendorProject)
		out = append(out, ThreatFeedItem{CVE: v.CVEID, Product: normalizeFeedProduct(v.Product), Title: v.VulnerabilityName, Severity: "HIGH", Description: v.ShortDescription + " " + v.RequiredAction, PublishedAt: published.UTC(), Source: "CISA KEV", KEV: true, Vendor: vendor})
	}
	return out, nil
}

func fetchNVDRecent(ctx context.Context, client *http.Client, start, end time.Time) ([]ThreatFeedItem, error) {
	return fetchNVDRecentWithURL(ctx, client, nvdCVEFeedURL, start, end)
}

func fetchNVDRecentWithURL(ctx context.Context, client *http.Client, baseURL string, start, end time.Time) ([]ThreatFeedItem, error) {
	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("pubStartDate", start.UTC().Format("2006-01-02T15:04:05.000"))
	q.Set("pubEndDate", end.UTC().Format("2006-01-02T15:04:05.000"))
	q.Set("resultsPerPage", "2000")
	u.RawQuery = q.Encode()
	var feed nvdResponse
	if err := fetchJSON(ctx, client, u.String(), &feed); err != nil {
		return nil, err
	}
	out := make([]ThreatFeedItem, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		c := v.CVE
		title, desc := c.ID, ""
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		product := ""
		for _, cfg := range c.Configurations {
			for _, n := range cfg.Nodes {
				for _, m := range n.CPEMatch {
					parts := strings.Split(m.Criteria, ":")
					if len(parts) > 4 {
						product = normalizeFeedProduct(parts[4])
						if product != "" {
							break
						}
					}
				}
				if product != "" {
					break
				}
			}
			if product != "" {
				break
			}
		}
		score, sev := 0.0, ""
		if len(c.Metrics.CVSSMetricV31) > 0 {
			score = c.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			sev = c.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		} else if len(c.Metrics.CVSSMetricV30) > 0 {
			score = c.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			sev = c.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
		}
		if sev != "CRITICAL" && sev != "HIGH" {
			continue
		}
		published, _ := time.Parse(time.RFC3339, c.Published)
		refs := []string{}
		for _, r := range c.References {
			refs = append(refs, r.URL)
		}
		out = append(out, ThreatFeedItem{CVE: c.ID, Product: product, Title: title, Severity: sev, CVSS: score, Description: desc, PublishedAt: published, Source: "NVD", References: refs})
	}
	return out, nil
}

func normalizeFeedProduct(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")
	return strings.TrimSpace(s)
}

func mergeFeedItemsIntoAdvisories(items map[string]ThreatFeedItem) {
	byProduct := map[string][]AdvisoryCVE{}
	for _, item := range items {
		if item.Product == "" {
			continue
		}
		byProduct[item.Product] = append(byProduct[item.Product], AdvisoryCVE{CVE: item.CVE, Title: item.Title, AffectedVersions: item.AffectedVersion, FixedVersion: item.FixedVersion, Severity: item.Severity, Description: item.Description, References: item.References})
	}
	merged := make([]AdvisoryEntry, 0, len(byProduct))
	for product, cves := range byProduct {
		merged = append(merged, AdvisoryEntry{Product: product, CVEs: cves})
	}
	dynamicAdvisoryMu.Lock()
	dynamicAdvisories = merged
	dynamicAdvisoryMu.Unlock()
}

func loadCachedFeedAdvisories(db *sql.DB) {
	if db == nil {
		return
	}
	rows, err := db.Query(`SELECT cve,product,title,severity,description,published_at,affected_version,fixed_version,references_json FROM cve_feed`)
	if err != nil {
		return
	}
	defer rows.Close()
	items := map[string]ThreatFeedItem{}
	for rows.Next() {
		var i ThreatFeedItem
		var published, refs string
		if rows.Scan(&i.CVE, &i.Product, &i.Title, &i.Severity, &i.Description, &published, &i.AffectedVersion, &i.FixedVersion, &refs) != nil {
			continue
		}
		i.PublishedAt, _ = time.Parse(time.RFC3339, published)
		_ = json.Unmarshal([]byte(refs), &i.References)
		items[i.CVE] = i
	}
	mergeFeedItemsIntoAdvisories(items)
}

func cachedAdvisoriesForProduct(product, version string) []AdvisoryCVE {
	dynamicAdvisoryMu.RLock()
	defer dynamicAdvisoryMu.RUnlock()
	var matches []AdvisoryCVE
	for _, entry := range dynamicAdvisories {
		if strings.EqualFold(entry.Product, normalizeFeedProduct(product)) || strings.EqualFold(entry.Product, normalizeFeedProduct(strings.ReplaceAll(product, " ", "-"))) {
			for _, cve := range entry.CVEs {
				if version != "" && (cve.AffectedVersions == "" || isVersionAffected(version, cve.AffectedVersions, cve.FixedVersion)) {
					matches = append(matches, cve)
				}
			}
		}
	}
	return matches
}

// extractTechnologiesFromHistory scans the scan_history table and extracts
// unique technology/product names from web audit and port scan results.
func (a *App) extractTechnologiesFromHistory() (map[string][]string, error) {
	if a == nil || a.historyDB == nil {
		return nil, fmt.Errorf("history database not available")
	}
	rows, err := a.historyDB.Query(`SELECT scan_type, target, result_json FROM scan_history WHERE scan_type IN ('http', 'port', 'cidr') ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Map of target -> list of technologies
	targetTechs := make(map[string][]string)
	seen := make(map[string]bool)

	for rows.Next() {
		var scanType, target, resultJSON string
		if err := rows.Scan(&scanType, &target, &resultJSON); err != nil {
			continue
		}
		key := target + "|" + scanType
		if seen[key] {
			continue
		}
		seen[key] = true

		var techs []string
		switch scanType {
		case "http":
			var results []BulkHeaderResult
			if err := json.Unmarshal([]byte(resultJSON), &results); err == nil {
				for _, r := range results {
					if r.Error != "" {
						continue
					}
					if r.Server != "" {
						techs = append(techs, normalizeFeedProduct(r.Server))
					}
					if r.PoweredBy != "" {
						techs = append(techs, normalizeFeedProduct(r.PoweredBy))
					}
					for _, t := range r.Technologies {
						techs = append(techs, normalizeFeedProduct(t))
					}
					for _, e := range r.EdgeServices {
						techs = append(techs, normalizeFeedProduct(e))
					}
				}
			}
		case "port", "cidr":
			var results []PortFinding
			if err := json.Unmarshal([]byte(resultJSON), &results); err == nil {
				for _, r := range results {
					if r.Banner != "" {
						if product, version := extractVersionFromBanner(r.Banner); product != "" {
							techs = append(techs, normalizeFeedProduct(product))
							if version != "" {
								techs = append(techs, normalizeFeedProduct(product+" "+version))
							}
						}
					}
					if r.Service != "" && r.Service != "unknown" {
						techs = append(techs, normalizeFeedProduct(r.Service))
					}
				}
			}
		}
		// Deduplicate
		uniqueTechs := make(map[string]bool)
		var finalTechs []string
		for _, t := range techs {
			if t != "" && !uniqueTechs[t] {
				uniqueTechs[t] = true
				finalTechs = append(finalTechs, t)
			}
		}
		if len(finalTechs) > 0 {
			targetTechs[target] = finalTechs
		}
	}
	return targetTechs, rows.Err()
}

// correlateCVEsWithAssets matches CVE feed items against scanned technologies.
func (a *App) correlateCVEsWithAssets(items []CVEItem) ([]CVEItem, error) {
	targetTechs, err := a.extractTechnologiesFromHistory()
	if err != nil {
		return items, err
	}
	if len(targetTechs) == 0 {
		return items, nil
	}

	for i := range items {
		cveProduct := normalizeFeedProduct(items[i].Product)
		if cveProduct == "" {
			continue
		}
		var matched []string
		for target, techs := range targetTechs {
			for _, tech := range techs {
				if tech == cveProduct || strings.Contains(tech, cveProduct) || strings.Contains(cveProduct, tech) {
					matched = append(matched, target)
					break
				}
			}
		}
		if len(matched) > 0 {
			items[i].MatchedTargets = matched
		}
	}
	return items, nil
}

// SyncLiveCVEFeed syncs CVE feeds from CISA KEV and NVD, correlates with scanned assets,
// applies retention policy, and returns a summary.
func (a *App) SyncLiveCVEFeed(proxyURL string) (CVEFeedSummary, error) {
	summary := CVEFeedSummary{}
	log.Printf("CVE Feed: SyncLiveCVEFeed called, a=%v, historyDB=%v", a != nil, a != nil && a.historyDB != nil)
	if a == nil || a.historyDB == nil {
		summary.SyncError = "local SQLite cache is not available"
		log.Println("CVE Feed: SQLite cache not available - a is nil or historyDB is nil")
		return summary, nil
	}

	log.Println("CVE Feed: Starting sync...")
	// Perform sync
	syncResult, err := a.SyncLatestCVEs()
	if err != nil {
		summary.SyncError = err.Error()
		log.Printf("CVE Feed: SyncLatestCVEs error: %v", err)
	} else if len(syncResult.Warnings) > 0 {
		summary.SyncError = strings.Join(syncResult.Warnings, "; ")
		log.Printf("CVE Feed: SyncLatestCVEs warnings: %v", syncResult.Warnings)
	} else {
		log.Printf("CVE Feed: SyncLatestCVEs OK - fetched=%d, stored=%d, CISA KEV=%d, NVD=%d", syncResult.Fetched, syncResult.Stored, syncResult.CISAKEV, syncResult.NVDRecent)
	}

	// Fetch updated cache with correlation
	cached, err := a.GetCachedCVEFeed("ALL", false)
	if err != nil {
		summary.SyncError = err.Error()
		return summary, nil
	}

	// Apply retention policy: keep last 90 days, max 1000 entries
	if err := a.applyCVECacheRetention(); err != nil {
		if summary.SyncError != "" {
			summary.SyncError += "; retention: " + err.Error()
		} else {
			summary.SyncError = "retention: " + err.Error()
		}
	}

	return cached, nil
}

// GetCachedCVEFeed returns cached CVE feed items with optional filtering and correlation.
func (a *App) GetCachedCVEFeed(filter string, onlyAffected bool) (CVEFeedSummary, error) {
	summary := CVEFeedSummary{}
	if a == nil || a.historyDB == nil {
		summary.SyncError = "local SQLite cache is not available"
		return summary, nil
	}

	if err := ensureCVEFeedTable(a.historyDB); err != nil {
		summary.SyncError = err.Error()
		return summary, nil
	}

	// Build query based on filter
	query := `SELECT cve_id, source, vendor, product, title, description, severity, cvss_score, published_date, due_date, is_kev, references_json, updated_at FROM cve_feed`
	args := []any{}

	switch strings.ToUpper(filter) {
	case "KEV":
		query += ` WHERE is_kev = 1`
	case "CRITICAL":
		query += ` WHERE severity = 'CRITICAL'`
	case "AFFECTED":
		// Will filter after correlation
	case "ALL":
		fallthrough
	default:
		// No additional filter
	}

	query += ` ORDER BY is_kev DESC, published_date DESC LIMIT 1000`

	rows, err := a.historyDB.Query(query, args...)
	if err != nil {
		summary.SyncError = err.Error()
		return summary, nil
	}
	defer rows.Close()

	items := make([]CVEItem, 0, 100)
	kevCount := 0
	affectedCount := 0
	var lastSynced string

	for rows.Next() {
		var item CVEItem
		var dueDate, refs string
		var isKEV int
		if err := rows.Scan(&item.CVEID, &item.Source, &item.Vendor, &item.Product, &item.Title, &item.Description, &item.Severity, &item.CVSSScore, &item.PublishedDate, &dueDate, &isKEV, &refs, &lastSynced); err != nil {
			continue
		}
		item.DueDate = dueDate
		item.IsKEV = isKEV == 1
		_ = json.Unmarshal([]byte(refs), &item.References)
		if item.References == nil {
			item.References = []string{}
		}
		if item.MatchedTargets == nil {
			item.MatchedTargets = []string{}
		}

		if item.IsKEV {
			kevCount++
		}
		items = append(items, item)
	}

	// Correlate with scanned assets
	items, _ = a.correlateCVEsWithAssets(items)

	// Apply onlyAffected filter
	if onlyAffected {
		filtered := make([]CVEItem, 0, len(items))
		for _, item := range items {
			if len(item.MatchedTargets) > 0 {
				filtered = append(filtered, item)
				affectedCount++
			}
		}
		items = filtered
	} else {
		for _, item := range items {
			if len(item.MatchedTargets) > 0 {
				affectedCount++
			}
		}
	}

	summary.Items = items
	summary.TotalCached = len(items)
	summary.KEVCount = kevCount
	summary.AffectedCount = affectedCount
	summary.LastSyncedAt = lastSynced

	return summary, nil
}

// applyCVECacheRetention enforces the retention policy: max 90 days, max 1000 entries.
func (a *App) applyCVECacheRetention() error {
	if a == nil || a.historyDB == nil {
		return fmt.Errorf("history database not available")
	}
	// Delete entries older than 90 days
	_, err := a.historyDB.Exec(`DELETE FROM cve_feed WHERE published_date < datetime('now', '-90 days')`)
	if err != nil {
		return err
	}
	// Keep only the most recent 1000 entries
	_, err = a.historyDB.Exec(`DELETE FROM cve_feed WHERE cve_id NOT IN (SELECT cve_id FROM cve_feed ORDER BY published_date DESC LIMIT 1000)`)
	return err
}
