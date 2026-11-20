package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
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
		cve TEXT PRIMARY KEY, product TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
		cvss REAL NOT NULL DEFAULT 0, description TEXT NOT NULL, published_at TEXT NOT NULL,
		source TEXT NOT NULL, kev INTEGER NOT NULL DEFAULT 0, affected_version TEXT,
		fixed_version TEXT, references_json TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL
	)`)
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
	} else {
		result.CISAKEV = len(kevItems)
		for _, item := range kevItems {
			items[item.CVE] = item
		}
	}
	nvdCtx, nvdCancel := context.WithTimeout(context.Background(), cveFeedTimeout)
	nvdItems, err := fetchNVDRecent(nvdCtx, client, time.Now().UTC().Add(-30*24*time.Hour), time.Now().UTC())
	nvdCancel()
	if err != nil {
		result.Warnings = append(result.Warnings, "NVD: "+err.Error())
	} else {
		result.NVDRecent = len(nvdItems)
		for _, item := range nvdItems {
			if old, ok := items[item.CVE]; ok {
				item.KEV = old.KEV
				if item.Product == "" {
					item.Product = old.Product
				}
				if old.Source == "CISA KEV" {
					item.Source = "CISA KEV + NVD"
				}
			}
			items[item.CVE] = item
		}
	}
	if len(items) == 0 {
		result.UsedCacheOnly = true
		return result, fmt.Errorf("feed sync failed; existing local cache remains available")
	}
	tx, err := a.historyDB.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO cve_feed (cve,product,title,severity,cvss,description,published_at,source,kev,affected_version,fixed_version,references_json,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET product=excluded.product,title=excluded.title,severity=excluded.severity,cvss=excluded.cvss,description=excluded.description,published_at=excluded.published_at,source=excluded.source,kev=excluded.kev,affected_version=excluded.affected_version,fixed_version=excluded.fixed_version,references_json=excluded.references_json,updated_at=excluded.updated_at`)
	if err != nil {
		return result, err
	}
	defer stmt.Close()
	for _, item := range items {
		refs, _ := json.Marshal(item.References)
		if _, err := stmt.Exec(item.CVE, item.Product, item.Title, item.Severity, item.CVSS, item.Description, item.PublishedAt.UTC().Format(time.RFC3339), item.Source, boolInt(item.KEV), item.AffectedVersion, item.FixedVersion, string(refs), time.Now().UTC().Format(time.RFC3339)); err != nil {
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
	if days != 7 && days != 30 {
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
	req.Header.Set("User-Agent", "Codexa-Scanner/1.1.5 (local-first; no API key)")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 25<<20)).Decode(dst)
}

func fetchCISAKEV(ctx context.Context, client *http.Client) ([]ThreatFeedItem, error) {
	var feed cisaKEVResponse
	if err := fetchJSON(ctx, client, cisaKEVFeedURL, &feed); err != nil {
		return nil, err
	}
	out := make([]ThreatFeedItem, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		published, _ := time.Parse("2006-01-02", v.DateAdded)
		out = append(out, ThreatFeedItem{CVE: v.CVEID, Product: normalizeFeedProduct(v.Product), Title: v.VulnerabilityName, Severity: "HIGH", Description: v.ShortDescription + " " + v.RequiredAction, PublishedAt: published.UTC(), Source: "CISA KEV", KEV: true})
	}
	return out, nil
}

func fetchNVDRecent(ctx context.Context, client *http.Client, start, end time.Time) ([]ThreatFeedItem, error) {
	u, _ := url.Parse(nvdCVEFeedURL)
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
