package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"gopkg.in/yaml.v3"
	"net/url"

	"github.com/go-pdf/fpdf"
)

// ==========================================
// 4. PASSIVE VERSION-TO-CVE ADVISORY MATCHER
// ==========================================

type AdvisoryCVE struct {
	CVE              string   `json:"cve"`
	Title            string   `json:"title"`
	AffectedVersions string   `json:"affectedVersions"`
	FixedVersion     string   `json:"fixedVersion"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	References       []string `json:"references"`
}

type AdvisoryEntry struct {
	Product string        `json:"product"`
	CVEs    []AdvisoryCVE `json:"cves"`
}

type AdvisoryMatch struct {
	Product         string        `json:"product"`
	DetectedVersion string        `json:"detectedVersion,omitempty"`
	Matches         []AdvisoryCVE `json:"matches"`
	Source          string        `json:"source"` // "banner", "server-header", "powered-by", "technology", "tls"
}

type CustomSecretPattern struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Pattern     string `json:"pattern" yaml:"pattern"`
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
}

type CustomHeaderRule struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Header      string `json:"header" yaml:"header"`
	Match       string `json:"match" yaml:"match"`
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
}

type CustomPathWordlist struct {
	ID     string   `json:"id" yaml:"id"`
	Name   string   `json:"name" yaml:"name"`
	Paths  []string `json:"paths" yaml:"paths"`
}

type CustomRulesFile struct {
	SecretPatterns []CustomSecretPattern `json:"secretPatterns" yaml:"secretPatterns"`
	HeaderRules    []CustomHeaderRule    `json:"headerRules" yaml:"headerRules"`
	PathWordlists  []CustomPathWordlist  `json:"pathWordlists" yaml:"pathWordlists"`
}

var (
	advisoryData     []AdvisoryEntry
	advisoryDataOnce sync.Once
	advisoryLoadErr  error
)

func loadAdvisoryData() ([]AdvisoryEntry, error) {
	advisoryDataOnce.Do(func() {
		data, err := os.ReadFile(filepath.Join("knowledge", "advisory.json"))
		if err != nil {
			advisoryLoadErr = fmt.Errorf("failed to read advisory data: %w", err)
			return
		}
		if err := json.Unmarshal(data, &advisoryData); err != nil {
			advisoryLoadErr = fmt.Errorf("failed to parse advisory data: %w", err)
			return
		}
	})
	return advisoryData, advisoryLoadErr
}

func loadCustomRules(path string) (*CustomRulesFile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read custom rules file: cannot find the file %q", path)
		}
		return nil, fmt.Errorf("failed to read custom rules file: %w", err)
	}
	// File size limit: 100KB
	if len(data) > 100*1024 {
		return nil, fmt.Errorf("custom rules file too large (max 100KB): %d bytes", len(data))
	}
	var rules CustomRulesFile
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".yaml" || ext == ".yml" {
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("failed to parse YAML custom rules: %w", err)
		}
	} else if ext == ".json" {
		if err := json.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("failed to parse JSON custom rules: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported custom rules file format (use .yaml, .yml, or .json): %s", path)
	}

	// Validate and compile secret patterns
	if len(rules.SecretPatterns) > 50 {
		return nil, fmt.Errorf("too many secret patterns (max 50): %d", len(rules.SecretPatterns))
	}
	for i, sp := range rules.SecretPatterns {
		if len(sp.Pattern) > 500 {
			return nil, fmt.Errorf("secret pattern %d too long (max 500 chars): %d", i, len(sp.Pattern))
		}
		if err := validateRegexPattern(sp.Pattern); err != nil {
			return nil, fmt.Errorf("secret pattern %d (%s) invalid: %w", i, sp.ID, err)
		}
		// Pre-compile to verify it works and cache for performance
		_, err := regexp.Compile(sp.Pattern)
		if err != nil {
			return nil, fmt.Errorf("secret pattern %d (%s) failed to compile: %w", i, sp.ID, err)
		}
	}

	// Validate header rules
	if len(rules.HeaderRules) > 50 {
		return nil, fmt.Errorf("too many header rules (max 50): %d", len(rules.HeaderRules))
	}
	for i, hr := range rules.HeaderRules {
		if len(hr.Match) > 500 {
			return nil, fmt.Errorf("header rule %d match pattern too long (max 500 chars): %d", i, len(hr.Match))
		}
		if err := validateRegexPattern(hr.Match); err != nil {
			return nil, fmt.Errorf("header rule %d (%s) match pattern invalid: %w", i, hr.ID, err)
		}
		_, err := regexp.Compile(hr.Match)
		if err != nil {
			return nil, fmt.Errorf("header rule %d (%s) match pattern failed to compile: %w", i, hr.ID, err)
		}
	}

	// Validate path wordlists
	if len(rules.PathWordlists) > 20 {
		return nil, fmt.Errorf("too many path wordlists (max 20): %d", len(rules.PathWordlists))
	}
	for i, pw := range rules.PathWordlists {
		if len(pw.Paths) > 200 {
			return nil, fmt.Errorf("path wordlist %d (%s) too many paths (max 200): %d", i, pw.ID, len(pw.Paths))
		}
		for j, p := range pw.Paths {
			if len(p) > 500 {
				return nil, fmt.Errorf("path wordlist %d (%s) path %d too long (max 500 chars): %d", i, pw.ID, j, len(p))
			}
		}
	}

	return &rules, nil
}

// validateRegexPattern checks for patterns that could cause catastrophic backtracking (ReDoS).
// Go's regexp engine uses RE2 (linear-time guarantee), but we still reject obviously dangerous patterns.
func validateRegexPattern(pattern string) error {
	// Reject patterns with nested quantifiers on overlapping character classes
	// e.g., (a+)+, (a*)*, (.+)+ - these can cause exponential backtracking in backtracking engines
	// Note: RE2 handles these safely, but we reject them for defense in depth and portability
	dangerousPatterns := []string{
		`\(\?\:.*[+*]\)[+*]`, // (?:...)+ or (?:...)*
		`\([^)]*[+*]\)[+*]`,   // (...) + or *
		`\(\?[^)]*[+*]\)[+*]`, // (?...) + or *
	}
	for _, dp := range dangerousPatterns {
		if matched, _ := regexp.MatchString(dp, pattern); matched {
			return fmt.Errorf("pattern contains potentially catastrophic nested quantifier")
		}
	}
	// Limit pattern complexity: reject patterns with excessive alternation or grouping
	if strings.Count(pattern, "|") > 20 {
		return fmt.Errorf("pattern has too many alternations (max 20)")
	}
	if strings.Count(pattern, "(") > 30 {
		return fmt.Errorf("pattern has too many capture groups (max 30)")
	}
	return nil
}

func extractVersionFromBanner(banner string) (product, version string) {
	bannerLower := strings.ToLower(banner)

	// SSH version extraction: SSH-2.0-OpenSSH_9.2p1
	if strings.HasPrefix(bannerLower, "ssh-") {
		if idx := strings.Index(bannerLower, "openssh_"); idx != -1 {
			versionPart := banner[idx+len("OpenSSH_"):]
			version = strings.TrimSpace(strings.Split(versionPart, " ")[0])
			return "OpenSSH", version
		}
		if idx := strings.Index(bannerLower, "dropbear"); idx != -1 {
			versionPart := banner[idx+len("Dropbear"):]
			version = strings.TrimSpace(strings.Split(versionPart, " ")[0])
			return "Dropbear", version
		}
	}

	// HTTP Server header: nginx/1.24.0, Apache/2.4.58, Microsoft-IIS/10.0
	if strings.Contains(bannerLower, "server:") || strings.Contains(bannerLower, "http/") {
		serverIdx := strings.Index(bannerLower, "server:")
		if serverIdx != -1 {
			serverLine := strings.TrimSpace(banner[serverIdx+len("server:"):])
			serverLine = strings.Split(serverLine, "\r")[0]
			serverLine = strings.Split(serverLine, "\n")[0]
			return parseServerHeader(serverLine)
		}
	}

	// FTP banner: 220 ProFTPD 1.3.7 Server
	if strings.HasPrefix(bannerLower, "220") || strings.HasPrefix(bannerLower, "230") {
		if strings.Contains(bannerLower, "proftpd") {
			return "ProFTPD", extractVersionAfter(banner, "ProFTPD")
		}
		if strings.Contains(bannerLower, "vsftpd") {
			return "vsftpd", extractVersionAfter(banner, "vsftpd")
		}
		if strings.Contains(bannerLower, "pure-ftpd") {
			return "Pure-FTPd", extractVersionAfter(banner, "Pure-FTPd")
		}
	}

	// SMTP banner: 220 mail.example.com ESMTP Postfix
	if strings.HasPrefix(bannerLower, "220") && strings.Contains(bannerLower, "postfix") {
		return "Postfix", extractVersionAfter(banner, "Postfix")
	}
	if strings.HasPrefix(bannerLower, "220") && strings.Contains(bannerLower, "exim") {
		return "Exim", extractVersionAfter(banner, "Exim")
	}

	// MySQL banner: 5.7.33-0ubuntu0.18.04.1
	if strings.Contains(bannerLower, "mysql") {
		return "MySQL", extractVersionAfter(banner, "MySQL")
	}

	// PostgreSQL banner
	if strings.Contains(bannerLower, "postgresql") {
		return "PostgreSQL", extractVersionAfter(banner, "PostgreSQL")
	}

	// Redis banner
	if strings.Contains(bannerLower, "redis") {
		return "Redis", extractVersionAfter(banner, "Redis")
	}

	// MongoDB banner
	if strings.Contains(bannerLower, "mongodb") {
		return "MongoDB", extractVersionAfter(banner, "MongoDB")
	}

	return "", ""
}

func parseServerHeader(server string) (product, version string) {
	server = strings.TrimSpace(server)
	parts := strings.Split(server, " ")
	for _, part := range parts {
		if strings.Contains(part, "/") {
			pv := strings.Split(part, "/")
			if len(pv) == 2 {
				return pv[0], pv[1]
			}
		}
	}
	// Try to extract product name from known patterns
	if strings.Contains(strings.ToLower(server), "nginx") {
		return "nginx", extractVersionAfter(server, "nginx/")
	}
	if strings.Contains(strings.ToLower(server), "apache") {
		return "Apache httpd", extractVersionAfter(server, "Apache/")
	}
	if strings.Contains(strings.ToLower(server), "iis") || strings.Contains(strings.ToLower(server), "microsoft") {
		return "Microsoft-IIS", extractVersionAfter(server, "Microsoft-IIS/")
	}
	if strings.Contains(strings.ToLower(server), "openresty") {
		return "OpenResty", extractVersionAfter(server, "openresty/")
	}
	return "", ""
}

func extractVersionAfter(haystack, needle string) string {
	idx := strings.Index(strings.ToLower(haystack), strings.ToLower(needle))
	if idx == -1 {
		return ""
	}
	after := haystack[idx+len(needle):]
	// Extract version-like pattern (numbers, dots, hyphens, letters)
	var version strings.Builder
	for i, r := range after {
		if (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			version.WriteRune(r)
		} else if version.Len() > 0 {
			break
		} else if i > 0 {
			break
		}
	}
	v := strings.Trim(version.String(), "._-")
	return v
}

func extractVersionFromPoweredBy(poweredBy string) (product, version string) {
	poweredBy = strings.TrimSpace(poweredBy)
	if poweredBy == "" {
		return "", ""
	}
	// X-Powered-By: PHP/8.2.0, Express, ASP.NET, Next.js
	if strings.Contains(strings.ToLower(poweredBy), "php") {
		return "PHP", extractVersionAfter(poweredBy, "PHP/")
	}
	if strings.Contains(strings.ToLower(poweredBy), "express") {
		return "Express", extractVersionAfter(poweredBy, "Express/")
	}
	if strings.Contains(strings.ToLower(poweredBy), "asp.net") {
		return "ASP.NET", extractVersionAfter(poweredBy, "ASP.NET/")
	}
	if strings.Contains(strings.ToLower(poweredBy), "next.js") || strings.Contains(strings.ToLower(poweredBy), "nextjs") {
		return "Next.js", extractVersionAfter(poweredBy, "Next.js/")
	}
	// Generic: Product/Version
	parts := strings.Split(poweredBy, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

func extractVersionFromTechnology(tech string) (product, version string) {
	techLower := strings.ToLower(tech)
	// Technologies from fingerprinting: "WordPress", "Laravel", "Next.js", "PHP", "Express", "ASP.NET"
	// These don't typically include versions, but we can check for version patterns
	if strings.Contains(techLower, "wordpress") {
		return "WordPress", ""
	}
	if strings.Contains(techLower, "laravel") {
		return "Laravel", ""
	}
	if strings.Contains(techLower, "next.js") {
		return "Next.js", ""
	}
	if strings.Contains(techLower, "php") {
		return "PHP", ""
	}
	if strings.Contains(techLower, "express") {
		return "Express", ""
	}
	if strings.Contains(techLower, "asp.net") {
		return "ASP.NET", ""
	}
	if strings.Contains(techLower, "django") {
		return "Django", ""
	}
	if strings.Contains(techLower, "rails") {
		return "Ruby on Rails", ""
	}
	return "", ""
}

func versionLessThan(v1, v2 string) bool {
	// Simple version comparison for semantic versions
	// Handles formats like: 1.2.3, 1.2.3-p1, 9.8p1, 7.2.5, etc.
	v1Parts := parseVersionParts(v1)
	v2Parts := parseVersionParts(v2)

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(v1Parts) {
			p1 = v1Parts[i]
		}
		if i < len(v2Parts) {
			p2 = v2Parts[i]
		}
		if p1 < p2 {
			return true
		}
		if p1 > p2 {
			return false
		}
	}
	return false
}

func parseVersionParts(version string) []int {
	var parts []int
	for _, part := range strings.Split(version, ".") {
		// Handle suffixes like "p1", "rc1", "-alpha"
		numStr := ""
		for _, r := range part {
			if r >= '0' && r <= '9' {
				numStr += string(r)
			} else {
				break
			}
		}
		if numStr != "" {
			if n, err := strconv.Atoi(numStr); err == nil {
				parts = append(parts, n)
			}
		} else {
			parts = append(parts, 0)
		}
	}
	return parts
}

func isVersionAffected(detectedVersion, affectedRange, fixedVersion string) bool {
	if detectedVersion == "" {
		return false
	}
	// affectedRange format: "< 9.8p1" or "< 3.0.16, < 3.1.6"
	// fixedVersion format: "9.8p1" or "3.0.16 / 3.1.6"

	// Check against fixed versions (more reliable)
	fixedVersions := strings.Split(fixedVersion, "/")
	for _, fv := range fixedVersions {
		fv = strings.TrimSpace(fv)
		if fv != "" && versionLessThan(detectedVersion, fv) {
			return true
		}
	}

	// Also check affected range
	ranges := strings.Split(affectedRange, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "<") {
			threshold := strings.TrimSpace(r[1:])
			if threshold != "" && versionLessThan(detectedVersion, threshold) {
				return true
			}
		}
	}
	return false
}

func matchAdvisoriesForProduct(product, version string) []AdvisoryCVE {
	advisories, err := loadAdvisoryData()
	if err != nil {
		return nil
	}
	var matches []AdvisoryCVE
	for _, entry := range advisories {
		if strings.EqualFold(entry.Product, product) {
			for _, cve := range entry.CVEs {
				if isVersionAffected(version, cve.AffectedVersions, cve.FixedVersion) {
					matches = append(matches, cve)
				}
			}
		}
	}
	return matches
}

func collectAdvisoryMatches(banner, serverHeader, poweredBy string, technologies []string, tlsVersion, cipherSuite string) []AdvisoryMatch {
	var matches []AdvisoryMatch
	seen := make(map[string]bool) // product:version:source to dedupe

	// From banner
	if product, version := extractVersionFromBanner(banner); product != "" && version != "" {
		key := product + ":" + version + ":banner"
		if !seen[key] {
			advisoryMatches := matchAdvisoriesForProduct(product, version)
			if len(advisoryMatches) > 0 {
				matches = append(matches, AdvisoryMatch{
					Product:         product,
					DetectedVersion: version,
					Matches:         advisoryMatches,
					Source:          "banner",
				})
				seen[key] = true
			}
		}
	}

	// From Server header
	if product, version := parseServerHeader(serverHeader); product != "" && version != "" {
		key := product + ":" + version + ":server-header"
		if !seen[key] {
			advisoryMatches := matchAdvisoriesForProduct(product, version)
			if len(advisoryMatches) > 0 {
				matches = append(matches, AdvisoryMatch{
					Product:         product,
					DetectedVersion: version,
					Matches:         advisoryMatches,
					Source:          "server-header",
				})
				seen[key] = true
			}
		}
	}

	// From X-Powered-By
	if product, version := extractVersionFromPoweredBy(poweredBy); product != "" && version != "" {
		key := product + ":" + version + ":powered-by"
		if !seen[key] {
			advisoryMatches := matchAdvisoriesForProduct(product, version)
			if len(advisoryMatches) > 0 {
				matches = append(matches, AdvisoryMatch{
					Product:         product,
					DetectedVersion: version,
					Matches:         advisoryMatches,
					Source:          "powered-by",
				})
				seen[key] = true
			}
		}
	}

	// From technologies (no version, just product name matching for critical advisories)
	for _, tech := range technologies {
		if product, _ := extractVersionFromTechnology(tech); product != "" {
			key := product + "::technology"
			if !seen[key] {
				advisoryMatches := matchAdvisoriesForProduct(product, "")
				if len(advisoryMatches) > 0 {
					matches = append(matches, AdvisoryMatch{
						Product:         product,
						DetectedVersion: "",
						Matches:         advisoryMatches,
						Source:          "technology",
					})
					seen[key] = true
				}
			}
		}
	}

	// TLS/SSL version checks
	if tlsVersion != "" {
		if strings.Contains(strings.ToLower(tlsVersion), "ssl") || strings.Contains(strings.ToLower(tlsVersion), "tls 1.0") || strings.Contains(strings.ToLower(tlsVersion), "tls 1.1") {
			// Match against OpenSSL advisories for weak protocols
			key := "OpenSSL::tls"
			if !seen[key] {
				advisoryMatches := matchAdvisoriesForProduct("OpenSSL", "")
				if len(advisoryMatches) > 0 {
					matches = append(matches, AdvisoryMatch{
						Product:         "OpenSSL",
						DetectedVersion: tlsVersion,
						Matches:         advisoryMatches,
						Source:          "tls",
					})
					seen[key] = true
				}
			}
		}
	}

	return matches
}

type App struct {
	ctx        context.Context
	scanMu     sync.Mutex
	activeScan *portScan
	nextScanID uint64
	historyDB  *sql.DB

	rateMu     sync.Mutex
	scanPaused bool
	pauseCond  *sync.Cond
	activeBulk bool
}

type ScanRateControl struct {
	RPS      int `json:"rps"`      // 0 = unlimited
	JitterMs int `json:"jitterMs"` // 0..N random extra delay
}

func (c ScanRateControl) normalized() ScanRateControl {
	if c.RPS < 0 {
		c.RPS = 0
	}
	if c.RPS > 50 {
		c.RPS = 50
	}
	if c.JitterMs < 0 {
		c.JitterMs = 0
	}
	if c.JitterMs > 5000 {
		c.JitterMs = 5000
	}
	return c
}

func NewApp() *App {
	a := &App{}
	a.pauseCond = sync.NewCond(&a.rateMu)
	return a
}

type portScan struct {
	id     uint64
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	status scanStatus
}

type scanStatus string

const (
	scanStatusRunning   scanStatus = "running"
	scanStatusCompleted scanStatus = "completed"
	scanStatusCancelled scanStatus = "cancelled"
	scanStatusFailed    scanStatus = "failed"

	defaultScanWorkers = 150
	maxScanWorkers     = 512
	defaultScanTimeout = 800
	maxScanTimeout     = 30_000
	scanResolveTimeout = 5 * time.Second
)

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	configDir, err := os.UserConfigDir()
	if err != nil {
		log.Printf("Codexa Scanner: local scan history unavailable: %v", err)
		return
	}
	dir := filepath.Join(configDir, "CodexaScanner")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("Codexa Scanner: local scan history unavailable: %v", err)
		return
	}
	db, err := openScanHistory(filepath.Join(dir, "history.sqlite"))
	if err != nil {
		log.Printf("Codexa Scanner: local scan history unavailable: %v", err)
		return
	}
	a.historyDB = db
	loadCachedFeedAdvisories(db)
}

func (a *App) shutdown(context.Context) {
	if a.historyDB != nil {
		if err := a.historyDB.Close(); err != nil {
			log.Printf("Codexa Scanner: closing scan history: %v", err)
		}
	}
}

// ==========================================
// 1. REAL-TIME PORT SCANNER + BANNER GRABBER
// ==========================================

type PortFinding struct {
	Port              int      `json:"port"`
	Service           string   `json:"service"`
	Banner            string   `json:"banner"`
	Protocol          string   `json:"protocol,omitempty"`           // e.g., "TLS", "SSH", "SMTP", "HTTP", "Redis"
	Version           string   `json:"version,omitempty"`            // Extracted version string
	Fingerprint       string   `json:"fingerprint,omitempty"`        // Additional fingerprint details
	TLSSupported      bool     `json:"tlsSupported,omitempty"`       // Whether TLS is supported on this port
	TLSCipher         string   `json:"tlsCipher,omitempty"`          // Negotiated TLS cipher
}

var commonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
	8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

func grabBanner(ctx context.Context, conn net.Conn, target string, port int) string {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))

	// HTTP/HTTPS port - send HEAD request
	if port == 80 || port == 8080 || port == 8000 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", target)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	raw := string(buf[:n])
	// HTTP response - extract Server header
	if strings.HasPrefix(raw, "HTTP/") {
		for _, line := range strings.Split(raw, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line)
			}
		}
		return strings.Split(raw, "\r\n")[0]
	}

	// Non-HTTP Banner (SSH, FTP, SMTP)
	clean := strings.TrimSpace(strings.Split(raw, "\n")[0])
	if len(clean) > 80 {
		clean = clean[:80] + "..."
	}
	return clean
}

func grabBannerWithProtocol(ctx context.Context, conn net.Conn, target string, port int) (string, string, string, bool, string) {
	// First get basic banner
	banner := grabBanner(ctx, conn, target, port)

	var protocol, version string
	var tlsSupported bool
	var tlsCipher string

	// Protocol-specific active probing
	switch port {
	case 22: // SSH
		protocol, version, _ = probeSSH(ctx, conn, target)
	case 25, 587, 465: // SMTP
		protocol, version, _ = probeSMTP(ctx, conn, target)
	case 443, 8443: // HTTPS
		protocol, version, _, tlsSupported, tlsCipher = probeTLS(ctx, conn, target)
	case 80, 8080, 8000: // HTTP
		protocol, version, _ = probeHTTP(ctx, conn, target)
	case 6379: // Redis
		protocol, version, _ = probeRedis(ctx, conn, target)
	}

	return banner, protocol, version, tlsSupported, tlsCipher
}

func probeSSH(ctx context.Context, conn net.Conn, target string) (string, string, string) {
	// SSH banner is typically sent immediately on connect
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", "", ""
	}
	raw := string(buf[:n])
	// SSH banner format: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
	if strings.HasPrefix(raw, "SSH-") {
		parts := strings.Split(raw, "-")
		if len(parts) >= 3 {
			version := strings.Join(parts[2:], "-")
			return "SSH", strings.TrimSpace(version), "SSH banner: " + strings.TrimSpace(raw)
		}
		return "SSH", "", "SSH banner: " + strings.TrimSpace(raw)
	}
	return "", "", ""
}

func probeSMTP(ctx context.Context, conn net.Conn, target string) (string, string, string) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Send EHLO
	_, err := fmt.Fprintf(conn, "EHLO %s\r\n", target)
	if err != nil {
		return "", "", ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", "", ""
	}
	raw := string(buf[:n])
	// Parse EHLO response for version
	lines := strings.Split(raw, "\n")
	var version string
	for _, line := range lines {
		if strings.HasPrefix(line, "220 ") || strings.HasPrefix(line, "250 ") {
			if version == "" {
				version = strings.TrimSpace(line)
			}
		}
	}
	return "SMTP", version, "SMTP EHLO response: " + strings.TrimSpace(raw)
}

func probeTLS(ctx context.Context, conn net.Conn, target string) (string, string, string, bool, string) {
	// Perform TLS handshake to get version and cipher
	tlsConfig := &tls.Config{
		ServerName:         target,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	err := tlsConn.HandshakeContext(ctx)
	if err != nil {
		return "", "", "", false, ""
	}
	defer tlsConn.Close()
	state := tlsConn.ConnectionState()
	version := tlsVersionName(state.Version)
	cipher := tls.CipherSuiteName(state.CipherSuite)
	return "TLS", version, "TLS " + version + " " + cipher, true, cipher
}

func probeHTTP(ctx context.Context, conn net.Conn, target string) (string, string, string) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Send OPTIONS request
	_, err := fmt.Fprintf(conn, "OPTIONS * HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	if err != nil {
		return "", "", ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", "", ""
	}
	raw := string(buf[:n])
	// Parse response for Server header and Allow header
	var server, allow string
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line)
		}
		if strings.HasPrefix(strings.ToLower(line), "allow:") {
			allow = strings.TrimSpace(line)
		}
	}
	details := "HTTP OPTIONS response"
	if server != "" {
		details += "; " + server
	}
	if allow != "" {
		details += "; " + allow
	}
	return "HTTP", server, details
}

func probeRedis(ctx context.Context, conn net.Conn, target string) (string, string, string) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Send PING command (Redis protocol: *1\r\n$4\r\nPING\r\n)
	_, err := fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n")
	if err != nil {
		return "", "", ""
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", "", ""
	}
	raw := string(buf[:n])
	// Redis PONG response: +PONG\r\n
	if strings.Contains(raw, "PONG") {
		return "Redis", "PONG", "Redis PING: +PONG"
	}
	return "Redis", "", "Redis response: " + strings.TrimSpace(raw)
}

func normalizePortScanTarget(raw string) (string, error) {
	for _, char := range raw {
		if unicode.IsControl(char) {
			return "", fmt.Errorf("target must not contain control characters")
		}
	}
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", fmt.Errorf("target is required")
	}
	for _, char := range target {
		if char > unicode.MaxASCII {
			return "", fmt.Errorf("use an ASCII hostname (IDN names must be written in punycode)")
		}
	}
	if address, err := netip.ParseAddr(target); err == nil {
		return address.String(), nil
	}
	if strings.ContainsAny(target, ":[]/?#@\\") || strings.ContainsAny(target, " \t") {
		return "", fmt.Errorf("enter a bare IP address or hostname without a URL, brackets, or port")
	}

	target = strings.ToLower(target)
	hostname := strings.TrimSuffix(target, ".")
	if hostname == "" || len(hostname) > 253 {
		return "", fmt.Errorf("hostname must contain between 1 and 253 characters")
	}
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("hostname labels must contain between 1 and 63 characters")
		}
		for i, char := range label {
			valid := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-'
			if !valid || char == '-' && (i == 0 || i == len(label)-1) {
				return "", fmt.Errorf("hostname labels may use letters, digits, and internal hyphens only")
			}
		}
	}
	allNumeric := true
	for _, label := range labels {
		for _, char := range label {
			if char < '0' || char > '9' {
				allNumeric = false
				break
			}
		}
	}
	if allNumeric {
		return "", fmt.Errorf("numeric-only target is not a valid IPv4 address or hostname")
	}
	return target, nil
}

func (a *App) StartPortScan(target string, startPort, endPort, workers, timeoutMs int, scopeConfirmed bool) string {
	if a == nil {
		return "Scanner unavailable"
	}
	var err error
	target, err = normalizePortScanTarget(target)
	if err != nil {
		return err.Error()
	}
	if !scopeConfirmed {
		return "Confirm authorization for this target and port range before scanning"
	}
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return "Invalid port range (1-65535)"
	}
	workers, timeout := normalizePortScanLimits(endPort-startPort+1, workers, timeoutMs)

	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	a.scanMu.Lock()
	if a.activeScan != nil {
		a.scanMu.Unlock()
		cancel()
		return "A scan is already running or stopping"
	}
	a.nextScanID++
	scan := &portScan{id: a.nextScanID, ctx: ctx, cancel: cancel, done: make(chan struct{}), status: scanStatusRunning}
	a.activeScan = scan
	a.scanMu.Unlock()

	a.emitScanEvent("scan:status", string(scanStatusRunning))
	go a.runPortScan(scan, target, startPort, endPort, workers, timeout)
	return "STARTED"
}

func normalizePortScanLimits(totalPorts, workers, timeoutMs int) (int, time.Duration) {
	if workers <= 0 {
		workers = defaultScanWorkers
	}
	if workers > maxScanWorkers {
		workers = maxScanWorkers
	}
	if totalPorts > 0 && workers > totalPorts {
		workers = totalPorts
	}
	if timeoutMs <= 0 {
		timeoutMs = defaultScanTimeout
	}
	if timeoutMs > maxScanTimeout {
		timeoutMs = maxScanTimeout
	}
	return workers, time.Duration(timeoutMs) * time.Millisecond
}

func (a *App) emitScanEvent(event string, data any) {
	if a != nil && a.ctx != nil {
		runtime.EventsEmit(a.ctx, event, data)
	}
}

type scanTargetResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func resolveScanTarget(ctx context.Context, target string, resolver scanTargetResolver) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(target); err == nil {
		return ip.String(), nil
	}
	addresses, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		return "", fmt.Errorf("resolve target: %w", err)
	}
	return selectScanAddress(addresses)
}

func selectScanAddress(addresses []net.IPAddr) (string, error) {
	valid := make([]net.IPAddr, 0, len(addresses))
	for _, address := range addresses {
		if address.IP.To16() != nil {
			valid = append(valid, address)
		}
	}
	if len(valid) == 0 {
		return "", fmt.Errorf("hostname has no usable IP addresses")
	}
	sort.Slice(valid, func(i, j int) bool {
		left4, right4 := valid[i].IP.To4(), valid[j].IP.To4()
		if (left4 != nil) != (right4 != nil) {
			return left4 != nil
		}
		left, right := valid[i].IP.To16(), valid[j].IP.To16()
		if left4 != nil {
			left, right = left4, right4
		}
		if order := bytes.Compare(left, right); order != 0 {
			return order < 0
		}
		return valid[i].Zone < valid[j].Zone
	})
	return valid[0].String(), nil
}

func (a *App) runPortScan(scan *portScan, target string, startPort, endPort, workers int, timeout time.Duration) {
	totalPorts := endPort - startPort + 1
	var scannedCount int64
	var wg sync.WaitGroup
	var findingsMu sync.Mutex
	var scanFindings []PortFinding
	ports := make(chan int, workers)
	dialer := &net.Dialer{Timeout: timeout}

	status := scanStatusCompleted
	defer func() {
		if recovered := recover(); recovered != nil {
			status = scanStatusFailed
			log.Printf("Codexa Scanner: port scan %d failed: %v", scan.id, recovered)
		}
		if scan.ctx.Err() != nil && status != scanStatusFailed {
			status = scanStatusCancelled
		}
		if status == scanStatusCompleted {
			findingsMu.Lock()
			snapshot := append([]PortFinding(nil), scanFindings...)
			findingsMu.Unlock()
			if err := a.saveHistory("port", target, snapshot, 0); err != nil {
				log.Printf("Codexa Scanner: saving port scan history: %v", err)
			}
		}
		scan.status = status
		scan.cancel()
		a.emitScanEvent("scan:status", string(status))
		a.emitScanEvent("scan:done", string(status))
		a.scanMu.Lock()
		if a.activeScan == scan {
			a.activeScan = nil
		}
		a.scanMu.Unlock()
		close(scan.done)
	}()

	resolveCtx, cancelResolve := context.WithTimeout(scan.ctx, scanResolveTimeout)
	resolvedTarget, err := resolveScanTarget(resolveCtx, target, net.DefaultResolver)
	cancelResolve()
	if err != nil {
		if scan.ctx.Err() != nil {
			status = scanStatusCancelled
		} else {
			status = scanStatusFailed
			a.emitScanEvent("scan:error", fmt.Sprintf("Could not resolve %q: %v", target, err))
		}
		return
	}
	a.emitScanEvent("scan:target", resolvedTarget)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				if scan.ctx.Err() != nil {
					return
				}
				address := net.JoinHostPort(resolvedTarget, strconv.Itoa(port))
conn, err := dialer.DialContext(scan.ctx, "tcp", address)
			if err == nil {
				banner, protocol, version, tlsSupported, tlsCipher := grabBannerWithProtocol(scan.ctx, conn, target, port)
				svc := commonPorts[port]
				if svc == "" {
					svc = "unknown"
				}
				finding := PortFinding{
					Port:         port,
					Service:      svc,
					Banner:       banner,
					Protocol:     protocol,
					Version:      version,
					TLSSupported: tlsSupported,
					TLSCipher:    tlsCipher,
				}
				findingsMu.Lock()
				scanFindings = append(scanFindings, finding)
				findingsMu.Unlock()
				a.emitScanEvent("port:found", finding)
			}

				curr := atomic.AddInt64(&scannedCount, 1)
				if scan.ctx.Err() == nil && (curr%25 == 0 || int(curr) == totalPorts) {
					pct := int((float64(curr) / float64(totalPorts)) * 100)
					a.emitScanEvent("scan:progress", pct)
				}
			}
		}()
	}

Loop:
	for port := startPort; port <= endPort; port++ {
		select {
		case <-scan.ctx.Done():
			break Loop
		case ports <- port:
		}
	}
	close(ports)
	wg.Wait()
}

func (a *App) StopPortScan() {
	if a == nil {
		return
	}
	a.scanMu.Lock()
	scan := a.activeScan
	a.scanMu.Unlock()
	if scan != nil {
		scan.cancel()
	}
}

// CIDRSweepResult contains results for a /24 CIDR port sweep.
type CIDRSweepResult struct {
	CIDR      string           `json:"cidr"`
	Hosts     []CIDRHostResult `json:"hosts"`
	Error     string           `json:"error,omitempty"`
	Scanned   int              `json:"scanned"`
	LiveHosts int              `json:"liveHosts"`
}

// CIDRHostResult contains port scan results for a single host in a CIDR sweep.
type CIDRHostResult struct {
	IP              string          `json:"ip"`
	Hostname        string          `json:"hostname,omitempty"`
	Ports           []PortFinding   `json:"ports,omitempty"`
	Error           string          `json:"error,omitempty"`
	AdvisoryMatches []AdvisoryMatch `json:"advisoryMatches,omitempty"`
}

// internal type for collecting sweep results
type cidrHostResult struct {
	ip              string
	hostname        string
	ports           []PortFinding
	err             string
	advisoryMatches []AdvisoryMatch
}

// StartCIDRSweep starts a bounded /24 CIDR port sweep with explicit scope confirmation.
func (a *App) StartCIDRSweep(cidr string, startPort, endPort, workers, timeoutMs int, scopeConfirmed bool, rps, jitterMs int) string {
	if a == nil {
		return "Scanner unavailable"
	}
	// Validate CIDR is IPv4 /24
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "Invalid CIDR notation (e.g., 192.168.1.0/24)"
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones != 24 {
		return "Only IPv4 /24 CIDR ranges are supported for sweep"
	}
	// Ensure it's a network address (host bits zero)
	if !ipNet.IP.Equal(ipNet.IP.Mask(ipNet.Mask)) {
		return "CIDR must be a network address (host bits zero), e.g., 192.168.1.0/24"
	}
	// Validate ports
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return "Invalid port range (1-65535)"
	}
	if !scopeConfirmed {
		return "Confirm authorization for this CIDR range and port range before sweeping"
	}
	workers, timeout := normalizePortScanLimits(endPort-startPort+1, workers, timeoutMs)

	rate := ScanRateControl{RPS: rps, JitterMs: jitterMs}.normalized()

	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	a.scanMu.Lock()
	if a.activeScan != nil {
		a.scanMu.Unlock()
		cancel()
		return "A scan is already running or stopping"
	}
	a.nextScanID++
	scan := &portScan{id: a.nextScanID, ctx: ctx, cancel: cancel, done: make(chan struct{}), status: scanStatusRunning}
	a.activeScan = scan
	a.scanMu.Unlock()

	a.emitScanEvent("scan:status", string(scanStatusRunning))
	go a.runCIDRSweep(scan, cidr, startPort, endPort, workers, timeout, rate)
	return "STARTED"
}

func (a *App) runCIDRSweep(scan *portScan, cidr string, startPort, endPort, workers int, timeout time.Duration, rate ScanRateControl) {
	_, ipNet, _ := net.ParseCIDR(cidr)
	// Generate all IPs in the /24
	baseIP := ipNet.IP.To4()
	if baseIP == nil {
		a.emitScanEvent("scan:error", "Invalid IPv4 CIDR")
		a.finishCIDRSweep(scan, cidr, scanStatusFailed, nil)
		return
	}

	totalIPs := 256
	portsPerHost := endPort - startPort + 1
	totalPortChecks := int64(totalIPs * portsPerHost)
	var scannedCount int64
	var liveHosts int64

	// Result collection
	results := make([]cidrHostResult, 0, totalIPs)
	var resultsMu sync.Mutex

	dialer := &net.Dialer{Timeout: timeout}

	// Host-level worker pool
	hostChan := make(chan uint8, workers)
	var wg sync.WaitGroup

	status := scanStatusCompleted
	defer func() {
		if recovered := recover(); recovered != nil {
			status = scanStatusFailed
			log.Printf("Codexa Scanner: CIDR sweep %d failed: %v", scan.id, recovered)
		}
		if scan.ctx.Err() != nil && status != scanStatusFailed {
			status = scanStatusCancelled
		}
		a.finishCIDRSweep(scan, cidr, status, results)
	}()

	a.emitScanEvent("scan:target", cidr)

	// Start host workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for hostOffset := range hostChan {
				if scan.ctx.Err() != nil {
					return
				}
				// Check pause
				a.waitIfPaused(scan.ctx)

				ip := make(net.IP, 4)
				copy(ip, baseIP)
				ip[3] = hostOffset
				ipStr := ip.String()

				// Quick host alive check on first port
				firstPortAddr := net.JoinHostPort(ipStr, strconv.Itoa(startPort))
				conn, err := dialer.DialContext(scan.ctx, "tcp", firstPortAddr)
				hostAlive := err == nil
				if conn != nil {
					conn.Close()
				}

				if !hostAlive {
					// Still count as scanned for progress
					curr := atomic.AddInt64(&scannedCount, int64(portsPerHost))
					if scan.ctx.Err() == nil {
						pct := int((float64(curr) / float64(totalPortChecks)) * 100)
						a.emitScanEvent("scan:progress", pct)
					}
					continue
				}

				atomic.AddInt64(&liveHosts, 1)

				// Try reverse DNS lookup (best effort)
				hostname := ""
				ctxResolve, cancelResolve := context.WithTimeout(scan.ctx, 2*time.Second)
				if names, err := net.DefaultResolver.LookupAddr(ctxResolve, ipStr); err == nil && len(names) > 0 {
					hostname = strings.TrimSuffix(names[0], ".")
				}
				cancelResolve()

// Scan ports on this live host
			var hostPorts []PortFinding
			var lastRate time.Time
			for port := startPort; port <= endPort; port++ {
				if scan.ctx.Err() != nil {
					break
				}
				var ok bool
				lastRate, ok = a.waitForRateSlot(scan.ctx, lastRate, rate)
				if !ok {
					break
				}

address := net.JoinHostPort(ipStr, strconv.Itoa(port))
					conn, err := dialer.DialContext(scan.ctx, "tcp", address)
					if err == nil {
						banner, protocol, version, tlsSupported, tlsCipher := grabBannerWithProtocol(scan.ctx, conn, ipStr, port)
						svc := commonPorts[port]
						if svc == "" {
							svc = "unknown"
						}
						finding := PortFinding{
							Port:         port,
							Service:      svc,
							Banner:       banner,
							Protocol:     protocol,
							Version:      version,
							TLSSupported: tlsSupported,
							TLSCipher:    tlsCipher,
						}
						hostPorts = append(hostPorts, finding)
						a.emitScanEvent("port:found", finding)
						conn.Close()
					}

					curr := atomic.AddInt64(&scannedCount, 1)
					if scan.ctx.Err() == nil && (curr%25 == 0 || curr == totalPortChecks) {
						pct := int((float64(curr) / float64(totalPortChecks)) * 100)
						a.emitScanEvent("scan:progress", pct)
					}
				}

				resultsMu.Lock()
				// Collect advisory matches from banners
				var advisoryMatches []AdvisoryMatch
				for _, pf := range hostPorts {
					if pf.Banner != "" {
						matches := collectAdvisoryMatches(pf.Banner, "", "", nil, "", "")
						advisoryMatches = append(advisoryMatches, matches...)
					}
				}
				// Deduplicate advisory matches
				seenAdv := make(map[string]bool)
				var uniqueAdv []AdvisoryMatch
				for _, am := range advisoryMatches {
					key := am.Product + ":" + am.DetectedVersion + ":" + am.Source
					if !seenAdv[key] {
						seenAdv[key] = true
						uniqueAdv = append(uniqueAdv, am)
					}
				}
				results = append(results, cidrHostResult{ip: ipStr, hostname: hostname, ports: hostPorts, advisoryMatches: uniqueAdv})
				resultsMu.Unlock()
			}
		}()
	}

	// Feed host offsets to workers
	for offset := 0; offset < 256; offset++ {
		select {
		case <-scan.ctx.Done():
			break
		case hostChan <- uint8(offset):
		}
	}
	close(hostChan)
	wg.Wait()

	// Sort results by IP
	sort.Slice(results, func(i, j int) bool {
		ip1 := net.ParseIP(results[i].ip).To4()
		ip2 := net.ParseIP(results[j].ip).To4()
		return bytes.Compare(ip1, ip2) < 0
	})
}

func (a *App) finishCIDRSweep(scan *portScan, cidr string, status scanStatus, results []cidrHostResult) {
	var sweepResult CIDRSweepResult
	if results != nil {
		sweepResult = CIDRSweepResult{
			CIDR:  cidr,
			Hosts: make([]CIDRHostResult, 0, len(results)),
		}
		for _, r := range results {
			sweepResult.Hosts = append(sweepResult.Hosts, CIDRHostResult{
				IP:              r.ip,
				Hostname:        r.hostname,
				Ports:           r.ports,
				Error:           r.err,
				AdvisoryMatches: r.advisoryMatches,
			})
		}
		sweepResult.Scanned = len(results)
		for _, h := range sweepResult.Hosts {
			if len(h.Ports) > 0 {
				sweepResult.LiveHosts++
			}
		}
	}

	if status == scanStatusCompleted {
		if err := a.saveHistory("cidr-sweep", cidr, sweepResult, 0); err != nil {
			log.Printf("Codexa Scanner: saving CIDR sweep history: %v", err)
		}
	}

	scan.status = status
	scan.cancel()
	a.emitScanEvent("scan:status", string(status))
	a.emitScanEvent("scan:done", string(status))
	a.emitScanEvent("cidr:sweep-done", sweepResult)
	a.scanMu.Lock()
	if a.activeScan == scan {
		a.activeScan = nil
	}
	a.scanMu.Unlock()
	close(scan.done)
}

// ==========================================
// 2. BULK HTTP SECURITY & TECH ANALYZER
// ==========================================

type BulkHeaderResult struct {
	URL             string                `json:"url"`
	FinalURL        string                `json:"finalUrl"`
	Assessment      string                `json:"assessment,omitempty"`
	Redirects       []RedirectHop         `json:"redirects,omitempty"`
	StatusCode      int                   `json:"statusCode"`
	Title           string                `json:"title"`
	Server          string                `json:"server"`
	PoweredBy       string                `json:"poweredBy"`
	Technologies    []string              `json:"technologies"`
	EdgeServices    []string              `json:"edgeServices"`
	Grade           string                `json:"grade"`
	RiskScore       int                   `json:"riskScore"`
	Missing         []string              `json:"missing"`
	Present         map[string]string     `json:"present"`
	TLS             *TLSDetails           `json:"tls,omitempty"`
	SecurityTxt     *WebResourceInspector `json:"securityTxt,omitempty"`
	RobotsTxt       *WebResourceInspector `json:"robotsTxt,omitempty"`
	GraphQL         *WebResourceInspector `json:"graphql,omitempty"`
	Swagger         *WebResourceInspector `json:"swagger,omitempty"`
	OpenAPI         *WebResourceInspector `json:"openapi,omitempty"`
	CloudStorage    []CloudStorageFinding `json:"cloudStorage,omitempty"`
	RateLimitAudit  *RateLimitAuditResult `json:"rateLimitAudit,omitempty"`
	WebhookOAuth    *WebhookOAuthAudit    `json:"webhookOAuth,omitempty"`
	AttackSurface   *AttackSurfaceSummary `json:"attackSurface,omitempty"`
	ClientSideAudit *ClientSideAudit      `json:"clientSideAudit,omitempty"`
	Findings        []SecurityFinding     `json:"findings"`
	AdvisoryMatches []AdvisoryMatch       `json:"advisoryMatches,omitempty"`
	Error           string                `json:"error"`
}

type WebResourceInspector struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
	Found      bool   `json:"found"`
	Body       string `json:"body,omitempty"`
	Error      string `json:"error,omitempty"`
	Note       string `json:"note,omitempty"`
}

// CloudStorageFinding captures publicly listable cloud storage bucket exposure.
type CloudStorageFinding struct {
	URL           string `json:"url"`
	Provider      string `json:"provider"`
	Bucket        string `json:"bucket,omitempty"`
	Listable      bool   `json:"listable"`
	StatusCode    int    `json:"statusCode"`
	Error         string `json:"error,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
}

// RateLimitAuditResult captures rate-limiting and cache-control header posture.
type RateLimitAuditResult struct {
	HasRateLimitHeaders  bool   `json:"hasRateLimitHeaders"`
	RateLimitHeaders     string `json:"rateLimitHeaders,omitempty"`
	HasRetryAfter        bool   `json:"hasRetryAfter"`
	RetryAfter           string `json:"retryAfter,omitempty"`
	CacheControl         string `json:"cacheControl,omitempty"`
	MissingNoStore       bool   `json:"missingNoStore"`
	IsSensitiveEndpoint  bool   `json:"isSensitiveEndpoint"`
	Note                 string `json:"note,omitempty"`
}

// WebhookOAuthAudit captures exposed webhook URLs and OAuth configuration parameters.
type WebhookOAuthAudit struct {
	Webhooks []WebhookFinding `json:"webhooks,omitempty"`
	OAuth    []OAuthFinding   `json:"oauth,omitempty"`
}

type WebhookFinding struct {
	Platform  string `json:"platform"`
	URL       string `json:"url"`
	Redacted  string `json:"redacted"`
	Note      string `json:"note,omitempty"`
}

type OAuthFinding struct {
	Parameter string `json:"parameter"`
	Value     string `json:"value,omitempty"`
	Redacted  string `json:"redacted"`
	Context   string `json:"context,omitempty"`
	Note      string `json:"note,omitempty"`
}

// AttackSurfaceSummary captures passive page form, parameter, and storage surface mapping.
type AttackSurfaceSummary struct {
	Forms            []FormFinding     `json:"forms,omitempty"`
	QueryParameters  []QueryParamFinding `json:"queryParameters,omitempty"`
	ThirdPartyScripts []ScriptOriginFinding `json:"thirdPartyScripts,omitempty"`
	StorageKeys      []StorageKeyFinding `json:"storageKeys,omitempty"`
}

type FormFinding struct {
	Action   string   `json:"action"`
	Method   string   `json:"method"`
	Inputs   []InputFinding `json:"inputs,omitempty"`
	IsLogin  bool     `json:"isLogin"`
	Context  string   `json:"context,omitempty"`
}

type InputFinding struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Autocomplete string `json:"autocomplete,omitempty"`
}

type QueryParamFinding struct {
	Name   string `json:"name"`
	Source string `json:"source"` // "url", "form", "js"
}

type ScriptOriginFinding struct {
	Origin      string `json:"origin"`
	IsThirdParty bool  `json:"isThirdParty"`
	URL         string `json:"url"`
}

type StorageKeyFinding struct {
	Type   string `json:"type"` // "localStorage", "sessionStorage"
	Key    string `json:"key"`
	Source string `json:"source"` // "js", "html"
}

// ClientSideClue captures bounded, redacted client-side exposure indicators.
type ClientSideClue struct {
	Kind       string `json:"kind"`
	Value      string `json:"value,omitempty"`
	Context    string `json:"context,omitempty"`
	ScriptURL  string `json:"scriptUrl,omitempty"`
	Line       int    `json:"line,omitempty"`
	Note       string `json:"note,omitempty"`
	Reachable  *bool  `json:"reachable,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
}

// ClientSideAudit summarizes bounded passive JS/bundle and parameter reflection checks.
type ClientSideAudit struct {
	ScriptsFetched      int              `json:"scriptsFetched"`
	ScriptsScanned      int              `json:"scriptsScanned"`
	Truncated           bool             `json:"truncated,omitempty"`
	SecretFindings      []ClientSideClue `json:"secretFindings,omitempty"`
	SourceMapClues      []ClientSideClue `json:"sourceMapClues,omitempty"`
	EndpointClues       []ClientSideClue `json:"endpointClues,omitempty"`
	DOMSinks            []ClientSideClue `json:"domSinks,omitempty"`
	ReflectedParamProbe *ClientSideClue  `json:"reflectedParamProbe,omitempty"`
	Notes               []string         `json:"notes,omitempty"`
}

type RedirectHop struct {
	From       string `json:"from"`
	To         string `json:"to"`
	StatusCode int    `json:"statusCode"`
}

type TLSDetails struct {
	Version             string    `json:"version"`
	CipherSuite         string    `json:"cipherSuite"`
	Subject             string    `json:"subject"`
	Issuer              string    `json:"issuer"`
	ExpiresAt           time.Time `json:"expiresAt"`
	DaysRemaining       int       `json:"daysRemaining"`
	Verified            bool      `json:"verified"`
	VerificationSummary string    `json:"verificationSummary,omitempty"`
	ChainSubjects       []string  `json:"chainSubjects,omitempty"`
	NotBefore           time.Time `json:"notBefore,omitempty"`
	SANCount            int       `json:"sanCount,omitempty"`
}

type SecurityFinding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Evidence       string `json:"evidence,omitempty"`
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
var mixedContentRegex = regexp.MustCompile(`(?i)(?:src|poster)\s*=\s*["']http://`)
var scriptSrcRegex = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`)
var sourceMapRegex = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)
var domSinkRegex = regexp.MustCompile(`\b(dangerouslySetInnerHTML|innerHTML|outerHTML|document\.write|eval)\b`)
var apiPathRegex = regexp.MustCompile(`(?i)(?:^|["'\(\s])(/(?:api|v1|v2|v3|trpc|graphql)(?:/[A-Za-z0-9._~\-/%]*)?)`)
var baasHostRegex = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.supabase\.co|[a-z0-9-]+\.firebaseio\.com|[a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.\-]+)\b`)

const (
	webAuditAssessmentLabel       = "Bounded active HTTP requests (main GET, redirects, resource inspectors, and optional bounded client-side probes) with passive response analysis"
	maxClientScripts              = 5
	maxClientScriptBytes    int64 = 512 * 1024
	reflectedProbeMarker          = "codexa_probe_123"
)

func (a *App) PauseScans() {
	if a == nil {
		return
	}
	a.rateMu.Lock()
	a.scanPaused = true
	a.rateMu.Unlock()
	a.emitScanControl("paused")
}

func (a *App) ResumeScans() {
	if a == nil {
		return
	}
	a.rateMu.Lock()
	a.scanPaused = false
	if a.pauseCond != nil {
		a.pauseCond.Broadcast()
	}
	a.rateMu.Unlock()
	a.emitScanControl("running")
}

func (a *App) emitScanControl(state string) {
	if a != nil && a.ctx != nil {
		runtime.EventsEmit(a.ctx, "scan:control", state)
	}
}

func (a *App) IsScansPaused() bool {
	if a == nil {
		return false
	}
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	return a.scanPaused
}

func (a *App) waitIfPaused(ctx context.Context) bool {
	if a == nil {
		return true
	}
	for {
		a.rateMu.Lock()
		paused := a.scanPaused
		a.rateMu.Unlock()
		if !paused {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (a *App) waitForRateSlot(ctx context.Context, last time.Time, rc ScanRateControl) (time.Time, bool) {
	rc = rc.normalized()
	if !a.waitIfPaused(ctx) {
		return last, false
	}
	delay := time.Duration(0)
	if rc.RPS > 0 {
		interval := time.Second / time.Duration(rc.RPS)
		if !last.IsZero() {
			next := last.Add(interval)
			if now := time.Now(); next.After(now) {
				delay = next.Sub(now)
			}
		}
	}
	if rc.JitterMs > 0 {
		delay += time.Duration(rand.Intn(rc.JitterMs+1)) * time.Millisecond
	}
	if delay > 0 {
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return last, false
		case <-t.C:
		}
	}
	if !a.waitIfPaused(ctx) {
		return time.Now(), false
	}
	return time.Now(), true
}

func parseTargetRules(raw string) []string {
	var rules []string
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 64*1024)
	seen := map[string]bool{}
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if u, err := url.Parse(line); err == nil && u.Hostname() != "" {
			line = u.Hostname()
		}
		line = strings.Trim(strings.ToLower(line), ".")
		if line == "" || strings.ContainsAny(line, "/\\\r\n") || seen[line] {
			continue
		}
		seen[line] = true
		rules = append(rules, line)
	}
	return rules
}

func targetMatchesRule(rawTarget string, rule string) bool {
	u, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.Trim(strings.ToLower(u.Hostname()), ".")
	rule = strings.Trim(strings.ToLower(rule), ".")
	if strings.HasPrefix(rule, "*.") {
		return strings.HasSuffix(host, rule[1:]) && host != strings.TrimPrefix(rule, "*.")
	}
	return host == rule
}

func filterBulkTargets(rawInput, scopeInput, excludeInput string) []string {
	scopeRules := parseTargetRules(scopeInput)
	excludeRules := parseTargetRules(excludeInput)
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(rawInput))
	scanner.Buffer(make([]byte, 1024), 64*1024)
	seen := map[string]bool{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		if len(scopeRules) > 0 {
			inScope := false
			for _, rule := range scopeRules {
				if targetMatchesRule(line, rule) {
					inScope = true
					break
				}
			}
			if !inScope {
				continue
			}
		}
		excluded := false
		for _, rule := range excludeRules {
			if targetMatchesRule(line, rule) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		seen[line] = true
		urls = append(urls, line)
		if len(urls) >= 100 {
			break
		}
	}
	return urls
}

func (a *App) AnalyzeBulkURLs(rawInput string, concurrency int, allowPrivateTargets bool, requestDelayMs int, rps int, jitterMs int, userAgent string, timeoutSeconds int, customHeaders map[string]string, proxyURL string, scopeInput string, excludeInput string, customRules *CustomRulesFile) []BulkHeaderResult {
	urls := filterBulkTargets(rawInput, scopeInput, excludeInput)

	if len(urls) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > 20 {
		concurrency = 20
	}
	if requestDelayMs < 0 {
		requestDelayMs = 0
	}
	if requestDelayMs > 5000 {
		requestDelayMs = 5000
	}
	rate := ScanRateControl{RPS: rps, JitterMs: jitterMs}.normalized()
	profile := resolveHTTPRequestProfile(HTTPRequestProfile{UserAgent: userAgent, TimeoutSeconds: timeoutSeconds, CustomHeaders: customHeaders, ProxyURL: proxyURL})

	secHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	results := make([]BulkHeaderResult, len(urls))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	var gateMu sync.Mutex
	var last time.Time
	nextSlot := func() bool {
		gateMu.Lock()
		defer gateMu.Unlock()
		t, ok := a.waitForRateSlot(ctx, last, rate)
		last = t
		return ok
	}

	for idx, rawURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			if !nextSlot() {
				inputURL := analysisURLForDisplay(target)
				results[i] = BulkHeaderResult{URL: inputURL, FinalURL: inputURL, Assessment: webAuditAssessmentLabel, Redirects: []RedirectHop{}, Error: "Scan paused/stopped before request"}
				return
			}
			if requestDelayMs > 0 {
				select {
				case <-ctx.Done():
					inputURL := analysisURLForDisplay(target)
					results[i] = BulkHeaderResult{URL: inputURL, FinalURL: inputURL, Assessment: webAuditAssessmentLabel, Redirects: []RedirectHop{}, Error: "Scan stopped"}
					return
				case <-time.After(time.Duration(requestDelayMs) * time.Millisecond):
				}
			}
			client, err := newScopedHTTPClientWithProfile(target, allowPrivateTargets, net.DefaultResolver, profile)
			if err != nil {
				inputURL := analysisURLForDisplay(target)
				results[i] = BulkHeaderResult{URL: inputURL, FinalURL: inputURL, Assessment: webAuditAssessmentLabel, Redirects: []RedirectHop{}, Error: err.Error()}
				return
			}
			results[i] = analyzeURL(target, client, secHeaders, profile, customRules)
			client.CloseIdleConnections()
		}(idx, rawURL)
	}

	wg.Wait()
	for _, res := range results {
		targetKey := res.URL
		if targetKey == "" {
			targetKey = res.FinalURL
		}
		targetKey = redactHistoryTarget(targetKey)
		if targetKey != "" {
			if err := a.saveHistory("http", targetKey, res, 0); err != nil {
				log.Printf("Codexa Scanner: saving HTTP target history: %v", err)
			}
		}
	}
	if err := a.saveHistory("http-bulk", fmt.Sprintf("bulk HTTP (%d targets)", len(urls)), results, 0); err != nil {
		log.Printf("Codexa Scanner: saving HTTP scan history: %v", err)
	}
	return results
}

func analyzeURL(target string, client *http.Client, secHeaders []string, profile HTTPRequestProfile, customRules *CustomRulesFile) BulkHeaderResult {
	inputURL, parsed, _, err := parseHTTPAnalysisURL(target)
	if err != nil {
		return BulkHeaderResult{URL: inputURL, Assessment: webAuditAssessmentLabel, Redirects: []RedirectHop{}, Error: err.Error()}
	}
	result := BulkHeaderResult{URL: inputURL, FinalURL: inputURL, Assessment: webAuditAssessmentLabel, Redirects: []RedirectHop{}, Present: make(map[string]string), Findings: []SecurityFinding{}}
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		result.Error = "Invalid URL."
		result.Assessment = webAuditAssessmentLabel
		return result
	}
	ua := profile.resolvedUserAgent()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Origin", "https://probe.codexa.invalid")
	for name, value := range profile.CustomHeaders {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	result.Redirects = snapshotRedirectHops(client)
	if err != nil {
		result.Error = httpAnalysisErrorMessage(err)
		var certErr x509.UnknownAuthorityError
		var hostnameErr x509.HostnameError
		var invalidErr x509.CertificateInvalidError
		switch {
		case errors.As(err, &certErr):
			result.Findings = append(result.Findings, SecurityFinding{ID: "tls-untrusted", Severity: "high", Title: "TLS certificate is not trusted", Description: "The system trust store rejected the remote certificate.", Recommendation: "Install a certificate issued by a trusted CA and serve the complete certificate chain."})
		case errors.As(err, &hostnameErr):
			result.Findings = append(result.Findings, SecurityFinding{ID: "tls-hostname", Severity: "high", Title: "TLS certificate hostname mismatch", Description: "The certificate does not match the requested hostname.", Recommendation: "Issue and serve a certificate whose subject alternative names include this hostname."})
		case errors.As(err, &invalidErr):
			result.Findings = append(result.Findings, SecurityFinding{ID: "tls-invalid", Severity: "high", Title: "TLS certificate is invalid", Description: "The system trust store rejected the certificate validity or constraints.", Recommendation: "Renew or correctly configure the certificate and its chain."})
		}
		inspectBase := *parsed
		inspectBase.Path = ""
		inspectBase.RawPath = ""
		inspectBase.RawQuery = ""
		inspectBase.Fragment = ""
		result.SecurityTxt = inspectWebResource(client, &inspectBase, "/.well-known/security.txt", 8192, "", ua)
		result.RobotsTxt = inspectWebResource(client, &inspectBase, "/robots.txt", 8192, "robots.txt is discovery guidance, not a security control.", ua)
		result.GraphQL = inspectWebResource(client, &inspectBase, "/graphql", 4096, "GraphQL introspection endpoint; check if schema introspection is enabled.", ua)
		result.Swagger = inspectWebResource(client, &inspectBase, "/swagger.json", 8192, "Swagger/OpenAPI 2.0 spec endpoint; unauthenticated exposure may leak API structure.", ua)
		result.OpenAPI = inspectWebResource(client, &inspectBase, "/openapi.json", 8192, "OpenAPI 3.x spec endpoint; unauthenticated exposure may leak API structure.", ua)
		result.RiskScore, result.Grade = gradeFindings(result.Findings)
		return result
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	result.FinalURL = resp.Request.URL.String()
	result.StatusCode = resp.StatusCode
	if matches := titleRegex.FindSubmatch(bodyBytes); len(matches) > 1 {
		result.Title = strings.TrimSpace(string(matches[1]))
	}
	result.Server = resp.Header.Get("Server")
	result.PoweredBy = resp.Header.Get("X-Powered-By")
	result.Technologies, result.EdgeServices = fingerprintResponse(resp, bodyBytes)
	for _, h := range secHeaders {
		if value := resp.Header.Get(h); value == "" {
			result.Missing = append(result.Missing, h)
		} else {
			result.Present[h] = value
		}
	}
	result.Findings = auditHTTPResponse(resp, bodyBytes, customRules)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		verified := len(resp.TLS.VerifiedChains) > 0
		chainSubjects := make([]string, 0, len(resp.TLS.PeerCertificates))
		for _, peerCert := range resp.TLS.PeerCertificates {
			if peerCert == nil {
				continue
			}
			name := peerCert.Subject.CommonName
			if name == "" {
				name = peerCert.Subject.String()
			}
			chainSubjects = append(chainSubjects, name)
		}
		result.TLS = &TLSDetails{
			Version:             tlsVersionName(resp.TLS.Version),
			CipherSuite:         tls.CipherSuiteName(resp.TLS.CipherSuite),
			Subject:             cert.Subject.CommonName,
			Issuer:              cert.Issuer.CommonName,
			ExpiresAt:           cert.NotAfter,
			NotBefore:           cert.NotBefore,
			DaysRemaining:       days,
			Verified:            verified,
			VerificationSummary: tlsVerificationSummary(verified, resp.TLS.VerifiedChains),
			ChainSubjects:       chainSubjects,
			SANCount:            len(cert.DNSNames) + len(cert.IPAddresses) + len(cert.EmailAddresses) + len(cert.URIs),
		}
		if days <= 30 {
			severity := "medium"
			if days <= 7 {
				severity = "high"
			}
			result.Findings = append(result.Findings, SecurityFinding{ID: "tls-expiring", Severity: severity, Title: "TLS certificate expires soon", Description: fmt.Sprintf("The verified certificate expires in %d day(s).", days), Recommendation: "Renew the certificate before its expiry and verify automated renewal."})
		}
	}
	inspectBase := *resp.Request.URL
	inspectBase.Path = ""
	inspectBase.RawPath = ""
	inspectBase.RawQuery = ""
	inspectBase.Fragment = ""
	result.SecurityTxt = inspectWebResource(client, &inspectBase, "/.well-known/security.txt", 8192, "", ua)
	result.RobotsTxt = inspectWebResource(client, &inspectBase, "/robots.txt", 8192, "robots.txt is discovery guidance, not a security control.", ua)
	result.GraphQL = inspectWebResource(client, &inspectBase, "/graphql", 4096, "GraphQL introspection endpoint; check if schema introspection is enabled.", ua)
	result.Swagger = inspectWebResource(client, &inspectBase, "/swagger.json", 8192, "Swagger/OpenAPI 2.0 spec endpoint; unauthenticated exposure may leak API structure.", ua)
	result.OpenAPI = inspectWebResource(client, &inspectBase, "/openapi.json", 8192, "OpenAPI 3.x spec endpoint; unauthenticated exposure may leak API structure.", ua)

	// Generate findings for exposed API documentation endpoints
	if result.GraphQL != nil && result.GraphQL.Found {
		body := strings.ToLower(result.GraphQL.Body)
		if strings.Contains(body, "__schema") || strings.Contains(body, "introspection") || result.GraphQL.StatusCode == 200 {
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "graphql-introspection-enabled",
				Severity:       "medium",
				Title:          "GraphQL introspection endpoint accessible",
				Description:    "The /graphql endpoint responded and may allow schema introspection. This can expose the full API schema to unauthenticated users.",
				Recommendation: "Disable introspection in production or restrict access to authenticated/authorized users only.",
				Evidence:       "GET " + result.GraphQL.URL + " returned " + strconv.Itoa(result.GraphQL.StatusCode),
			})
		}
	}
	if result.Swagger != nil && result.Swagger.Found && result.Swagger.StatusCode == 200 {
		result.Findings = append(result.Findings, SecurityFinding{
			ID:             "swagger-spec-exposed",
			Severity:       "low",
			Title:          "Swagger/OpenAPI 2.0 specification publicly accessible",
			Description:    "The /swagger.json endpoint returned a 200 OK response, potentially exposing the full API specification without authentication.",
			Recommendation: "Restrict access to API documentation endpoints to authorized users or internal networks only.",
			Evidence:       "GET " + result.Swagger.URL + " returned 200 OK",
		})
	}
	if result.OpenAPI != nil && result.OpenAPI.Found && result.OpenAPI.StatusCode == 200 {
		result.Findings = append(result.Findings, SecurityFinding{
			ID:             "openapi-spec-exposed",
			Severity:       "low",
			Title:          "OpenAPI 3.x specification publicly accessible",
			Description:    "The /openapi.json endpoint returned a 200 OK response, potentially exposing the full API specification without authentication.",
			Recommendation: "Restrict access to API documentation endpoints to authorized users or internal networks only.",
			Evidence:       "GET " + result.OpenAPI.URL + " returned 200 OK",
		})
	}

	clientSide, csFindings := auditClientSideExposure(client, resp.Request.URL, bodyBytes, result.Findings, ua, customRules)
	if clientSide != nil {
		result.ClientSideAudit = clientSide
	}
	if len(csFindings) > 0 {
		result.Findings = append(result.Findings, csFindings...)
	}

	// Cloud storage bucket exposure audit
	cloudFindings := auditCloudStorageExposure(client, bodyBytes, resp.Request.URL, ua)
	if len(cloudFindings) > 0 {
		result.CloudStorage = cloudFindings
		for _, cf := range cloudFindings {
			severity := "info"
			titleSuffix := ""
			descSuffix := ""
			if cf.Listable {
				severity = "high"
				titleSuffix = " (publicly listable)"
				descSuffix = "The bucket allows public listing of objects."
			} else if cf.StatusCode == 200 {
				severity = "medium"
				titleSuffix = " (accessible)"
				descSuffix = "The bucket was accessible but listing was not confirmed."
			} else {
				descSuffix = "The bucket was referenced but not accessible."
			}
			evidence := "URL: " + cf.URL
			if cf.Evidence != "" {
				evidence += "; " + cf.Evidence
			}
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "cloud-storage-" + strings.ToLower(strings.ReplaceAll(cf.Provider, " ", "-")) + "-" + sanitizeIDFragment(cf.Bucket),
				Severity:       severity,
				Title:          cf.Provider + " bucket referenced" + titleSuffix,
				Description:    "A reference to " + cf.Provider + " bucket " + cf.Bucket + " was found in the response. " + descSuffix,
				Recommendation: cf.Remediation,
				Evidence:       evidence,
			})
		}
	}

	// Rate-limiting and cache-control header audit
	rateLimitAudit := auditRateLimitAndCacheControl(resp)
	if rateLimitAudit != nil {
		result.RateLimitAudit = rateLimitAudit
		if rateLimitAudit.IsSensitiveEndpoint {
			if !rateLimitAudit.HasRateLimitHeaders {
				result.Findings = append(result.Findings, SecurityFinding{
					ID:             "rate-limit-headers-missing",
					Severity:       "medium",
					Title:          "Rate-limit headers missing on sensitive endpoint",
					Description:    "The sensitive endpoint did not return standard rate-limiting headers (X-RateLimit-*, RateLimit-*, Retry-After). This makes it harder for clients to respect rate limits and increases abuse risk.",
					Recommendation: "Implement rate limiting and return appropriate headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After) on sensitive endpoints.",
					Evidence:       "Path: " + resp.Request.URL.Path + "; Headers checked: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, X-Rate-Limit-Limit, X-Rate-Limit-Remaining, X-Rate-Limit-Reset, Retry-After",
				})
			}
			if rateLimitAudit.MissingNoStore {
				result.Findings = append(result.Findings, SecurityFinding{
					ID:             "cache-control-no-store-missing",
					Severity:       "medium",
					Title:          "Cache-Control: no-store missing on sensitive response",
					Description:    "The sensitive response does not include Cache-Control: no-store, which may allow browsers or proxies to cache sensitive data.",
					Recommendation: "Add Cache-Control: no-store, no-cache, must-revalidate to sensitive responses to prevent caching.",
					Evidence:       "Path: " + resp.Request.URL.Path + "; Cache-Control: " + resp.Header.Get("Cache-Control"),
				})
			}
		}
	}

	// Webhook and OAuth posture audit
	scriptURLs := extractFirstPartyScriptURLs(resp.Request.URL, bodyBytes, maxClientScripts)
	webhookOAuth := auditWebhookAndOAuth(client, bodyBytes, resp.Request.URL, ua, scriptURLs)
	if webhookOAuth != nil && (len(webhookOAuth.Webhooks) > 0 || len(webhookOAuth.OAuth) > 0) {
		result.WebhookOAuth = webhookOAuth
		for _, wf := range webhookOAuth.Webhooks {
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "webhook-exposed-" + strings.ToLower(wf.Platform),
				Severity:       "high",
				Title:          wf.Platform + " webhook URL exposed in client-side code",
				Description:    "An exposed " + wf.Platform + " webhook URL was found in client-side JavaScript. This may allow unauthorized message sending or data exfiltration.",
				Recommendation: "Move webhook URLs to server-side code. Use server-side proxies with proper authentication and rate limiting.",
				Evidence:       "Redacted URL: " + wf.Redacted,
			})
		}
		for _, of := range webhookOAuth.OAuth {
			severity := "info"
			if of.Parameter == "client_secret" {
				severity = "high"
			} else if of.Parameter == "redirect_uri" {
				severity = "medium"
			}
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "oauth-param-" + of.Parameter,
				Severity:       severity,
				Title:          "OAuth " + of.Parameter + " exposed in client-side code",
				Description:    "An OAuth " + of.Parameter + " parameter was found in client-side JavaScript. " + of.Note,
				Recommendation: "Review OAuth parameter exposure. Public client_id is expected for SPAs, but client_secret and redirect_uri should not be in client-side code. Use PKCE for public clients.",
				Evidence:       "Parameter: " + of.Parameter + ", Redacted value: " + of.Redacted + ", Context: " + of.Context,
			})
		}
	}

	// Attack surface mapping (forms, params, scripts, storage)
	attackSurface := auditAttackSurface(client, bodyBytes, resp.Request.URL, ua, scriptURLs)
	if attackSurface != nil && (len(attackSurface.Forms) > 0 || len(attackSurface.QueryParameters) > 0 || len(attackSurface.ThirdPartyScripts) > 0 || len(attackSurface.StorageKeys) > 0) {
		result.AttackSurface = attackSurface
		// Generate findings for notable attack surface elements
		for _, form := range attackSurface.Forms {
			severity := "info"
			if form.IsLogin {
				severity = "medium"
			}
			loginSuffix := ""
			if form.IsLogin {
				loginSuffix = " (likely login)"
			}
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "attack-surface-form-" + sanitizeIDFragment(form.Action),
				Severity:       severity,
				Title:          "HTML form discovered" + loginSuffix,
				Description:    "An HTML form was found with action=" + form.Action + " and method=" + form.Method + ". It contains " + strconv.Itoa(len(form.Inputs)) + " input field(s).",
				Recommendation: "Review form inputs for sensitive data handling. Ensure CSRF protection, input validation, and appropriate autocomplete settings. Login forms should use HTTPS and have proper rate limiting.",
				Evidence:       "Action: " + form.Action + ", Method: " + form.Method + ", Inputs: " + strconv.Itoa(len(form.Inputs)),
			})
		}
		if len(attackSurface.QueryParameters) > 0 {
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "attack-surface-query-params",
				Severity:       "info",
				Title:          "Query parameters discovered",
				Description:    strconv.Itoa(len(attackSurface.QueryParameters)) + " unique query parameter(s) found in URL and form actions. These are potential input vectors for testing.",
				Recommendation: "Review each parameter for input validation, encoding, and authorization checks.",
				Evidence:       "Parameters: " + joinParamNames(attackSurface.QueryParameters),
			})
		}
		if len(attackSurface.ThirdPartyScripts) > 0 {
			thirdPartyCount := 0
			for _, s := range attackSurface.ThirdPartyScripts {
				if s.IsThirdParty {
					thirdPartyCount++
				}
			}
			tpSuffix := ""
			if thirdPartyCount > 0 {
				tpSuffix = " (" + strconv.Itoa(thirdPartyCount) + " third-party)"
			}
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "attack-surface-third-party-scripts",
				Severity:       "info",
				Title:          "Third-party scripts loaded" + tpSuffix,
				Description:    strconv.Itoa(len(attackSurface.ThirdPartyScripts)) + " script origin(s) found. Third-party scripts can introduce supply chain risks.",
				Recommendation: "Review third-party script origins for trustworthiness. Consider using Subresource Integrity (SRI) and Content Security Policy to mitigate risks.",
				Evidence:       "Script origins: " + joinScriptOrigins(attackSurface.ThirdPartyScripts),
			})
		}
		if len(attackSurface.StorageKeys) > 0 {
			result.Findings = append(result.Findings, SecurityFinding{
				ID:             "attack-surface-storage-keys",
				Severity:       "info",
				Title:          "Client-side storage keys discovered",
				Description:    strconv.Itoa(len(attackSurface.StorageKeys)) + " localStorage/sessionStorage key(s) referenced in JavaScript. These may store sensitive data.",
				Recommendation: "Review stored data for sensitivity. Avoid storing tokens, PII, or secrets in client-side storage. Use secure, HttpOnly cookies for sensitive session data.",
				Evidence:       "Keys: " + joinStorageKeys(attackSurface.StorageKeys),
			})
		}
	}

	// Collect advisory matches
	tlsVersion := ""
	cipherSuite := ""
	if result.TLS != nil {
		tlsVersion = result.TLS.Version
		cipherSuite = result.TLS.CipherSuite
	}
	result.AdvisoryMatches = collectAdvisoryMatches("", result.Server, result.PoweredBy, result.Technologies, tlsVersion, cipherSuite)

	result.RiskScore, result.Grade = gradeFindings(result.Findings)
	return result
}

func auditClientSideExposure(client *http.Client, pageURL *url.URL, body []byte, existing []SecurityFinding, ua string, customRules *CustomRulesFile) (*ClientSideAudit, []SecurityFinding) {
	if client == nil || pageURL == nil || len(body) == 0 {
		return nil, nil
	}
	audit := &ClientSideAudit{}
	findings := make([]SecurityFinding, 0, 8)

	if probe := probeReflectedParameter(client, pageURL, existing, ua); probe != nil {
		audit.ReflectedParamProbe = probe
		if probe.Kind == "reflected" {
			findings = append(findings, SecurityFinding{
				ID:             "reflected-parameter-clue",
				Severity:       "info",
				Title:          "Harmless reflected parameter indicator (passive)",
				Description:    "A benign alphanumeric marker appended to an existing query parameter was echoed unencoded in the sampled HTML response. This is a passive reflection clue, not proof of exploitability. Review alongside CSP script restrictions and cookie HttpOnly posture.",
				Recommendation: "Contextually encode user-controlled parameter values on output and review input handling in authorized context; combine with restrictive CSP and appropriate cookie protections.",
				Evidence:       "Benign marker reflected in sampled response body (marker not stored as secret evidence)",
			})
		}
	}

	scriptURLs := extractFirstPartyScriptURLs(pageURL, body, maxClientScripts)
	audit.ScriptsFetched = len(scriptURLs)
	if len(scriptURLs) == 0 {
		return audit, findings
	}
	seenSecrets := map[string]bool{}
	seenEndpoints := map[string]bool{}
	seenSinks := map[string]bool{}
	seenMaps := map[string]bool{}

	for _, scriptURL := range scriptURLs {
		content, ok := fetchBoundedTextResource(client, scriptURL, maxClientScriptBytes, ua)
		if !ok {
			audit.Notes = append(audit.Notes, "Could not fetch bounded script: "+truncateForPDF(scriptURL, 120))
			continue
		}
		audit.ScriptsScanned++

		for _, clue := range scanScriptSecrets(scriptURL, content, customRules) {
			key := clue.Kind + "|" + clue.ScriptURL + "|" + clue.Value
			if seenSecrets[key] {
				continue
			}
			seenSecrets[key] = true
			audit.SecretFindings = append(audit.SecretFindings, clue)
			findings = append(findings, SecurityFinding{
				ID:             "client-secret-pattern-" + sanitizeIDFragment(clue.Kind),
				Severity:       "high",
				Title:          "Possible client-side secret/token pattern in script (passive, redacted)",
				Description:    "A bounded passive scan found text matching a common credential/token pattern in a fetched first-party script. Pattern/entropy heuristics may produce false positives.",
				Recommendation: "If real, rotate exposed credentials immediately, remove secrets from client-side bundles, and use server-side proxies or scoped public tokens.",
				Evidence:       fmt.Sprintf("%s in %s: %s", clue.Kind, truncateForPDF(clue.ScriptURL, 100), clue.Value),
			})
		}

		if mapClue := detectSourceMap(client, pageURL, scriptURL, content, ua); mapClue != nil {
			mkey := mapClue.ScriptURL + "|" + mapClue.Value
			if !seenMaps[mkey] {
				seenMaps[mkey] = true
				audit.SourceMapClues = append(audit.SourceMapClues, *mapClue)
				if mapClue.Reachable != nil && *mapClue.Reachable {
					findings = append(findings, SecurityFinding{
						ID:             "source-map-reachable",
						Severity:       "medium",
						Title:          "Publicly reachable source map clue",
						Description:    "A fetched script references a source map and a bounded same-origin HEAD request indicates the map URL is reachable. Source maps can expose original source and implementation details.",
						Recommendation: "Remove production source maps from public access or restrict access if not required.",
						Evidence:       fmt.Sprintf("Script %s references %s (HEAD status %d)", truncateForPDF(mapClue.ScriptURL, 90), truncateForPDF(mapClue.Value, 90), mapClue.StatusCode),
					})
				}
			}
		}

		for _, clue := range extractEndpointClues(pageURL, scriptURL, content) {
			key := clue.Kind + "|" + clue.Value
			if seenEndpoints[key] {
				continue
			}
			seenEndpoints[key] = true
			audit.EndpointClues = append(audit.EndpointClues, clue)
		}

		for _, clue := range scanDOMSinks(scriptURL, content) {
			key := clue.Kind + "|" + clue.ScriptURL + "|" + strconv.Itoa(clue.Line)
			if seenSinks[key] {
				continue
			}
			seenSinks[key] = true
			audit.DOMSinks = append(audit.DOMSinks, clue)
		}
	}

	if len(audit.EndpointClues) > 0 {
		findings = append(findings, SecurityFinding{
			ID:             "client-endpoint-clues",
			Severity:       "info",
			Title:          "Frontend API/BaaS endpoint clues discovered (passive)",
			Description:    "Bounded parsing of fetched scripts found internal API paths or cloud/BaaS host references. Discovery clues only, not proof of exposure or vulnerability.",
			Recommendation: "Review discovered endpoints for intended exposure, authentication, and authorization. Same-origin paths may be candidates for Web Audit or Path Discovery within authorized scope.",
			Evidence:       fmt.Sprintf("%d unique endpoint clue(s) extracted from bounded scripts", len(audit.EndpointClues)),
		})
	}
	if len(audit.DOMSinks) > 0 {
		findings = append(findings, SecurityFinding{
			ID:             "dom-xss-sink-clues",
			Severity:       "info",
			Title:          "Potential DOM XSS sink usage in client scripts (passive)",
			Description:    "Bounded passive scanning found DOM sink APIs (e.g. innerHTML/outerHTML/document.write/eval/dangerouslySetInnerHTML) in fetched scripts. Presence is a code clue, not proof of exploitable XSS.",
			Recommendation: "Review sink usage with untrusted data flow, prefer safe DOM APIs/text assignment, sanitize where necessary, and enforce a restrictive CSP.",
			Evidence:       fmt.Sprintf("%d sink clue(s) with script URL/line context", len(audit.DOMSinks)),
		})
	}
	if audit.ScriptsFetched >= maxClientScripts {
		audit.Truncated = true
		audit.Notes = append(audit.Notes, fmt.Sprintf("Script scan capped at %d first-party scripts and %d KiB each", maxClientScripts, maxClientScriptBytes/1024))
	}

	return audit, findings
}

func probeReflectedParameter(client *http.Client, pageURL *url.URL, existing []SecurityFinding, ua string) *ClientSideClue {
	if pageURL == nil || pageURL.RawQuery == "" {
		return nil
	}
	q := pageURL.Query()
	paramName := "codexa_probe"
	if _, exists := q[paramName]; exists {
		paramName = "codexa_probe_check"
	}
	q.Set(paramName, reflectedProbeMarker)
	probeURL := *pageURL
	probeURL.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return &ClientSideClue{Kind: "skipped", Note: "Could not build reflected-parameter probe request"}
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return &ClientSideClue{Kind: "skipped", Note: "Reflected-parameter probe request failed"}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	clue := &ClientSideClue{Kind: "not-reflected", StatusCode: resp.StatusCode, Note: "Benign marker not observed unencoded in sampled response body"}
	if bytes.Contains(body, []byte(reflectedProbeMarker)) {
		clue.Kind = "reflected"
		clue.Value = "Marker reflected (value redacted)"
		posture := []string{}
		for _, f := range existing {
			id := strings.ToLower(f.ID)
			if strings.Contains(id, "csp") || strings.Contains(id, "cookie-httponly") {
				posture = append(posture, f.ID)
			}
		}
		if len(posture) > 0 {
			clue.Context = "Observed posture clues: " + strings.Join(posture, ", ")
		}
	}
	return clue
}

func extractFirstPartyScriptURLs(pageURL *url.URL, body []byte, limit int) []string {
	if pageURL == nil || len(body) == 0 || limit <= 0 {
		return nil
	}
	matches := scriptSrcRegex.FindAllSubmatch(body, -1)
	seen := map[string]bool{}
	out := make([]string, 0, limit)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" {
			continue
		}
		lr := strings.ToLower(raw)
		if strings.HasPrefix(lr, "data:") || strings.HasPrefix(lr, "javascript:") || strings.HasPrefix(lr, "blob:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := pageURL.ResolveReference(ref)
		if !strings.EqualFold(abs.Scheme, "http") && !strings.EqualFold(abs.Scheme, "https") {
			continue
		}
		if !strings.EqualFold(abs.Hostname(), pageURL.Hostname()) {
			continue
		}
		abs.Fragment = ""
		u := abs.String()
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func fetchBoundedTextResource(client *http.Client, target string, maxBytes int64, ua string) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil && len(b) == 0 {
		return "", false
	}
	return string(b), true
}

func redactSecretPreview(s string) string {
	if len(s) <= 8 {
		return "[REDACTED]"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

func scanScriptSecrets(scriptURL, content string, customRules *CustomRulesFile) []ClientSideClue {
	patterns := []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"openai-like-key", regexp.MustCompile(`\bsk-(?:proj-)[A-Za-z0-9_-]{16,}\b|\bsk-[A-Za-z0-9]{20,}\b`)},
		{"stripe-live-key", regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,}\b`)},
		{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{20,}\b`)},
		{"aws-access-key-id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{"github-token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
		{"supabase-service-role-clue", regexp.MustCompile(`(?i)service_role.{0,20}eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	}
	if customRules != nil {
		for _, sp := range customRules.SecretPatterns {
			if sp.Pattern != "" {
				re, err := regexp.Compile(sp.Pattern)
				if err == nil {
					patterns = append(patterns, struct {
						kind string
						re   *regexp.Regexp
					}{kind: sp.ID, re: re})
				}
			}
		}
	}
	seen := map[string]bool{}
	clues := make([]ClientSideClue, 0, 4)
	for _, p := range patterns {
		ms := p.re.FindAllString(content, 3)
		for _, m := range ms {
			key := p.kind + "|" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			clues = append(clues, ClientSideClue{Kind: p.kind, Value: redactSecretPreview(m), ScriptURL: scriptURL, Note: "Pattern/heuristic match (passive, redacted preview)"})
		}
	}
	return clues
}

func detectSourceMap(client *http.Client, pageURL *url.URL, scriptURL, content string, ua string) *ClientSideClue {
	m := sourceMapRegex.FindStringSubmatch(content)
	if len(m) < 2 {
		return nil
	}
	raw := strings.TrimSpace(m[1])
	if raw == "" || strings.HasPrefix(strings.ToLower(raw), "data:") {
		return &ClientSideClue{Kind: "source-map", ScriptURL: scriptURL, Value: "(inline/data source map reference)", Note: "Inline source map reference observed"}
	}
	base, err := url.Parse(scriptURL)
	if err != nil {
		base = pageURL
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return &ClientSideClue{Kind: "source-map", ScriptURL: scriptURL, Value: truncateForPDF(raw, 120), Note: "Source map directive found but URL could not be resolved"}
	}
	abs := base.ResolveReference(ref)
	if abs == nil || !strings.EqualFold(abs.Hostname(), pageURL.Hostname()) {
		if abs != nil {
			return &ClientSideClue{Kind: "source-map", ScriptURL: scriptURL, Value: truncateForPDF(abs.String(), 120), Note: "Cross-origin source map reference ignored (not probed)"}
		}
		return &ClientSideClue{Kind: "source-map", ScriptURL: scriptURL, Value: truncateForPDF(raw, 120), Note: "Source map reference could not be resolved"}
	}
	clue := &ClientSideClue{Kind: "source-map", ScriptURL: scriptURL, Value: abs.String(), Note: "Bounded same-origin HEAD check performed"}
	reachable, status := headReachable(client, abs.String(), ua)
	clue.Reachable = &reachable
	clue.StatusCode = status
	return clue
}

func headReachable(client *http.Client, target string, ua string) (bool, int) {
	req, err := http.NewRequest(http.MethodHead, target, nil)
	if err != nil {
		return false, 0
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode >= 200 && resp.StatusCode < 400, resp.StatusCode
}

func extractEndpointClues(pageURL *url.URL, scriptURL, content string) []ClientSideClue {
	out := make([]ClientSideClue, 0, 8)
	seen := map[string]bool{}
	for _, m := range apiPathRegex.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		p := strings.TrimSpace(m[1])
		if p == "" {
			continue
		}
		val := p
		kind := "api-path"
		if pageURL != nil {
			u := *pageURL
			u.Path = p
			u.RawPath = ""
			u.RawQuery = ""
			u.Fragment = ""
			val = u.String()
			kind = "same-origin-api-path"
		}
		key := kind + "|" + val
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ClientSideClue{Kind: kind, Value: val, ScriptURL: scriptURL, Note: "Discovered in bounded script content; candidate for authorized review"})
		if len(out) >= 20 {
			return out
		}
	}
	for _, m := range baasHostRegex.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(m[1]))
		if host == "" {
			continue
		}
		key := "baas-host|" + host
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ClientSideClue{Kind: "baas-host", Value: host, ScriptURL: scriptURL, Note: "Cloud/BaaS host reference found in bounded script content"})
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func scanDOMSinks(scriptURL, content string) []ClientSideClue {
	lines := strings.Split(content, "\n")
	out := make([]ClientSideClue, 0, 8)
	seen := map[string]bool{}
	for i, line := range lines {
		locs := domSinkRegex.FindAllString(line, -1)
		if len(locs) == 0 {
			continue
		}
		for _, sink := range locs {
			key := sink + "|" + strconv.Itoa(i+1)
			if seen[key] {
				continue
			}
			seen[key] = true
			ctx := strings.TrimSpace(line)
			if len(ctx) > 120 {
				ctx = ctx[:120] + "..."
			}
			out = append(out, ClientSideClue{Kind: "dom-sink", Value: sink, ScriptURL: scriptURL, Line: i + 1, Context: sanitizeForPDF(ctx), Note: "Passive sink usage clue; data-flow not analyzed"})
			if len(out) >= 20 {
				return out
			}
		}
	}
	return out
}

func sanitizeIDFragment(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if r == '_' || r == ' ' {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "clue"
	}
	return out
}

func inspectWebResource(client *http.Client, base *url.URL, path string, maxBytes int64, note string, ua string) *WebResourceInspector {
	target := joinFuzzURL(base, path)
	inspector := &WebResourceInspector{URL: target, Note: note}
	fetchClient := client
	if client != nil {
		transport := client.Transport
		if trace, ok := transport.(*redirectTraceTransport); ok && trace != nil {
			transport = trace.base
		}
		fetchClient = &http.Client{
			Timeout:   client.Timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		inspector.Error = "Invalid inspector URL."
		return inspector
	}
	req.Header.Set("User-Agent", ua)
	resp, err := fetchClient.Do(req)
	if err != nil {
		inspector.Error = httpAnalysisErrorMessage(err)
		return inspector
	}
	defer resp.Body.Close()
	inspector.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		inspector.Found = true
		inspector.Body = strings.TrimSpace(string(body))
		if inspector.Body == "" {
			inspector.Body = "(empty response body)"
		}
	}
	return inspector
}

func auditCloudStorageExposure(client *http.Client, body []byte, baseURL *url.URL, ua string) []CloudStorageFinding {
	if client == nil || baseURL == nil || len(body) == 0 {
		return nil
	}
	var findings []CloudStorageFinding

	// Cloud storage URL patterns
	patterns := []struct {
		regex     *regexp.Regexp
		provider  string
		bucketExt func(string) string
	}{
		{regexp.MustCompile(`https?://([a-z0-9.-]+)\.s3\.amazonaws\.com`), "AWS S3", func(s string) string { return extractBetween(s, "https://", ".s3.amazonaws.com") }},
		{regexp.MustCompile(`https?://s3\.amazonaws\.com/([a-z0-9.-]+)`), "AWS S3", func(s string) string { return extractBetween(s, "s3.amazonaws.com/", "/") }},
		{regexp.MustCompile(`https?://([a-z0-9.-]+)\.storage\.googleapis\.com`), "Google Cloud Storage", func(s string) string { return extractBetween(s, "https://", ".storage.googleapis.com") }},
		{regexp.MustCompile(`https?://storage\.googleapis\.com/([a-z0-9.-]+)`), "Google Cloud Storage", func(s string) string { return extractBetween(s, "storage.googleapis.com/", "/") }},
		{regexp.MustCompile(`https?://([a-z0-9.-]+)\.blob\.core\.windows\.net`), "Azure Blob Storage", func(s string) string { return extractBetween(s, "https://", ".blob.core.windows.net") }},
	}

	seen := make(map[string]bool)
	bodyStr := string(body)

	for _, p := range patterns {
		matches := p.regex.FindAllString(bodyStr, -1)
		for _, match := range matches {
			key := p.provider + "|" + match
			if seen[key] {
				continue
			}
			seen[key] = true

			bucket := p.bucketExt(match)
			finding := CloudStorageFinding{
				URL:      match,
				Provider: p.provider,
				Bucket:   bucket,
			}

			// Check if bucket is publicly listable with a bounded HEAD request
			checkClient := &http.Client{
				Timeout: client.Timeout,
				Transport: client.Transport,
			}
			req, err := http.NewRequest(http.MethodHead, match, nil)
			if err == nil {
				req.Header.Set("User-Agent", ua)
				resp, err := checkClient.Do(req)
				if err == nil {
					finding.StatusCode = resp.StatusCode
					resp.Body.Close()
					if resp.StatusCode == 200 {
						// Try a GET to see if it returns ListBucketResult XML
						reqGet, _ := http.NewRequest(http.MethodGet, match+"?list-type=2", nil)
						reqGet.Header.Set("User-Agent", ua)
						respGet, err := checkClient.Do(reqGet)
						if err == nil {
							bodyBytes, _ := io.ReadAll(io.LimitReader(respGet.Body, 16*1024))
							respGet.Body.Close()
							bodyStr := string(bodyBytes)
							if strings.Contains(bodyStr, "<ListBucketResult") || strings.Contains(bodyStr, "Contents>") {
								finding.Listable = true
								finding.Evidence = "Returned ListBucketResult XML"
							} else if respGet.StatusCode == 200 && (strings.Contains(strings.ToLower(bodyStr), "index") || strings.Contains(strings.ToLower(bodyStr), "contents")) {
								finding.Listable = true
								finding.Evidence = "Publicly accessible bucket listing"
							}
						}
					}
				}
			}

			if finding.Listable {
				finding.Remediation = "Restrict bucket ACL/policy to remove public list permissions. Use bucket policies or IAM to limit access to authorized principals only."
			} else if finding.StatusCode == 200 {
				finding.Remediation = "Bucket returned 200 OK but listing not confirmed. Verify bucket permissions and consider restricting public access."
			} else {
				finding.Remediation = "Bucket not publicly listable. Monitor for configuration changes."
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

func extractBetween(s, start, end string) string {
	startIdx := strings.Index(s, start)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(start)
	endIdx := strings.Index(s[startIdx:], end)
	if endIdx == -1 {
		return s[startIdx:]
	}
	return s[startIdx : startIdx+endIdx]
}

func auditRateLimitAndCacheControl(resp *http.Response) *RateLimitAuditResult {
	if resp == nil || resp.Request == nil {
		return nil
	}
	result := &RateLimitAuditResult{}

	// Check for rate limit headers
	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
		"RateLimit-Limit",
		"RateLimit-Remaining",
		"RateLimit-Reset",
		"X-Rate-Limit-Limit",
		"X-Rate-Limit-Remaining",
		"X-Rate-Limit-Reset",
	}
	var foundRateLimit []string
	for _, h := range rateLimitHeaders {
		if v := resp.Header.Get(h); v != "" {
			foundRateLimit = append(foundRateLimit, h+": "+v)
		}
	}
	if len(foundRateLimit) > 0 {
		result.HasRateLimitHeaders = true
		result.RateLimitHeaders = strings.Join(foundRateLimit, "; ")
	}

	// Check for Retry-After header
	if v := resp.Header.Get("Retry-After"); v != "" {
		result.HasRetryAfter = true
		result.RetryAfter = v
	}

	// Check Cache-Control
	cc := resp.Header.Get("Cache-Control")
	result.CacheControl = cc
	result.MissingNoStore = cc == "" || !strings.Contains(strings.ToLower(cc), "no-store")

	// Heuristic: sensitive endpoint if path contains auth, login, api, password, token, session
	path := resp.Request.URL.Path
	sensitivePaths := []string{"/login", "/auth", "/api/", "/password", "/token", "/session", "/credential", "/secret", "/key", "/admin"}
	result.IsSensitiveEndpoint = false
	for _, sp := range sensitivePaths {
		if strings.Contains(strings.ToLower(path), sp) {
			result.IsSensitiveEndpoint = true
			break
		}
	}

	// Note
	if result.IsSensitiveEndpoint {
		if !result.HasRateLimitHeaders {
			result.Note = "Sensitive endpoint missing rate-limit headers (X-RateLimit-*, RateLimit-*, Retry-After). Consider implementing rate limiting to prevent abuse."
		}
		if result.MissingNoStore {
			result.Note += " Missing Cache-Control: no-store on sensitive response. Sensitive data should not be cached."
		}
	}

	return result
}

func auditWebhookAndOAuth(client *http.Client, body []byte, baseURL *url.URL, ua string, scriptURLs []string) *WebhookOAuthAudit {
	if len(body) == 0 && len(scriptURLs) == 0 {
		return nil
	}
	result := &WebhookOAuthAudit{}

	// Webhook URL patterns
	webhookPatterns := []struct {
		platform string
		regex    *regexp.Regexp
	}{
		{"Slack", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9/]+`)},
		{"Slack", regexp.MustCompile(`https://hooks\.slack\.com/workflows/[A-Z0-9/]+`)},
		{"Discord", regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`)},
		{"Telegram", regexp.MustCompile(`https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+/sendMessage`)},
		{"Microsoft Teams", regexp.MustCompile(`https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9/]+`)},
		{"Generic Webhook", regexp.MustCompile(`https?://[a-z0-9.-]+/(webhook|webhooks?|callback)[^"'\s<>]*`)},
	}

	// OAuth parameter patterns
	oauthPatterns := []struct {
		param  string
		regex  *regexp.Regexp
	}{
		{"client_id", regexp.MustCompile(`client_id["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]+)["']?`)},
		{"redirect_uri", regexp.MustCompile(`redirect_uri["']?\s*[:=]\s*["']?([^"'\s&]+)["']?`)},
		{"client_secret", regexp.MustCompile(`client_secret["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]+)["']?`)},
		{"scope", regexp.MustCompile(`scope["']?\s*[:=]\s*["']?([^"'\s]+)["']?`)},
		{"state", regexp.MustCompile(`state["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]+)["']?`)},
		{"response_type", regexp.MustCompile(`response_type["']?\s*[:=]\s*["']?([^"'\s]+)["']?`)},
		{"grant_type", regexp.MustCompile(`grant_type["']?\s*[:=]\s*["']?([^"'\s]+)["']?`)},
	}

	seenWebhooks := make(map[string]bool)
	seenOAuth := make(map[string]bool)

	// Scan response body
	allContent := string(body)
	for _, scriptURL := range scriptURLs {
		content, ok := fetchBoundedTextResource(client, scriptURL, 512*1024, ua)
		if ok {
			allContent += "\n" + content
		}
	}

	// Find webhooks
	for _, wp := range webhookPatterns {
		matches := wp.regex.FindAllString(allContent, -1)
		for _, match := range matches {
			key := wp.platform + "|" + match
			if seenWebhooks[key] {
				continue
			}
			seenWebhooks[key] = true

			redacted := redactWebhookURL(match)
			result.Webhooks = append(result.Webhooks, WebhookFinding{
				Platform: wp.platform,
				URL:      match,
				Redacted: redacted,
				Note:     "Exposed " + wp.platform + " webhook URL found in client-side code. This may allow unauthorized message sending or data exfiltration.",
			})
		}
	}

	// Find OAuth parameters
	for _, op := range oauthPatterns {
		matches := op.regex.FindAllStringSubmatch(allContent, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				value := match[1]
				key := op.param + "|" + value
				if seenOAuth[key] {
					continue
				}
				seenOAuth[key] = true

				redacted := redactValue(value)
				result.OAuth = append(result.OAuth, OAuthFinding{
					Parameter: op.param,
					Value:     value,
					Redacted:  redacted,
					Context:   "Found in client-side JavaScript bundle",
					Note:      "OAuth " + op.param + " exposed in client-side code. Review if this is intentional (e.g., public client_id for SPA) or accidental leakage.",
				})
			}
		}
	}

	return result
}

func redactWebhookURL(url string) string {
	// Redact tokens in webhook URLs
	for _, prefix := range []string{"/services/", "/webhooks/", "/api/webhooks/", "bot", "sendMessage"} {
		idx := strings.Index(url, prefix)
		if idx >= 0 {
			// Keep the prefix and domain, redact the token part
			keep := url[:idx+len(prefix)]
			return keep + "[REDACTED]"
		}
	}
	// Generic redaction for tokens after last /
	lastSlash := strings.LastIndex(url, "/")
	if lastSlash >= 0 && lastSlash < len(url)-1 {
		return url[:lastSlash+1] + "[REDACTED]"
	}
	return "[REDACTED]"
}

func redactValue(value string) string {
	if len(value) <= 8 {
		return "[REDACTED]"
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

func auditAttackSurface(client *http.Client, body []byte, baseURL *url.URL, ua string, scriptURLs []string) *AttackSurfaceSummary {
	if len(body) == 0 && len(scriptURLs) == 0 {
		return nil
	}
	result := &AttackSurfaceSummary{}

	bodyStr := string(body)

	// 1. Extract HTML forms
	formRegex := regexp.MustCompile(`(?i)<form[^>]*action=["']?([^"'>\s]+)["']?[^>]*method=["']?([^"'>\s]+)["']?[^>]*>(.*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, match := range formMatches {
		if len(match) >= 4 {
			action := match[1]
			method := strings.ToUpper(match[2])
			formContent := match[3]

			// Extract inputs
			inputRegex := regexp.MustCompile(`(?i)<input[^>]*name=["']?([^"'>\s]+)["']?[^>]*type=["']?([^"'>\s]+)["']?[^>]*autocomplete=["']?([^"'>\s]+)["']?`)
			inputMatches := inputRegex.FindAllStringSubmatch(formContent, -1)
			var inputs []InputFinding
			isLogin := false
			for _, in := range inputMatches {
				if len(in) >= 3 {
					inputType := strings.ToLower(in[2])
					inputs = append(inputs, InputFinding{
						Name:        in[1],
						Type:        inputType,
						Autocomplete: in[3],
					})
					if inputType == "password" || strings.Contains(strings.ToLower(in[1]), "pass") || strings.Contains(strings.ToLower(in[1]), "user") || strings.Contains(strings.ToLower(in[1]), "email") {
						isLogin = true
					}
				}
			}

			// Also check for textarea and select
			textareaRegex := regexp.MustCompile(`(?i)<textarea[^>]*name=["']?([^"'>\s]+)["']?`)
			textareaMatches := textareaRegex.FindAllStringSubmatch(formContent, -1)
			for _, tm := range textareaMatches {
				if len(tm) >= 2 {
					inputs = append(inputs, InputFinding{Name: tm[1], Type: "textarea"})
				}
			}

			result.Forms = append(result.Forms, FormFinding{
				Action:  action,
				Method:  method,
				Inputs:  inputs,
				IsLogin: isLogin,
				Context: "HTML form",
			})
		}
	}

	// 2. Extract query parameters from URL
	if baseURL != nil {
		q := baseURL.Query()
		for name := range q {
			result.QueryParameters = append(result.QueryParameters, QueryParamFinding{
				Name:   name,
				Source: "url",
			})
		}
	}

	// 3. Extract query parameters from form actions
	formActionRegex := regexp.MustCompile(`(?i)action=["']?([^"'>\s]+)["']?`)
	actionMatches := formActionRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, match := range actionMatches {
		if len(match) >= 2 {
			actionURL := match[1]
			if parsed, err := url.Parse(actionURL); err == nil {
				q := parsed.Query()
				for name := range q {
					result.QueryParameters = append(result.QueryParameters, QueryParamFinding{
						Name:   name,
						Source: "form",
					})
				}
			}
		}
	}

	// 4. Extract third-party script origins
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*src=["']?([^"'>\s]+)["']?`)
	scriptMatches := scriptRegex.FindAllStringSubmatch(bodyStr, -1)
	pageOrigin := baseURL.Scheme + "://" + baseURL.Host
	for _, match := range scriptMatches {
		if len(match) >= 2 {
			scriptURL := match[1]
			parsed, err := url.Parse(scriptURL)
			if err == nil {
				isThirdParty := parsed.Scheme != "" && parsed.Host != "" && (parsed.Scheme+"://"+parsed.Host) != pageOrigin
				result.ThirdPartyScripts = append(result.ThirdPartyScripts, ScriptOriginFinding{
					Origin:        parsed.Host,
					IsThirdParty:  isThirdParty,
					URL:           scriptURL,
				})
			}
		}
	}

	// 5. Extract storage keys from JS bundles
	storagePatterns := []struct {
		regex *regexp.Regexp
		stype string
	}{
		{regexp.MustCompile(`localStorage\.(?:getItem|setItem|removeItem)\s*\(\s*["']([^"']+)["']`), "localStorage"},
		{regexp.MustCompile(`sessionStorage\.(?:getItem|setItem|removeItem)\s*\(\s*["']([^"']+)["']`), "sessionStorage"},
		{regexp.MustCompile(`localStorage\[["']([^"']+)["']\]`), "localStorage"},
		{regexp.MustCompile(`sessionStorage\[["']([^"']+)["']\]`), "sessionStorage"},
	}

	allContent := bodyStr
	for _, scriptURL := range scriptURLs {
		content, ok := fetchBoundedTextResource(client, scriptURL, 512*1024, ua)
		if ok {
			allContent += "\n" + content
		}
	}

	for _, sp := range storagePatterns {
		matches := sp.regex.FindAllStringSubmatch(allContent, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				result.StorageKeys = append(result.StorageKeys, StorageKeyFinding{
					Type:   sp.stype,
					Key:    match[1],
					Source: "js",
				})
			}
		}
	}

	// Deduplicate
	seenForms := make(map[string]bool)
	uniqueForms := []FormFinding{}
	for _, f := range result.Forms {
		key := f.Action + "|" + f.Method
		if !seenForms[key] {
			seenForms[key] = true
			uniqueForms = append(uniqueForms, f)
		}
	}
	result.Forms = uniqueForms

	seenParams := make(map[string]bool)
	uniqueParams := []QueryParamFinding{}
	for _, p := range result.QueryParameters {
		key := p.Name + "|" + p.Source
		if !seenParams[key] {
			seenParams[key] = true
			uniqueParams = append(uniqueParams, p)
		}
	}
	result.QueryParameters = uniqueParams

	seenScripts := make(map[string]bool)
	uniqueScripts := []ScriptOriginFinding{}
	for _, s := range result.ThirdPartyScripts {
		key := s.Origin + "|" + s.URL
		if !seenScripts[key] {
			seenScripts[key] = true
			uniqueScripts = append(uniqueScripts, s)
		}
	}
	result.ThirdPartyScripts = uniqueScripts

	seenStorage := make(map[string]bool)
	uniqueStorage := []StorageKeyFinding{}
	for _, s := range result.StorageKeys {
		key := s.Type + "|" + s.Key
		if !seenStorage[key] {
			seenStorage[key] = true
			uniqueStorage = append(uniqueStorage, s)
		}
	}
	result.StorageKeys = uniqueStorage

	return result
}

func joinParamNames(params []QueryParamFinding) string {
	var names []string
	for _, p := range params {
		names = append(names, p.Name)
	}
	return strings.Join(names, ", ")
}

func joinScriptOrigins(scripts []ScriptOriginFinding) string {
	var origins []string
	for _, s := range scripts {
		origins = append(origins, s.Origin)
	}
	return strings.Join(origins, ", ")
}

func joinStorageKeys(keys []StorageKeyFinding) string {
	var keyStrs []string
	for _, k := range keys {
		keyStrs = append(keyStrs, k.Type+":"+k.Key)
	}
	return strings.Join(keyStrs, ", ")
}

func tlsVerificationSummary(verified bool, chains [][]*x509.Certificate) string {
	if verified && len(chains) > 0 {
		return fmt.Sprintf("Verified by system trust store (%d chain(s) presented)", len(chains))
	}
	if verified {
		return "Verified by system trust store"
	}
	return "Not verified by system trust store; peer certificate details are from the presented chain only"
}

func auditHTTPResponse(resp *http.Response, body []byte, customRules *CustomRulesFile) []SecurityFinding {
	findings := make([]SecurityFinding, 0, 12)
	add := func(id, severity, title, description, recommendation, evidence string) {
		findings = append(findings, SecurityFinding{ID: id, Severity: severity, Title: title, Description: description, Recommendation: recommendation, Evidence: evidence})
	}
	secure := resp.Request != nil && resp.Request.URL.Scheme == "https"
	if !secure {
		add("https-not-enforced", "high", "Page is served over plain HTTP", "The final page URL is not protected by HTTPS; network observers may read or alter traffic.", "Enable HTTPS with a valid certificate and redirect HTTP requests to HTTPS.", resp.Request.URL.String())
	} else if resp.Header.Get("Strict-Transport-Security") == "" {
		add("hsts-missing", "medium", "HSTS header is missing", "HTTPS responses do not instruct browsers to prefer secure transport on future visits.", "After confirming HTTPS works for all subdomains, set an appropriate Strict-Transport-Security max-age and consider includeSubDomains.", "Strict-Transport-Security absent")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		add("csp-missing", "medium", "Content Security Policy is missing", "No CSP was observed in the response; this removes a browser-side mitigation against injected content.", "Define a restrictive Content-Security-Policy based on the site's required resources; test in report-only mode first.", "Content-Security-Policy absent")
	} else {
		cspValue := strings.Join(resp.Header.Values("Content-Security-Policy"), ", ")
		findings = append(findings, auditCSPDirectives(cspValue)...)
	}
	csp := strings.ToLower(resp.Header.Get("Content-Security-Policy"))
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		add("clickjacking-protection-missing", "medium", "Clickjacking protection is missing", "Neither X-Frame-Options nor CSP frame-ancestors was observed.", "Set Content-Security-Policy frame-ancestors; use X-Frame-Options for legacy browser support if needed.", "No frame-ancestors or X-Frame-Options")
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Content-Type-Options")), "nosniff") {
		add("nosniff-missing", "low", "MIME sniffing protection is missing", "X-Content-Type-Options is absent or is not set to nosniff.", "Set X-Content-Type-Options: nosniff and serve accurate Content-Type values.", resp.Header.Get("X-Content-Type-Options"))
	}
	if resp.Header.Get("Referrer-Policy") == "" {
		add("referrer-policy-missing", "low", "Referrer-Policy is missing", "The response does not define a referrer policy.", "Set a policy such as strict-origin-when-cross-origin, adjusted to application requirements.", "Referrer-Policy absent")
	}
	if resp.Header.Get("Permissions-Policy") == "" {
		add("permissions-policy-missing", "info", "Permissions-Policy is missing", "No browser feature policy was observed.", "Consider disabling browser features the application does not need.", "Permissions-Policy absent")
	}
	for cookieIndex, cookie := range resp.Cookies() {
		findingSuffix := fmt.Sprintf("-%d", cookieIndex+1)
		if !cookie.Secure {
			severity := "medium"
			if !secure {
				severity = "high"
			}
			add("cookie-secure-missing"+findingSuffix, severity, "Cookie lacks Secure attribute", "A Set-Cookie value was returned without the Secure flag.", "Set Secure on cookies intended for HTTPS-only delivery.", cookie.Name)
		}
		if !cookie.HttpOnly {
			add("cookie-httponly-missing"+findingSuffix, "low", "Cookie lacks HttpOnly attribute", "A Set-Cookie value was returned without HttpOnly; client-side scripts may be able to read it.", "Set HttpOnly unless browser-side access is explicitly required.", cookie.Name)
		}
		if cookie.SameSite == 0 {
			add("cookie-samesite-missing"+findingSuffix, "low", "Cookie lacks an explicit SameSite policy", "A Set-Cookie value did not specify SameSite.", "Choose an explicit SameSite policy (Lax or Strict where compatible; None requires Secure).", cookie.Name)
		}
	}
	if secure && mixedContentRegex.Match(body) {
		add("mixed-content-reference", "medium", "HTTPS page references an HTTP resource", "The sampled HTML contains a resource src/poster URL using plain HTTP.", "Load active resources over HTTPS or remove the insecure reference.", "HTTP resource URL found in first 64 KiB of response")
	}
	if resp.Header.Get("X-Powered-By") != "" || resp.Header.Get("Server") != "" {
		evidence := strings.TrimSpace(resp.Header.Get("Server") + " " + resp.Header.Get("X-Powered-By"))
		add("technology-disclosure", "info", "Server technology headers are exposed", "Response headers disclose implementation details that may help fingerprint the stack.", "Remove unnecessary product/version tokens; this is informational and is not proof of a vulnerability.", evidence)
	}
	findings = append(findings, auditCORSPolicy(resp, resp.Request)...)
	findings = append(findings, auditDBErrorDisclosure(body)...)
	findings = append(findings, auditJWTPayloadClues(resp)...)

	// Apply custom header rules
	if customRules != nil {
		for _, hr := range customRules.HeaderRules {
			if hr.Header != "" && hr.Match != "" {
				headerValue := resp.Header.Get(hr.Header)
				if headerValue != "" {
					matched, err := regexp.MatchString(hr.Match, headerValue)
					if err == nil && matched {
						severity := hr.Severity
						if severity == "" {
							severity = "medium"
						}
						add("custom-header-"+sanitizeIDFragment(hr.ID), severity, hr.Name, hr.Description, "Review the header configuration based on the custom rule.", fmt.Sprintf("Header %s matched pattern: %s", hr.Header, headerValue))
					}
				}
			}
		}
	}

	return findings
}

func auditCORSPolicy(resp *http.Response, request *http.Request) []SecurityFinding {
	if resp == nil {
		return nil
	}
	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
	if acao == "" {
		return nil
	}
	findings := make([]SecurityFinding, 0, 3)
	if acao == "*" && acac {
		findings = append(findings, SecurityFinding{
			ID:             "cors-wildcard-credentials",
			Severity:       "high",
			Title:          "CORS allows wildcard origin with credentials",
			Description:    "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true. Browsers block this combination, but it indicates a misconfigured cross-origin policy.",
			Recommendation: "Set a specific trusted origin for Access-Control-Allow-Origin when credentials are required, and avoid wildcard origins with credentials.",
			Evidence:       "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
		})
		return findings
	}
	if acao == "*" {
		findings = append(findings, SecurityFinding{
			ID:             "cors-wildcard-origin",
			Severity:       "info",
			Title:          "CORS allows any origin",
			Description:    "Access-Control-Allow-Origin is '*', allowing cross-origin reads from any origin for responses eligible under CORS rules.",
			Recommendation: "Restrict allowed origins to trusted domains if the response contains non-public data or authenticated operations.",
			Evidence:       "Access-Control-Allow-Origin: *",
		})
		return findings
	}
	reqOrigin := ""
	if request != nil {
		reqOrigin = strings.TrimSpace(request.Header.Get("Origin"))
	}
	varyHasOrigin := strings.Contains(strings.ToLower(resp.Header.Get("Vary")), "origin")
	if reqOrigin != "" && strings.EqualFold(acao, reqOrigin) && !varyHasOrigin {
		sev := "medium"
		desc := "Access-Control-Allow-Origin echoes the request Origin without Vary: Origin. This can indicate unsafe origin reflection if the server does not strictly validate an allowlist."
		if acac {
			sev = "high"
			desc = "Access-Control-Allow-Origin echoes the request Origin with credentials enabled and without Vary: Origin. This is a strong passive clue of unsafe CORS origin reflection."
		}
		findings = append(findings, SecurityFinding{
			ID:             "cors-origin-reflection",
			Severity:       sev,
			Title:          "CORS origin reflection clue (passive)",
			Description:    desc,
			Recommendation: "Validate request origins against an explicit allowlist, return a fixed trusted origin (not arbitrary reflection), and include Vary: Origin when responses differ by origin.",
			Evidence:       "Observed ACAO echoed request Origin; Vary did not include Origin",
		})
	}
	return findings
}

func auditDBErrorDisclosure(body []byte) []SecurityFinding {
	if len(body) == 0 {
		return nil
	}
	sample := body
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	lower := strings.ToLower(string(sample))
	patterns := []struct {
		id    string
		match string
		label string
	}{
		{"db-error-sql-syntax", "sql syntax", "SQL syntax error"},
		{"db-error-mysql", "mysql_fetch", "MySQL error string"},
		{"db-error-postgres", "pg::syntaxerror", "PostgreSQL syntax error"},
		{"db-error-oracle", "ora-", "Oracle error code"},
		{"db-error-sqlite", "sqlite3::sqlexception", "SQLite exception"},
		{"db-error-sqlstate", "sqlstate[", "SQLSTATE error"},
		{"db-error-pdo", "pdoexception", "PDO exception"},
		{"db-error-mongodb", "mongoerror", "MongoDB error"},
	}
	for _, p := range patterns {
		idx := strings.Index(lower, p.match)
		if idx < 0 {
			continue
		}
		start := idx - 40
		if start < 0 {
			start = 0
		}
		end := idx + len(p.match) + 60
		if end > len(sample) {
			end = len(sample)
		}
		snippet := strings.Join(strings.Fields(string(sample[start:end])), " ")
		if len(snippet) > 160 {
			snippet = snippet[:160] + "..."
		}
		return []SecurityFinding{{
			ID:             p.id,
			Severity:       "medium",
			Title:          "Possible database error disclosure in response",
			Description:    "The sampled response body contains text resembling a database error (" + p.label + "). This may expose internal query or schema details.",
			Recommendation: "Return generic error messages to clients and log detailed database errors server-side only.",
			Evidence:       snippet,
		}}
	}
	return nil
}

func auditJWTPayloadClues(resp *http.Response) []SecurityFinding {
	if resp == nil {
		return nil
	}
	candidates := make([]string, 0, 4)
	for _, values := range resp.Header {
		for _, v := range values {
			candidates = append(candidates, v)
		}
	}
	for _, c := range resp.Cookies() {
		if c != nil && c.Value != "" {
			candidates = append(candidates, c.Value)
		}
	}
	for _, cand := range candidates {
		for _, token := range extractJWTCandidates(cand) {
			if finding, ok := inspectJWTClue(token); ok {
				return []SecurityFinding{finding}
			}
		}
	}
	return nil
}

func extractJWTCandidates(s string) []string {
	out := make([]string, 0, 2)
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ';' || r == ',' || r == '"' || r == '\'' || r == '(' || r == ')' || r == '\t' || r == '\n' || r == '\r'
	}) {
		if strings.HasPrefix(part, "Bearer ") {
			part = strings.TrimPrefix(part, "Bearer ")
		}
		if strings.Count(part, ".") != 2 || !strings.HasPrefix(part, "eyJ") {
			continue
		}
		out = append(out, part)
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func inspectJWTClue(token string) (SecurityFinding, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2+1 {
		return SecurityFinding{}, false
	}
	decode := func(seg string) ([]byte, error) {
		if m := len(seg) % 4; m != 0 {
			seg += strings.Repeat("=", 4-m)
		}
		seg = strings.ReplaceAll(seg, "-", "+")
		seg = strings.ReplaceAll(seg, "_", "/")
		return base64.StdEncoding.DecodeString(seg)
	}
	headerBytes, err := decode(parts[0])
	if err != nil {
		return SecurityFinding{}, false
	}
	payloadBytes, err := decode(parts[1])
	if err != nil {
		return SecurityFinding{}, false
	}
	var header map[string]any
	var payload map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return SecurityFinding{}, false
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return SecurityFinding{}, false
	}
	alg, _ := header["alg"].(string)
	_, hasExp := payload["exp"]
	_, hasNbf := payload["nbf"]
	if strings.EqualFold(strings.TrimSpace(alg), "none") {
		return SecurityFinding{
			ID:             "jwt-alg-none",
			Severity:       "high",
			Title:          "JWT header indicates alg:none",
			Description:    "A JWT observed in response headers/cookies declares algorithm 'none' in its header metadata. This is a common misconfiguration clue (passive decode only; signature not verified).",
			Recommendation: "Reject tokens with alg 'none' server-side and require a strong signing algorithm (e.g., RS256/ES256/HS256 as appropriate).",
			Evidence:       "Decoded JWT header alg=none (token value redacted)",
		}, true
	}
	if !hasExp && !hasNbf {
		return SecurityFinding{
			ID:             "jwt-missing-exp",
			Severity:       "info",
			Title:          "JWT payload has no exp/nbf claim",
			Description:    "A JWT observed in response headers/cookies does not include 'exp' or 'nbf' claims in decoded payload metadata. This may indicate long-lived tokens depending on context (passive decode only).",
			Recommendation: "Include appropriate expiration (exp) and, where relevant, not-before (nbf) claims and enforce them server-side.",
			Evidence:       "Decoded JWT payload missing exp/nbf (token value redacted)",
		}, true
	}
	return SecurityFinding{}, false
}

func auditCSPDirectives(raw string) []SecurityFinding {
	directives := parseCSPDirectives(raw)
	if len(directives) == 0 {
		return nil
	}
	findings := make([]SecurityFinding, 0, 4)
	add := func(id, severity, title, description, recommendation, evidence string) {
		findings = append(findings, SecurityFinding{ID: id, Severity: severity, Title: title, Description: description, Recommendation: recommendation, Evidence: evidence})
	}
	scriptSources := cspDirectiveSources(directives, "script-src", "default-src")
	if hasCSPToken(scriptSources, "'unsafe-inline'") {
		add("csp-script-unsafe-inline", "medium", "CSP allows unsafe inline scripts", "script-src (or default-src fallback) includes 'unsafe-inline', which weakens protection against injected scripts.", "Avoid 'unsafe-inline' for scripts where possible; prefer nonces/hashes and refactor inline handlers.", "Directive allows: 'unsafe-inline'")
	}
	if hasCSPToken(scriptSources, "'unsafe-eval'") {
		add("csp-script-unsafe-eval", "medium", "CSP allows unsafe script evaluation", "script-src (or default-src fallback) includes 'unsafe-eval', which permits string-to-code APIs.", "Remove 'unsafe-eval' unless strictly required and isolate any remaining dynamic evaluation.", "Directive allows: 'unsafe-eval'")
	}
	if hasCSPToken(scriptSources, "*") {
		add("csp-script-wildcard-source", "medium", "CSP script sources include a wildcard", "script-src (or default-src fallback) allows '*', which broadly permits script origins.", "Restrict script-src to specific trusted origins and avoid wildcard script sources.", "Directive allows: *")
	}
	if _, ok := directives["default-src"]; !ok {
		add("csp-default-src-missing", "info", "CSP has no default-src directive", "No default-src directive was observed; unspecified fetch directives do not inherit a restrictive baseline.", "Consider adding a restrictive default-src (for example 'self' or 'none') and override only required directives.", "Observed directives: "+cspDirectiveNames(directives))
	}
	if !hasCSPDirective(directives, "object-src") && !cspDirectiveRestrictsObjects(directives) {
		add("csp-object-src-missing", "info", "CSP does not restrict object sources", "No object-src directive or restrictive default-src baseline was observed for plugin/object embeddings.", "Consider setting object-src 'none' unless plugins are explicitly required.", "Observed directives: "+cspDirectiveNames(directives))
	}
	if !hasCSPDirective(directives, "base-uri") {
		add("csp-base-uri-missing", "info", "CSP does not define base-uri", "No base-uri directive was observed; this leaves document base URL changes less constrained.", "Consider setting base-uri to trusted origins (often 'self' or 'none') based on application needs.", "Observed directives: "+cspDirectiveNames(directives))
	}
	return findings
}

func parseCSPDirectives(raw string) map[string][]string {
	out := make(map[string][]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if name == "" {
			continue
		}
		values := make([]string, 0, len(fields)-1)
		for _, value := range fields[1:] {
			values = append(values, strings.ToLower(value))
		}
		out[name] = values
	}
	return out
}

func cspDirectiveSources(directives map[string][]string, names ...string) []string {
	for _, name := range names {
		if values, ok := directives[name]; ok {
			return values
		}
	}
	return nil
}

func hasCSPDirective(directives map[string][]string, name string) bool {
	_, ok := directives[name]
	return ok
}

func hasCSPToken(values []string, token string) bool {
	token = strings.ToLower(token)
	for _, value := range values {
		if value == token {
			return true
		}
	}
	return false
}

func cspDirectiveRestrictsObjects(directives map[string][]string) bool {
	values, ok := directives["default-src"]
	if !ok {
		return false
	}
	return hasCSPToken(values, "'none'") || hasCSPToken(values, "'self'")
}

func cspDirectiveNames(directives map[string][]string) string {
	if len(directives) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(directives))
	for name := range directives {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func gradeFindings(findings []SecurityFinding) (int, string) {
	score := 0
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			score += 40
		case "high":
			score += 25
		case "medium":
			score += 15
		case "low":
			score += 5
		default:
			score++
		}
	}
	if score > 100 {
		score = 100
	}
	switch {
	case score == 0:
		return score, "A+"
	case score <= 10:
		return score, "A"
	case score <= 25:
		return score, "B"
	case score <= 50:
		return score, "C"
	case score <= 75:
		return score, "D"
	default:
		return score, "F"
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

const (
	reportSchemaVersion = "1.0"
	reportGenerator     = "Codexa Scanner"
	reportBrandName     = "Codexa Scanner"
	reportDeveloper     = "Developed by H!D3-C4rD (https://arkaryan.net/)"
)

// ReportRedactionPolicy documents bounded best-effort redaction applied to
// persisted history and exported reports. It is not a guarantee that all
// sensitive data is removed.
type ReportRedactionPolicy struct {
	Applied bool     `json:"applied"`
	Scope   []string `json:"scope"`
	Note    string   `json:"note"`
}

// ReportMetadata captures export context for the shared, versioned report model.
type ReportMetadata struct {
	DefaultFilename string `json:"defaultFilename,omitempty"`
	Target          string `json:"target,omitempty"`
	RecordCount     int    `json:"recordCount,omitempty"`
}

// ReportSeverityBreakdown summarizes finding severities when available.
type ReportSeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// ReportSummary provides an executive/technical overview derived from report data.
type ReportSummary struct {
	Title             string                   `json:"title"`
	Overview          string                   `json:"overview"`
	Targets           int                      `json:"targets,omitempty"`
	Errors            int                      `json:"errors,omitempty"`
	AverageRiskScore  int                      `json:"averageRiskScore,omitempty"`
	SeverityBreakdown *ReportSeverityBreakdown `json:"severityBreakdown,omitempty"`
	TopFindings       []string                 `json:"topFindings,omitempty"`
	Recommendations   []string                 `json:"recommendations,omitempty"`
}

// ScanReportEnvelope is the shared, versioned report/export model used by JSON,
// HTML/Markdown content generation inputs where applicable, and PDF exports.
// Data is always redacted according to Redaction before serialization.
type ScanReportEnvelope struct {
	ReportVersion string                `json:"reportVersion"`
	GeneratedAt   string                `json:"generatedAt"`
	Tool          string                `json:"tool"`
	ReportType    string                `json:"reportType"`
	Metadata      ReportMetadata        `json:"metadata,omitempty"`
	Redaction     ReportRedactionPolicy `json:"redaction"`
	Summary       *ReportSummary        `json:"summary,omitempty"`
	Comparison    any                   `json:"comparison,omitempty"`
	Data          any                   `json:"data"`
}

var defaultReportRedactionPolicy = ReportRedactionPolicy{
	Applied: true,
	Scope: []string{
		"embedded URL credentials (userinfo)",
		"sensitive URL query parameters and fragments",
		"sensitive result keys (password, secret, token, authorization, cookie, credential, session, api key variants)",
	},
	Note: "Bounded best-effort redaction; not a complete guarantee. Review exports for remaining sensitive data before sharing.",
}

func inferReportType(defaultFilename string, data any) string {
	name := strings.ToLower(strings.TrimSpace(defaultFilename))
	switch {
	case strings.Contains(name, "engagement"):
		return "engagement"
	case strings.Contains(name, "scan_history"):
		return "scan-history"
	case strings.Contains(name, "http"), strings.Contains(name, "web"):
		return "web-audit"
	case strings.Contains(name, "port"):
		return "port-scan"
	case strings.Contains(name, "dns"):
		return "dns"
	case strings.Contains(name, "tls"):
		return "tls"
	case strings.Contains(name, "subdomain"):
		return "subdomains"
	case strings.Contains(name, "fuzz"), strings.Contains(name, "path"):
		return "path-fuzzer"
	case strings.Contains(name, "ip"):
		return "ip-info"
	}
	if entries, ok := data.([]any); ok && len(entries) > 0 {
		if m, ok := entries[0].(map[string]any); ok {
			if _, hasScanType := m["scanType"]; hasScanType {
				if _, hasResult := m["result"]; hasResult {
					return "scan-history"
				}
			}
		}
	}
	return "scan-report"
}

func buildScanReportEnvelope(defaultFilename string, data any) ScanReportEnvelope {
	if m, ok := data.(map[string]any); ok {
		if _, hasVersion := m["reportVersion"]; hasVersion {
			if _, hasData := m["data"]; hasData {
				if _, hasTool := m["tool"]; hasTool {
					// Normalize existing envelope fields while preserving content.
					if _, ok := m["redaction"]; !ok {
						m["redaction"] = defaultReportRedactionPolicy
					}
					if _, ok := m["generatedAt"]; !ok {
						m["generatedAt"] = time.Now().UTC().Format(time.RFC3339)
					}
					if _, ok := m["reportType"]; !ok {
						m["reportType"] = inferReportType(defaultFilename, m["data"])
					}
					if b, err := json.Marshal(m); err == nil {
						var env ScanReportEnvelope
						if err := json.Unmarshal(b, &env); err == nil {
							if env.ReportVersion == "" {
								env.ReportVersion = reportSchemaVersion
							}
							if env.Tool == "" {
								env.Tool = reportGenerator
							}
							if env.GeneratedAt == "" {
								env.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
							}
							if env.Metadata.DefaultFilename == "" {
								env.Metadata.DefaultFilename = defaultFilename
							}
							return env
						}
					}
				}
			}
		}
		// Allow callers to pass { "data": ..., "comparison": ..., "metadata": ... }
		if inner, hasData := m["data"]; hasData {
			reportType := inferReportType(defaultFilename, inner)
			env := ScanReportEnvelope{
				ReportVersion: reportSchemaVersion,
				GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
				Tool:          reportGenerator,
				ReportType:    reportType,
				Metadata:      ReportMetadata{DefaultFilename: defaultFilename},
				Redaction:     defaultReportRedactionPolicy,
				Data:          inner,
				Comparison:    m["comparison"],
			}
			if meta, ok := m["metadata"].(map[string]any); ok {
				if b, err := json.Marshal(meta); err == nil {
					_ = json.Unmarshal(b, &env.Metadata)
				}
				if env.Metadata.DefaultFilename == "" {
					env.Metadata.DefaultFilename = defaultFilename
				}
			}
			env.Summary = deriveReportSummary(reportType, inner)
			return env
		}
	}
	reportType := inferReportType(defaultFilename, data)
	env := ScanReportEnvelope{
		ReportVersion: reportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Tool:          reportGenerator,
		ReportType:    reportType,
		Metadata: ReportMetadata{
			DefaultFilename: defaultFilename,
		},
		Redaction: defaultReportRedactionPolicy,
		Data:      data,
	}
	if arr, ok := data.([]any); ok {
		env.Metadata.RecordCount = len(arr)
	}
	env.Summary = deriveReportSummary(reportType, data)
	return env
}

func deriveReportSummary(reportType string, data any) *ReportSummary {
	switch reportType {
	case "web-audit":
		return deriveWebAuditSummary(data)
	case "engagement":
		return deriveEngagementSummary(data)
	case "scan-history":
		return deriveHistorySummary(data)
	default:
		return &ReportSummary{
			Title:    "Scan Report",
			Overview: "Shared, versioned scan report generated by Codexa Scanner. Review findings and redact remaining sensitive data before sharing.",
		}
	}
}

func deriveHistorySummary(data any) *ReportSummary {
	arr, ok := data.([]any)
	if !ok {
		return &ReportSummary{
			Title:    "Scan History Report",
			Overview: "Locally stored scan history export. Entries may include different scan types; review before sharing.",
		}
	}
	types := map[string]int{}
	targets := map[string]bool{}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if t := asString(m["scanType"]); t != "" {
			types[t]++
		}
		if t := asString(m["target"]); t != "" {
			targets[t] = true
		}
	}
	top := make([]string, 0, len(types))
	for k, v := range types {
		top = append(top, fmt.Sprintf("%s: %d", k, v))
	}
	// stable-ish small output
	if len(top) > 5 {
		top = top[:5]
	}
	return &ReportSummary{
		Title:           "Scan History Report",
		Overview:        "Shared, versioned export of locally stored scan history. Contains bounded, redacted records from the History view; review before sharing.",
		Targets:         len(targets),
		TopFindings:     top,
		Recommendations: []string{"Review exported history for sensitive targets or internal context before sharing externally."},
	}
}

func deriveEngagementSummary(data any) *ReportSummary {
	summary := deriveHistorySummary(data)
	summary.Title = "Consolidated Engagement Report"
	summary.Overview = "Shared, versioned report of selected authorized assessment records across multiple targets and scan types. Review and redact remaining sensitive data before sharing."
	return summary
}

func deriveWebAuditSummary(data any) *ReportSummary {
	results, ok := normalizeWebAuditResults(data)
	if !ok {
		return &ReportSummary{
			Title:    "Web Audit Report",
			Overview: "Bounded passive Web Audit results. Findings are heuristics, not proof of exploitability.",
		}
	}
	breakdown := &ReportSeverityBreakdown{}
	top := make([]string, 0, 5)
	recs := make([]string, 0, 5)
	seenRec := map[string]bool{}
	riskTotal, graded, errorsCount := 0, 0, 0
	for _, r := range results {
		errText, _ := r["error"].(string)
		if strings.TrimSpace(errText) != "" {
			errorsCount++
			continue
		}
		if rs, ok := numberToInt(r["riskScore"]); ok {
			riskTotal += rs
			graded++
		}
		findings, _ := r["findings"].([]any)
		for _, f := range findings {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			sev := strings.ToLower(strings.TrimSpace(asString(fm["severity"])))
			switch sev {
			case "critical":
				breakdown.Critical++
			case "high":
				breakdown.High++
			case "medium":
				breakdown.Medium++
			case "low":
				breakdown.Low++
			default:
				breakdown.Info++
			}
			breakdown.Total++
			title := asString(fm["title"])
			if title != "" && len(top) < 5 {
				label := fmt.Sprintf("[%s] %s", strings.ToUpper(sevOrInfo(sev)), title)
				dup := false
				for _, t := range top {
					if t == label {
						dup = true
						break
					}
				}
				if !dup {
					top = append(top, label)
				}
			}
			rec := strings.TrimSpace(asString(fm["recommendation"]))
			if rec != "" && !seenRec[rec] && len(recs) < 6 {
				seenRec[rec] = true
				recs = append(recs, rec)
			}
		}
	}
	avg := 0
	if graded > 0 {
		avg = riskTotal / graded
	}
	return &ReportSummary{
		Title:    "Web Audit Summary Report",
		Overview: "Executive summary of bounded passive Web Audit observations. Findings are heuristics and should be validated in authorized context before remediation prioritization.",
		Targets:  len(results), Errors: errorsCount, AverageRiskScore: avg,
		SeverityBreakdown: breakdown, TopFindings: top, Recommendations: recs,
	}
}

func sevOrInfo(sev string) string {
	if sev == "" {
		return "info"
	}
	return sev
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func numberToInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i), true
		}
	}
	return 0, false
}

func normalizeWebAuditResults(data any) ([]map[string]any, bool) {
	arr, ok := data.([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			// Heuristic: web audit result usually has url/finalUrl/findings/statusCode
			if _, hasURL := m["url"]; hasURL {
				out = append(out, m)
				continue
			}
			if _, hasFindings := m["findings"]; hasFindings {
				out = append(out, m)
			}
		}
	}
	if len(out) == 0 && len(arr) > 0 {
		// try to coerce all maps anyway
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out, len(out) > 0
}

func prepareScanReportEnvelope(defaultFilename string, jsonData string) (ScanReportEnvelope, []byte, error) {
	if strings.TrimSpace(jsonData) == "" {
		jsonData = "null"
	}
	var raw interface{}
	if err := json.Unmarshal([]byte(jsonData), &raw); err != nil {
		raw = jsonData
	}
	redacted := redactHistoryResult(raw)
	env := buildScanReportEnvelope(defaultFilename, redacted)

	// If caller passed an already-enveloped report, prefer normalized map to preserve extra fields.
	var outBytes []byte
	if m, ok := redacted.(map[string]any); ok {
		if _, hasVersion := m["reportVersion"]; hasVersion {
			if _, hasData := m["data"]; hasData {
				if _, hasTool := m["tool"]; hasTool {
					if _, ok := m["redaction"]; !ok {
						m["redaction"] = env.Redaction
					}
					if _, ok := m["generatedAt"]; !ok {
						m["generatedAt"] = env.GeneratedAt
					}
					if _, ok := m["reportType"]; !ok {
						m["reportType"] = env.ReportType
					}
					if _, ok := m["metadata"]; !ok {
						m["metadata"] = env.Metadata
					}
					if _, ok := m["summary"]; !ok && env.Summary != nil {
						m["summary"] = env.Summary
					}
					if b, err := json.MarshalIndent(m, "", "  "); err == nil {
						outBytes = b
					}
				}
			}
		}
	}
	if outBytes == nil {
		b, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			b, err = json.Marshal(env)
			if err != nil {
				return ScanReportEnvelope{}, nil, err
			}
		}
		outBytes = b
	}
	return env, outBytes, nil
}

// ExportJSON saves scan data as a versioned, redacted JSON report envelope.
func (a *App) ExportJSON(defaultFilename string, jsonData string) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Scan Report (JSON)",
		DefaultFilename: defaultFilename,
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON Files (*.json)", Pattern: "*.json"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}

	_, outBytes, err := prepareScanReportEnvelope(defaultFilename, jsonData)
	if err != nil {
		return "", err
	}
	err = os.WriteFile(path, outBytes, 0644)
	return path, err
}

func (a *App) ExportPortsCSV(findings []PortFinding) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Port Scan Report (CSV)",
		DefaultFilename: "port_scan_report.csv",
		Filters: []runtime.FileFilter{
			{DisplayName: "CSV Files (*.csv)", Pattern: "*.csv"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}

	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Port", "Protocol", "Service", "Banner"})
	for _, f := range findings {
		writer.Write([]string{strconv.Itoa(f.Port), "TCP", f.Service, f.Banner})
	}

	return path, nil
}

// ExportPDF saves a branded PDF report (executive summary, findings, severity,
// risk, recommendations, metadata, and optional supported historical comparison).
func (a *App) ExportPDF(defaultFilename string, jsonData string) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Scan Report (PDF)",
		DefaultFilename: defaultFilename,
		Filters: []runtime.FileFilter{
			{DisplayName: "PDF Files (*.pdf)", Pattern: "*.pdf"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}
	env, _, err := prepareScanReportEnvelope(defaultFilename, jsonData)
	if err != nil {
		return "", err
	}
	if err := writePDFReport(path, env); err != nil {
		return "", err
	}
	return path, nil
}

// ExportText saves text content (HTML/Markdown/etc.) to a user-selected file.
func (a *App) ExportText(defaultFilename string, content string, filterName string, pattern string) (string, error) {
	if strings.TrimSpace(filterName) == "" {
		filterName = "Text Files (*.*)"
	}
	if strings.TrimSpace(pattern) == "" {
		pattern = "*.*"
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Report",
		DefaultFilename: defaultFilename,
		Filters: []runtime.FileFilter{
			{DisplayName: filterName, Pattern: pattern},
		},
	})
	if err != nil || path == "" {
		return "", err
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", err
	}
	return path, nil
}

func writePDFReport(path string, env ScanReportEnvelope) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle(reportBrandName+" Report", false)
	pdf.SetAuthor(reportBrandName, false)
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 16)
	pdf.AddPage()

	left, _, right, _ := pdf.GetMargins()
	pageW, _ := pdf.GetPageSize()
	contentW := pageW - left - right

	// Branded header band
	pdf.SetFillColor(6, 78, 59) // emerald-900
	pdf.Rect(0, 0, pageW, 28, "F")
	pdf.SetXY(left, 8)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(236, 253, 245)
	pdf.CellFormat(0, 8, reportBrandName, "", 1, "L", false, 0, "")
	pdf.SetX(left)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(167, 243, 208)
	pdf.CellFormat(0, 5, reportDeveloper+"  -  Bounded passive security assessment report", "", 1, "L", false, 0, "")
	pdf.SetTextColor(15, 23, 42)
	pdf.SetY(34)

	title := "Scan Report"
	if env.Summary != nil && strings.TrimSpace(env.Summary.Title) != "" {
		title = env.Summary.Title
	}
	pdf.SetFont("Helvetica", "B", 15)
	pdf.MultiCell(contentW, 7, title, "", "L", false)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(71, 85, 105)
	pdf.MultiCell(contentW, 4.8, fmt.Sprintf("Generated: %s   -   Report type: %s   -   Schema: v%s", env.GeneratedAt, env.ReportType, env.ReportVersion), "", "L", false)
	if t := strings.TrimSpace(env.Metadata.Target); t != "" {
		pdf.MultiCell(contentW, 4.8, "Target: "+truncateForPDF(t, 140), "", "L", false)
	}
	if env.Metadata.RecordCount > 0 {
		pdf.MultiCell(contentW, 4.8, fmt.Sprintf("Records: %d", env.Metadata.RecordCount), "", "L", false)
	}
	pdf.SetTextColor(15, 23, 42)
	pdf.Ln(2)

	// Executive summary card
	overview := "Bounded assessment report. Review findings and redact remaining sensitive data before sharing."
	if env.Summary != nil && strings.TrimSpace(env.Summary.Overview) != "" {
		overview = env.Summary.Overview
	}
	pdfSectionTitle(pdf, contentW, "Executive Summary")
	pdfCardStart(pdf, contentW)
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(contentW-6, 5.2, overview, "", "L", false)
	if env.Summary != nil {
		pdf.Ln(1)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.MultiCell(contentW-6, 5, fmt.Sprintf("Targets analyzed: %d    Errors: %d    Average risk: %d/100", env.Summary.Targets, env.Summary.Errors, env.Summary.AverageRiskScore), "", "L", false)
	}
	pdfCardEnd(pdf)
	pdf.Ln(2)

	// Severity breakdown
	if env.Summary != nil && env.Summary.SeverityBreakdown != nil {
		b := env.Summary.SeverityBreakdown
		pdfSectionTitle(pdf, contentW, "Severity Breakdown")
		cols := []struct {
			label string
			value int
			fill  [3]int
			text  [3]int
		}{
			{"Critical", b.Critical, [3]int{254, 226, 226}, [3]int{153, 27, 27}},
			{"High", b.High, [3]int{255, 237, 213}, [3]int{154, 52, 18}},
			{"Medium", b.Medium, [3]int{254, 249, 195}, [3]int{133, 77, 14}},
			{"Low", b.Low, [3]int{219, 234, 254}, [3]int{30, 64, 175}},
			{"Info", b.Info, [3]int{241, 245, 249}, [3]int{51, 65, 85}},
		}
		colW := (contentW - 8) / 5.0
		x := left
		y := pdf.GetY()
		for i, c := range cols {
			pdf.SetXY(x, y)
			pdf.SetFillColor(c.fill[0], c.fill[1], c.fill[2])
			pdf.SetDrawColor(226, 232, 240)
			pdf.Rect(x, y, colW, 16, "FD")
			pdf.SetXY(x, y+2.5)
			pdf.SetFont("Helvetica", "B", 12)
			pdf.SetTextColor(c.text[0], c.text[1], c.text[2])
			pdf.CellFormat(colW, 6, fmt.Sprintf("%d", c.value), "", 0, "C", false, 0, "")
			pdf.SetXY(x, y+9)
			pdf.SetFont("Helvetica", "", 8)
			pdf.CellFormat(colW, 4, c.label, "", 0, "C", false, 0, "")
			x += colW + 2
			if i == 4 {
				_ = i
			}
		}
		pdf.SetTextColor(15, 23, 42)
		pdf.SetDrawColor(0, 0, 0)
		pdf.SetY(y + 19)
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(71, 85, 105)
		pdf.CellFormat(contentW, 5, fmt.Sprintf("Total findings: %d", b.Total), "", 1, "L", false, 0, "")
		pdf.SetTextColor(15, 23, 42)
		pdf.Ln(2)
	}

	// Key findings
	if env.Summary != nil && len(env.Summary.TopFindings) > 0 {
		pdfSectionTitle(pdf, contentW, "Key Findings")
		pdfCardStart(pdf, contentW)
		pdf.SetFont("Helvetica", "", 9.5)
		for _, f := range env.Summary.TopFindings {
			pdfBullet(pdf, contentW-6, sanitizeForPDF(truncateForPDF(f, 180)))
		}
		pdfCardEnd(pdf)
		pdf.Ln(2)
	}

	// Recommendations
	if env.Summary != nil && len(env.Summary.Recommendations) > 0 {
		pdfSectionTitle(pdf, contentW, "Recommendations")
		pdfCardStart(pdf, contentW)
		pdf.SetFont("Helvetica", "", 9.5)
		for _, r := range env.Summary.Recommendations {
			pdfBullet(pdf, contentW-6, sanitizeForPDF(truncateForPDF(r, 220)))
		}
		pdfCardEnd(pdf)
		pdf.Ln(2)
	}

	// Historical comparison
	if env.Comparison != nil {
		pdfSectionTitle(pdf, contentW, "Historical Comparison (Supported)")
		pdfCardStart(pdf, contentW)
		compBytes, err := json.MarshalIndent(env.Comparison, "", "  ")
		if err == nil {
			pdf.SetFont("Courier", "", 8)
			for _, line := range splitPDFLines(string(compBytes), 4000) {
				pdf.MultiCell(contentW-6, 4.2, sanitizeForPDF(truncateForPDF(line, 180)), "", "L", false)
			}
		} else {
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(contentW-6, 5, "Comparison data available but could not be rendered.", "", "L", false)
		}
		pdfCardEnd(pdf)
		pdf.Ln(2)
	}

	// Technical findings
	if env.ReportType == "web-audit" {
		writeWebAuditPDFDetails(pdf, env.Data)
		pdf.Ln(1)
	}

	// Metadata & redaction
	pdfSectionTitle(pdf, contentW, "Metadata & Redaction Policy")
	pdfCardStart(pdf, contentW)
	pdf.SetFont("Helvetica", "", 9)
	pdfKeyValue(pdf, contentW-6, "Tool", env.Tool)
	pdfKeyValue(pdf, contentW-6, "Report version", env.ReportVersion)
	pdfKeyValue(pdf, contentW-6, "Report type", env.ReportType)
	if strings.TrimSpace(env.Metadata.DefaultFilename) != "" {
		pdfKeyValue(pdf, contentW-6, "Suggested file", env.Metadata.DefaultFilename)
	}
	pdfKeyValue(pdf, contentW-6, "Redaction applied", fmt.Sprintf("%v", env.Redaction.Applied))
	if len(env.Redaction.Scope) > 0 {
		pdf.MultiCell(contentW-6, 4.8, sanitizeForPDF("Scope: "+strings.Join(env.Redaction.Scope, "; ")), "", "L", false)
	}
	if env.Redaction.Note != "" {
		pdf.MultiCell(contentW-6, 4.8, sanitizeForPDF("Note: "+env.Redaction.Note), "", "L", false)
	}
	pdfCardEnd(pdf)

	pdf.Ln(3)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(100, 116, 139)
	pdf.MultiCell(contentW, 4, sanitizeForPDF("Bounded passive observations. Grades and risk scores are heuristics, not CVSS and not proof of exploitability. Use only on explicitly authorized targets. Review and manually redact remaining sensitive data before sharing."), "", "L", false)

	if err := pdf.Error(); err != nil {
		return err
	}
	return pdf.OutputFileAndClose(path)
}

func pdfSectionTitle(pdf *fpdf.Fpdf, contentW float64, title string) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(15, 23, 42)
	pdf.CellFormat(0, 7, sanitizeForPDF(title), "", 1, "L", false, 0, "")
	x := pdf.GetX()
	y := pdf.GetY() - 0.5
	pdf.SetDrawColor(16, 185, 129)
	pdf.SetLineWidth(0.6)
	pdf.Line(x, y, x+22, y)
	pdf.SetLineWidth(0.2)
	pdf.SetDrawColor(0, 0, 0)
	pdf.Ln(1.5)
}

func pdfCardStart(pdf *fpdf.Fpdf, contentW float64) {
	y := pdf.GetY()
	pdf.SetFillColor(248, 250, 252)
	pdf.SetDrawColor(226, 232, 240)
	pdf.Rect(pdf.GetX(), y, contentW, 0.1, "")
	pdf.SetXY(pdf.GetX()+3, y+2.5)
}

func pdfCardEnd(pdf *fpdf.Fpdf) {
	// draw a light bottom spacer line by moving cursor; fpdf lacks easy dynamic card height, so add spacing
	pdf.SetDrawColor(0, 0, 0)
	pdf.Ln(2)
}

func pdfBullet(pdf *fpdf.Fpdf, w float64, text string) {
	x := pdf.GetX()
	pdf.CellFormat(4, 5, "-", "", 0, "L", false, 0, "")
	pdf.MultiCell(w-4, 5, text, "", "L", false)
	pdf.SetX(x)
}

func pdfKeyValue(pdf *fpdf.Fpdf, w float64, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	x := pdf.GetX()
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(36, 5, key+":", "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(w-36, 5, sanitizeForPDF(truncateForPDF(value, 220)), "", "L", false)
	pdf.SetX(x)
}

func writeWebAuditPDFDetails(pdf *fpdf.Fpdf, data any) {
	results, ok := normalizeWebAuditResults(data)
	if !ok || len(results) == 0 {
		return
	}
	left, _, right, _ := pdf.GetMargins()
	pageW, _ := pdf.GetPageSize()
	contentW := pageW - left - right
	pdfSectionTitle(pdf, contentW, "Technical Findings (Web Audit)")
	maxTargets := 50
	for i, r := range results {
		if i >= maxTargets {
			pdf.SetFont("Helvetica", "I", 9)
			pdf.SetTextColor(71, 85, 105)
			pdf.MultiCell(contentW, 5, sanitizeForPDF(fmt.Sprintf("... %d additional targets omitted from PDF detail (see JSON export for full data).", len(results)-maxTargets)), "", "L", false)
			pdf.SetTextColor(15, 23, 42)
			break
		}
		url := asString(r["url"])
		if url == "" {
			url = asString(r["finalUrl"])
		}
		if url == "" {
			url = fmt.Sprintf("Target %d", i+1)
		}
		status, _ := numberToInt(r["statusCode"])
		risk, _ := numberToInt(r["riskScore"])
		grade := asString(r["grade"])
		errText := asString(r["error"])
		findings, _ := r["findings"].([]any)

		// target header bar
		y := pdf.GetY()
		if y > 250 {
			pdf.AddPage()
			y = pdf.GetY()
		}
		pdf.SetFillColor(241, 245, 249)
		pdf.SetDrawColor(226, 232, 240)
		pdf.Rect(left, y, contentW, 8, "FD")
		pdf.SetXY(left+2, y+1.5)
		pdf.SetFont("Helvetica", "B", 9.5)
		pdf.SetTextColor(15, 23, 42)
		pdf.CellFormat(contentW-4, 5, sanitizeForPDF(truncateForPDF(url, 120)), "", 1, "L", false, 0, "")
		pdf.SetXY(left+2, pdf.GetY()+0.5)

		if strings.TrimSpace(errText) != "" {
			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(185, 28, 28)
			pdf.MultiCell(contentW-4, 4.8, sanitizeForPDF("Error: "+truncateForPDF(errText, 240)), "", "L", false)
			pdf.SetTextColor(15, 23, 42)
			pdf.Ln(2)
			continue
		}

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(51, 65, 85)
		meta := fmt.Sprintf("Status: %d   Grade: %s   Risk: %d/100   Findings: %d", status, gradeOrDash(grade), risk, len(findings))
		pdf.MultiCell(contentW-4, 4.8, sanitizeForPDF(meta), "", "L", false)
		if final := asString(r["finalUrl"]); final != "" && final != url {
			pdf.MultiCell(contentW-4, 4.8, sanitizeForPDF("Final URL: "+truncateForPDF(final, 140)), "", "L", false)
		}
		pdf.SetTextColor(15, 23, 42)

		if len(findings) == 0 {
			pdf.SetFont("Helvetica", "I", 9)
			pdf.SetTextColor(71, 85, 105)
			pdf.MultiCell(contentW-4, 4.8, "No passive findings reported for this target.", "", "L", false)
			pdf.SetTextColor(15, 23, 42)
			pdf.Ln(1.5)
			continue
		}

		limit := len(findings)
		if limit > 20 {
			limit = 20
		}
		for j := 0; j < limit; j++ {
			fm, _ := findings[j].(map[string]any)
			if fm == nil {
				continue
			}
			sev := strings.ToUpper(sevOrInfo(asString(fm["severity"])))
			title := asString(fm["title"])
			desc := asString(fm["description"])
			rec := asString(fm["recommendation"])
			ev := asString(fm["evidence"])
			pdf.SetFont("Helvetica", "B", 9)
			pdf.MultiCell(contentW-4, 4.8, sanitizeForPDF(fmt.Sprintf("[%s] %s", sev, truncateForPDF(title, 150))), "", "L", false)
			pdf.SetFont("Helvetica", "", 8.8)
			if desc != "" {
				pdf.MultiCell(contentW-4, 4.5, sanitizeForPDF(truncateForPDF(desc, 260)), "", "L", false)
			}
			if ev != "" {
				pdf.SetTextColor(71, 85, 105)
				pdf.MultiCell(contentW-4, 4.3, sanitizeForPDF("Evidence: "+truncateForPDF(ev, 220)), "", "L", false)
				pdf.SetTextColor(15, 23, 42)
			}
			if rec != "" {
				pdf.SetTextColor(6, 95, 70)
				pdf.MultiCell(contentW-4, 4.3, sanitizeForPDF("Remediation: "+truncateForPDF(rec, 240)), "", "L", false)
				pdf.SetTextColor(15, 23, 42)
			}
			pdf.Ln(0.8)
		}
		if len(findings) > limit {
			pdf.SetFont("Helvetica", "I", 8.5)
			pdf.SetTextColor(71, 85, 105)
			pdf.MultiCell(contentW-4, 4.5, sanitizeForPDF(fmt.Sprintf("... %d additional findings omitted for this target in PDF (see JSON).", len(findings)-limit)), "", "L", false)
			pdf.SetTextColor(15, 23, 42)
		}
		pdf.Ln(2)
	}
}

func gradeOrDash(g string) string {
	if strings.TrimSpace(g) == "" {
		return "-"
	}
	return g
}

func truncateForPDF(s string, max int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")), " ")
	s = sanitizeForPDF(s)
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "..."
}

func splitPDFLines(s string, maxChars int) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = sanitizeForPDF(s)
	if len(s) > maxChars {
		s = s[:maxChars] + "\n... (truncated)"
	}
	return strings.Split(s, "\n")
}

func sanitizeForPDF(s string) string {
	if s == "" {
		return s
	}
	// fpdf core fonts are single-byte; replace common problematic Unicode with ASCII equivalents.
	repl := strings.NewReplacer(
		"\u2022", "-", "\u2023", "-", "\u25E6", "-", "\u2043", "-", "\u2219", "-",
		"\u2013", "-", "\u2014", "-", "\u2212", "-",
		"\u2018", "'", "\u2019", "'", "\u201A", "'", "\u2032", "'",
		"\u201C", "\"", "\u201D", "\"", "\u201E", "\"",
		"\u2026", "...", "\u00A0", " ", "\u2192", "->", "\u2190", "<-", "\u00B7", "-",
	)
	s = repl.Replace(s)
	// Normalize whitespace/control chars and drop other non-Latin-1 runes to avoid garbled output.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20:
			b.WriteRune(' ')
		case r <= 0xFF:
			b.WriteRune(r)
		default:
			b.WriteRune('?')
		}
	}
	return b.String()
}

// ==========================================
// 15. TOOL INTEROPERABILITY - NMAP XML & SUBDOMAIN IMPORT
// ==========================================

// NmapXML structures for parsing nmap -oX output
type nmapXML struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status  nmapStatus   `xml:"status"`
	Address []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports   nmapPorts    `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostname []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Port []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string     `xml:"protocol,attr"`
	PortID   int        `xml:"portid,attr"`
	State    nmapState  `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Extrainfo string `xml:"extrainfo,attr"`
	Method  string `xml:"method,attr"`
	Conf    string `xml:"conf,attr"`
}

// NmapImportResult represents the result of importing Nmap XML
type NmapImportResult struct {
	HostsProcessed    int      `json:"hostsProcessed"`
	HostsUp           int      `json:"hostsUp"`
	PortsFound        int      `json:"portsFound"`
	WebEndpointsFound int      `json:"webEndpointsFound"`
	Errors            []string `json:"errors,omitempty"`
}

// SubdomainImportResult represents the result of importing subdomain list
type SubdomainImportResult struct {
	SubdomainsLoaded int      `json:"subdomainsLoaded"`
	DuplicatesRemoved int     `json:"duplicatesRemoved"`
	InvalidEntries   int      `json:"invalidEntries"`
	Errors           []string `json:"errors,omitempty"`
}

// ImportNmapXML parses nmap -oX XML output and stores port scan results in history.
// It also returns discovered HTTP/HTTPS endpoints for optional Web Audit.
func (a *App) ImportNmapXML(xmlData string) NmapImportResult {
	result := NmapImportResult{}
	if strings.TrimSpace(xmlData) == "" {
		result.Errors = append(result.Errors, "empty XML input")
		return result
	}

	var nmap nmapXML
	if err := xml.Unmarshal([]byte(xmlData), &nmap); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse Nmap XML: %v", err))
		return result
	}

	webEndpoints := make(map[string]bool)
	seenTargets := make(map[string]bool)

	for _, host := range nmap.Hosts {
		if host.Status.State != "up" {
			continue
		}
		result.HostsProcessed++
		result.HostsUp++

		// Get the primary IP address
		var ip string
		for _, addr := range host.Address {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}

		// Get hostname if available
		hostname := ip
		for _, hn := range host.Hostnames.Hostname {
			if hn.Type == "PTR" || hn.Type == "user" {
				hostname = hn.Name
				break
			}
		}

		// Skip if already processed this target
		targetKey := normalizeTargetKey(ip, hostname)
		if seenTargets[targetKey] {
			continue
		}
		seenTargets[targetKey] = true

		// Process open ports
		var findings []PortFinding
		for _, port := range host.Ports.Port {
			if port.State.State != "open" {
				continue
			}
			result.PortsFound++

			serviceName := port.Service.Name
			if serviceName == "" {
				serviceName = commonPorts[port.PortID]
				if serviceName == "" {
					serviceName = "unknown"
				}
			}

			// Build banner from service info
			bannerParts := []string{}
			if port.Service.Product != "" {
				bannerParts = append(bannerParts, port.Service.Product)
			}
			if port.Service.Version != "" {
				bannerParts = append(bannerParts, port.Service.Version)
			}
			if port.Service.Extrainfo != "" {
				bannerParts = append(bannerParts, port.Service.Extrainfo)
			}
			banner := strings.Join(bannerParts, " ")

			finding := PortFinding{Port: port.PortID, Service: serviceName, Banner: banner}
			findings = append(findings, finding)

			// Check for HTTP/HTTPS ports
			if port.PortID == 80 || port.PortID == 443 || port.PortID == 8080 || port.PortID == 8443 {
				scheme := "http"
				if port.PortID == 443 || port.PortID == 8443 {
					scheme = "https"
				}
				endpoint := fmt.Sprintf("%s://%s:%d", scheme, ip, port.PortID)
				webEndpoints[endpoint] = true
				result.WebEndpointsFound++
			}
		}

		// Save to history
		if len(findings) > 0 {
			if err := a.saveHistory("port", targetKey, findings, 0); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to save history for %s: %v", targetKey, err))
			}
		}
	}

	return result
}

// normalizeTargetKey creates a consistent key for a target
func normalizeTargetKey(ip, hostname string) string {
	if hostname != "" && hostname != ip {
		return hostname
	}
	return ip
}

// ImportSubdomains imports a newline-delimited subdomain list from external recon tools.
// Each line should contain a single subdomain (e.g., from subfinder, amass).
func (a *App) ImportSubdomains(subdomainData string) SubdomainImportResult {
	result := SubdomainImportResult{}
	if strings.TrimSpace(subdomainData) == "" {
		result.Errors = append(result.Errors, "empty subdomain input")
		return result
	}

	seen := make(map[string]bool)
	lines := strings.Split(subdomainData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Basic validation - must be a valid hostname
		if !isValidHostname(line) {
			result.InvalidEntries++
			result.Errors = append(result.Errors, fmt.Sprintf("invalid hostname: %s", line))
			continue
		}

		// Normalize
		line = strings.ToLower(strings.TrimSuffix(line, "."))

		if seen[line] {
			result.DuplicatesRemoved++
			continue
		}
		seen[line] = true
		result.SubdomainsLoaded++
	}

	return result
}

// isValidHostname checks if a string is a valid hostname
func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	if strings.ContainsAny(host, " \t\r\n:/\\[]@") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

// ImportNmapXMLFile imports Nmap XML from a file
func (a *App) ImportNmapXMLFile(filePath string) (NmapImportResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return NmapImportResult{}, fmt.Errorf("failed to read file: %w", err)
	}
	// Limit file size to 10MB
	if len(data) > 10*1024*1024 {
		return NmapImportResult{}, fmt.Errorf("file too large (max 10MB)")
	}
	return a.ImportNmapXML(string(data)), nil
}

// ImportSubdomainsFile imports subdomains from a file
func (a *App) ImportSubdomainsFile(filePath string) (SubdomainImportResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return SubdomainImportResult{}, fmt.Errorf("failed to read file: %w", err)
	}
	// Limit file size to 1MB
	if len(data) > 1024*1024 {
		return SubdomainImportResult{}, fmt.Errorf("file too large (max 1MB)")
	}
	return a.ImportSubdomains(string(data)), nil
}

// ==========================================
// 15.2 RAW HTTP REQUEST/RESPONSE INSPECTOR & BOUNDED REPLAY
// ==========================================

// HTTPInspectorRequest represents a request to inspect or replay
type HTTPInspectorRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	AllowPrivate bool             `json:"allowPrivate,omitempty"`
	TimeoutSeconds int            `json:"timeoutSeconds,omitempty"`
}

// HTTPInspectorResponse represents the response from inspection or replay
type HTTPInspectorResponse struct {
	Request  *HTTPInspectorRequestDebug `json:"request,omitempty"`
	Response *HTTPInspectorResponseDebug `json:"response,omitempty"`
	Error    string                     `json:"error,omitempty"`
}

type HTTPInspectorRequestDebug struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type HTTPInspectorResponseDebug struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	BodyTruncated bool           `json:"bodyTruncated,omitempty"`
	TLS        *TLSDetails       `json:"tls,omitempty"`
}

// InspectHTTP inspects a URL and returns raw request/response details without storing in history
func (a *App) InspectHTTP(req HTTPInspectorRequest) HTTPInspectorResponse {
	if strings.TrimSpace(req.URL) == "" {
		return HTTPInspectorResponse{Error: "URL is required"}
	}

	// Validate URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return HTTPInspectorResponse{Error: fmt.Sprintf("invalid URL: %v", err)}
	}

	// Only allow HTTP/HTTPS
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return HTTPInspectorResponse{Error: "only HTTP and HTTPS schemes are allowed"}
	}

	// Default method
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}

	// Validate method - only safe methods allowed
	allowedMethods := map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}
	if !allowedMethods[method] {
		return HTTPInspectorResponse{Error: fmt.Sprintf("method %s not allowed (only GET, HEAD, OPTIONS)", method)}
	}

	// Timeout
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	if timeout > 60 {
		timeout = 60
	}

	// Build request
	httpReq, err := http.NewRequest(method, req.URL, nil)
	if err != nil {
		return HTTPInspectorResponse{Error: fmt.Sprintf("failed to create request: %v", err)}
	}

	// Add custom headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Default user agent if not set
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", "Codexa Scanner HTTP Inspector")
	}

	// Create client with scoped transport
	profile := resolveHTTPRequestProfile(HTTPRequestProfile{
		TimeoutSeconds: timeout,
		CustomHeaders:  nil,
		ProxyURL:       "",
	})

	client, err := newScopedHTTPClientWithProfile(req.URL, req.AllowPrivate, net.DefaultResolver, profile)
	if err != nil {
		return HTTPInspectorResponse{Error: fmt.Sprintf("failed to create client: %v", err)}
	}

	// Capture request for debugging
	reqDebug := HTTPInspectorRequestDebug{
		URL:     req.URL,
		Method:  method,
		Headers: make(map[string]string),
	}
	for k, v := range httpReq.Header {
		reqDebug.Headers[k] = strings.Join(v, ", ")
	}
	if req.Body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		reqDebug.Body = req.Body
	}

	// Send request
	resp, err := client.Do(httpReq)
	if err != nil {
		return HTTPInspectorResponse{
			Request: &reqDebug,
			Error:   fmt.Sprintf("request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read response body (bounded)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyTruncated := false
	if resp.ContentLength > 64*1024 || int64(len(bodyBytes)) >= 64*1024 {
		bodyTruncated = true
	}

	// Capture response headers
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	// TLS details if HTTPS
	var tlsDetails *TLSDetails
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		verified := len(resp.TLS.VerifiedChains) > 0
		chainSubjects := make([]string, 0, len(resp.TLS.PeerCertificates))
		for _, peerCert := range resp.TLS.PeerCertificates {
			if peerCert == nil {
				continue
			}
			name := peerCert.Subject.CommonName
			if name == "" {
				name = peerCert.Subject.String()
			}
			chainSubjects = append(chainSubjects, name)
		}
		tlsDetails = &TLSDetails{
			Version:             tlsVersionName(resp.TLS.Version),
			CipherSuite:         tls.CipherSuiteName(resp.TLS.CipherSuite),
			Subject:             cert.Subject.CommonName,
			Issuer:              cert.Issuer.CommonName,
			ExpiresAt:           cert.NotAfter,
			NotBefore:           cert.NotBefore,
			DaysRemaining:       days,
			Verified:            verified,
			VerificationSummary: tlsVerificationSummary(verified, resp.TLS.VerifiedChains),
			ChainSubjects:       chainSubjects,
			SANCount:            len(cert.DNSNames) + len(cert.IPAddresses) + len(cert.EmailAddresses) + len(cert.URIs),
		}
	}

	return HTTPInspectorResponse{
		Request: &reqDebug,
		Response: &HTTPInspectorResponseDebug{
			StatusCode:    resp.StatusCode,
			Headers:       respHeaders,
			Body:          string(bodyBytes),
			BodyTruncated: bodyTruncated,
			TLS:           tlsDetails,
		},
	}
}

// ReplayHTTPRequest replays a previously captured request with optional modifications
func (a *App) ReplayHTTPRequest(originalReq HTTPInspectorRequest, modifications HTTPInspectorRequest) HTTPInspectorResponse {
	// Merge modifications into original request
	mergedReq := originalReq
	if modifications.Method != "" {
		mergedReq.Method = modifications.Method
	}
	if modifications.URL != "" {
		mergedReq.URL = modifications.URL
	}
	if modifications.Headers != nil {
		if mergedReq.Headers == nil {
			mergedReq.Headers = make(map[string]string)
		}
		for k, v := range modifications.Headers {
			mergedReq.Headers[k] = v
		}
	}
	if modifications.Body != "" {
		mergedReq.Body = modifications.Body
	}
	if modifications.AllowPrivate {
		mergedReq.AllowPrivate = true
	}
	if modifications.TimeoutSeconds > 0 {
		mergedReq.TimeoutSeconds = modifications.TimeoutSeconds
	}

	// Validate that the modified URL is within the same host/port scope as original
	originalURL, err := url.Parse(originalReq.URL)
	if err != nil {
		return HTTPInspectorResponse{Error: "original URL invalid"}
	}
	modifiedURL, err := url.Parse(mergedReq.URL)
	if err != nil {
		return HTTPInspectorResponse{Error: "modified URL invalid"}
	}

	// Check host and port match (scope enforcement)
	if !strings.EqualFold(originalURL.Hostname(), modifiedURL.Hostname()) {
		return HTTPInspectorResponse{Error: "replay URL must be within the same host scope"}
	}
	originalPort := originalURL.Port()
	modifiedPort := modifiedURL.Port()
	if originalPort == "" {
		if originalURL.Scheme == "https" {
			originalPort = "443"
		} else {
			originalPort = "80"
		}
	}
	if modifiedPort == "" {
		if modifiedURL.Scheme == "https" {
			modifiedPort = "443"
		} else {
			modifiedPort = "80"
		}
	}
	if originalPort != modifiedPort {
		return HTTPInspectorResponse{Error: "replay URL must be within the same port scope"}
	}

	return a.InspectHTTP(mergedReq)
}

// ==========================================
// 16. WORKSPACE PERSISTENCE & ANALYST TRIAGE
// ==========================================

// Workspace represents an engagement workspace for organizing scan data.
type Workspace struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

// FindingTag represents a triage tag for a specific finding in a history entry.
type FindingTag struct {
	ID        int64     `json:"id"`
	HistoryID int64     `json:"historyId"`
	FindingID string    `json:"findingId"`
	Tag       string    `json:"tag"`
	CreatedAt time.Time `json:"createdAt"`
}

// FindingNote represents an analyst note for a specific finding in a history entry.
type FindingNote struct {
	ID        int64     `json:"id"`
	HistoryID int64     `json:"historyId"`
	FindingID string    `json:"findingId"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// CreateWorkspace creates a new engagement workspace.
func (a *App) CreateWorkspace(name, description string) (int64, error) {
	if a == nil || a.historyDB == nil {
		return 0, errors.New("database unavailable")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, errors.New("workspace name is required")
	}
	description = strings.TrimSpace(description)
	result, err := a.historyDB.Exec(`INSERT INTO workspaces(name, description, created_at)
		VALUES (?, ?, ?)`, name, description, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// ListWorkspaces returns all engagement workspaces.
func (a *App) ListWorkspaces() []Workspace {
	if a == nil || a.historyDB == nil {
		return []Workspace{}
	}
	rows, err := a.historyDB.Query(`SELECT id, name, description, created_at FROM workspaces ORDER BY created_at DESC`)
	if err != nil {
		return []Workspace{}
	}
	defer rows.Close()
	var workspaces []Workspace
	for rows.Next() {
		var w Workspace
		var created string
		if err := rows.Scan(&w.ID, &w.Name, &w.Description, &created); err != nil {
			continue
		}
		w.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		workspaces = append(workspaces, w)
	}
	return workspaces
}

// DeleteWorkspace deletes a workspace by ID. Sets workspace_id to NULL in scan_history.
func (a *App) DeleteWorkspace(id int64) error {
	if a == nil || a.historyDB == nil || id <= 0 {
		return errors.New("invalid workspace ID")
	}
	_, err := a.historyDB.Exec(`DELETE FROM workspaces WHERE id = ?`, id)
	return err
}

// GetWorkspaceScans returns scan history entries for a specific workspace.
func (a *App) GetWorkspaceScans(workspaceID int64, limit int) []HistoryEntry {
	if a == nil || a.historyDB == nil || workspaceID <= 0 || limit <= 0 {
		return []HistoryEntry{}
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := a.historyDB.Query(`SELECT id, scan_type, target, result_json, created_at FROM scan_history
		WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`, workspaceID, limit)
	if err != nil {
		return []HistoryEntry{}
	}
	defer rows.Close()
	var entries []HistoryEntry
	for rows.Next() {
		var entry HistoryEntry
		var raw, created string
		if err := rows.Scan(&entry.ID, &entry.ScanType, &entry.Target, &raw, &created); err != nil {
			continue
		}
		entry.Result = raw
		entry.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		entries = append(entries, entry)
	}
	return entries
}

// SetFindingTag sets or updates a triage tag for a finding in a history entry.
// Valid tags: "verified", "false_positive", "needs_review", "accepted_risk"
func (a *App) SetFindingTag(historyID int64, findingID, tag string) error {
	if a == nil || a.historyDB == nil || historyID <= 0 || findingID == "" || tag == "" {
		return errors.New("invalid parameters")
	}
	validTags := map[string]bool{"verified": true, "false_positive": true, "needs_review": true, "accepted_risk": true}
	if !validTags[tag] {
		return fmt.Errorf("invalid tag: %s (must be one of: verified, false_positive, needs_review, accepted_risk)", tag)
	}
	_, err := a.historyDB.Exec(`INSERT INTO finding_tags(history_id, finding_id, tag, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(history_id, finding_id) DO UPDATE SET tag = excluded.tag`, historyID, findingID, tag, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// GetFindingTags returns all triage tags for a history entry.
func (a *App) GetFindingTags(historyID int64) []FindingTag {
	if a == nil || a.historyDB == nil || historyID <= 0 {
		return []FindingTag{}
	}
	rows, err := a.historyDB.Query(`SELECT id, history_id, finding_id, tag, created_at FROM finding_tags WHERE history_id = ?`, historyID)
	if err != nil {
		return []FindingTag{}
	}
	defer rows.Close()
	var tags []FindingTag
	for rows.Next() {
		var t FindingTag
		var created string
		if err := rows.Scan(&t.ID, &t.HistoryID, &t.FindingID, &t.Tag, &created); err != nil {
			continue
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		tags = append(tags, t)
	}
	return tags
}

// DeleteFindingTag removes a triage tag for a finding.
func (a *App) DeleteFindingTag(historyID int64, findingID string) error {
	if a == nil || a.historyDB == nil || historyID <= 0 || findingID == "" {
		return errors.New("invalid parameters")
	}
	_, err := a.historyDB.Exec(`DELETE FROM finding_tags WHERE history_id = ? AND finding_id = ?`, historyID, findingID)
	return err
}

// SetFindingNote sets or updates an analyst note for a finding in a history entry.
func (a *App) SetFindingNote(historyID int64, findingID, note string) error {
	if a == nil || a.historyDB == nil || historyID <= 0 || findingID == "" {
		return errors.New("invalid parameters")
	}
	note = strings.TrimSpace(note)
	if note == "" {
		return a.DeleteFindingNote(historyID, findingID)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := a.historyDB.Exec(`INSERT INTO finding_notes(history_id, finding_id, note, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(history_id, finding_id) DO UPDATE SET note = excluded.note, updated_at = excluded.updated_at`, historyID, findingID, note, now, now)
	return err
}

// GetFindingNotes returns all analyst notes for a history entry.
func (a *App) GetFindingNotes(historyID int64) []FindingNote {
	if a == nil || a.historyDB == nil || historyID <= 0 {
		return []FindingNote{}
	}
	rows, err := a.historyDB.Query(`SELECT id, history_id, finding_id, note, created_at, updated_at FROM finding_notes WHERE history_id = ?`, historyID)
	if err != nil {
		return []FindingNote{}
	}
	defer rows.Close()
	var notes []FindingNote
	for rows.Next() {
		var n FindingNote
		var created, updated string
		if err := rows.Scan(&n.ID, &n.HistoryID, &n.FindingID, &n.Note, &created, &updated); err != nil {
			continue
		}
		n.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		n.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		notes = append(notes, n)
	}
	return notes
}

// DeleteFindingNote removes an analyst note for a finding.
func (a *App) DeleteFindingNote(historyID int64, findingID string) error {
	if a == nil || a.historyDB == nil || historyID <= 0 || findingID == "" {
		return errors.New("invalid parameters")
	}
	_, err := a.historyDB.Exec(`DELETE FROM finding_notes WHERE history_id = ? AND finding_id = ?`, historyID, findingID)
	return err
}

// UpdateHistoryWorkspace assigns a history entry to a workspace (or removes assignment with 0).
func (a *App) UpdateHistoryWorkspace(historyID int64, workspaceID int64) error {
	if a == nil || a.historyDB == nil || historyID <= 0 {
		return errors.New("invalid parameters")
	}
	var wsID any
	if workspaceID > 0 {
		wsID = workspaceID
	}
	_, err := a.historyDB.Exec(`UPDATE scan_history SET workspace_id = ? WHERE id = ?`, wsID, historyID)
	return err
}

// ImportNmapXMLToWorkspace imports Nmap XML and stores results in a specific workspace.
func (a *App) ImportNmapXMLToWorkspace(xmlData string, workspaceID int64) NmapImportResult {
	result := NmapImportResult{}
	if strings.TrimSpace(xmlData) == "" {
		result.Errors = append(result.Errors, "empty XML input")
		return result
	}

	var nmap nmapXML
	if err := xml.Unmarshal([]byte(xmlData), &nmap); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse Nmap XML: %v", err))
		return result
	}

	webEndpoints := make(map[string]bool)
	seenTargets := make(map[string]bool)

	for _, host := range nmap.Hosts {
		if host.Status.State != "up" {
			continue
		}
		result.HostsProcessed++
		result.HostsUp++

		var ip string
		for _, addr := range host.Address {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}

		hostname := ip
		for _, hn := range host.Hostnames.Hostname {
			if hn.Type == "PTR" || hn.Type == "user" {
				hostname = hn.Name
				break
			}
		}

		targetKey := normalizeTargetKey(ip, hostname)
		if seenTargets[targetKey] {
			continue
		}
		seenTargets[targetKey] = true

		var findings []PortFinding
		for _, port := range host.Ports.Port {
			if port.State.State != "open" {
				continue
			}
			result.PortsFound++

			serviceName := port.Service.Name
			if serviceName == "" {
				serviceName = commonPorts[port.PortID]
				if serviceName == "" {
					serviceName = "unknown"
				}
			}

			bannerParts := []string{}
			if port.Service.Product != "" {
				bannerParts = append(bannerParts, port.Service.Product)
			}
			if port.Service.Version != "" {
				bannerParts = append(bannerParts, port.Service.Version)
			}
			if port.Service.Extrainfo != "" {
				bannerParts = append(bannerParts, port.Service.Extrainfo)
			}
			banner := strings.Join(bannerParts, " ")

			finding := PortFinding{Port: port.PortID, Service: serviceName, Banner: banner}
			findings = append(findings, finding)

			if port.PortID == 80 || port.PortID == 443 || port.PortID == 8080 || port.PortID == 8443 {
				scheme := "http"
				if port.PortID == 443 || port.PortID == 8443 {
					scheme = "https"
				}
				endpoint := fmt.Sprintf("%s://%s:%d", scheme, ip, port.PortID)
				webEndpoints[endpoint] = true
				result.WebEndpointsFound++
			}
		}

		if len(findings) > 0 {
			if err := a.saveHistory("port", targetKey, findings, workspaceID); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to save history for %s: %v", targetKey, err))
			}
		}
	}

	return result
}

// ImportSubdomainsToWorkspace imports subdomains and stores results in a specific workspace.
func (a *App) ImportSubdomainsToWorkspace(subdomainData string, workspaceID int64) SubdomainImportResult {
	result := SubdomainImportResult{}
	if strings.TrimSpace(subdomainData) == "" {
		result.Errors = append(result.Errors, "empty subdomain input")
		return result
	}

	seen := make(map[string]bool)
	lines := strings.Split(subdomainData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !isValidHostname(line) {
			result.InvalidEntries++
			result.Errors = append(result.Errors, fmt.Sprintf("invalid hostname: %s", line))
			continue
		}

		line = strings.ToLower(strings.TrimSuffix(line, "."))

		if seen[line] {
			result.DuplicatesRemoved++
			continue
		}
		seen[line] = true
		result.SubdomainsLoaded++

		// Save each subdomain as a separate subdomain scan result
		if err := a.saveHistory("subdomain", line, line, workspaceID); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to save history for %s: %v", line, err))
		}
	}

	return result
}
