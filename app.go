package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx        context.Context
	scanCancel context.CancelFunc
	historyDB  *sql.DB
}

func NewApp() *App {
	return &App{}
}

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
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

var commonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
	8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

func grabBanner(conn net.Conn, target string, port int) string {
	conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))

	// HTTP/HTTPS port ဖြစ်နေရင် HEAD request လှမ်းပို့ပြီး Server header ယူမယ်
	if port == 80 || port == 8080 || port == 8000 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", target)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	raw := string(buf[:n])
	// HTTP response ဖြစ်ရင် Server header ကိုပဲ သန့်သန့်လေး ဆွဲထုတ်မယ်
	if strings.HasPrefix(raw, "HTTP/") {
		for _, line := range strings.Split(raw, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line)
			}
		}
		return strings.Split(raw, "\r\n")[0]
	}

	// တခြား Banner တွေ (SSH, FTP, SMTP) အတွက် ပထမဆုံးစာကြောင်းကို ယူမယ်
	clean := strings.TrimSpace(strings.Split(raw, "\n")[0])
	if len(clean) > 80 {
		clean = clean[:80] + "..."
	}
	return clean
}

func (a *App) StartPortScan(target string, startPort, endPort, workers, timeoutMs int) string {
	if target == "" {
		return "Target is required"
	}
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return "Invalid port range (1-65535)"
	}
	if workers <= 0 {
		workers = 150
	}
	if timeoutMs <= 0 {
		timeoutMs = 800
	}

	// အရင် Scan run နေတာရှိရင် အရင်ရပ်မယ်
	if a.scanCancel != nil {
		a.scanCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	totalPorts := endPort - startPort + 1
	var scannedCount int64

	go func() {
		defer cancel()
		ports := make(chan int, workers)
		var wg sync.WaitGroup
		var findingsMu sync.Mutex
		var scanFindings []PortFinding
		timeout := time.Duration(timeoutMs) * time.Millisecond

		// Worker Pool စတင်ခြင်း
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for p := range ports {
					select {
					case <-ctx.Done():
						return
					default:
						address := fmt.Sprintf("%s:%d", target, p)
						conn, err := net.DialTimeout("tcp", address, timeout)
						if err == nil {
							banner := grabBanner(conn, target, p)
							conn.Close()

							svc := commonPorts[p]
							if svc == "" {
								svc = "unknown"
							}
							finding := PortFinding{Port: p, Service: svc, Banner: banner}
							findingsMu.Lock()
							scanFindings = append(scanFindings, finding)
							findingsMu.Unlock()

							// Notify the frontend as soon as an open port is found.
							runtime.EventsEmit(a.ctx, "port:found", finding)
						}

						curr := atomic.AddInt64(&scannedCount, 1)
						// UI ကိုဝန်မပိစေဖို့ port 25 ခုတစ်ခါ Progress update ပို့မယ်
						if curr%25 == 0 || int(curr) == totalPorts {
							pct := int((float64(curr) / float64(totalPorts)) * 100)
							runtime.EventsEmit(a.ctx, "scan:progress", pct)
						}
					}
				}
			}()
		}

		// Ports တွေကို Channel ထဲ ထည့်ခြင်း
	Loop:
		for p := startPort; p <= endPort; p++ {
			select {
			case <-ctx.Done():
				break Loop
			case ports <- p:
			}
		}
		close(ports)
		wg.Wait()
		findingsMu.Lock()
		snapshot := append([]PortFinding(nil), scanFindings...)
		findingsMu.Unlock()
		if err := a.saveHistory("port", target, snapshot); err != nil {
			log.Printf("Codexa Scanner: saving port scan history: %v", err)
		}

		runtime.EventsEmit(a.ctx, "scan:done", true)
	}()

	return "STARTED"
}

func (a *App) StopPortScan() {
	if a.scanCancel != nil {
		a.scanCancel()
	}
}

// ==========================================
// 2. BULK HTTP SECURITY & TECH ANALYZER
// ==========================================

type BulkHeaderResult struct {
	URL          string            `json:"url"`
	FinalURL     string            `json:"finalUrl"`
	StatusCode   int               `json:"statusCode"`
	Title        string            `json:"title"`
	Server       string            `json:"server"`
	PoweredBy    string            `json:"poweredBy"`
	Technologies []string          `json:"technologies"`
	EdgeServices []string          `json:"edgeServices"`
	Grade        string            `json:"grade"`
	RiskScore    int               `json:"riskScore"`
	Missing      []string          `json:"missing"`
	Present      map[string]string `json:"present"`
	TLS          *TLSDetails       `json:"tls,omitempty"`
	Findings     []SecurityFinding `json:"findings"`
	Error        string            `json:"error"`
}

type TLSDetails struct {
	Version       string    `json:"version"`
	CipherSuite   string    `json:"cipherSuite"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	ExpiresAt     time.Time `json:"expiresAt"`
	DaysRemaining int       `json:"daysRemaining"`
	Verified      bool      `json:"verified"`
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

func (a *App) AnalyzeBulkURLs(rawInput string, concurrency int) []BulkHeaderResult {
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(rawInput))
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if len(urls) >= 100 {
				break
			}
			urls = append(urls, line)
		}
	}

	if len(urls) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > 20 {
		concurrency = 20
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

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

	for idx, rawURL := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = analyzeURL(target, client, secHeaders)
		}(idx, rawURL)
	}

	wg.Wait()
	if err := a.saveHistory("http", fmt.Sprintf("bulk HTTP (%d targets)", len(urls)), results); err != nil {
		log.Printf("Codexa Scanner: saving HTTP scan history: %v", err)
	}
	return results
}

func analyzeURL(target string, client *http.Client, secHeaders []string) BulkHeaderResult {
	inputURL := strings.TrimSpace(target)
	if !strings.Contains(inputURL, "://") {
		inputURL = "https://" + inputURL
	}
	parsed, err := url.Parse(inputURL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return BulkHeaderResult{URL: inputURL, Error: "Enter a valid http:// or https:// URL without embedded credentials."}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return BulkHeaderResult{URL: inputURL, Error: "Enter a valid http:// or https:// URL without embedded credentials."}
	}
	result := BulkHeaderResult{URL: inputURL, FinalURL: inputURL, Present: make(map[string]string), Findings: []SecurityFinding{}}
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		result.Error = "Invalid URL."
		return result
	}
	req.Header.Set("User-Agent", "Codexa-Scanner/1.1 (passive authorized security assessment)")
	resp, err := client.Do(req)
	if err != nil {
		result.Error = "Connection failed, timed out, or TLS certificate verification failed. No insecure TLS bypass was used."
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
	result.Findings = auditHTTPResponse(resp, bodyBytes)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		result.TLS = &TLSDetails{Version: tlsVersionName(resp.TLS.Version), CipherSuite: tls.CipherSuiteName(resp.TLS.CipherSuite), Subject: cert.Subject.CommonName, Issuer: cert.Issuer.CommonName, ExpiresAt: cert.NotAfter, DaysRemaining: days, Verified: len(resp.TLS.VerifiedChains) > 0}
		if days <= 30 {
			severity := "medium"
			if days <= 7 {
				severity = "high"
			}
			result.Findings = append(result.Findings, SecurityFinding{ID: "tls-expiring", Severity: severity, Title: "TLS certificate expires soon", Description: fmt.Sprintf("The verified certificate expires in %d day(s).", days), Recommendation: "Renew the certificate before its expiry and verify automated renewal."})
		}
	}
	result.RiskScore, result.Grade = gradeFindings(result.Findings)
	return result
}

func auditHTTPResponse(resp *http.Response, body []byte) []SecurityFinding {
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
	return findings
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

// ==========================================
// 3. NATIVE EXPORT (JSON & CSV)
// ==========================================

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

	// Pretty print JSON
	var raw interface{}
	if err := json.Unmarshal([]byte(jsonData), &raw); err == nil {
		if pretty, err := json.MarshalIndent(raw, "", "  "); err == nil {
			jsonData = string(pretty)
		}
	}

	err = os.WriteFile(path, []byte(jsonData), 0644)
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
