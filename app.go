package main

import (
	"bufio"
	"bytes"
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
	"net/url"
)

type App struct {
	ctx        context.Context
	scanMu     sync.Mutex
	activeScan *portScan
	nextScanID uint64
	historyDB  *sql.DB
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

func grabBanner(ctx context.Context, conn net.Conn, target string, port int) string {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	defer conn.Close()
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
			if err := a.saveHistory("port", target, snapshot); err != nil {
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
					banner := grabBanner(scan.ctx, conn, target, port)
					svc := commonPorts[port]
					if svc == "" {
						svc = "unknown"
					}
					finding := PortFinding{Port: port, Service: svc, Banner: banner}
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

// ==========================================
// 2. BULK HTTP SECURITY & TECH ANALYZER
// ==========================================

type BulkHeaderResult struct {
	URL          string                `json:"url"`
	FinalURL     string                `json:"finalUrl"`
	Assessment   string                `json:"assessment,omitempty"`
	Redirects    []RedirectHop         `json:"redirects,omitempty"`
	StatusCode   int                   `json:"statusCode"`
	Title        string                `json:"title"`
	Server       string                `json:"server"`
	PoweredBy    string                `json:"poweredBy"`
	Technologies []string              `json:"technologies"`
	EdgeServices []string              `json:"edgeServices"`
	Grade        string                `json:"grade"`
	RiskScore    int                   `json:"riskScore"`
	Missing      []string              `json:"missing"`
	Present      map[string]string     `json:"present"`
	TLS          *TLSDetails           `json:"tls,omitempty"`
	SecurityTxt  *WebResourceInspector `json:"securityTxt,omitempty"`
	RobotsTxt    *WebResourceInspector `json:"robotsTxt,omitempty"`
	Findings     []SecurityFinding     `json:"findings"`
	Error        string                `json:"error"`
}

type WebResourceInspector struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
	Found      bool   `json:"found"`
	Body       string `json:"body,omitempty"`
	Error      string `json:"error,omitempty"`
	Note       string `json:"note,omitempty"`
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

const webAuditAssessmentLabel = "Bounded active HTTP requests (main GET, redirects, and resource inspectors) with passive response analysis"

func (a *App) AnalyzeBulkURLs(rawInput string, concurrency int, allowPrivateTargets bool, requestDelayMs int) []BulkHeaderResult {
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
	if requestDelayMs < 0 {
		requestDelayMs = 0
	}
	if requestDelayMs > 5000 {
		requestDelayMs = 5000
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
			if requestDelayMs > 0 {
				time.Sleep(time.Duration(requestDelayMs) * time.Millisecond)
			}
			client, err := newScopedHTTPClient(target, allowPrivateTargets, net.DefaultResolver)
			if err != nil {
				inputURL := analysisURLForDisplay(target)
				results[i] = BulkHeaderResult{URL: inputURL, FinalURL: inputURL, Assessment: webAuditAssessmentLabel, Redirects: []RedirectHop{}, Error: err.Error()}
				return
			}
			results[i] = analyzeURL(target, client, secHeaders)
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
			if err := a.saveHistory("http", targetKey, res); err != nil {
				log.Printf("Codexa Scanner: saving HTTP target history: %v", err)
			}
		}
	}
	if err := a.saveHistory("http-bulk", fmt.Sprintf("bulk HTTP (%d targets)", len(urls)), results); err != nil {
		log.Printf("Codexa Scanner: saving HTTP scan history: %v", err)
	}
	return results
}

func analyzeURL(target string, client *http.Client, secHeaders []string) BulkHeaderResult {
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
	req.Header.Set("User-Agent", "Codexa-Scanner/1.1 (passive authorized security assessment)")
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
		result.SecurityTxt = inspectWebResource(client, &inspectBase, "/.well-known/security.txt", 8192, "")
		result.RobotsTxt = inspectWebResource(client, &inspectBase, "/robots.txt", 8192, "robots.txt is discovery guidance, not a security control.")
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
	result.SecurityTxt = inspectWebResource(client, &inspectBase, "/.well-known/security.txt", 8192, "")
	result.RobotsTxt = inspectWebResource(client, &inspectBase, "/robots.txt", 8192, "robots.txt is discovery guidance, not a security control.")

	result.RiskScore, result.Grade = gradeFindings(result.Findings)
	return result
}

func inspectWebResource(client *http.Client, base *url.URL, path string, maxBytes int64, note string) *WebResourceInspector {
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
	req.Header.Set("User-Agent", "Codexa-Scanner/1.1 (passive authorized security assessment)")
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

func tlsVerificationSummary(verified bool, chains [][]*x509.Certificate) string {
	if verified && len(chains) > 0 {
		return fmt.Sprintf("Verified by system trust store (%d chain(s) presented)", len(chains))
	}
	if verified {
		return "Verified by system trust store"
	}
	return "Not verified by system trust store; peer certificate details are from the presented chain only"
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
	return findings
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
)

type reportRedactionPolicy struct {
	Applied bool     `json:"applied"`
	Scope   []string `json:"scope"`
	Note    string   `json:"note"`
}

type scanReportEnvelope struct {
	ReportVersion string                `json:"reportVersion"`
	GeneratedAt   string                `json:"generatedAt"`
	Tool          string                `json:"tool"`
	ReportType    string                `json:"reportType"`
	Redaction     reportRedactionPolicy `json:"redaction"`
	Data          any                   `json:"data"`
}

var defaultReportRedactionPolicy = reportRedactionPolicy{
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

func buildScanReportEnvelope(defaultFilename string, data any) scanReportEnvelope {
	if m, ok := data.(map[string]any); ok {
		if _, hasVersion := m["reportVersion"]; hasVersion {
			if _, hasData := m["data"]; hasData {
				if _, hasTool := m["tool"]; hasTool {
					// Assume already a report envelope; normalize policy/timestamp if missing.
					if _, ok := m["redaction"]; !ok {
						m["redaction"] = defaultReportRedactionPolicy
					}
					if _, ok := m["generatedAt"]; !ok {
						m["generatedAt"] = time.Now().UTC().Format(time.RFC3339)
					}
					if _, ok := m["reportType"]; !ok {
						m["reportType"] = inferReportType(defaultFilename, m["data"])
					}
					// Preserve as-is by returning wrapped map via Data? easier: return envelope with map in Data loses shape.
				}
			}
		}
	}
	return scanReportEnvelope{
		ReportVersion: reportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Tool:          reportGenerator,
		ReportType:    inferReportType(defaultFilename, data),
		Redaction:     defaultReportRedactionPolicy,
		Data:          data,
	}
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

	// Parse, redact, and wrap in a versioned report envelope before saving.
	if jsonData == "" {
		jsonData = "null"
	}
	var raw interface{}
	if err := json.Unmarshal([]byte(jsonData), &raw); err != nil {
		raw = jsonData
	}
	redacted := redactHistoryResult(raw)

	var outBytes []byte
	if m, ok := redacted.(map[string]any); ok {
		if _, hasVersion := m["reportVersion"]; hasVersion {
			if _, hasData := m["data"]; hasData {
				if _, hasTool := m["tool"]; hasTool {
					if _, ok := m["redaction"]; !ok {
						m["redaction"] = defaultReportRedactionPolicy
					}
					if _, ok := m["generatedAt"]; !ok {
						m["generatedAt"] = time.Now().UTC().Format(time.RFC3339)
					}
					if _, ok := m["reportType"]; !ok {
						m["reportType"] = inferReportType(defaultFilename, m["data"])
					}
					if b, err := json.MarshalIndent(m, "", "  "); err == nil {
						outBytes = b
					}
				}
			}
		}
	}
	if outBytes == nil {
		envelope := buildScanReportEnvelope(defaultFilename, redacted)
		if b, err := json.MarshalIndent(envelope, "", "  "); err == nil {
			outBytes = b
		} else if b, err := json.Marshal(envelope); err == nil {
			outBytes = b
		} else {
			return "", err
		}
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

// ExportText saves plain text content (HTML/Markdown reports) via a native dialog.
func (a *App) ExportText(defaultFilename string, content string, filterName string, pattern string) (string, error) {
	if filterName == "" {
		filterName = "Text Files (*.txt)"
	}
	if pattern == "" {
		pattern = "*.txt"
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Report",
		DefaultFilename: defaultFilename,
		Filters:         []runtime.FileFilter{{DisplayName: filterName, Pattern: pattern}},
	})
	if err != nil || path == "" {
		return "", err
	}
	return path, os.WriteFile(path, []byte(content), 0644)
}
