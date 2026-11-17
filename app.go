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

	"github.com/go-pdf/fpdf"
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
	findings = append(findings, auditCORSPolicy(resp)...)
	findings = append(findings, auditDBErrorDisclosure(body)...)
	findings = append(findings, auditJWTPayloadClues(resp)...)
	return findings
}

func auditCORSPolicy(resp *http.Response) []SecurityFinding {
	if resp == nil {
		return nil
	}
	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
	if acao == "" {
		return nil
	}
	findings := make([]SecurityFinding, 0, 2)
	if acao == "*" && acac {
		findings = append(findings, SecurityFinding{
			ID:             "cors-wildcard-credentials",
			Severity:       "high",
			Title:          "CORS allows wildcard origin with credentials",
			Description:    "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true. Browsers block this combination, but it indicates a misconfigured cross-origin policy.",
			Recommendation: "Set a specific trusted origin for Access-Control-Allow-Origin when credentials are required, and avoid wildcard origins with credentials.",
			Evidence:       "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
		})
	} else if acao == "*" {
		findings = append(findings, SecurityFinding{
			ID:             "cors-wildcard-origin",
			Severity:       "info",
			Title:          "CORS allows any origin",
			Description:    "Access-Control-Allow-Origin is '*', allowing cross-origin reads from any origin for responses eligible under CORS rules.",
			Recommendation: "Restrict allowed origins to trusted domains if the response contains non-public data or authenticated operations.",
			Evidence:       "Access-Control-Allow-Origin: *",
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
	Title             string                  `json:"title"`
	Overview          string                  `json:"overview"`
	Targets           int                     `json:"targets,omitempty"`
	Errors            int                     `json:"errors,omitempty"`
	AverageRiskScore  int                     `json:"averageRiskScore,omitempty"`
	SeverityBreakdown *ReportSeverityBreakdown `json:"severityBreakdown,omitempty"`
	TopFindings       []string                `json:"topFindings,omitempty"`
	Recommendations   []string                `json:"recommendations,omitempty"`
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
		Title:        "Scan History Report",
		Overview:     "Shared, versioned export of locally stored scan history. Contains bounded, redacted records from the History view; review before sharing.",
		Targets:      len(targets),
		TopFindings:  top,
		Recommendations: []string{"Review exported history for sensitive targets or internal context before sharing externally."},
	}
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
