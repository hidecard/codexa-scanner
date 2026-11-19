package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const discoveryLimit = 500
const discoveryWorkers = 20

// SubdomainResult contains names found passively and, when requested, by DNS wordlist probing.
type SubdomainResult struct {
	Domain        string         `json:"domain"`
	Names         []string       `json:"names"`
	Errors        []string       `json:"errors,omitempty"`
	TakeoverClues []TakeoverClue `json:"takeoverClues,omitempty"`
}

type TakeoverClue struct {
	Subdomain   string `json:"subdomain"`
	CNAMETarget string `json:"cnameTarget"`
	Provider    string `json:"provider"`
	Status      string `json:"status"` // "unresolved", "unclaimed", "potential"
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

// PathFinding intentionally contains no response body or body-derived data.
type PathFinding struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"statusCode"`
	ContentLength int64  `json:"contentLength"`
}
type PathFuzzResult struct {
	BaseURL string        `json:"baseUrl"`
	Paths   []PathFinding `json:"paths"`
	Error   string        `json:"error,omitempty"`
}

type TLSProbeStatus string

const (
	TLSProbeSupported       TLSProbeStatus = "supported"
	TLSProbeNotSupported    TLSProbeStatus = "not_supported"
	TLSProbeInconclusive    TLSProbeStatus = "inconclusive"
	tlsAlertProtocolVersion                = 70
)

type TLSInspection struct {
	Host               string         `json:"host"`
	Port               string         `json:"port"`
	Subject            string         `json:"subject"`
	Issuer             string         `json:"issuer"`
	NotBefore          time.Time      `json:"notBefore"`
	NotAfter           time.Time      `json:"notAfter"`
	DaysRemaining      int            `json:"daysRemaining"`
	SANs               []string       `json:"sans"`
	SelfSigned         bool           `json:"selfSigned"`
	Trusted            bool           `json:"trusted"`
	ValidationError    string         `json:"validationError,omitempty"`
	TLSVersion         string         `json:"tlsVersion"`
	CipherSuite        string         `json:"cipherSuite"`
	TLS10Status        TLSProbeStatus `json:"tls10Status"`
	TLS11Status        TLSProbeStatus `json:"tls11Status"`
	TLS10Error         string         `json:"tls10Error,omitempty"`
	TLS11Error         string         `json:"tls11Error,omitempty"`
	NegotiatedProtocol string         `json:"negotiatedProtocol,omitempty"`
	HTTP2Supported     bool           `json:"http2Supported"`
	HTTP3Advertised    bool           `json:"http3Advertised"`
	HTTP3Advertisement string         `json:"http3Advertisement,omitempty"`
	WeakTLS12Ciphers   []string       `json:"weakTls12Ciphers,omitempty"`
	WeakCipherWarning  string         `json:"weakCipherWarning,omitempty"`
}
type DNSIntelligenceResult struct {
	Domain      string               `json:"domain"`
	A           []string             `json:"a"`
	AAAA        []string             `json:"aaaa"`
	MX          []string             `json:"mx"`
	NS          []string             `json:"ns"`
	TXT         []string             `json:"txt"`
	SPF         []string             `json:"spf"`
	DMARC       []string             `json:"dmarc"`
	DKIM        []DKIMRecord         `json:"dkim,omitempty"`
	PTR         map[string][]string  `json:"ptr"`
	RDAP        []RDAPInfo           `json:"rdap,omitempty"`
	Errors      []string             `json:"errors,omitempty"`
	EmailPolicy *EmailPolicyAnalysis `json:"emailPolicy,omitempty"`
}

type DKIMRecord struct {
	Selector string `json:"selector"`
	Record   string `json:"record"`
	KeyType  string `json:"keyType,omitempty"`
	KeySize  int    `json:"keySize,omitempty"`
	Note     string `json:"note,omitempty"`
}

type EmailPolicyAnalysis struct {
	SPF    SPFAnalysis   `json:"spf"`
	DMARC  DMARCAnalysis `json:"dmarc"`
	DKIM   DKIMAnalysis  `json:"dkim"`
	Rating string        `json:"rating"` // "strong", "moderate", "weak", "missing"
}

type SPFAnalysis struct {
	Record         string   `json:"record"`
	HasSPF         bool     `json:"hasSPF"`
	AllMechanism   string   `json:"allMechanism,omitempty"` // "+all", "~all", "-all", "?all"
	WeakMechanisms []string `json:"weakMechanisms,omitempty"`
	Includes       []string `json:"includes,omitempty"`
	Redirects      []string `json:"redirects,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

type DMARCAnalysis struct {
	Record          string    `json:"record"`
	HasDMARC        bool      `json:"hasDMARC"`
	Policy          string    `json:"policy,omitempty"` // "none", "quarantine", "reject"
	SubdomainPolicy string    `json:"subdomainPolicy,omitempty"`
	Percent         int       `json:"percent,omitempty"`
	RUA             []string  `json:"rua,omitempty"`
	RUF             []string  `json:"ruf,omitempty"`
	Alignment       Alignment `json:"alignment,omitempty"`
	Warnings        []string  `json:"warnings,omitempty"`
}

type Alignment struct {
	SPF  string `json:"spf,omitempty"` // "r" (relaxed), "s" (strict)
	DKIM string `json:"dkim,omitempty"`
}

type DKIMAnalysis struct {
	RecordsFound int      `json:"recordsFound"`
	Selectors    []string `json:"selectors,omitempty"`
	KeyTypes     []string `json:"keyTypes,omitempty"`
	KeySizes     []int    `json:"keySizes,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}
type RDAPInfo struct {
	IP            string `json:"ip"`
	NetworkHandle string `json:"networkHandle,omitempty"`
	Country       string `json:"country,omitempty"`
	Name          string `json:"name,omitempty"`
	Source        string `json:"source"`
}
type IPInformationResult struct {
	IP           string    `json:"ip"`
	AddressClass string    `json:"addressClass"`
	ReverseDNS   []string  `json:"reverseDns"`
	RDAP         *RDAPInfo `json:"rdap,omitempty"`
	Sources      []string  `json:"sources"`
	Errors       []string  `json:"errors,omitempty"`
}

func validateDiscoveryDomain(raw string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(d) == 0 || len(d) > 253 || strings.ContainsAny(d, "/:@?#[]\\ \t\r\n") {
		return "", fmt.Errorf("invalid domain")
	}
	if net.ParseIP(d) != nil {
		return "", fmt.Errorf("domain name required")
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid domain label")
			}
		}
	}
	return d, nil
}
func validateDiscoveryURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("enter a valid http(s) base URL without credentials")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("enter a valid http(s) base URL without credentials")
	}
	if strings.ContainsAny(u.Host, "\r\n\\") {
		return nil, fmt.Errorf("invalid host")
	}
	return u, nil
}
func validWordLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func validFuzzPath(s string) bool {
	if s == "" || len(s) > 2048 || strings.ContainsAny(s, "\\\r\n\x00?#%") {
		return false
	}
	if strings.HasPrefix(s, "//") || strings.Contains(s, ":") {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(s, "/"), "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

// EnumerateSubdomains queries crt.sh and optionally resolves safe single-label wordlist entries.
func (a *App) EnumerateSubdomains(domain string, wordlist []string, brute bool) SubdomainResult {
	d, err := validateDiscoveryDomain(domain)
	r := SubdomainResult{Domain: d, Names: []string{}}
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return r
	}
	found := map[string]bool{}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, "https://crt.sh/?q=%25."+url.QueryEscape(d)+"&output=json", nil)
	if resp, e := client.Do(req); e == nil {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var rows []struct {
				Names string `json:"name_value"`
			}
			if json.Unmarshal(data, &rows) == nil {
				for _, row := range rows {
					for _, name := range strings.Split(row.Names, "\n") {
						name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
						if _, e := validateDiscoveryDomain(name); e == nil && (name == d || strings.HasSuffix(name, "."+d)) {
							found[name] = true
						}
					}
				}
			}
		} else {
			r.Errors = append(r.Errors, fmt.Sprintf("crt.sh returned HTTP %d", resp.StatusCode))
		}
	} else {
		r.Errors = append(r.Errors, "crt.sh query failed")
	}
	if brute {
		labels := make([]string, 0, min(len(wordlist), discoveryLimit))
		seen := map[string]bool{}
		for _, w := range wordlist {
			w = strings.TrimSpace(w)
			if !validWordLabel(w) || seen[strings.ToLower(w)] {
				continue
			}
			seen[strings.ToLower(w)] = true
			labels = append(labels, w)
			if len(labels) >= discoveryLimit {
				break
			}
		}
		sem := make(chan struct{}, 10)
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, label := range labels {
			wg.Add(1)
			sem <- struct{}{}
			go func(l string) {
				defer wg.Done()
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if ips, e := net.DefaultResolver.LookupIPAddr(ctx, l+"."+d); e == nil && len(ips) > 0 {
					mu.Lock()
					found[strings.ToLower(l+"."+d)] = true
					mu.Unlock()
				}
			}(label)
		}
		wg.Wait()
	}
	for n := range found {
		r.Names = append(r.Names, n)
	}
	sortStrings(r.Names)
	if len(r.Names) > discoveryLimit {
		r.Names = r.Names[:discoveryLimit]
	}

	// Check for subdomain takeover clues (dangling CNAMEs)
	r.TakeoverClues = checkTakeoverClues(r.Names)

	_ = a.saveHistory("subdomain", d, r)
	return r
}

// checkTakeoverClues checks discovered subdomains for dangling CNAME records
// pointing to known cloud hosting providers that may indicate takeover risk.
func checkTakeoverClues(subdomains []string) []TakeoverClue {
	var clues []TakeoverClue
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := net.DefaultResolver

	// Known cloud provider CNAME patterns
	providerPatterns := map[string][]struct {
		pattern        string
		provider       string
		checkUnclaimed func(string) (bool, string)
	}{
		"github.io": {
			{pattern: "github.io", provider: "GitHub Pages",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "GitHub Pages: verify the repository exists and has Pages enabled"
				}},
		},
		"herokuapp.com": {
			{pattern: "herokuapp.com", provider: "Heroku",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Heroku: verify the app exists and is not deleted"
				}},
		},
		"vercel.app": {
			{pattern: "vercel.app", provider: "Vercel",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Vercel: verify the project exists and is deployed"
				}},
			{pattern: "now.sh", provider: "Vercel (legacy now.sh)",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Vercel (legacy): verify the project exists"
				}},
		},
		"netlify.app": {
			{pattern: "netlify.app", provider: "Netlify",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Netlify: verify the site exists and is deployed"
				}},
			{pattern: "netlify.com", provider: "Netlify (legacy)",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Netlify: verify the site exists"
				}},
		},
		"amazonaws.com": {
			{pattern: "s3.amazonaws.com", provider: "AWS S3",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "AWS S3: verify the bucket exists and is configured for static website hosting"
				}},
			{pattern: "cloudfront.net", provider: "AWS CloudFront",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "AWS CloudFront: verify the distribution exists"
				}},
			{pattern: "elasticbeanstalk.com", provider: "AWS Elastic Beanstalk",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "AWS Elastic Beanstalk: verify the environment exists"
				}},
		},
		"azure.com": {
			{pattern: "azurewebsites.net", provider: "Azure App Service",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Azure App Service: verify the web app exists"
				}},
			{pattern: "blob.core.windows.net", provider: "Azure Blob Storage",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Azure Blob Storage: verify the storage account and container exist"
				}},
			{pattern: "trafficmanager.net", provider: "Azure Traffic Manager",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Azure Traffic Manager: verify the profile exists"
				}},
		},
		"surge.sh": {
			{pattern: "surge.sh", provider: "Surge.sh",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Surge.sh: verify the project exists"
				}},
		},
		"firebaseapp.com": {
			{pattern: "firebaseapp.com", provider: "Firebase Hosting",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Firebase Hosting: verify the project exists"
				}},
			{pattern: "web.app", provider: "Firebase Hosting (web.app)",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Firebase Hosting: verify the project exists"
				}},
		},
		"gitlab.io": {
			{pattern: "gitlab.io", provider: "GitLab Pages",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "GitLab Pages: verify the project exists and Pages is enabled"
				}},
		},
		"shopify.com": {
			{pattern: "myshopify.com", provider: "Shopify",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Shopify: verify the store exists"
				}},
		},
		"ghost.io": {
			{pattern: "ghost.io", provider: "Ghost",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Ghost: verify the publication exists"
				}},
		},
		"wpengine.com": {
			{pattern: "wpengine.com", provider: "WP Engine",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "WP Engine: verify the site exists"
				}},
		},
		"fastly.net": {
			{pattern: "fastly.net", provider: "Fastly",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Fastly: verify the service exists"
				}},
		},
		"pantheon.io": {
			{pattern: "pantheon.io", provider: "Pantheon",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Pantheon: verify the site exists"
				}},
		},
		"bitbucket.io": {
			{pattern: "bitbucket.io", provider: "Bitbucket Pages",
				checkUnclaimed: func(target string) (bool, string) {
					return true, "Bitbucket Pages: verify the repository exists"
				}},
		},
	}

	for _, sub := range subdomains {
		cnames, err := res.LookupCNAME(ctx, sub)
		if err != nil {
			continue
		}
		cname := strings.TrimSuffix(cnames, ".")
		if cname == "" || cname == sub {
			continue
		}

		matched := false
		for _, patterns := range providerPatterns {
			for _, p := range patterns {
				if strings.Contains(strings.ToLower(cname), p.pattern) {
					// Try to resolve the CNAME target to check if it exists
					ips, err := res.LookupIPAddr(ctx, cname)
					status := "potential"
					evidence := fmt.Sprintf("CNAME points to %s (%s)", cname, p.provider)

					if err != nil || len(ips) == 0 {
						status = "unresolved"
						evidence = fmt.Sprintf("CNAME target %s does not resolve (%s)", cname, p.provider)
					} else {
						// For some providers, we can do additional checks
						// For now, mark as "potential" if it resolves
						// A more thorough check would require HTTP requests
					}

					unclaimed, remediation := p.checkUnclaimed(cname)
					if unclaimed && status == "unresolved" {
						status = "unclaimed"
					}

					clues = append(clues, TakeoverClue{
						Subdomain:   sub,
						CNAMETarget: cname,
						Provider:    p.provider,
						Status:      status,
						Evidence:    evidence,
						Remediation: remediation,
					})
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}
	return clues
}

// FuzzPaths sends bounded HEAD requests only; it never reads response bodies. Redirects are disabled.
func (a *App) FuzzPaths(baseURL string, paths []string, concurrency int, requestDelayMs int, rps int, jitterMs int, userAgent string, timeoutSeconds int, proxyURL string) PathFuzzResult {
	u, err := validateDiscoveryURL(baseURL)
	r := PathFuzzResult{BaseURL: baseURL, Paths: []PathFinding{}}
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if concurrency < 1 {
		concurrency = 5
	}
	if concurrency > discoveryWorkers {
		concurrency = discoveryWorkers
	}
	if requestDelayMs < 0 {
		requestDelayMs = 0
	}
	if requestDelayMs > 5000 {
		requestDelayMs = 5000
	}
	rate := ScanRateControl{RPS: rps, JitterMs: jitterMs}.normalized()
	profile := resolveHTTPRequestProfile(HTTPRequestProfile{UserAgent: userAgent, TimeoutSeconds: timeoutSeconds, ProxyURL: proxyURL})
	ua := profile.UserAgent
	clean := make([]string, 0, min(len(paths), discoveryLimit))
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if !validFuzzPath(p) || seen[p] {
			continue
		}
		seen[p] = true
		clean = append(clean, p)
		if len(clean) >= discoveryLimit {
			break
		}
	}
	client := newScopedHTTPClientForFuzzer(u.String(), profile)
	baselineStatus, baselineLength := 0, int64(-1)
	if req, e := http.NewRequest(http.MethodHead, joinFuzzURL(u, "/__codexa_missing_probe_7f31d9"), nil); e == nil {
		req.Header.Set("User-Agent", ua)
		if resp, e := client.Do(req); e == nil {
			baselineStatus = resp.StatusCode
			baselineLength = resp.ContentLength
			resp.Body.Close()
		}
	}
	sem := make(chan struct{}, concurrency)
	results := make([]PathFinding, len(clean))
	keep := make([]bool, len(clean))
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
	for i, p := range clean {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			if !nextSlot() {
				return
			}
			if requestDelayMs > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(requestDelayMs) * time.Millisecond):
				}
			}
			target := joinFuzzURL(u, p)
			req, e := http.NewRequest(http.MethodHead, target, nil)
			if e != nil {
				return
			}
			req.Header.Set("User-Agent", ua)
			resp, e := client.Do(req)
			if e != nil {
				return
			}
			resp.Body.Close()
			if isInterestingPathStatus(resp.StatusCode) && !isGenericNotFound(resp.StatusCode, resp.ContentLength, baselineStatus, baselineLength) {
				results[i] = PathFinding{URL: target, StatusCode: resp.StatusCode, ContentLength: resp.ContentLength}
				keep[i] = true
			}
		}(i, p)
	}
	wg.Wait()
	for i := range results {
		if keep[i] {
			r.Paths = append(r.Paths, results[i])
		}
	}
	_ = a.saveHistory("fuzzer", u.String(), r)
	return r
}

func isInterestingPathStatus(status int) bool {
	switch status {
	case http.StatusOK, http.StatusNoContent, http.StatusMovedPermanently, http.StatusFound,
		http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
		http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}

func isGenericNotFound(status int, size int64, baselineStatus int, baselineSize int64) bool {
	if baselineStatus == 0 || status != baselineStatus {
		return false
	}
	// When the server omits Content-Length, conservatively treat matching status
	// codes as catch-all responses; otherwise require both status and size to match.
	return baselineSize < 0 || size < 0 || size == baselineSize
}

func newScopedHTTPClientForFuzzer(target string, profile HTTPRequestProfile) *http.Client {
	prof := resolveHTTPRequestProfile(profile)
	return &http.Client{
		Timeout: time.Duration(prof.TimeoutSeconds) * time.Second,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				if prof.ProxyURL == "" {
					return nil, nil
				}
				return url.Parse(prof.ProxyURL)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func joinFuzzURL(base *url.URL, p string) string {
	b := *base
	b.RawQuery = ""
	b.Fragment = ""
	b.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(p, "/")
	return b.String()
}

func (a *App) InspectTLS(target string) TLSInspection {
	target = strings.TrimSpace(target)
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}
	out := TLSInspection{Host: host, Port: port, SANs: []string{}}
	if strings.TrimSpace(host) == "" || strings.ContainsAny(host, "/\\\r\n") {
		out.ValidationError = "invalid host"
		return out
	}
	if p, e := net.LookupPort("tcp", port); e != nil || p < 1 || p > 65535 {
		out.ValidationError = "invalid port"
		return out
	}
	addr := net.JoinHostPort(host, port)
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if e != nil {
		out.ValidationError = e.Error()
		var ua x509.UnknownAuthorityError
		var he x509.HostnameError
		var ci x509.CertificateInvalidError
		if errors.As(e, &ua) || errors.As(e, &he) || errors.As(e, &ci) {
			out.Trusted = false
		}
		// Retry only to inspect the presented certificate after verified validation failed.
		// The result is explicitly marked untrusted; this connection is never used for HTTP.
		diagnostic := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true} //nolint:gosec
		if c, de := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, diagnostic); de == nil {
			state := c.ConnectionState()
			out.TLSVersion = tlsVersionName(state.Version)
			out.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
			fillTLSProtocol(&out, state)
			if len(state.PeerCertificates) > 0 {
				fillTLSCertificate(&out, state.PeerCertificates[0])
			}
			c.Close()
		}
		inspectTLS12WeakCiphers(&out, host, addr)
		inspectHTTP3Advertisement(&out, host, port)
		probeLegacyTLS(&out, host, addr)
		_ = a.saveHistory("tls", net.JoinHostPort(host, port), out)
		return out
	}
	defer conn.Close()
	state := conn.ConnectionState()
	out.TLSVersion = tlsVersionName(state.Version)
	out.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	fillTLSProtocol(&out, state)
	out.Trusted = len(state.VerifiedChains) > 0
	if len(state.PeerCertificates) > 0 {
		fillTLSCertificate(&out, state.PeerCertificates[0])
	}
	inspectTLS12WeakCiphers(&out, host, addr)
	inspectHTTP3Advertisement(&out, host, port)
	probeLegacyTLS(&out, host, addr)
	_ = a.saveHistory("tls", net.JoinHostPort(host, port), out)
	return out
}

func fillTLSProtocol(out *TLSInspection, state tls.ConnectionState) {
	out.NegotiatedProtocol = state.NegotiatedProtocol
	out.HTTP2Supported = state.NegotiatedProtocol == "h2"
	if out.TLSVersion == tlsVersionName(tls.VersionTLS12) && isWeakTLSCipherName(out.CipherSuite) {
		out.WeakCipherWarning = fmt.Sprintf("Negotiated legacy TLS 1.2 cipher %s.", out.CipherSuite)
	}
}

func isWeakTLSCipherName(name string) bool {
	upper := strings.ToUpper(name)
	return strings.Contains(upper, "_CBC_") || strings.Contains(upper, "3DES") || strings.Contains(upper, "RC4") || strings.Contains(upper, "_NULL_")
}

type weakTLS12Cipher struct {
	id   uint16
	name string
}

var weakTLS12Ciphers = []weakTLS12Cipher{
	{id: 0x0005, name: "TLS_RSA_WITH_RC4_128_SHA"},
	{id: 0x000a, name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	{id: 0x002f, name: "TLS_RSA_WITH_AES_128_CBC_SHA"},
	{id: 0x0035, name: "TLS_RSA_WITH_AES_256_CBC_SHA"},
	{id: 0xc008, name: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
	{id: 0xc009, name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
	{id: 0xc00a, name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
	{id: 0xc012, name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	{id: 0xc013, name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
	{id: 0xc014, name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
}

func inspectTLS12WeakCiphers(out *TLSInspection, host, addr string) {
	for _, candidate := range weakTLS12Ciphers {
		cfg := &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{candidate.id},
			InsecureSkipVerify: true, //nolint:gosec -- handshake-only capability probe; never used for HTTP or trust decisions.
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 1200 * time.Millisecond}, "tcp", addr, cfg)
		if err != nil {
			continue
		}
		state := conn.ConnectionState()
		conn.Close()
		if state.Version == tls.VersionTLS12 && state.CipherSuite == candidate.id {
			out.WeakTLS12Ciphers = append(out.WeakTLS12Ciphers, candidate.name)
		}
	}
	sortStrings(out.WeakTLS12Ciphers)
	if len(out.WeakTLS12Ciphers) > 0 && out.WeakCipherWarning == "" {
		out.WeakCipherWarning = "The server accepted one or more legacy TLS 1.2 cipher suites; prefer modern AEAD suites."
	}
}

func inspectHTTP3Advertisement(out *TLSInspection, host, port string) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true, //nolint:gosec -- reads only response headers for a diagnostic; certificate trust is reported separately.
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get("https://" + net.JoinHostPort(host, port) + "/")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	altSvc := resp.Header.Get("Alt-Svc")
	if advertisement := parseHTTP3Advertisement(altSvc); advertisement != "" {
		out.HTTP3Advertised = true
		out.HTTP3Advertisement = advertisement
	}
	if out.NegotiatedProtocol == "" {
		out.NegotiatedProtocol = resp.Proto
		out.HTTP2Supported = resp.ProtoMajor == 2
	}
}

func parseHTTP3Advertisement(altSvc string) string {
	for _, part := range strings.Split(altSvc, ",") {
		value := strings.TrimSpace(part)
		lower := strings.ToLower(value)
		if strings.HasPrefix(lower, "h3=") || strings.HasPrefix(lower, "h3-") || strings.HasPrefix(lower, "h3\"") {
			return value
		}
	}
	return ""
}

func probeLegacyTLS(out *TLSInspection, host, addr string) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		status, detail := probeLegacyTLSVersion(host, addr, version)
		if version == tls.VersionTLS10 {
			out.TLS10Status = status
			out.TLS10Error = detail
		} else {
			out.TLS11Status = status
			out.TLS11Error = detail
		}
	}
}

func probeLegacyTLSVersion(host, addr string, version uint16) (TLSProbeStatus, string) {
	// This skips trust verification for a handshake-only capability probe;
	// the result is never used to trust the server or exchange app data.
	probe := &tls.Config{ServerName: host, MinVersion: version, MaxVersion: version, InsecureSkipVerify: true} //nolint:gosec
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, probe)
	if err != nil {
		return classifyLegacyTLSProbe(version, 0, err)
	}
	defer conn.Close()
	return classifyLegacyTLSProbe(version, conn.ConnectionState().Version, nil)
}

func classifyLegacyTLSProbe(version, negotiatedVersion uint16, err error) (TLSProbeStatus, string) {
	versionName := tlsVersionName(version)
	if err == nil {
		if negotiatedVersion == version {
			return TLSProbeSupported, ""
		}
		return TLSProbeInconclusive, fmt.Sprintf("Probe negotiated %s instead of the requested %s.", tlsVersionName(negotiatedVersion), versionName)
	}
	if errors.Is(err, tls.AlertError(tlsAlertProtocolVersion)) {
		return TLSProbeNotSupported, fmt.Sprintf("TLS peer explicitly rejected %s: %v.", versionName, err)
	}
	return TLSProbeInconclusive, fmt.Sprintf("Could not determine whether %s is supported: %v", versionName, err)
}

func fillTLSCertificate(out *TLSInspection, c *x509.Certificate) {
	out.Subject = c.Subject.String()
	out.Issuer = c.Issuer.String()
	out.NotBefore = c.NotBefore
	out.NotAfter = c.NotAfter
	out.DaysRemaining = int(time.Until(c.NotAfter).Hours() / 24)
	out.SANs = append(out.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out.SANs = append(out.SANs, ip.String())
	}
	out.SelfSigned = c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil && string(c.RawSubject) == string(c.RawIssuer)
}

func (a *App) DNSIntelligence(domain string, includeRDAP bool) DNSIntelligenceResult {
	d, err := validateDiscoveryDomain(domain)
	r := DNSIntelligenceResult{
		Domain: d, A: []string{}, AAAA: []string{}, MX: []string{}, NS: []string{},
		TXT: []string{}, SPF: []string{}, DMARC: []string{}, DKIM: []DKIMRecord{},
		PTR: map[string][]string{}, RDAP: []RDAPInfo{},
	}
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := net.DefaultResolver
	if ips, e := res.LookupIPAddr(ctx, d); e == nil {
		for _, ip := range ips {
			if v := ip.IP.To4(); v != nil {
				r.A = append(r.A, v.String())
			} else {
				r.AAAA = append(r.AAAA, ip.IP.String())
			}
			if ptr, pe := res.LookupAddr(ctx, ip.IP.String()); pe == nil {
				r.PTR[ip.IP.String()] = ptr
			}
			if includeRDAP && len(r.RDAP) < 10 && ip.IP.IsGlobalUnicast() && !ip.IP.IsPrivate() && !ip.IP.IsLoopback() && !ip.IP.IsLinkLocalUnicast() {
				if info, re := lookupRDAP(ip.IP.String()); re == nil {
					r.RDAP = append(r.RDAP, info)
				}
			}
		}
	} else {
		r.Errors = append(r.Errors, "A/AAAA lookup failed")
	}
	if mx, e := res.LookupMX(ctx, d); e == nil {
		for _, v := range mx {
			r.MX = append(r.MX, strings.TrimSuffix(v.Host, ".")+" (pref "+fmt.Sprint(v.Pref)+")")
		}
	}
	if ns, e := res.LookupNS(ctx, d); e == nil {
		for _, v := range ns {
			r.NS = append(r.NS, strings.TrimSuffix(v.Host, "."))
		}
	}
	if txt, e := res.LookupTXT(ctx, d); e == nil {
		for _, v := range txt {
			r.TXT = append(r.TXT, v)
			if strings.HasPrefix(strings.ToLower(v), "v=spf1") {
				r.SPF = append(r.SPF, v)
			}
		}
	}
	if txt, e := res.LookupTXT(ctx, "_dmarc."+d); e == nil {
		r.DMARC = txt
	}

	// DKIM lookup for common selectors
	commonSelectors := []string{"default", "google", "k1", "k2", "selector1", "selector2", "dkim", "mail", "email", "s1", "s2", "2023", "2024"}
	for _, selector := range commonSelectors {
		dkimDomain := selector + "._domainkey." + d
		if txt, e := res.LookupTXT(ctx, dkimDomain); e == nil && len(txt) > 0 {
			for _, v := range txt {
				if strings.HasPrefix(strings.ToLower(v), "v=dkim1") {
					dkimRec := parseDKIMRecord(selector, v)
					r.DKIM = append(r.DKIM, dkimRec)
					break
				}
			}
		}
	}

	sortStrings(r.A)
	sortStrings(r.AAAA)
	sortStrings(r.MX)
	sortStrings(r.NS)
	sortStrings(r.TXT)
	sortStrings(r.SPF)
	sortStrings(r.DMARC)

	// Analyze email security policies
	r.EmailPolicy = analyzeEmailPolicies(r.SPF, r.DMARC, r.DKIM)

	_ = a.saveHistory("dns", d, r)
	return r
}

// IPInformation returns source-labeled, non-geolocational metadata for one IP.
// Public addresses may be enriched through RDAP; private and special-use
// addresses are classified locally and are never sent to the RDAP service.
func (a *App) IPInformation(raw string) IPInformationResult {
	r := IPInformationResult{ReverseDNS: []string{}, Sources: []string{}}
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		r.Errors = append(r.Errors, "enter a valid IPv4 or IPv6 address")
		return r
	}
	r.IP = ip.String()
	r.AddressClass = classifyIPAddress(ip)
	r.Sources = append(r.Sources, "Local address classification")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(ctx, r.IP); err == nil {
		r.ReverseDNS = append(r.ReverseDNS, names...)
		r.Sources = append(r.Sources, "System DNS resolver (PTR)")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		r.Errors = append(r.Errors, "reverse DNS lookup failed")
	}
	if r.AddressClass == "public" {
		if info, err := lookupRDAP(r.IP); err == nil {
			r.RDAP = &info
			r.Sources = append(r.Sources, info.Source)
		} else {
			r.Errors = append(r.Errors, "RDAP lookup failed: "+err.Error())
		}
	} else {
		r.Errors = append(r.Errors, "RDAP is not queried for private or special-use addresses")
	}
	sortStrings(r.ReverseDNS)
	_ = a.saveHistory("ip", r.IP, r)
	return r
}

func classifyIPAddress(ip net.IP) string {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return "special-use"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link-local"
	}
	if ip.IsPrivate() {
		return "private"
	}
	if ip.IsGlobalUnicast() {
		return "public"
	}
	return "special-use"
}

func lookupRDAP(ip string) (RDAPInfo, error) {
	out := RDAPInfo{IP: ip, Source: "rdap.org (RDAP referral)"}
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("stopped after 5 RDAP redirects")
		}
		return nil
	}}
	req, e := http.NewRequest(http.MethodGet, "https://rdap.org/ip/"+url.PathEscape(ip), nil)
	if e != nil {
		return out, e
	}
	resp, e := client.Do(req)
	if e != nil {
		return out, e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("RDAP HTTP %d", resp.StatusCode)
	}
	var raw struct {
		Handle  string `json:"handle"`
		Name    string `json:"name"`
		Country string `json:"country"`
		Start   string `json:"startAddress"`
		End     string `json:"endAddress"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&raw); e != nil {
		return out, e
	}
	out.NetworkHandle = raw.Handle
	out.Name = raw.Name
	out.Country = raw.Country
	return out, nil
}
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func parseDKIMRecord(selector, record string) DKIMRecord {
	dkim := DKIMRecord{Selector: selector, Record: record}
	// Parse v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "k=") {
			dkim.KeyType = strings.TrimPrefix(part, "k=")
		}
		if strings.HasPrefix(part, "p=") {
			pubKey := strings.TrimPrefix(part, "p=")
			// Estimate key size from base64 encoded public key
			if len(pubKey) > 0 {
				decoded, err := base64.StdEncoding.DecodeString(pubKey)
				if err == nil && len(decoded) > 0 {
					// Rough estimation: RSA key size in bits ≈ (decoded bytes - overhead) * 8
					// For RSA, the modulus is typically the bulk of the key
					dkim.KeySize = estimateRSAKeySize(decoded)
				}
			}
		}
		if strings.HasPrefix(part, "h=") {
			dkim.Note = "hash: " + strings.TrimPrefix(part, "h=")
		}
		if strings.HasPrefix(part, "s=") {
			if dkim.Note != "" {
				dkim.Note += ", "
			}
			dkim.Note += "service: " + strings.TrimPrefix(part, "s=")
		}
	}
	if dkim.KeySize > 0 && dkim.KeySize < 2048 {
		dkim.Note += " (key size < 2048 bits, considered weak)"
	}
	return dkim
}

func estimateRSAKeySize(der []byte) int {
	// Very rough estimation: try to parse as ASN.1 DER to find modulus
	// For simplicity, use length-based estimation
	// Typical RSA public key DER: SEQUENCE { modulus INTEGER, exponent INTEGER }
	// modulus length in bytes ≈ key size / 8
	if len(der) > 100 {
		// Modulus is usually the largest component
		return (len(der) - 20) * 8 // rough estimate
	}
	return 0
}

func analyzeEmailPolicies(spfRecords, dmarcRecords []string, dkimRecords []DKIMRecord) *EmailPolicyAnalysis {
	analysis := &EmailPolicyAnalysis{
		SPF:   analyzeSPF(spfRecords),
		DMARC: analyzeDMARC(dmarcRecords),
		DKIM:  analyzeDKIM(dkimRecords),
	}
	analysis.Rating = calculateEmailPolicyRating(analysis)
	return analysis
}

func analyzeSPF(records []string) SPFAnalysis {
	result := SPFAnalysis{}
	if len(records) == 0 {
		result.Warnings = append(result.Warnings, "No SPF record found")
		return result
	}
	record := records[0] // Use first SPF record
	result.Record = record
	result.HasSPF = true

	// Parse mechanisms
	parts := strings.Fields(record)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)

		// Check all mechanism
		if lower == "+all" || lower == "~all" || lower == "-all" || lower == "?all" {
			result.AllMechanism = part
			if lower == "+all" {
				result.Warnings = append(result.Warnings, "SPF uses '+all' (allows any sender) - HIGH RISK")
			} else if lower == "~all" {
				result.Warnings = append(result.Warnings, "SPF uses '~all' (soft fail) - consider '-all' for stricter policy")
			}
		}

		// Check includes
		if strings.HasPrefix(lower, "include:") {
			result.Includes = append(result.Includes, strings.TrimPrefix(part, "include:"))
		}

		// Check redirects
		if strings.HasPrefix(lower, "redirect=") {
			result.Redirects = append(result.Redirects, strings.TrimPrefix(part, "redirect="))
		}

		// Check for weak mechanisms
		if strings.HasPrefix(lower, "ip4:") || strings.HasPrefix(lower, "ip6:") {
			// These are fine, just note them
		}
		if strings.HasPrefix(lower, "a") || strings.HasPrefix(lower, "mx") || strings.HasPrefix(lower, "ptr") {
			result.WeakMechanisms = append(result.WeakMechanisms, part)
		}
		// Check for deprecated "ptr" mechanism
		if lower == "ptr" {
			result.Warnings = append(result.Warnings, "SPF uses deprecated 'ptr' mechanism")
		}
	}

	// Check for missing all mechanism
	if result.AllMechanism == "" {
		result.Warnings = append(result.Warnings, "SPF record missing 'all' mechanism (defaults to '?all' - neutral)")
	}

	return result
}

func analyzeDMARC(records []string) DMARCAnalysis {
	result := DMARCAnalysis{}
	if len(records) == 0 {
		result.Warnings = append(result.Warnings, "No DMARC record found (_dmarc subdomain missing)")
		return result
	}
	record := records[0]
	result.Record = record
	result.HasDMARC = true

	// Parse DMARC tags
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)

		if strings.HasPrefix(lower, "p=") {
			result.Policy = strings.TrimPrefix(part, "p=")
			if result.Policy == "none" {
				result.Warnings = append(result.Warnings, "DMARC policy is 'p=none' (monitor only) - consider 'p=quarantine' or 'p=reject'")
			} else if result.Policy == "quarantine" {
				result.Warnings = append(result.Warnings, "DMARC policy is 'p=quarantine' - consider 'p=reject' for strongest protection")
			}
		}
		if strings.HasPrefix(lower, "sp=") {
			result.SubdomainPolicy = strings.TrimPrefix(part, "sp=")
		}
		if strings.HasPrefix(lower, "pct=") {
			if pct, err := strconv.Atoi(strings.TrimPrefix(part, "pct=")); err == nil {
				result.Percent = pct
				if pct < 100 {
					result.Warnings = append(result.Warnings, fmt.Sprintf("DMARC percent is %d%% (not 100%%)", pct))
				}
			}
		}
		if strings.HasPrefix(lower, "rua=") {
			result.RUA = append(result.RUA, strings.TrimPrefix(part, "rua="))
		}
		if strings.HasPrefix(lower, "ruf=") {
			result.RUF = append(result.RUF, strings.TrimPrefix(part, "ruf="))
		}
		if strings.HasPrefix(lower, "aspf=") {
			result.Alignment.SPF = strings.TrimPrefix(part, "aspf=")
		}
		if strings.HasPrefix(lower, "adkim=") {
			result.Alignment.DKIM = strings.TrimPrefix(part, "adkim=")
		}
	}

	// Default values if not specified
	if result.Policy == "" {
		result.Policy = "none"
		result.Warnings = append(result.Warnings, "DMARC policy tag 'p=' missing (defaults to 'none')")
	}
	if result.Percent == 0 {
		result.Percent = 100
	}
	if result.Alignment.SPF == "" {
		result.Alignment.SPF = "r"
	}
	if result.Alignment.DKIM == "" {
		result.Alignment.DKIM = "r"
	}

	return result
}

func analyzeDKIM(records []DKIMRecord) DKIMAnalysis {
	result := DKIMAnalysis{
		RecordsFound: len(records),
		Selectors:    make([]string, 0, len(records)),
		KeyTypes:     make([]string, 0, len(records)),
		KeySizes:     make([]int, 0, len(records)),
	}
	seenSelectors := make(map[string]bool)
	seenKeyTypes := make(map[string]bool)
	seenKeySizes := make(map[int]bool)

	for _, rec := range records {
		if !seenSelectors[rec.Selector] {
			seenSelectors[rec.Selector] = true
			result.Selectors = append(result.Selectors, rec.Selector)
		}
		if rec.KeyType != "" && !seenKeyTypes[rec.KeyType] {
			seenKeyTypes[rec.KeyType] = true
			result.KeyTypes = append(result.KeyTypes, rec.KeyType)
		}
		if rec.KeySize > 0 && !seenKeySizes[rec.KeySize] {
			seenKeySizes[rec.KeySize] = true
			result.KeySizes = append(result.KeySizes, rec.KeySize)
			if rec.KeySize < 2048 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("DKIM selector '%s' uses %d-bit key (recommend >= 2048 bits)", rec.Selector, rec.KeySize))
			}
		}
		if rec.Note != "" {
			result.Warnings = append(result.Warnings, rec.Note)
		}
	}

	if len(records) == 0 {
		result.Warnings = append(result.Warnings, "No DKIM records found for common selectors (checked: default, google, k1, k2, selector1, selector2, dkim, mail, email, s1, s2, 2023, 2024)")
	} else if len(records) == 1 {
		result.Warnings = append(result.Warnings, "Only one DKIM selector found - consider multiple selectors for key rotation")
	}

	return result
}

func calculateEmailPolicyRating(analysis *EmailPolicyAnalysis) string {
	score := 0
	maxScore := 0

	// SPF scoring (max 3)
	maxScore += 3
	if analysis.SPF.HasSPF {
		score += 1
		if analysis.SPF.AllMechanism == "-all" {
			score += 2
		} else if analysis.SPF.AllMechanism == "~all" {
			score += 1
		} else if analysis.SPF.AllMechanism == "+all" {
			score -= 1 // penalty
		}
	}

	// DMARC scoring (max 4)
	maxScore += 4
	if analysis.DMARC.HasDMARC {
		score += 1
		if analysis.DMARC.Policy == "reject" {
			score += 3
		} else if analysis.DMARC.Policy == "quarantine" {
			score += 2
		} else if analysis.DMARC.Policy == "none" {
			score += 0
		}
		if analysis.DMARC.Percent == 100 {
			score += 1
		}
	}

	// DKIM scoring (max 3)
	maxScore += 3
	if analysis.DKIM.RecordsFound > 0 {
		score += 1
		strongKeys := 0
		for _, size := range analysis.DKIM.KeySizes {
			if size >= 2048 {
				strongKeys++
			}
		}
		if strongKeys > 0 {
			score += 1
		}
		if analysis.DKIM.RecordsFound > 1 {
			score += 1
		}
	}

	// Calculate percentage
	if maxScore == 0 {
		return "missing"
	}
	pct := float64(score) / float64(maxScore)
	if pct >= 0.8 {
		return "strong"
	} else if pct >= 0.5 {
		return "moderate"
	} else if pct >= 0.2 {
		return "weak"
	}
	return "missing"
}
