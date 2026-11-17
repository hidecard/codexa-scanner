package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const discoveryLimit = 500
const discoveryWorkers = 20

// SubdomainResult contains names found passively and, when requested, by DNS wordlist probing.
type SubdomainResult struct {
	Domain string   `json:"domain"`
	Names  []string `json:"names"`
	Errors []string `json:"errors,omitempty"`
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
	Host            string         `json:"host"`
	Port            string         `json:"port"`
	Subject         string         `json:"subject"`
	Issuer          string         `json:"issuer"`
	NotBefore       time.Time      `json:"notBefore"`
	NotAfter        time.Time      `json:"notAfter"`
	DaysRemaining   int            `json:"daysRemaining"`
	SANs            []string       `json:"sans"`
	SelfSigned      bool           `json:"selfSigned"`
	Trusted         bool           `json:"trusted"`
	ValidationError string         `json:"validationError,omitempty"`
	TLSVersion      string         `json:"tlsVersion"`
	CipherSuite     string         `json:"cipherSuite"`
	TLS10Status     TLSProbeStatus `json:"tls10Status"`
	TLS11Status     TLSProbeStatus `json:"tls11Status"`
	TLS10Error      string         `json:"tls10Error,omitempty"`
	TLS11Error      string         `json:"tls11Error,omitempty"`
}
type DNSIntelligenceResult struct {
	Domain string              `json:"domain"`
	A      []string            `json:"a"`
	AAAA   []string            `json:"aaaa"`
	MX     []string            `json:"mx"`
	NS     []string            `json:"ns"`
	TXT    []string            `json:"txt"`
	SPF    []string            `json:"spf"`
	DMARC  []string            `json:"dmarc"`
	PTR    map[string][]string `json:"ptr"`
	RDAP   []RDAPInfo          `json:"rdap,omitempty"`
	Errors []string            `json:"errors,omitempty"`
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
	ReverseDNS  []string  `json:"reverseDns"`
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
	_ = a.saveHistory("subdomain", d, r)
	return r
}

// FuzzPaths sends bounded HEAD requests only; it never reads response bodies. Redirects are disabled.
func (a *App) FuzzPaths(baseURL string, paths []string, concurrency int, requestDelayMs int) PathFuzzResult {
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
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Use a random-looking missing resource to identify generic catch-all responses, using HEAD only.
	baselineStatus := 0
	baselineLength := int64(-1)
	if req, e := http.NewRequest(http.MethodHead, joinFuzzURL(u, "/__codexa_missing_probe_7f31d9"), nil); e == nil {
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
	for i, p := range clean {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			if requestDelayMs > 0 {
				time.Sleep(time.Duration(requestDelayMs) * time.Millisecond)
			}
			target := joinFuzzURL(u, p)
			req, e := http.NewRequest(http.MethodHead, target, nil)
			if e != nil {
				return
			}
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
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13}
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
		diagnostic := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true} //nolint:gosec
		if c, de := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, diagnostic); de == nil {
			state := c.ConnectionState()
			out.TLSVersion = tlsVersionName(state.Version)
			out.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
			if len(state.PeerCertificates) > 0 {
				fillTLSCertificate(&out, state.PeerCertificates[0])
			}
			c.Close()
		}
		probeLegacyTLS(&out, host, addr)
		_ = a.saveHistory("tls", net.JoinHostPort(host, port), out)
		return out
	}
	defer conn.Close()
	state := conn.ConnectionState()
	out.TLSVersion = tlsVersionName(state.Version)
	out.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	out.Trusted = len(state.VerifiedChains) > 0
	if len(state.PeerCertificates) > 0 {
		fillTLSCertificate(&out, state.PeerCertificates[0])
	}
	probeLegacyTLS(&out, host, addr)
	_ = a.saveHistory("tls", net.JoinHostPort(host, port), out)
	return out
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
		TXT: []string{}, SPF: []string{}, DMARC: []string{}, PTR: map[string][]string{},
		RDAP: []RDAPInfo{},
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
	sortStrings(r.A)
	sortStrings(r.AAAA)
	sortStrings(r.MX)
	sortStrings(r.NS)
	sortStrings(r.TXT)
	sortStrings(r.SPF)
	sortStrings(r.DMARC)
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
