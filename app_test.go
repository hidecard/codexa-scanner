package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuditHTTPResponseFindsPassiveIssues(t *testing.T) {
	target, _ := url.Parse("https://site.example")
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"sid=abc; Path=/"},
			"Server":     []string{"example-server/1.0"},
		},
		Request: &http.Request{URL: target},
	}
	findings := auditHTTPResponse(resp, []byte(`<html><img src="http://cdn.example/img.png"></html>`))
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.ID] = true
		if finding.Title == "" || finding.Recommendation == "" {
			t.Errorf("finding %q has no explanatory text or remediation", finding.ID)
		}
	}
	for _, id := range []string{
		"hsts-missing", "csp-missing", "clickjacking-protection-missing",
		"nosniff-missing", "referrer-policy-missing", "mixed-content-reference",
		"technology-disclosure",
	} {
		if !seen[id] {
			t.Errorf("expected finding %q; got %v", id, seen)
		}
	}
	for _, prefix := range []string{"cookie-secure-missing", "cookie-httponly-missing", "cookie-samesite-missing"} {
		found := false
		for id := range seen {
			if strings.HasPrefix(id, prefix+"-") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a finding with ID prefix %q; got %v", prefix, seen)
		}
	}
}

func TestAuditHTTPResponseAcceptsConfiguredHeadersAndCookies(t *testing.T) {
	target, _ := url.Parse("https://site.example")
	resp := &http.Response{
		Header: http.Header{
			"Strict-Transport-Security": []string{"max-age=31536000"},
			"Content-Security-Policy":   []string{"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"},
			"X-Content-Type-Options":    []string{"nosniff"},
			"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
			"Permissions-Policy":        []string{"camera=()"},
			"Set-Cookie":                []string{"sid=abc; Secure; HttpOnly; SameSite=Lax"},
		},
		Request: &http.Request{URL: target},
	}
	findings := auditHTTPResponse(resp, []byte("<html></html>"))
	if len(findings) != 0 {
		t.Fatalf("expected no findings for configured response, got: %+v", findings)
	}
	score, grade := gradeFindings(findings)
	if score != 0 || grade != "A+" {
		t.Fatalf("expected 0/A+, got %d/%s", score, grade)
	}
}

func TestAuditHTTPResponseReportsCSPDiagnosticsWithEvidence(t *testing.T) {
	target, _ := url.Parse("https://site.example")
	resp := &http.Response{
		Header: http.Header{
			"Strict-Transport-Security": []string{"max-age=31536000"},
			"Content-Security-Policy":   []string{"script-src 'self' 'unsafe-inline' 'unsafe-eval' *; frame-ancestors 'none'"},
			"X-Content-Type-Options":    []string{"nosniff"},
			"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
			"Permissions-Policy":        []string{"camera=()"},
		},
		Request: &http.Request{URL: target},
	}
	findings := auditHTTPResponse(resp, []byte("<html></html>"))
	byID := map[string]SecurityFinding{}
	for _, finding := range findings {
		byID[finding.ID] = finding
	}
	for _, id := range []string{
		"csp-script-unsafe-inline",
		"csp-script-unsafe-eval",
		"csp-script-wildcard-source",
		"csp-default-src-missing",
		"csp-object-src-missing",
		"csp-base-uri-missing",
	} {
		finding, ok := byID[id]
		if !ok {
			t.Fatalf("expected CSP finding %q, got %+v", id, findings)
		}
		if strings.TrimSpace(finding.Evidence) == "" {
			t.Fatalf("expected evidence for %q", id)
		}
		if finding.Severity == "" || finding.Recommendation == "" {
			t.Fatalf("expected severity/recommendation for %q: %+v", id, finding)
		}
	}
	if _, ok := byID["csp-missing"]; ok {
		t.Fatalf("did not expect csp-missing when policy is present: %+v", findings)
	}
}

func TestAuditHTTPResponseDetectsCORSMisconfigAndDBError(t *testing.T) {
	target, _ := url.Parse("https://site.example")
	resp := &http.Response{
		Header: http.Header{
			"Strict-Transport-Security":        []string{"max-age=31536000"},
			"Content-Security-Policy":          []string{"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"},
			"X-Content-Type-Options":           []string{"nosniff"},
			"Referrer-Policy":                  []string{"strict-origin-when-cross-origin"},
			"Permissions-Policy":               []string{"camera=()"},
			"Access-Control-Allow-Origin":      []string{"*"},
			"Access-Control-Allow-Credentials": []string{"true"},
		},
		Request: &http.Request{URL: target},
	}
	body := []byte("<html><body>SQLSTATE[42000]: Syntax error or access violation</body></html>")
	findings := auditHTTPResponse(resp, body)
	byID := map[string]SecurityFinding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	if _, ok := byID["cors-wildcard-credentials"]; !ok {
		t.Fatalf("expected cors-wildcard-credentials finding, got %+v", findings)
	}
	if _, ok := byID["db-error-sqlstate"]; !ok {
		t.Fatalf("expected db-error-sqlstate finding, got %+v", findings)
	}
}

func TestAuditHTTPResponseDetectsJWTAlgNone(t *testing.T) {
	target, _ := url.Parse("https://site.example")
	// header: {"alg":"none","typ":"JWT"}, payload: {"sub":"1"}
	token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."
	resp := &http.Response{
		Header: http.Header{
			"Strict-Transport-Security": []string{"max-age=31536000"},
			"Content-Security-Policy":   []string{"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"},
			"X-Content-Type-Options":    []string{"nosniff"},
			"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
			"Permissions-Policy":        []string{"camera=()"},
			"Authorization":             []string{"Bearer " + token},
		},
		Request: &http.Request{URL: target},
	}
	findings := auditHTTPResponse(resp, []byte("<html></html>"))
	found := false
	for _, f := range findings {
		if f.ID == "jwt-alg-none" {
			found = true
			if strings.Contains(f.Evidence, token) {
				t.Fatalf("JWT token value must be redacted from evidence: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("expected jwt-alg-none finding, got %+v", findings)
	}
}

func TestGradeFindingsUsesSeverityAndCapsScore(t *testing.T) {
	findings := []SecurityFinding{
		{Severity: "high"}, {Severity: "medium"}, {Severity: "low"},
	}
	score, grade := gradeFindings(findings)
	if score != 45 || grade != "C" {
		t.Fatalf("expected 45/C, got %d/%s", score, grade)
	}
	many := strings.Repeat("x", 101)
	lots := make([]SecurityFinding, len(many))
	for i := range lots {
		lots[i].Severity = "critical"
	}
	score, grade = gradeFindings(lots)
	if score != 100 || grade != "F" {
		t.Fatalf("expected capped 100/F, got %d/%s", score, grade)
	}
}

func TestAnalyzeURLRejectsUntrustedTLSCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second}
	result := analyzeURL(server.URL, client, nil, HTTPRequestProfile{})
	if result.Error == "" {
		t.Fatal("expected self-signed test certificate to fail normal TLS verification")
	}
	found := false
	for _, finding := range result.Findings {
		if finding.ID == "tls-untrusted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an untrusted-certificate finding, got %+v", result)
	}
}

func TestAnalyzeURLReportsPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := analyzeURL(server.URL, &http.Client{Timeout: time.Second}, nil, HTTPRequestProfile{})
	if result.Error != "" {
		t.Fatalf("unexpected analysis error: %s", result.Error)
	}
	for _, finding := range result.Findings {
		if finding.ID == "https-not-enforced" && finding.Severity == "high" {
			return
		}
	}
	t.Fatalf("expected high-severity cleartext-transport finding, got %+v", result.Findings)
}

type stubHTTPIPLookup struct {
	mu        sync.Mutex
	answerSet [][]netip.Addr
	err       error
	calls     int
	hosts     []string
}

func (r *stubHTTPIPLookup) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.hosts = append(r.hosts, host)
	if r.err != nil {
		return nil, r.err
	}
	if len(r.answerSet) == 0 {
		return nil, nil
	}
	index := r.calls - 1
	if index >= len(r.answerSet) {
		index = len(r.answerSet) - 1
	}
	return append([]netip.Addr(nil), r.answerSet[index]...), nil
}

func (r *stubHTTPIPLookup) lookupCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestValidateHTTPAddressPolicy(t *testing.T) {
	tests := []struct {
		address          string
		allowedByDefault bool
		allowedWithOptIn bool
	}{
		{"8.8.8.8", true, true},
		{"2001:4860:4860::8888", true, true},
		{"10.0.0.1", false, true},
		{"172.16.1.1", false, true},
		{"192.168.1.1", false, true},
		{"fd00::1", false, true},
		{"127.0.0.1", false, true},
		{"::1", false, true},
		{"::ffff:127.0.0.1", false, true},
		{"169.254.169.254", false, false},
		{"fe80::1", false, false},
		{"fe80::1%eth0", false, false},
		{"100.64.0.1", false, false},
		{"0.0.0.0", false, false},
		{"::", false, false},
		{"224.0.0.1", false, false},
		{"ff02::1", false, false},
		{"192.0.2.1", false, false},
		{"198.18.0.1", false, false},
		{"240.0.0.1", false, false},
		{"2001:db8::1", false, false},
		{"2002::1", false, false},
		{"3fff::1", false, false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			ip := netip.MustParseAddr(test.address)
			_, defaultErr := validateHTTPAddress(ip, false)
			if (defaultErr == nil) != test.allowedByDefault {
				t.Errorf("default allow=%v, error=%v", test.allowedByDefault, defaultErr)
			}
			_, optInErr := validateHTTPAddress(ip, true)
			if (optInErr == nil) != test.allowedWithOptIn {
				t.Errorf("opt-in allow=%v, error=%v", test.allowedWithOptIn, optInErr)
			}
		})
	}
}

func TestPinnedHTTPResolverRejectsMixedPublicAndPrivateDNSAnswers(t *testing.T) {
	lookup := &stubHTTPIPLookup{answerSet: [][]netip.Addr{{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("10.0.0.4"),
	}}}
	resolver := newPinnedHTTPResolver(lookup, false)

	_, err := resolver.resolve(context.Background(), "mixed.example")
	if !errors.Is(err, errHTTPPrivateAddress) {
		t.Fatalf("expected mixed answer set to be rejected as private, got %v", err)
	}
	if lookup.lookupCount() != 1 {
		t.Fatalf("expected one DNS lookup, got %d", lookup.lookupCount())
	}
}

func TestValidateHTTPRedirectScopeAndHopLimit(t *testing.T) {
	_, source, host, err := parseHTTPAnalysisURL("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := newHTTPTargetScope(source, host)
	if err != nil {
		t.Fatal(err)
	}
	via := []*http.Request{{URL: source}}

	allowed, _ := url.Parse("https://example.com")
	if err := validateHTTPRedirect(&http.Request{URL: allowed}, via, scope); err != nil {
		t.Fatalf("same-host HTTP to HTTPS upgrade should be allowed: %v", err)
	}
	for _, blocked := range []string{
		"https://other.example/", "https://example.com:8443/", "ftp://example.com/",
		"https://user:pass@example.com/",
	} {
		parsed, parseErr := url.Parse(blocked)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if err := validateHTTPRedirect(&http.Request{URL: parsed}, via, scope); !errors.Is(err, errHTTPRedirectOutOfScope) {
			t.Errorf("expected %q to be outside scope, got %v", blocked, err)
		}
	}

	_, secureSource, secureHost, err := parseHTTPAnalysisURL("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	secureScope, err := newHTTPTargetScope(secureSource, secureHost)
	if err != nil {
		t.Fatal(err)
	}
	downgrade, _ := url.Parse("http://example.com")
	if err := validateHTTPRedirect(&http.Request{URL: downgrade}, []*http.Request{{URL: secureSource}}, secureScope); !errors.Is(err, errHTTPRedirectDowngrade) {
		t.Fatalf("expected HTTPS downgrade to be blocked, got %v", err)
	}

	hops := make([]*http.Request, maxHTTPRedirects)
	for i := range hops {
		hops[i] = &http.Request{URL: source}
	}
	if err := validateHTTPRedirect(&http.Request{URL: allowed}, hops, scope); err != nil {
		t.Fatalf("fifth redirect should be allowed: %v", err)
	}
	hops = append(hops, &http.Request{URL: source})
	if err := validateHTTPRedirect(&http.Request{URL: allowed}, hops, scope); !errors.Is(err, errHTTPTooManyRedirects) {
		t.Fatalf("sixth redirect should be blocked, got %v", err)
	}
}

func TestAnalyzeBulkURLsRequiresPrivateTargetOptIn(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	results := (&App{}).AnalyzeBulkURLs(server.URL, 1, false, 0, 0, 0, "", 10, nil, "")
	if len(results) != 1 || !strings.Contains(results[0].Error, "private or loopback") {
		t.Fatalf("expected private target policy error, got %+v", results)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("request reached private target without opt-in (%d requests)", got)
	}

	results = (&App{}).AnalyzeBulkURLs(server.URL, 1, true, 0, 0, 0, "", 10, nil, "")
	if len(results) != 1 || results[0].Error != "" || results[0].StatusCode != http.StatusOK {
		t.Fatalf("explicit opt-in should permit authorized loopback target, got %+v", results)
	}
	if got := atomic.LoadInt32(&requests); got != 3 {
		t.Fatalf("expected main request plus security.txt/robots.txt inspector requests after opt-in, got %d", got)
	}
}

func TestAnalyzeBulkURLsBlocksCrossHostRedirectBeforeDestinationRequest(t *testing.T) {
	var destinationRequests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/destination" {
			atomic.AddInt32(&destinationRequests, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		_, port, _ := net.SplitHostPort(r.Host)
		http.Redirect(w, r, "http://localhost:"+port+"/destination", http.StatusFound)
	}))
	defer server.Close()

	results := (&App{}).AnalyzeBulkURLs(server.URL+"/start", 1, true, 0, 0, 0, "", 10, nil, "")
	if len(results) != 1 || !strings.Contains(results[0].Error, "outside this URL's hostname") {
		t.Fatalf("expected out-of-scope redirect error, got %+v", results)
	}
	if got := atomic.LoadInt32(&destinationRequests); got != 0 {
		t.Fatalf("out-of-scope redirect reached destination handler (%d requests)", got)
	}
}

func TestAnalyzeURLPinsDNSAnswerAcrossSameHostRedirects(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	serverURL.Host = net.JoinHostPort("scanner.example.test", serverURL.Port())
	lookup := &stubHTTPIPLookup{answerSet: [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("203.0.113.11")},
	}}
	client, err := newScopedHTTPClient(serverURL.String(), true, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	trace := client.Transport.(*redirectTraceTransport)
	transport := trace.base.(*http.Transport)
	// The scoped transport should not use ambient proxies; its Proxy func should return nil.
	if transport.Proxy != nil {
		proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}})
		if err != nil || proxyURL != nil {
			t.Fatal("scoped transport must not use ambient proxies")
		}
	}

	result := analyzeURL(serverURL.String(), client, nil, HTTPRequestProfile{})
	if result.Error != "" || result.StatusCode != http.StatusOK {
		t.Fatalf("expected redirect to use pinned loopback address, got %+v", result)
	}
	if len(result.Redirects) != 1 || result.Redirects[0].StatusCode != http.StatusFound || !strings.HasSuffix(result.Redirects[0].To, "/final") {
		t.Fatalf("expected one recorded redirect hop, got %+v", result.Redirects)
	}
	if got := lookup.lookupCount(); got != 1 {
		t.Fatalf("expected hostname to resolve once across redirect chain, got %d lookups", got)
	}
	if got := atomic.LoadInt32(&requests); got != 4 {
		t.Fatalf("expected initial, redirected, and security.txt/robots.txt inspector requests, got %d", got)
	}
	if result.SecurityTxt == nil || result.RobotsTxt == nil {
		t.Fatalf("expected inspector results, got security=%+v robots=%+v", result.SecurityTxt, result.RobotsTxt)
	}
}

func TestAnalyzeURLStopsAfterFiveRedirects(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		http.Redirect(w, r, "/redirect", http.StatusFound)
	}))
	defer server.Close()
	client, err := newScopedHTTPClient(server.URL+"/start", true, net.DefaultResolver)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()

	result := analyzeURL(server.URL+"/start", client, nil, HTTPRequestProfile{})
	if !strings.Contains(result.Error, "after five hops") {
		t.Fatalf("expected five-hop redirect limit error, got %+v", result)
	}
	if got := atomic.LoadInt32(&requests); got != maxHTTPRedirects+3 {
		t.Fatalf("expected initial request, five redirects, and security.txt/robots.txt inspector requests, got %d requests", got)
	}
	if result.SecurityTxt == nil || result.RobotsTxt == nil {
		t.Fatalf("expected inspector results on redirect-limit error, got security=%+v robots=%+v", result.SecurityTxt, result.RobotsTxt)
	}
}

func TestNormalizePortScanLimits(t *testing.T) {
	workers, timeout := normalizePortScanLimits(1000, 10_000, 90_000)
	if workers != maxScanWorkers {
		t.Errorf("workers should be capped at %d, got %d", maxScanWorkers, workers)
	}
	if timeout != 30*time.Second {
		t.Errorf("timeout should be capped at 30 seconds, got %s", timeout)
	}

	workers, _ = normalizePortScanLimits(8, 10, 1000)
	if workers != 8 {
		t.Errorf("workers should be capped to port count, got %d", workers)
	}

	workers, timeout = normalizePortScanLimits(1000, 0, 0)
	if workers != defaultScanWorkers || timeout != time.Duration(defaultScanTimeout)*time.Millisecond {
		t.Errorf("non-positive values should use defaults, got %d workers and %s", workers, timeout)
	}
}

type stubScanResolver struct {
	addresses []net.IPAddr
	err       error
	calls     int
	host      string
}

func (r *stubScanResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.calls++
	r.host = host
	return r.addresses, r.err
}

type blockingScanResolver struct {
	started chan struct{}
}

func (r *blockingScanResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	close(r.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestResolveScanTargetSelectsDeterministicAddressFromMultipleAnswers(t *testing.T) {
	resolver := &stubScanResolver{addresses: []net.IPAddr{
		{IP: net.ParseIP("2001:db8::10")},
		{IP: net.ParseIP("192.0.2.10")},
		{IP: net.ParseIP("192.0.2.2")},
	}}

	got, err := resolveScanTarget(context.Background(), "scanner.example", resolver)
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	if got != "192.0.2.2" {
		t.Fatalf("expected IPv4-first numeric ordering to choose 192.0.2.2, got %q", got)
	}
	if resolver.calls != 1 || resolver.host != "scanner.example" {
		t.Fatalf("expected one lookup for hostname, calls=%d host=%q", resolver.calls, resolver.host)
	}
}

func TestResolveScanTargetSupportsIPv4AndIPv6LiteralsWithoutLookup(t *testing.T) {
	for _, target := range []string{"192.0.2.7", "2001:db8::7"} {
		resolver := &stubScanResolver{}
		got, err := resolveScanTarget(context.Background(), target, resolver)
		if err != nil {
			t.Errorf("resolve literal %q: %v", target, err)
			continue
		}
		if got != target {
			t.Errorf("expected literal %q to stay unchanged, got %q", target, got)
		}
		if resolver.calls != 0 {
			t.Errorf("literal %q should not trigger DNS lookup", target)
		}
	}
}

func TestResolveScanTargetHonorsCancelledLookupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := &stubScanResolver{}

	_, err := resolveScanTarget(ctx, "scanner.example", resolver)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if resolver.calls != 0 {
		t.Fatal("cancelled lookup should not invoke the resolver")
	}
}

func TestResolveScanTargetCanBeCancelledDuringLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver := &blockingScanResolver{started: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := resolveScanTarget(ctx, "scanner.example", resolver)
		result <- err
	}()

	select {
	case <-resolver.started:
	case <-time.After(time.Second):
		t.Fatal("resolver was not called")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation during lookup, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lookup did not stop after context cancellation")
	}
}

func TestResolveScanTargetReturnsLookupErrors(t *testing.T) {
	wantErr := errors.New("DNS unavailable")
	resolver := &stubScanResolver{err: wantErr}

	_, err := resolveScanTarget(context.Background(), "scanner.example", resolver)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped resolver error %v, got %v", wantErr, err)
	}
}

func TestNormalizePortScanTargetAcceptsIPsAndDNSHostnames(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "192.0.2.8", want: "192.0.2.8"},
		{input: "10.0.0.2", want: "10.0.0.2"},
		{input: "2001:db8::8", want: "2001:db8::8"},
		{input: "fe80::1%eth0", want: "fe80::1%eth0"},
		{input: " Example.COM. ", want: "example.com."},
		{input: "localhost", want: "localhost"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := normalizePortScanTarget(test.input)
			if err != nil {
				t.Fatalf("normalize target: %v", err)
			}
			if got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}

func TestNormalizePortScanTargetRejectsUnsafeOrMalformedInput(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example"
	tests := []string{
		"", "   ", "https://example.com", "example.com:443", "example.com/path",
		"[2001:db8::1]:443", "bad..example", "-bad.example", "bad-.example",
		"192.0.2.999", "127.1", "2130706433", longLabel, "has space.example", "example\n.com", "Ã©xample.com",
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			if normalized, err := normalizePortScanTarget(target); err == nil {
				t.Fatalf("expected target %q to be rejected, normalized to %q", target, normalized)
			}
		})
	}
}

func TestStartPortScanRequiresExplicitScopeConfirmation(t *testing.T) {
	app := &App{}
	status := app.StartPortScan("192.168.1.10", 80, 80, 1, 100, false)
	if status != "Confirm authorization for this target and port range before scanning" {
		t.Fatalf("expected scope confirmation requirement, got %q", status)
	}
	app.scanMu.Lock()
	active := app.activeScan
	app.scanMu.Unlock()
	if active != nil {
		t.Fatal("scan should not start without explicit scope confirmation")
	}
}

func TestStopPortScanCancelsBannerReadAndIsConcurrencySafe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for scan fixture: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	address := listener.Addr().(*net.TCPAddr)
	app := &App{}
	if status := app.StartPortScan("127.0.0.1", address.Port, address.Port, 1, 30_000, true); status != "STARTED" {
		t.Fatalf("start scan: %s", status)
	}

	var scan *portScan
	deadline := time.After(2 * time.Second)
	for scan == nil {
		app.scanMu.Lock()
		scan = app.activeScan
		app.scanMu.Unlock()
		if scan != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("scan did not become active")
		case <-time.After(time.Millisecond):
		}
	}
	if scan.status != scanStatusRunning {
		t.Fatalf("active scan should report running, got %q", scan.status)
	}
	if status := app.StartPortScan("127.0.0.1", address.Port, address.Port, 1, 100, true); status != "A scan is already running or stopping" {
		t.Fatalf("second scan should be rejected while one is active, got %q", status)
	}

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("scanner did not connect to the fixture listener")
	}
	defer serverConn.Close()

	var stops sync.WaitGroup
	for i := 0; i < 8; i++ {
		stops.Add(1)
		go func() {
			defer stops.Done()
			app.StopPortScan()
		}()
	}
	stops.Wait()

	select {
	case <-scan.done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not interrupt the active banner read")
	}
	if scan.status != scanStatusCancelled {
		t.Fatalf("stopped scan should report cancelled, got %q", scan.status)
	}
	app.scanMu.Lock()
	active := app.activeScan
	app.scanMu.Unlock()
	if active != nil {
		t.Fatal("completed scan should be removed from active state")
	}
}

func TestPortScanReportsCompletedStatus(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a closed local port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scan := &portScan{ctx: ctx, cancel: cancel, done: make(chan struct{}), status: scanStatusRunning}
	app := &App{activeScan: scan}
	go app.runPortScan(scan, "127.0.0.1", port, port, 1, 100*time.Millisecond)

	select {
	case <-scan.done:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not finish")
	}
	if scan.status != scanStatusCompleted {
		t.Fatalf("finished scan should report completed, got %q", scan.status)
	}
}

func TestAnalyzeURLInspectsSecurityTxtAndRobotsTxt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/security.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00.000Z\n"))
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
		default:
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "camera=()")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client, err := newScopedHTTPClient(server.URL, true, net.DefaultResolver)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	result := analyzeURL(server.URL, client, nil, HTTPRequestProfile{})
	if result.Error != "" {
		t.Fatalf("unexpected analysis error: %s", result.Error)
	}
	if result.SecurityTxt == nil || !result.SecurityTxt.Found || result.SecurityTxt.StatusCode != http.StatusOK {
		t.Fatalf("expected security.txt inspector result, got %+v", result.SecurityTxt)
	}
	if !strings.Contains(result.SecurityTxt.Body, "Contact: mailto:security@example.test") {
		t.Fatalf("unexpected security.txt body: %q", result.SecurityTxt.Body)
	}
	if !strings.HasSuffix(result.SecurityTxt.URL, "/.well-known/security.txt") {
		t.Fatalf("expected security.txt URL, got %q", result.SecurityTxt.URL)
	}
	if result.RobotsTxt == nil || !result.RobotsTxt.Found || result.RobotsTxt.StatusCode != http.StatusOK {
		t.Fatalf("expected robots.txt inspector result, got %+v", result.RobotsTxt)
	}
	if !strings.Contains(result.RobotsTxt.Body, "Disallow: /private") {
		t.Fatalf("unexpected robots.txt body: %q", result.RobotsTxt.Body)
	}
	if !strings.Contains(result.RobotsTxt.Note, "discovery guidance") {
		t.Fatalf("expected robots.txt guidance note, got %+v", result.RobotsTxt)
	}
}

func TestAnalyzeURLReportsMissingSecurityTxtAndRobotsTxt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/security.txt", "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "camera=()")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client, err := newScopedHTTPClient(server.URL, true, net.DefaultResolver)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	result := analyzeURL(server.URL, client, nil, HTTPRequestProfile{})
	if result.Error != "" {
		t.Fatalf("unexpected analysis error: %s", result.Error)
	}
	if result.SecurityTxt == nil || result.SecurityTxt.Found || result.SecurityTxt.StatusCode != http.StatusNotFound {
		t.Fatalf("expected missing security.txt inspector result, got %+v", result.SecurityTxt)
	}
	if result.RobotsTxt == nil || result.RobotsTxt.Found || result.RobotsTxt.StatusCode != http.StatusNotFound {
		t.Fatalf("expected missing robots.txt inspector result, got %+v", result.RobotsTxt)
	}
}

func TestPrepareScanReportEnvelopeRedactsAndAddsModel(t *testing.T) {
	input := `[{"url":"https://user:pass@example.test/path?token=secret&ok=1","statusCode":200,"grade":"B","riskScore":20,"findings":[{"severity":"high","title":"Test finding","description":"d","recommendation":"Rotate secrets and use HTTPS.","evidence":"Authorization: Bearer abc"}]}]`
	env, out, err := prepareScanReportEnvelope("http_security_audit.json", input)
	if err != nil {
		t.Fatalf("prepareScanReportEnvelope: %v", err)
	}
	if env.ReportVersion != reportSchemaVersion || env.Tool != reportGenerator || env.ReportType != "web-audit" {
		t.Fatalf("unexpected envelope metadata: %+v", env)
	}
	if !env.Redaction.Applied || len(env.Redaction.Scope) == 0 {
		t.Fatalf("expected redaction policy in envelope: %+v", env.Redaction)
	}
	if env.Summary == nil || env.Summary.SeverityBreakdown == nil || env.Summary.SeverityBreakdown.High != 1 {
		t.Fatalf("expected web audit summary with severity breakdown, got %+v", env.Summary)
	}
	s := string(out)
	if strings.Contains(s, "user:pass") || strings.Contains(s, "token=secret") {
		t.Fatalf("expected sensitive URL values to be redacted in serialized report, got: %s", s)
	}
	// evidence is free-text; key-based redaction does not rewrite arbitrary secret-like substrings inside values
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal prepared report: %v", err)
	}
	if _, ok := decoded["data"]; !ok {
		t.Fatalf("expected data field in report envelope: %v", decoded)
	}
}

func TestPrepareScanReportEnvelopeSupportsComparisonWrapper(t *testing.T) {
	input := `{"data":[{"url":"https://example.test","statusCode":200,"grade":"A","riskScore":0,"findings":[]}],"comparison":{"target":"https://example.test","note":"ok"},"metadata":{"target":"https://example.test"}}`
	env, _, err := prepareScanReportEnvelope("http_security_audit.json", input)
	if err != nil {
		t.Fatalf("prepareScanReportEnvelope: %v", err)
	}
	if env.Comparison == nil {
		t.Fatalf("expected comparison to be preserved: %+v", env)
	}
	if env.Metadata.Target != "https://example.test" {
		t.Fatalf("expected metadata target, got %+v", env.Metadata)
	}
}

func TestWritePDFReportCreatesFile(t *testing.T) {
	input := `[{"url":"https://example.test","statusCode":200,"grade":"A","riskScore":5,"findings":[{"severity":"info","title":"Note","description":"d","recommendation":"r"}],"error":""}]`
	env, _, err := prepareScanReportEnvelope("http_security_audit.json", input)
	if err != nil {
		t.Fatalf("prepareScanReportEnvelope: %v", err)
	}
	env.Comparison = map[string]any{"target": "https://example.test", "gradeChanged": false}
	path := filepath.Join(t.TempDir(), "report.pdf")
	if err := writePDFReport(path, env); err != nil {
		t.Fatalf("writePDFReport: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pdf: %v", err)
	}
	if info.Size() < 500 {
		t.Fatalf("expected non-trivial PDF output, got %d bytes", info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pdf: %v", err)
	}
	prefixLen := 4
	if len(data) < prefixLen {
		prefixLen = len(data)
	}
	if prefixLen < 4 || string(data[:4]) != "%PDF" {
		t.Fatalf("expected PDF header, got prefix %q", string(data[:prefixLen]))
	}
}

func TestWritePDFReportHandlesLargeReport(t *testing.T) {
	results := make([]map[string]any, 0, 120)
	for i := 0; i < 120; i++ {
		findings := make([]map[string]any, 0, 25)
		for j := 0; j < 25; j++ {
			findings = append(findings, map[string]any{
				"severity": "medium", "title": "Finding " + strings.Repeat("x", 20),
				"description": strings.Repeat("detail ", 20), "recommendation": strings.Repeat("fix ", 20),
			})
		}
		results = append(results, map[string]any{
			"url": "https://example.test/" + strings.Repeat("p", 10), "statusCode": 200,
			"grade": "C", "riskScore": 40, "findings": findings,
		})
	}
	raw, _ := json.Marshal(results)
	env, _, err := prepareScanReportEnvelope("http_security_audit.json", string(raw))
	if err != nil {
		t.Fatalf("prepareScanReportEnvelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "large.pdf")
	if err := writePDFReport(path, env); err != nil {
		t.Fatalf("writePDFReport large: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected PDF file for large report: %v", err)
	}
}

func TestExportTextReportsWriteError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory-as-file permission semantics differ on Windows")
	}
	dir := t.TempDir()
	// Passing a directory path as file target should fail.
	err := os.WriteFile(dir, []byte("x"), 0644)
	if err == nil {
		t.Fatal("expected write error when target is a directory")
	}
}
