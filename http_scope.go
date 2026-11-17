package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxHTTPRedirects     = 5
	httpDNSLookupTimeout = 5 * time.Second
)

var (
	errHTTPRedirectOutOfScope = errors.New("redirect is outside the selected target scope")
	errHTTPRedirectDowngrade  = errors.New("HTTPS-to-HTTP redirects are not allowed")
	errHTTPTooManyRedirects   = errors.New("stopped after five redirects")
	errHTTPPrivateAddress     = errors.New("target resolves to a private or loopback address")
	errHTTPSpecialAddress     = errors.New("target resolves to a special-use or non-routable address")
	errHTTPDNSResolution      = errors.New("target DNS resolution failed")
	errHTTPNoDNSAnswers       = errors.New("target DNS lookup returned no addresses")
)

var (
	httpGlobalIPv6Prefix   = netip.MustParsePrefix("2000::/3")
	httpSpecialUsePrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

type httpIPLookup interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type pinnedHTTPResolver struct {
	lookup       httpIPLookup
	allowPrivate bool
	mu           sync.Mutex
	addresses    map[string]netip.Addr
}

func newPinnedHTTPResolver(lookup httpIPLookup, allowPrivate bool) *pinnedHTTPResolver {
	return &pinnedHTTPResolver{
		lookup:       lookup,
		allowPrivate: allowPrivate,
		addresses:    make(map[string]netip.Addr),
	}
}

func (r *pinnedHTTPResolver) resolve(ctx context.Context, host string) (netip.Addr, error) {
	canonical, err := normalizeHTTPHostname(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", errHTTPSpecialAddress, err)
	}
	if ip, err := netip.ParseAddr(canonical); err == nil {
		return validateHTTPAddress(ip, r.allowPrivate)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if ip, ok := r.addresses[canonical]; ok {
		return ip, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, httpDNSLookupTimeout)
	defer cancel()
	queryHost := canonical
	if !strings.HasSuffix(queryHost, ".") {
		queryHost += "."
	}
	answers, err := r.lookup.LookupNetIP(lookupCtx, "ip", queryHost)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", errHTTPDNSResolution, err)
	}
	selected, err := selectPinnedHTTPAddress(answers, r.allowPrivate)
	if err != nil {
		return netip.Addr{}, err
	}
	r.addresses[canonical] = selected
	return selected, nil
}

func selectPinnedHTTPAddress(answers []netip.Addr, allowPrivate bool) (netip.Addr, error) {
	if len(answers) == 0 {
		return netip.Addr{}, errHTTPNoDNSAnswers
	}
	valid := make([]netip.Addr, 0, len(answers))
	for _, answer := range answers {
		ip, err := validateHTTPAddress(answer, allowPrivate)
		if err != nil {
			// Reject mixed public/private answer sets instead of selecting only the
			// convenient answer; the complete DNS response is part of the policy check.
			return netip.Addr{}, err
		}
		valid = append(valid, ip)
	}
	sort.Slice(valid, func(i, j int) bool {
		left4, right4 := valid[i].Is4(), valid[j].Is4()
		if left4 != right4 {
			return left4
		}
		return valid[i].Compare(valid[j]) < 0
	})
	return valid[0], nil
}

func validateHTTPAddress(ip netip.Addr, allowPrivate bool) (netip.Addr, error) {
	if !ip.IsValid() {
		return netip.Addr{}, errHTTPSpecialAddress
	}
	if ip.Zone() != "" {
		return netip.Addr{}, errHTTPSpecialAddress
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return netip.Addr{}, errHTTPSpecialAddress
	}
	for _, prefix := range httpSpecialUsePrefixes {
		if prefix.Contains(ip) {
			return netip.Addr{}, errHTTPSpecialAddress
		}
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		if allowPrivate {
			return ip, nil
		}
		return netip.Addr{}, errHTTPPrivateAddress
	}
	if !ip.IsGlobalUnicast() {
		return netip.Addr{}, errHTTPSpecialAddress
	}
	if ip.Is6() && !httpGlobalIPv6Prefix.Contains(ip) {
		return netip.Addr{}, errHTTPSpecialAddress
	}
	return ip, nil
}

func normalizeHTTPHostname(host string) (string, error) {
	normalized, err := normalizePortScanTarget(host)
	if err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(normalized); err == nil {
		return ip.String(), nil
	}
	return strings.TrimSuffix(strings.ToLower(normalized), "."), nil
}

func analysisURLForDisplay(target string) string {
	inputURL := strings.TrimSpace(target)
	if !strings.Contains(inputURL, "://") {
		inputURL = "https://" + inputURL
	}
	return inputURL
}

func parseHTTPAnalysisURL(target string) (string, *url.URL, string, error) {
	inputURL := analysisURLForDisplay(target)
	parsed, err := url.Parse(inputURL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return inputURL, nil, "", errors.New("enter a valid http:// or https:// URL without embedded credentials")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return inputURL, nil, "", errors.New("enter a valid http:// or https:// URL without embedded credentials")
	}
	host, err := normalizeHTTPHostname(parsed.Hostname())
	if err != nil {
		return inputURL, nil, "", errors.New("enter a valid http:// or https:// URL with a valid IP address or hostname")
	}
	if _, err := effectiveHTTPPort(parsed); err != nil {
		return inputURL, nil, "", errors.New("URL port must be between 1 and 65535")
	}
	return inputURL, parsed, host, nil
}

func effectiveHTTPPort(parsed *url.URL) (string, error) {
	port := parsed.Port()
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "http") {
			return "80", nil
		}
		if strings.EqualFold(parsed.Scheme, "https") {
			return "443", nil
		}
		return "", errHTTPRedirectOutOfScope
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return "", fmt.Errorf("invalid port")
	}
	return strconv.Itoa(value), nil
}

type httpTargetScope struct {
	host  string
	ports map[string]struct{}
}

func newHTTPTargetScope(parsed *url.URL, host string) (httpTargetScope, error) {
	port, err := effectiveHTTPPort(parsed)
	if err != nil {
		return httpTargetScope{}, err
	}
	ports := map[string]struct{}{port: {}}
	if parsed.Scheme == "http" && port == "80" {
		ports["443"] = struct{}{}
	}
	if parsed.Scheme == "https" && port == "443" {
		ports["80"] = struct{}{}
	}
	return httpTargetScope{host: host, ports: ports}, nil
}

func (s httpTargetScope) allows(parsed *url.URL) bool {
	if parsed == nil || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	host, err := normalizeHTTPHostname(parsed.Hostname())
	if err != nil || host != s.host {
		return false
	}
	port, err := effectiveHTTPPort(parsed)
	if err != nil {
		return false
	}
	_, ok := s.ports[port]
	return ok
}

func validateHTTPRedirect(request *http.Request, via []*http.Request, scope httpTargetScope) error {
	if len(via) > maxHTTPRedirects {
		return errHTTPTooManyRedirects
	}
	if request == nil || request.URL == nil || len(via) == 0 || request.URL.User != nil || !scope.allows(request.URL) {
		return errHTTPRedirectOutOfScope
	}
	if strings.EqualFold(via[0].URL.Scheme, "https") && strings.EqualFold(request.URL.Scheme, "http") {
		return errHTTPRedirectDowngrade
	}
	return nil
}

func newScopedHTTPClient(target string, allowPrivate bool, lookup httpIPLookup) (*http.Client, error) {
	_, parsed, host, err := parseHTTPAnalysisURL(target)
	if err != nil {
		return nil, err
	}
	scope, err := newHTTPTargetScope(parsed, host)
	if err != nil {
		return nil, err
	}
	pinned := newPinnedHTTPResolver(lookup, allowPrivate)
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		// An ambient proxy could resolve the hostname elsewhere and bypass our pins.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			requestHost, requestPort, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid destination", errHTTPRedirectOutOfScope)
			}
			canonicalHost, err := normalizeHTTPHostname(requestHost)
			if err != nil || canonicalHost != scope.host {
				return nil, fmt.Errorf("%w: host is not in scope", errHTTPRedirectOutOfScope)
			}
			portNumber, err := strconv.Atoi(requestPort)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				return nil, fmt.Errorf("%w: invalid port", errHTTPRedirectOutOfScope)
			}
			requestPort = strconv.Itoa(portNumber)
			if _, allowed := scope.ports[requestPort]; !allowed {
				return nil, fmt.Errorf("%w: port is not in scope", errHTTPRedirectOutOfScope)
			}
			ip, err := pinned.resolve(ctx, requestHost)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), requestPort))
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return validateHTTPRedirect(request, via, scope)
		},
	}, nil
}

func httpAnalysisErrorMessage(err error) string {
	switch {
	case errors.Is(err, errHTTPRedirectOutOfScope):
		return "Redirect blocked: destination is outside this URL's hostname and allowed port scope."
	case errors.Is(err, errHTTPRedirectDowngrade):
		return "Redirect blocked: HTTPS-to-HTTP downgrade is not allowed."
	case errors.Is(err, errHTTPTooManyRedirects):
		return "Redirect blocked after five hops."
	case errors.Is(err, errHTTPPrivateAddress):
		return "Target resolves to a private or loopback address. Enable the private/lab option only for an authorized target."
	case errors.Is(err, errHTTPSpecialAddress):
		return "Target resolves to a link-local, multicast, reserved, or otherwise disallowed special-use address."
	case errors.Is(err, errHTTPDNSResolution):
		return "Target DNS resolution failed. Verify the hostname and try again."
	case errors.Is(err, errHTTPNoDNSAnswers):
		return "Target DNS lookup returned no usable addresses."
	default:
		return "Connection failed, timed out, or TLS certificate verification failed. No insecure TLS bypass was used."
	}
}
