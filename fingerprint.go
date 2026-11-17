package main

import (
	"net/http"
	"strings"
)

// fingerprintResponse passively identifies technology and edge-product clues in
// one already-received response. It performs no network activity. Labels mean
// only that the corresponding observable token was present, not that a product
// is definitively installed or that a security control is effective.
func fingerprintResponse(resp *http.Response, body []byte) (technologies []string, edge []string) {
	if resp == nil {
		return nil, nil
	}

	const sampleLimit = 64 * 1024
	if len(body) > sampleLimit {
		body = body[:sampleLimit]
	}
	text := strings.ToLower(string(body))

	var techSeen, edgeSeen = make(map[string]bool), make(map[string]bool)
	addTech := func(name string) {
		if !techSeen[name] {
			techSeen[name] = true
			technologies = append(technologies, name)
		}
	}
	addEdge := func(name string) {
		if !edgeSeen[name] {
			edgeSeen[name] = true
			edge = append(edge, name)
		}
	}
	headerValue := func(header string) string {
		for key, values := range resp.Header {
			if strings.EqualFold(key, header) {
				return strings.Join(values, ",")
			}
		}
		return ""
	}
	headerHas := func(header, token string) bool {
		return strings.Contains(strings.ToLower(headerValue(header)), token)
	}
	headerPresent := func(header string) bool {
		return strings.TrimSpace(headerValue(header)) != ""
	}
	hasBody := func(tokens ...string) bool {
		for _, token := range tokens {
			if strings.Contains(text, token) {
				return true
			}
		}
		return false
	}
	cookies := make(map[string]bool)
	for _, cookie := range resp.Cookies() {
		cookies[strings.ToLower(cookie.Name)] = true
	}
	cookieIs := func(names ...string) bool {
		for _, name := range names {
			if cookies[strings.ToLower(name)] {
				return true
			}
		}
		return false
	}
	cookieHasPrefix := func(prefixes ...string) bool {
		for cookieName := range cookies {
			for _, prefix := range prefixes {
				if strings.HasPrefix(cookieName, strings.ToLower(prefix)) {
					return true
				}
			}
		}
		return false
	}

	// Platform and framework fingerprints.
	if cookieIs("wordpress_logged_in", "wp-settings") || cookieHasPrefix("wordpress_logged_in_", "wp-settings-") || hasBody("/wp-content/", "/wp-includes/") {
		addTech("WordPress")
	}
	if cookieIs("laravel_session", "laravel_session_") || headerHas("Set-Cookie", "laravel_session=") {
		addTech("Laravel")
	}
	if headerHas("X-Powered-By", "next.js") || headerPresent("X-Nextjs-Cache") || hasBody("__next_data__", "id=\"__next\"", "id='__next'", "/_next/static/") {
		addTech("Next.js")
	}
	if headerHas("X-Powered-By", "php") || headerHas("X-Powered-By", "php/") || cookieIs("phpsessid") {
		addTech("PHP")
	}
	if headerHas("X-Powered-By", "express") || cookieIs("connect.sid") {
		addTech("Express")
	}
	if headerHas("X-Powered-By", "asp.net") || headerPresent("X-Aspnet-Version") || headerPresent("X-Aspnetmvc-Version") || cookieIs("asp.net_sessionid", ".aspxauth") {
		addTech("ASP.NET")
	}

	// Edge / filtering fingerprints, intentionally separate from app stacks.
	if headerPresent("CF-Ray") || headerPresent("CF-Cache-Status") || cookieIs("__cf_bm", "cf_clearance") {
		addEdge("Cloudflare")
	}
	if headerHas("Via", "cloudfront") || headerPresent("X-Amz-Cf-Id") || headerPresent("X-Amz-Cf-Pop") {
		addEdge("AWS CloudFront")
	}
	if headerPresent("X-Amzn-Waf-Action") || headerPresent("X-Amzn-Requestid") && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
		addEdge("AWS WAF")
	}
	if headerPresent("Akamai-GRN") || headerPresent("X-Akamai-Transformed") || cookieIs("ak_bmsc", "bm_sv", "akavpau_") {
		addEdge("Akamai")
	}

	return technologies, edge
}
