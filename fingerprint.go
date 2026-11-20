package main

import (
	"net/http"
	"strings"
)

// fingerprintResponse passively identifies technology and edge-product clues in
// one already-received response. It performs no network activity. Labels mean
// only that the corresponding observable token was present, not that a product
// is definitively installed or that a security control is effective.
func fingerprintResponse(resp *http.Response, body []byte) (technologies []string, edge []string, wafs []WAFDetection) {
	if resp == nil {
		return nil, nil, nil
	}

	const sampleLimit = 64 * 1024
	if len(body) > sampleLimit {
		body = body[:sampleLimit]
	}
	text := strings.ToLower(string(body))

	var techSeen, edgeSeen, wafSeen = make(map[string]bool), make(map[string]bool), make(map[string]bool)
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
	addWAF := func(waf WAFDetection) {
		if !wafSeen[waf.Name] {
			wafSeen[waf.Name] = true
			wafs = append(wafs, waf)
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
	if headerHas("X-Powered-By", "nuxt") || headerPresent("X-Nuxt") || hasBody("__nuxt", "/_nuxt/") {
		addTech("Nuxt.js")
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
	if headerHas("X-Powered-By", "django") || cookieIs("csrftoken", "sessionid") && headerHas("Server", "gunicorn") {
		addTech("Django")
	}
	if headerHas("X-Powered-By", "rails") || cookieIs("_session_id", "_rails_session") {
		addTech("Ruby on Rails")
	}
	if headerHas("X-Powered-By", "spring") || headerPresent("X-Application-Context") || cookieIs("jsessionid") {
		addTech("Spring")
	}
	if headerHas("X-Powered-By", "flask") || cookieIs("session") && headerHas("Server", "werkzeug") {
		addTech("Flask")
	}
	if headerHas("Server", "nginx") || headerPresent("X-Nginx-Cache") {
		addTech("Nginx")
	}
	if headerHas("Server", "apache") || headerPresent("X-Powered-By") && (headerHas("X-Powered-By", "apache") || headerHas("Server", "httpd")) {
		addTech("Apache")
	}
	if headerHas("Server", "litespeed") || headerPresent("X-LiteSpeed-Cache") {
		addTech("LiteSpeed")
	}
	if headerHas("Server", "caddy") {
		addTech("Caddy")
	}
	if headerHas("Server", "iis") || headerPresent("X-Powered-By") && headerHas("X-Powered-By", "asp.net") {
		addTech("IIS")
	}
	if hasBody("react.development.js", "react.production.min.js", "__REACT_DEVTOOLS_GLOBAL_HOOK__") {
		addTech("React")
	}
	if hasBody("vue.runtime.esm-browser.js", "vue.global.prod.js", "__VUE_DEVTOOLS_GLOBAL_HOOK__") {
		addTech("Vue.js")
	}
	if hasBody("angular.min.js", "angular.js", "ng-version") {
		addTech("Angular")
	}
	if hasBody("svelte", "__SVELTE_DEVTOOLS_HOOK__") {
		addTech("Svelte")
	}
	if hasBody("jquery") {
		addTech("jQuery")
	}
	if hasBody("bootstrap") {
		addTech("Bootstrap")
	}
	if hasBody("tailwindcss", "tailwind.css", "tw-") {
		addTech("Tailwind CSS")
	}
	if headerPresent("X-Drupal-Cache") || cookieIs("sess", "session") && hasBody("/sites/default/") {
		addTech("Drupal")
	}
	if headerPresent("X-Generator") && headerHas("X-Generator", "joomla") || hasBody("/components/com_", "/media/system/js/") {
		addTech("Joomla")
	}
	if headerPresent("X-Generator") && headerHas("X-Generator", "magento") || cookieIs("mage-cache-sessid", "frontend", "frontend_cid") {
		addTech("Magento")
	}
	if headerPresent("X-Shopify-Stage") || headerHas("Server", "shopify") || hasBody("shopify") && hasBody("cdn.shopify.com") {
		addTech("Shopify")
	}
	if headerHas("Server", "envoy") || headerPresent("X-Envoy-Upstream-Service-Time") {
		addEdge("Envoy Proxy")
	}
	if headerHas("Server", "openresty") {
		addEdge("OpenResty")
	}
	if headerHas("Server", "traefik") || headerPresent("X-Traefik") {
		addEdge("Traefik")
	}
	if headerHas("Server", "haproxy") || headerPresent("X-Haproxy") {
		addEdge("HAProxy")
	}
	if headerHas("Server", "varnish") || headerPresent("X-Varnish") {
		addEdge("Varnish")
	}
	if headerPresent("X-Served-By") && headerHas("X-Served-By", "fastly") {
		addEdge("Fastly")
	}
	if headerHas("Server", "cloudflare") || headerPresent("CF-Ray") || headerPresent("CF-Cache-Status") || cookieIs("__cf_bm", "cf_clearance") {
		addEdge("Cloudflare")
	}
	if headerHas("Via", "cloudfront") || headerPresent("X-Amz-Cf-Id") || headerPresent("X-Amz-Cf-Pop") {
		addEdge("AWS CloudFront")
	}
	if headerPresent("X-Amzn-Waf-Action") || (headerPresent("X-Amzn-Requestid") && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests)) {
		addEdge("AWS WAF")
	}
	if headerPresent("Akamai-GRN") || headerPresent("X-Akamai-Transformed") || cookieIs("ak_bmsc", "bm_sv", "akavpau_") {
		addEdge("Akamai")
	}
	if headerPresent("X-Sucuri-ID") || headerPresent("X-Sucuri-Cache") || cookieIs("sucuri_cloudproxy_uuid") {
		addEdge("Sucuri")
	}
	if headerPresent("X-FW-Event") || cookieIs("visid_incap", "incap_ses", "_fw_crm_v") {
		addEdge("Incapsula/Imperva")
	}
	if headerPresent("X-F5-Server") || headerPresent("X-F5-Request-ID") || cookieIs("TS", "BIGipServer") {
		addEdge("F5 BIG-IP")
	}
	if headerPresent("X-WAF-Event") || headerPresent("X-Mod-Security-Transaction") || headerHas("Server", "mod_security") {
		addEdge("ModSecurity")
	}
	if headerPresent("X-Cache-Status") && headerHas("X-Cache-Status", "HIT") && (headerHas("Server", "nginx") || headerHas("Server", "apache")) {
		addEdge("Reverse Proxy Cache")
	}

	// WAF Detection with confidence scoring
	// Cloudflare WAF
	if headerPresent("CF-Ray") && (headerHas("CF-Ray", "WAF") || resp.StatusCode == http.StatusForbidden || resp.StatusCode == 503 || hasBody("attention required", "cloudflare", "ray id")) {
		addWAF(WAFDetection{
			Name:        "Cloudflare WAF",
			Category:    "WAF",
			Headers:     []string{"CF-Ray", "CF-Cache-Status", "Server"},
			Cookies:     []string{"__cf_bm", "cf_clearance"},
			StatusCodes: []int{403, 503},
			Confidence:  "high",
			Note:        "Detected via CF-Ray header and challenge page indicators",
		})
	} else if headerPresent("CF-Ray") || cookieIs("__cf_bm", "cf_clearance") {
		addWAF(WAFDetection{
			Name:        "Cloudflare",
			Category:    "CDN",
			Headers:     []string{"CF-Ray", "CF-Cache-Status"},
			Cookies:     []string{"__cf_bm", "cf_clearance"},
			Confidence:  "high",
			Note:        "CDN detected; WAF features may be enabled",
		})
	}

	// AWS WAF
	if headerPresent("X-Amzn-Waf-Action") || headerPresent("X-Amzn-Requestid") || cookieIs("awsalb", "awsalbcors") {
		addWAF(WAFDetection{
			Name:        "AWS WAF / ALB",
			Category:    "WAF",
			Headers:     []string{"X-Amzn-Waf-Action", "X-Amzn-Requestid", "X-Amz-Cf-Id"},
			Cookies:     []string{"awsalb", "awsalbcors"},
			StatusCodes: []int{403, 429},
			Confidence:  "high",
			Note:        "AWS WAF or ALB with WAF rules detected",
		})
	}

	// Akamai WAF
	if headerPresent("Akamai-GRN") || headerPresent("X-Akamai-Transformed") || cookieIs("ak_bmsc", "bm_sv", "akavpau_") {
		addWAF(WAFDetection{
			Name:        "Akamai",
			Category:    "WAF",
			Headers:     []string{"Akamai-GRN", "X-Akamai-Transformed", "X-Akamai-Request-ID"},
			Cookies:     []string{"ak_bmsc", "bm_sv", "akavpau_"},
			Confidence:  "high",
			Note:        "Akamai edge platform with WAF capabilities",
		})
	}

	// Imperva/Incapsula
	if headerPresent("X-Sucuri-ID") || headerPresent("X-Sucuri-Cache") || cookieIs("sucuri_cloudproxy_uuid") {
		addWAF(WAFDetection{
			Name:        "Sucuri CloudProxy",
			Category:    "WAF",
			Headers:     []string{"X-Sucuri-ID", "X-Sucuri-Cache"},
			Cookies:     []string{"sucuri_cloudproxy_uuid"},
			Confidence:  "high",
			Note:        "Sucuri WAF/CDN detected",
		})
	}
	if headerPresent("X-FW-Event") || cookieIs("visid_incap", "incap_ses", "_fw_crm_v") {
		addWAF(WAFDetection{
			Name:        "Imperva Incapsula",
			Category:    "WAF",
			Headers:     []string{"X-FW-Event", "X-Iinfo", "X-CDN"},
			Cookies:     []string{"visid_incap", "incap_ses", "_fw_crm_v"},
			Confidence:  "high",
			Note:        "Imperva Incapsula WAF detected",
		})
	}

	// F5 BIG-IP ASM
	if headerPresent("X-F5-Server") || headerPresent("X-F5-Request-ID") || cookieIs("TS", "BIGipServer") {
		addWAF(WAFDetection{
			Name:        "F5 BIG-IP ASM",
			Category:    "WAF",
			Headers:     []string{"X-F5-Server", "X-F5-Request-ID"},
			Cookies:     []string{"TS", "BIGipServer"},
			Confidence:  "medium",
			Note:        "F5 BIG-IP with ASM module detected",
		})
	}

	// ModSecurity
	if headerPresent("X-WAF-Event") || headerPresent("X-Mod-Security-Transaction") || headerHas("Server", "mod_security") {
		addWAF(WAFDetection{
			Name:        "ModSecurity",
			Category:    "WAF",
			Headers:     []string{"X-WAF-Event", "X-Mod-Security-Transaction", "Server"},
			Confidence:  "high",
			Note:        "ModSecurity WAF detected via headers",
		})
	}

	// FortiWeb
	if headerPresent("X-FortiWeb") || cookieIs("fw_crm") || hasBody("fortiweb", "fortiguard") {
		addWAF(WAFDetection{
			Name:        "FortiWeb",
			Category:    "WAF",
			Headers:     []string{"X-FortiWeb", "Server"},
			Cookies:     []string{"fw_crm"},
			BodyMatches: []string{"fortiweb", "fortiguard"},
			Confidence:  "medium",
			Note:        "FortiWeb WAF indicators found",
		})
	}

	// Generic WAF indicators from response body
	if hasBody("web application firewall", "blocked by", "access denied", "request blocked", "security policy", "waf blocked") {
		addWAF(WAFDetection{
			Name:        "Generic WAF",
			Category:    "WAF",
			BodyMatches: []string{"web application firewall", "blocked by", "access denied", "request blocked", "security policy", "waf blocked"},
			StatusCodes: []int{403, 406, 501, 503},
			Confidence:  "low",
			Note:        "Generic WAF block page detected in response body",
		})
	}

	// Challenge pages (CAPTCHA, JS challenge)
	if hasBody("captcha", "challenge", "checking your browser", "please wait", "ddos protection", "ray id") && (resp.StatusCode == 403 || resp.StatusCode == 503 || resp.StatusCode == 429) {
		addWAF(WAFDetection{
			Name:        "Challenge Page",
			Category:    "WAF",
			BodyMatches: []string{"captcha", "challenge", "checking your browser", "please wait", "ddos protection", "ray id"},
			StatusCodes: []int{403, 429, 503},
			Confidence:  "medium",
			Note:        "Anti-bot challenge page detected",
		})
	}

	return technologies, edge, wafs
}