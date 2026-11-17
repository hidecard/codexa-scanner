# Web Audit User Guide

## What this module does

Web Audit performs bounded passive HTTP/HTTPS inspection for submitted URLs. It reports response metadata, page title, common security headers, cookie flags, HTTPS/TLS information, mixed-content clues, passive technology or edge-product fingerprints, CSP configuration diagnostics with evidence, passive CORS/JWT posture clues, sampled database-error disclosure clues, and bounded read-only inspectors for `/.well-known/security.txt` and `/robots.txt`. It does not log in, crawl linked routes, submit forms, test authorization, or exploit vulnerabilities.

## Before you start

Use only URLs that are explicitly approved. Enter one HTTP or HTTPS URL per line, up to 100 URLs. URLs with embedded credentials are rejected. Each submitted URL defines its own hostname and port scope. Private RFC1918, IPv6 ULA, and loopback destinations require the one-shot private/lab checkbox; link-local, multicast, unspecified, and reserved/special-use addresses remain blocked.

## Step-by-step

1. Open **Web Audit** and paste the approved URLs into the text area.
2. Set the bounded HTTP concurrency value. Keep it low when the authorization requires conservative traffic.
3. Enable **Private/lab access** only when every private target in the batch is authorized. The option resets after a batch.
4. Select **Analyze All Targets** and wait for the busy state to clear.
5. Review each response card. Expand **Redirect chain** to see each observed 3xx status, source URL, and destination URL.
6. Expand **Resource inspectors** to review `/.well-known/security.txt` and `/robots.txt`. `robots.txt` is discovery guidance, not a security control.
7. Review **Passive findings** for header/cookie/TLS/mixed-content issues, CSP directive diagnostics, CORS/JWT posture clues, and database-error disclosure clues. Each finding includes evidence and remediation guidance. JWT token values are never shown (metadata-only, passive decode).
8. Export the JSON report only after reviewing it for sensitive URLs, headers, cookies, inspector bodies, and internal hostnames.

## Redirect and DNS behavior

Same-host redirects are allowed, including standard HTTP port 80 to HTTPS port 443 upgrades. Cross-host redirects, HTTPS-to-HTTP downgrades, and other out-of-scope ports are blocked. The chain is capped at five hops. The result keeps hops already observed even if a later hop is blocked. Hostnames are resolved as a complete answer set and one deterministic address is pinned through the request chain. Ambient proxies are bypassed. The security.txt and robots.txt inspectors use the same scoped HTTP client and bounded read-only GET fetches for the target origin.

## How to read results

Web Audit uses **bounded active requests** (main GET to each URL, observed redirects, and read-only `/.well-known/security.txt`/`/robots.txt` fetches on the submitted origin) and **passive analysis** of observed responses (headers, cookies, TLS metadata, sampled body clues, findings, and labels). Each result includes an assessment label in the UI and JSON export to distinguish these.

`Status` is the final HTTP response status when a response was received. `Final URL` is the last URL reached. The redirect chain shows the intermediate route. `Present` and `Missing` describe observed response headers, not the complete server configuration. When HTTPS is used, Web Audit reports TLS version/cipher, verification summary, leaf subject/issuer, validity window, SAN count, and presented certificate chain subjects from the peer certificates observed during the request (details may be limited when verification fails). CSP diagnostics are explicit, directive-based heuristics (for example `script-src` allowing `'unsafe-inline'`, `'unsafe-eval'`, or `*`, and missing `default-src`/`object-src`/`base-uri` baselines) reported with evidence; they do not claim a policy is safe or complete. CORS checks flag `Access-Control-Allow-Origin: *` (informational) and the misconfigured combination of wildcard origin with `Access-Control-Allow-Credentials: true` (high clue). JWT checks passively decode header/payload metadata from observed response headers/cookies to flag `alg:none` or missing `exp`/`nbf` claims without signature verification or brute-forcing; token values are redacted. Sampled response bodies are checked for common database error signatures (e.g. SQLSTATE/SQL syntax/driver exceptions) as disclosure clues only. `security.txt` and `robots.txt` inspector results report the requested URL, HTTP status, and a bounded response body when a readable 2xx response is returned; missing or non-2xx resources are reported as not found. `robots.txt` content may describe crawler guidance and discovery hints but is not an access control or a security guarantee. Findings include severity, evidence, and remediation guidance. Grade and risk score are bounded heuristics, not CVSS and not proof of exploitability. Technology and edge/WAF labels are clues based on observable tokens and can be false positives.

## Troubleshooting and limits

A connection or TLS error may indicate DNS failure, blocked scope, a certificate problem, timeout, or a remote refusal. Read the displayed error and confirm the URL scheme and authorization. A private target requires the explicit opt-in. Each main response body is limited to a bounded sample for title, mixed-content, and fingerprint clues; security.txt and robots.txt bodies are limited to a bounded read-only sample. CSP parsing is best-effort and directive-oriented; complex policies, nonces/hashes, and application context may require manual review. A clean result means only that these passive checks observed no issue; it does not mean the site is secure.
