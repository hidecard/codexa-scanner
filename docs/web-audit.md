# Web Audit User Guide

## What this module does

Web Audit performs bounded passive HTTP/HTTPS inspection for submitted URLs. It reports response metadata, page title, common security headers, cookie flags, HTTPS/TLS information, mixed-content clues, and passive technology or edge-product fingerprints. It does not log in, crawl linked routes, submit forms, test authorization, or exploit vulnerabilities.

## Before you start

Use only URLs that are explicitly approved. Enter one HTTP or HTTPS URL per line, up to 100 URLs. URLs with embedded credentials are rejected. Each submitted URL defines its own hostname and port scope. Private RFC1918, IPv6 ULA, and loopback destinations require the one-shot private/lab checkbox; link-local, multicast, unspecified, and reserved/special-use addresses remain blocked.

## Step-by-step

1. Open **Web Audit** and paste the approved URLs into the text area.
2. Set the bounded HTTP concurrency value. Keep it low when the authorization requires conservative traffic.
3. Enable **Private/lab access** only when every private target in the batch is authorized. The option resets after a batch.
4. Select **Analyze All Targets** and wait for the busy state to clear.
5. Review each response card. Expand **Redirect chain** to see each observed 3xx status, source URL, and destination URL.
6. Export the JSON report only after reviewing it for sensitive URLs, headers, cookies, and internal hostnames.

## Redirect and DNS behavior

Same-host redirects are allowed, including standard HTTP port 80 to HTTPS port 443 upgrades. Cross-host redirects, HTTPS-to-HTTP downgrades, and other out-of-scope ports are blocked. The chain is capped at five hops. The result keeps hops already observed even if a later hop is blocked. Hostnames are resolved as a complete answer set and one deterministic address is pinned through the request chain. Ambient proxies are bypassed.

## How to read results

`Status` is the final HTTP response status when a response was received. `Final URL` is the last URL reached. The redirect chain shows the intermediate route. `Present` and `Missing` describe observed response headers, not the complete server configuration. Findings include severity, evidence, and remediation guidance. Grade and risk score are bounded heuristics, not CVSS and not proof of exploitability. Technology and edge/WAF labels are clues based on observable tokens and can be false positives.

## Troubleshooting and limits

A connection or TLS error may indicate DNS failure, blocked scope, a certificate problem, timeout, or a remote refusal. Read the displayed error and confirm the URL scheme and authorization. A private target requires the explicit opt-in. Each response body is limited to a bounded sample for title, mixed-content, and fingerprint clues. A clean result means only that these passive checks observed no issue; it does not mean the site is secure.
