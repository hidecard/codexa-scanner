# Web Audit User Guide

## What this module does

Web Audit performs bounded, scope-constrained HTTP/HTTPS inspection for submitted URLs. It reports response metadata, page title, redirect chain, common security headers, cookie flags, HTTPS/TLS information, mixed-content clues, passive technology or edge-product fingerprints, CSP configuration diagnostics with evidence, passive CORS/JWT posture clues, sampled database-error disclosure clues, bounded read-only `/.well-known/security.txt` and `/robots.txt` inspectors, and a bounded client-side exposure audit (first-party JS bundle secret-pattern clues with redacted previews, source-map reachability clues, API/BaaS endpoint extraction, DOM sink clues, and a harmless reflected-parameter indicator when query parameters exist). It does not log in, crawl linked routes, submit forms, test authorization, or exploit vulnerabilities.

## Before you start

Use only URLs that are explicitly approved. Enter one HTTP or HTTPS URL per line, up to 100 URLs. URLs with embedded credentials are rejected. Each submitted URL defines its own hostname and port scope. Private RFC1918, IPv6 ULA, and loopback destinations require the one-shot private/lab checkbox; link-local, multicast, unspecified, and reserved/special-use addresses remain blocked.

## Step-by-step

1. Open **Web Audit** and paste the approved URLs into the text area.
2. Set bounded HTTP concurrency and optional request delay (0–5000 ms). Keep values low when authorization requires conservative traffic.
3. Enable **Private/lab access** only when every private target in the batch is authorized. The option resets after a batch.
4. Select **Analyze All Targets** and wait for the busy state to clear.
5. Review each response card. Expand **Redirect chain** to see each observed 3xx status, source URL, and destination URL.
6. Expand **Resource inspectors** to review `/.well-known/security.txt` and `/robots.txt`. `robots.txt` is discovery guidance, not a security control.
7. Expand **Client-side exposure audit (bounded passive)** to review script scan counts, reflected-parameter probe result (when applicable), redacted secret-pattern clues, source-map reachability clues, extracted API/BaaS endpoint clues, and DOM sink clues with script URL/line context.
8. Review **Passive findings** for header/cookie/TLS/mixed-content issues, CSP directive diagnostics, CORS/JWT posture clues (including origin reflection clue), database-error disclosure clues, and client-side exposure findings. Each finding includes evidence and remediation guidance. Secret/token values and JWT token values are not shown in clear text (redacted/metadata-only where applicable).
9. Where applicable, expand **Safe CLI verification commands** and copy a suggested read-only `curl -I`, `openssl s_client`, or `dig` command for manual verification. These commands are suggestions only and are never run by the app. URL credentials, query strings, and fragments are excluded; review the resulting command and authorization scope before running it in a terminal.
10. Export reports only after reviewing for sensitive URLs, headers, cookies, inspector bodies, client-side clues, and internal hostnames. Supported exports: JSON (versioned/redacted envelope), HTML, Markdown, PDF (branded/shared report model).

## Redirect, DNS, and probe behavior

Same-host redirects are allowed, including standard HTTP port 80 to HTTPS port 443 upgrades. Cross-host redirects, HTTPS-to-HTTP downgrades, and other out-of-scope ports are blocked. The chain is capped at five hops. The result keeps hops already observed even if a later hop is blocked. Hostnames are resolved as a complete answer set and one deterministic address is pinned through the request chain. Ambient proxies are bypassed. Inspectors and bounded client-side probes use the same scoped HTTP client and target-scope controls.

Client-side checks are bounded: up to 5 first-party scripts fetched (512 KiB each), same-origin source-map `HEAD` reachability checks only, and (when query parameters exist) a single harmless probe request that appends a benign alphanumeric marker to test unencoded reflection in the sampled response. No exploit payloads are sent.

## How to read results

Web Audit uses **bounded active requests** (main GET, observed redirects, read-only `security.txt`/`robots.txt` fetches, and optional bounded client-side probes/fetches described above) and **passive analysis** of observed responses. Each result includes an assessment label in the UI and exports.

`Status` is the final HTTP response status when a response was received. `Final URL` is the last URL reached. The redirect chain shows the intermediate route. `Present` and `Missing` describe observed response headers, not complete server configuration. When HTTPS is used, Web Audit reports TLS version/cipher, verification summary, leaf subject/issuer, validity window, SAN count, and presented certificate chain subjects from observed peer certificates (details may be limited when verification fails).

CSP diagnostics are explicit, directive-based heuristics with evidence; they do not claim a policy is safe or complete. CORS checks flag `Access-Control-Allow-Origin: *` (informational), wildcard+credentials misconfiguration (high), and origin reflection clues when `ACAO` echoes the request `Origin` without `Vary: Origin` (medium/high depending on credentials). JWT checks passively decode header/payload metadata to flag `alg:none` or missing `exp`/`nbf` claims without signature verification or brute-forcing; token values are redacted. Sampled response bodies are checked for common database error signatures as disclosure clues only.

Client-side audit clues are passive/bounded indicators: secret-pattern matches are redacted previews (heuristics, may be false positives); reachable source maps may expose source code; extracted API/BaaS endpoints are discovery clues for authorized review; DOM sink matches indicate potentially risky APIs without data-flow analysis; reflected-parameter probe results indicate unencoded echo of a benign marker, not proof of XSS. `robots.txt` content is discovery guidance, not an access control or security guarantee.

Findings include severity, evidence, and remediation guidance. Grade and risk score are bounded heuristics, not CVSS and not proof of exploitability. Technology and edge/WAF labels are clues based on observable tokens and can be false positives.

## Troubleshooting and limits

A connection or TLS error may indicate DNS failure, blocked scope, a certificate problem, timeout, or a remote refusal. Read the displayed error and confirm the URL scheme and authorization. A private target requires the explicit opt-in. Main/inspector/script response bodies are bounded samples. CSP parsing is best-effort and directive-oriented. Client-side scanning is capped (first-party scripts/count/size), same-origin for script/sourcemap probing, and pattern-based; it can miss obfuscated or dynamically loaded code and can produce false positives. A clean result means only that these bounded checks observed no issue; it does not mean the site is secure.
