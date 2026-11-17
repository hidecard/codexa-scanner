# Codexa Scanner

Desktop network reconnaissance and HTTP security-header inspection application built with Go, Wails v2, React, and TypeScript. The GUI credits **Develop by H!D3-C4rD**.

> **Authorized-use notice:** Use only against systems you own or have explicit permission to assess. Port scanning and HTTP requests may be logged, trigger defensive controls, or violate policy or law when performed without authorization. Checks are passive and non-exploitative; results are indicators for review, not proof of exploitability or a substitute for a professional assessment.

## Features

- Concurrent TCP port checks with capped worker count and connection timeout, live findings/progress, cancellation-aware status, and one stable target address per scan.
- Hostnames are resolved once per scan (with a bounded lookup); one deterministic address is pinned for every port and shown in the UI. IPv4 is preferred, then addresses are ordered numerically; other DNS answers are not scanned in the same run.
- Port-scan targets accept bare IPv4/IPv6 addresses or ASCII DNS hostnames; URLs, ports, malformed names, and control characters are rejected. Each scan requires explicit authorization confirmation for its exact target and selected port range. Authorized private/lab targets are not blanket-blocked.
- Best-effort service identification and banner collection for reachable ports.
- Bulk HTTP/HTTPS URL checks with bounded concurrency, page title and response metadata extraction; each URL has its own host/port redirect scope and a five-hop cap. Same-host redirects are allowed, including HTTP port 80 to HTTPS port 443; cross-host redirects, HTTPS downgrades, and other port changes are blocked.
- Hostnames resolve once per submitted URL; the complete DNS answer set is policy-checked and one deterministic address is pinned through the request/redirect chain. Literal IPs skip DNS. Ambient proxies are disabled so they cannot bypass address checks.
- Private RFC1918, IPv6 ULA, and loopback targets require a default-off, one-shot opt-in for authorized lab use. Link-local, multicast, unspecified, and special-use/reserved addresses remain blocked.
- Passive checks for HTTPS transport, verified TLS certificate expiry/trust/hostname errors, mixed-content references, common security headers, and `Secure`/`HttpOnly`/`SameSite` cookie attributes.
- Actionable findings with severity, evidence, remediation guidance, a capped 0–100 heuristic risk score, and an A+–F grade.
- Bulk analysis of up to 100 URLs with bounded concurrency and redirect depth.
- Subdomain discovery from Certificate Transparency data, with an optional, capped DNS wordlist lookup; discovered names can be sent to the HTTP analyzer.
- A path discovery module that uses HEAD requests only, compares status/Content-Length to a randomized missing-path baseline, and never returns response bodies.
- A TLS inspector for certificate trust/self-signed state, expiry, subject alternative names, and negotiated cipher. TLS 1.0/1.1 probes report Supported after an exact-version handshake, Not supported only after an explicit `protocol_version` alert, and otherwise Inconclusive with the probe error.
- Passive technology and edge-product clues based on observed response headers, cookie names, and a bounded HTML sample. Fingerprints are clues, not confirmation of a WAF or product.
- DNS/network intelligence for A, AAAA, MX, NS, TXT, SPF, DMARC and reverse PTR records; optional RDAP registration/country metadata is fetched from an external service.
- Local SQLite history for scan snapshots, capped at 2,000 records, with a latest-two-scan port diff for a target.
- Native save dialogs for JSON reports and port CSV exports.
- Cross-platform desktop UI powered by Wails.

## How it works

The React UI calls Go methods exposed by Wails. Before a port scan, the backend accepts only a bare IPv4/IPv6 address or ASCII DNS hostname, rejects URL/port syntax and malformed input, and requires the user to confirm authorization for the exact target and selected port range. Private and lab targets remain available when authorized; there is no blanket private-IP block. `StartPortScan` resolves a hostname once, with a five-second lookup timeout, then pins one deterministic address for the entire scan: IPv4 is preferred and addresses within a family are ordered numerically. A literal IPv4/IPv6 target skips DNS. When a name has multiple A/AAAA answers, only the selected address is scanned in that run, and the UI shows the pinned address. TCP connections use a bounded worker pool and per-connection timeout; reachable ports stream to the interface, and cancellation/completion/failure are reflected in scan status. The passive web analyzer issues bounded HTTP GET requests and reads up to 64 KiB per response for title, mixed-content and technology clues. Each submitted URL defines its own hostname/port scope: same-host redirects are allowed, HTTP on port 80 may upgrade to HTTPS on port 443, cross-host redirects and HTTPS-to-HTTP downgrades are blocked, and other port changes are rejected. DNS answers are checked in full and one deterministic address is pinned throughout the request chain; no environment proxy is used. Private RFC1918, IPv6 ULA, and loopback targets are blocked by default and require a one-shot opt-in, while link-local, multicast, unspecified, and special-use/reserved addresses remain blocked. TLS is validated with the system trust store. Security findings include severity, evidence and remediation guidance and can be exported as JSON. Subdomain lookups query crt.sh and are capped at 500 names; optional DNS label checks are bounded. Path discovery is limited to 500 candidate paths, sends HEAD only, follows no redirects and omits response bodies. TLS legacy-version checks are handshakes only. DNS results are saved locally; optional RDAP lookups contact the public RDAP service only for public IP addresses. Local history is kept in the OS user-configuration directory under `CodexaScanner/history.sqlite` and automatically pruned to the latest 2,000 records. The database is not uploaded by the app and is not encrypted; delete that file while the app is closed to clear history. On platforms supporting Unix-style permissions, access is restricted to the current user.

The risk score is a simple severity-weighted heuristic, not CVSS and not a formal risk score. The passive web-audit module does not authenticate, crawl linked routes, submit forms, test authorization, or exploit vulnerabilities. The separate path module is an active but bounded HEAD-only check; it does not fetch or display path response bodies. TLS 1.0/1.1 results are best-effort because the local Go crypto policy can prevent a legacy handshake independently of the remote server. RDAP country/network data describes registry records and is not precise geolocation or a guaranteed ASN mapping. Technology/WAF fingerprints may be incomplete or false positives. Port banners and server headers can be absent, incomplete, or deliberately misleading. A clean report does not mean a site is vulnerability-free.

## Build locally

Prerequisites: Go 1.22+, Node.js 20+, npm, and the platform prerequisites for [Wails v2](https://wails.io/docs/gettingstarted/installation/). Linux builds need GTK/WebKit development libraries. Windows builds should be run on Windows with WebView2 available.

```sh
npm install --prefix frontend
cd frontend && npm run build && cd ..
go mod tidy
wails build -platform linux/amd64
```

For development, run `wails dev` from the repository root after installing dependencies. Wails CLI installation instructions are available in the official Wails documentation.

## CI artifacts

GitHub Actions runs on pushes to `main`, version tags (`v*`), and pull requests. Linux CI builds a Debian package (`.deb`) and Windows CI builds the portable application executable (`.exe`). On a version tag, the workflow also attaches both artifacts to a GitHub Release. Download artifacts from the Actions run's **Artifacts** section or the GitHub Release.

## Repository topics

`codexa-scanner`, `security`, `network-scanner`, `port-scanner`, `http-security`, `wails`, `golang`, `react`, `typescript`, `reconnaissance`

## Disclaimer

This software is provided for authorized testing, education, and defensive security work. You are responsible for obtaining permission, complying with applicable laws, and respecting target scope and rate limits. The authors accept no liability for misuse or damage.
