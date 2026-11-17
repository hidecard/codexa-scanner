# Codexa Scanner User Guide

## 1. Authorized use

Use Codexa Scanner only against systems you own or have explicit permission to assess. Port scans, DNS lookups, CT queries, HEAD requests, HTTP requests, PTR lookups, and RDAP requests can be logged or visible to service providers. The application is a bounded defensive assessment tool; it does not authenticate, exploit vulnerabilities, submit forms, or test authorization.

## 2. Install and run

Prerequisites are Go 1.22+, Node.js 20+, npm, and the platform prerequisites for Wails v2. Install dependencies and build the frontend:

```sh
npm ci --prefix frontend
npm run build --prefix frontend
```

For development, run `wails dev` from the repository root. For a Linux desktop build, use `wails build -platform linux/amd64` after installing GTK/WebKit development libraries. Windows builds should be run on Windows with WebView2 available.

## 3. Choose the right feature

Use **Ports** when you need bounded TCP reachability checks for one approved host. Use **Web Audit** for passive HTTP/HTTPS headers, cookies, TLS metadata, findings, and redirect chains. Use **Subdomains** for CT names and optional bounded DNS wordlist checks. Use **Path Fuzzer** for authorized HEAD-only route observations. Use **TLS** for certificate and protocol inspection. Use **DNS** for record families and optional RDAP enrichment. Use **IP Info** for source-labeled classification, PTR, and public-IP RDAP metadata. Use **History** to review local records, compare the latest two port snapshots, and export reports.

Each feature guide explains its accepted input format, step-by-step workflow, output interpretation, limits, and troubleshooting:

- [Port Scanner](port-scanner.md)
- [Web Audit](web-audit.md)
- [Subdomain Discovery](subdomain-discovery.md)
- [Path Fuzzer](path-fuzzer.md)
- [TLS Inspector](tls-inspector.md)
- [DNS Intelligence](dns-intelligence.md)
- [IP Information](ip-information.md)
- [History and Reports](history-and-reports.md)

## 4. Recommended assessment workflow

Start with the smallest authorized scope. Confirm the target and activity before each module. Review results and evidence rather than treating a clean result as proof of safety. If follow-up activity is needed, record the approved scope and rate limits before continuing. Export only the data required for the audience and redact sensitive values before delivery.

## 5. Common UI behavior

Busy buttons are disabled during an operation. Backend failures are shown as actionable error messages and busy indicators are cleared even when a request fails. Port scans stream findings and expose completed, cancelled, and failed states. A one-shot authorization confirmation is required for the exact port target and range; changing either resets the confirmation.

Private RFC1918, IPv6 ULA, and loopback HTTP targets are blocked by default and can be enabled once for authorized lab work. Link-local, multicast, unspecified, and reserved/special-use addresses remain blocked. Redirects are constrained to the submitted URL's hostname and allowed ports.

## 6. Local history and privacy

History is stored in the operating system user configuration directory under `CodexaScanner/history.sqlite`, capped at 2,000 entries. The database is not uploaded and is not encrypted. URL query strings, headers, cookies, banners, private hostnames, PTR names, RDAP fields, and scan results can contain sensitive information. Review and redact data before sharing. Close the app before manually deleting the database to clear local history.

## 7. Troubleshooting

If a target is rejected, use the input format documented by that feature and remove unapproved URL syntax, credentials, or port values. If HTTP analysis fails, check the URL scheme, authorization, redirect scope, certificate trust, and private/lab option. `Inconclusive` TLS 1.0/1.1 results can be caused by local crypto policy, timeouts, or network errors and are not proof that the protocol is supported. If history is unavailable, scan modules remain usable but history-dependent views may be empty. Reports are indicators for review, not CVSS scores or proof of exploitability.
