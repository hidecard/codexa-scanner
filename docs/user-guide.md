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

Use **Ports** when you need bounded TCP reachability checks for one approved host (with quick presets). Use **Web Audit** for passive HTTP/HTTPS headers, cookies, TLS metadata, findings, redirect chains, bounded security.txt/robots.txt inspectors, passive CORS/JWT metadata and sampled DB-error disclosure clues, request delay control, HTML/Markdown/JSON exports, and per-URL snapshot diff. Use **Subdomains** for CT names and optional bounded DNS wordlist checks. Use **Path Fuzzer** for authorized HEAD-only route observations with framework presets and request delay control. Use **TLS** for certificate and protocol inspection. Use **DNS** for record families and optional RDAP enrichment. Use **IP Info** for source-labeled classification, PTR, and public-IP RDAP metadata. Use **History** to review/search/filter local records, compare latest port/Web Audit snapshots, delete/clear/export history, select records across targets and scan types, and build consolidated engagement reports.

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

Start with the smallest authorized scope. Confirm the target and activity before each module. Review results and evidence rather than treating a clean result as proof of safety. If follow-up activity is needed, record the approved scope and rate limits before continuing. In History, select only the records needed for the engagement and export a consolidated JSON/PDF report. Export only the data required for the audience and redact sensitive values before delivery.

## 5. Common UI behavior

Busy buttons are disabled during an operation. Backend failures are shown as actionable error messages and busy indicators are cleared even when a request fails. Port scans stream findings and expose completed, cancelled, and failed states. A one-shot authorization confirmation is required for the exact port target and range; changing either resets the confirmation.

Private RFC1918, IPv6 ULA, and loopback HTTP targets are blocked by default and can be enabled once for authorized lab work. Link-local, multicast, unspecified, and reserved/special-use addresses remain blocked. Redirects are constrained to the submitted URL's hostname and allowed ports.

## 6. Local history and privacy

History is stored in the operating system user configuration directory under `CodexaScanner/history.sqlite`, capped at 2,000 entries. The database is not uploaded and is not encrypted. Before persistence and before JSON export, the app applies bounded redaction for embedded URL credentials, sensitive URL query/fragments, and sensitive result keys (password/secret/token/authorization/cookie/credential fields). This reduces accidental retention but is not a complete guarantee; URL paths, hostnames, banners, PTR names, RDAP fields, and other scan results can still contain sensitive information. Review and redact data before sharing. Close the app before manually deleting the database to clear local history.

## 7. Troubleshooting

If a target is rejected, use the input format documented by that feature and remove unapproved URL syntax, credentials, or port values. If HTTP analysis fails, check the URL scheme, authorization, redirect scope, certificate trust, and private/lab option. `Inconclusive` TLS 1.0/1.1 results can be caused by local crypto policy, timeouts, or network errors and are not proof that the protocol is supported. If history is unavailable, scan modules remain usable but history-dependent views may be empty. Reports are indicators for review, not CVSS scores or proof of exploitability.

## 8. Releases and installer verification (v1.1.5)

- GitHub releases (tags `v*`) produce Linux `.deb`, Windows `.exe`, and macOS Intel/Apple Silicon `.dmg` artifacts via `.github/workflows/build.yml` (see [Release & Installer Verification](release-verification.md)).
- CI hardening: workflow permissions are least-privilege (`contents: read`, release job only `contents: write`), Linux CI runs `go test -race ./...` + `go vet ./...`, Windows CI runs `go test ./...` + `go vet ./...`, and frontend dependencies are pinned to exact versions with a committed lockfile.
- Clean-machine install/upgrade/uninstall and SQLite history data-retention checks for v1.1.5 artifacts must be performed on fresh systems and recorded per [Release & Installer Verification](release-verification.md).
