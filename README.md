# Codexa Scanner

Desktop network reconnaissance and HTTP security-header inspection application built with Go, Wails v2, React, and TypeScript. The GUI credits **Develop by H!D3-C4rD**.

> **Authorized-use notice:** Use only against systems you own or have explicit permission to assess. Port scanning and HTTP requests may be logged, trigger defensive controls, or violate policy or law when performed without authorization. Checks are passive and non-exploitative; results are indicators for review, not proof of exploitability or a substitute for a professional assessment.

## Features

- Concurrent TCP port checks with live findings, progress updates, and cancellation.
- Best-effort service identification and banner collection for reachable ports.
- Bulk HTTP/HTTPS URL checks with bounded concurrency, page title and response metadata extraction.
- Passive checks for HTTPS transport, verified TLS certificate expiry/trust/hostname errors, mixed-content references, common security headers, and `Secure`/`HttpOnly`/`SameSite` cookie attributes.
- Actionable findings with severity, evidence, remediation guidance, a capped 0–100 heuristic risk score, and an A+–F grade.
- Bulk analysis of up to 100 URLs with bounded concurrency and redirect depth.
- Native save dialogs for JSON reports and port CSV exports.
- Cross-platform desktop UI powered by Wails.

## How it works

The React UI calls Go methods exposed by Wails. `StartPortScan` starts a worker pool and attempts TCP connections to the selected host and port range. Reachable ports are emitted to the UI as `port:found` events; progress and completion use `scan:progress` and `scan:done`. `StopPortScan` cancels the scan context. For bulk analysis, the Go backend issues bounded-concurrency HTTP GET requests, follows at most five redirects, validates TLS using Go's system trust store, and reads at most 64 KiB per response. It extracts the HTML title and evaluates transport security, selected headers, cookie attributes and sampled mixed-content references. Results include finding descriptions, severity, evidence and remediation guidance and can be exported as JSON.

The risk score is a simple severity-weighted heuristic, not CVSS and not a formal risk score. Checks do not authenticate, crawl linked routes, submit forms, fuzz inputs, test authorization, or exploit vulnerabilities. Only the sampled first 64 KiB of a response is inspected for mixed content. Port banners and server headers can be absent, incomplete, or deliberately misleading. A clean report does not mean a site is vulnerability-free.

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
