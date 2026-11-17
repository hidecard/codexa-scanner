# Codexa Scanner

Desktop network reconnaissance and HTTP security-header inspection application built with Go, Wails v2, React, and TypeScript. The GUI credits **Develop by H!D3-C4rD**.

> **Authorized-use notice:** Use only against systems you own or have explicit permission to assess. Port scanning and HTTP requests may be logged, trigger defensive controls, or violate policy or law when performed without authorization. The HTTP analyzer currently skips TLS certificate verification; findings are informational and are not a substitute for a professional security review.

## Features

- Concurrent TCP port checks with live findings, progress updates, and cancellation.
- Best-effort service identification and banner collection for reachable ports.
- Bulk HTTP/HTTPS URL checks with bounded concurrency, page title and response metadata extraction.
- Presence/missing status for six common security headers and a simple heuristic grade (A+ to F).
- Native save dialogs for JSON reports and port CSV exports.
- Cross-platform desktop UI powered by Wails.

## How it works

The React UI calls Go methods exposed by Wails. `StartPortScan` starts a worker pool and attempts TCP connections to the selected host and port range. Reachable ports are emitted to the UI as `port:found` events; progress and completion use `scan:progress` and `scan:done`. `StopPortScan` cancels the scan context. For bulk analysis, the Go backend issues bounded-concurrency HTTP GET requests, reads up to 32 KiB of each response body to look for an HTML title, inspects response headers, and returns results for display/export. Reports are written through the operating system's save dialog.

The header grade is a basic count of missing headers, not a formal risk score. Port banners and server headers can be absent, incomplete, or deliberately misleading. TLS verification is disabled in the supplied analyzer code, so do not treat a successful HTTPS request as certificate validation.

## Build locally

Prerequisites: Go 1.23+, Node.js 20+, npm, and the platform prerequisites for [Wails v2](https://wails.io/docs/gettingstarted/installation/). Linux builds need GTK/WebKit development libraries. Windows builds should be run on Windows with WebView2 available.

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