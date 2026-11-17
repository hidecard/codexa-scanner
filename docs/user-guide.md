# Codexa Scanner User Guide

## 1. Authorized use

Use Codexa Scanner only against systems you own or have explicit permission to assess. Port scans and HTTP requests can be logged and may trigger defensive controls. The application is intended for defensive, authorized assessment; it does not authenticate, exploit vulnerabilities, submit forms, or test authorization.

## 2. Install and run

Prerequisites are Go 1.22+, Node.js 20+, npm, and the platform prerequisites for Wails v2. Install dependencies and build the frontend:

```sh
npm ci --prefix frontend
npm run build --prefix frontend
```

For a development session, run `wails dev` from the repository root. For a Linux desktop build, use `wails build -platform linux/amd64` after installing GTK/WebKit development libraries.

## 3. Recommended workflow

1. Start with the target's smallest authorized scope.
2. Use **Ports** to identify reachable TCP services.
3. Use **Web Audit** for explicitly approved HTTP/HTTPS URLs.
4. Use **TLS**, **DNS**, **Subdomains**, or **Path Fuzzer** only when that activity is in scope.
5. Review findings and evidence rather than treating a clean result as proof of safety.
6. Export JSON or CSV when a report is needed, then review the output for sensitive data before sharing.

## 4. Common UI behavior

Busy buttons are disabled during an operation. Backend failures are shown as actionable error messages and busy indicators are cleared even when a request fails. Port scans stream findings and expose completed, cancelled, and failed states. A one-shot authorization confirmation is required for the exact port target and range; changing either resets the confirmation.

Private RFC1918, IPv6 ULA, and loopback HTTP targets are blocked by default and can be enabled once for authorized lab work. Link-local, multicast, unspecified, and reserved/special-use addresses remain blocked.

## 5. Local history and privacy

History is stored locally in the operating system user configuration directory under `CodexaScanner/history.sqlite`, capped at 2,000 entries. The database is not uploaded and is not encrypted. URL query strings and scan results can contain sensitive information, so redact or delete data before sharing. Close the app before manually deleting the database to clear local history.

## 6. Troubleshooting

- If a target is rejected, enter a bare IP address or ASCII hostname where the module requires one; do not add a URL, brackets, credentials, or an embedded port unless the field explicitly supports it.
- If HTTP analysis fails, check the URL scheme, authorization, redirect scope, certificate trust, and whether the target is private/lab.
- `Inconclusive` TLS 1.0/1.1 results can be caused by local crypto policy, timeouts, or network errors; they are not proof that the protocol is supported.
- If history is unavailable, the scan modules remain usable but history-dependent views may be empty.
- Reports are indicators for review, not CVSS scores or proof of exploitability.
