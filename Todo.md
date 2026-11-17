# Codexa Scanner — Product & Engineering Todo

Last reviewed: 2026-11-17  
Repository: `hidecard/codexa-scanner`  
Current baseline: commit `75ef9cf` — responsive UI/scrollbar improvements.  
Status rule: `[x]` verified complete; `[ ]` not complete; `[~]` partial/in progress; `[=]` already exists and should not be reimplemented; `[-]` intentionally deferred/not required for the current release scope.

## Review policy

For each item, first check the current code and tests, decide whether the work is needed, implement only the smallest justified change, run the closest tests, then update this file with the result. Existing features are not counted as new work. Security behavior must preserve authorized use of private/lab networks while making scope explicit; do not silently disable legitimate assessment workflows.

## Current progress

- [x] Reviewed the supplied roadmap against the current repository rather than accepting every recommendation as a missing feature.
- [x] Responsive UI baseline: removed the 900px minimum width, adapted navigation/forms/results for smaller screens, removed most nested scroll panels, and hid scrollbar chrome while retaining scrolling. Committed as `75ef9cf`.
- [~] Phase 1 — Backend stability & target safety. This is the current implementation priority.
- [ ] Phases 2–8 — reviewed and prioritized below; not implemented yet unless individually marked existing/deferred.

## Phase 1 — Backend stability & target safety (Critical)

**Review:** Required before calling the app production-ready. P1.1 now bounds port-scan resources, protects scan lifecycle state, uses per-scan cancellation and context-aware dialing, and reports terminal status. P1.2 now provides stable/pinned resolution; target input validation, redirect scope/SSRF controls, TLS probe confidence, and consistent frontend error states remain. The HTTP analyzer follows redirects without checking each destination. Existing DNS/path validation does not cover the port-scanner target. Preserve scanning of authorized private/lab hosts; do not add a blanket private-IP deny rule.

- [x] **P1.1 Bound scan inputs and make scan lifecycle concurrency-safe.** Capped workers at 512 and dial timeout at 30 seconds; each scan now has its own context; active-scan state is mutex-protected; overlapping starts are rejected; cancellation closes active banner connections; completed/cancelled/failed terminal states are reflected in the UI. Tests cover limits, active-start rejection, cancellation, and completed/cancelled status.
- [x] **P1.2 Use stable target resolution.** Context-aware, five-second-bounded lookup resolves once per scan; IPv4 and IPv6 literals skip DNS. Hostname answers are deterministically ordered (IPv4 first, then numeric address order), one address is pinned for every port, and the UI shows it. Multiple DNS answers are not all scanned in this iteration because that would require per-address findings/history changes. Tests cover multiple answers, literal IPv4/IPv6, lookup errors, and cancellation during lookup.
- [ ] **P1.3 Validate port-scan targets and introduce explicit scope controls.** Accept valid IPv4/IPv6 and DNS names; reject URL syntax, embedded ports, malformed names, and control characters. Design a clear in-scope target/host policy without blocking legitimate private networks by default.
- [ ] **P1.4 Validate HTTP redirect destinations and DNS resolution.** Prevent redirects from escaping an explicitly selected scope or reaching disallowed local addresses; handle rebinding/redirect chains consistently and test with local HTTP fixtures. Private-network access should remain an explicit user choice for authorized lab assessment.
- [ ] **P1.5 Report TLS 1.0/1.1 probes as Supported / Not supported / Inconclusive.** Current boolean plus generic error conflates remote capability with local Go crypto policy. Show useful probe errors in the UI; avoid claiming unsupported when evidence is inconclusive.
- [ ] **P1.6 Make frontend loading/error handling consistent.** Add `try/catch/finally` around asynchronous scan/analyzer/history calls so loading flags always reset and actionable errors reach the UI. `handleBulkAnalyze` currently has no `finally`.

**Not required in this phase:** Replacing Go/Wails/React/SQLite, a blanket ban on private targets, a proxy/VPN feature, or a large backend directory move. Those add scope without resolving the concrete stability/security defects above.

## Phase 2 — Network intelligence (High; incremental)

**Review:** Core DNS intelligence (A/AAAA/MX/NS/TXT/SPF/DMARC/PTR), optional public-IP RDAP lookup, certificate-transparency subdomain discovery, and latest-two port-scan diff already exist. Avoid duplicate implementations. New visualizations and historical DNS/certificate comparisons are useful follow-ups but not prerequisites for safe scanning.

- [=] DNS records, RDAP metadata, subdomain discovery, and bounded optional DNS wordlist checks exist.
- [=] Port change detection exists for the latest two port scans of a target; it is not a general network comparison engine.
- [ ] Add an IP information view only if its output can be sourced and labeled reliably; keep ASN/provider data clearly attributed and non-geolocational.
- [-] Network topology graph — defer until the scanner collects trustworthy host-to-host relationship data; current scan results do not justify a topology map.
- [-] Certificate Transparency change history and DNS record comparison — defer until users can choose retention, privacy, and comparison windows in History.
- [-] Standalone ASN feature — optional; do not duplicate or overstate existing RDAP network/country data.

**Not required now:** A graph/dashboard for its own sake, unsupported geolocation, or repeated copies of the existing DNS/RDAP and port-diff logic.

## Phase 3 — Web security assessment (High)

**Review:** The current analyzer already checks common headers, CSP presence/frame-ancestors, cookie flags, HTTPS/TLS metadata, basic mixed-content references, server/technology clues, and redirect final URL. The feature list is therefore partly implemented. Improve coverage carefully to avoid false claims; keep passive checks separate from active requests.

- [=] Common security headers, basic CSP presence, cookie `Secure`/`HttpOnly`/`SameSite`, basic mixed-content clues, TLS certificate details, and passive technology/edge fingerprints exist.
- [~] Redirect chain detail and redirect destination validation: final URL is stored, but each hop/scope is not surfaced or constrained yet; covered by P1.4.
- [ ] Security.txt and robots.txt inspectors — bounded, read-only fetches; label robots.txt as discovery guidance, not a security control.
- [ ] Expand CSP configuration diagnostics with explicit heuristics and evidence; do not claim a policy is safe solely because it exists.
- [ ] Improve certificate-chain reporting beyond the current trusted/untrusted summary, if the Go trust result allows reliable detail.
- [ ] Separate passive and active assessment labels in the interface and report output.
- [-] Broad “misconfiguration detection” catch-all — do not add vague heuristics; add only individually testable checks with evidence and remediation.

**Not required now:** Rewriting the existing checks or claiming comprehensive vulnerability scanning; the product remains a bounded, non-exploitative assessment tool.

## Phase 4 — Dashboard and navigation (High for product polish)

**Review:** The app has module tabs but no dashboard. The recent responsive UI baseline is complete; it should not be mistaken for the proposed dashboard. A landing summary is helpful but depends on usable history and reliable scan states.

- [x] Responsive navigation, form/results layouts, reduced nested scrolling, hidden scrollbar chrome, touch/keyboard focus improvements (`75ef9cf`).
- [ ] Design a Dashboard from data the app actually stores: recent scans, open ports, finding severity, and report links; show empty/error states.
- [ ] Group modules into Network Intelligence, Web Security, Assessment, Reports, History, and Settings only when the number of modules makes grouping clearer; avoid duplicating navigation controls.
- [-] Charts for unavailable or unretained metrics — defer until data definitions and retention are agreed.

**Not required now:** Building every proposed screen before the backend states/data are stable.

## Phase 5 — Professional reports (High for external delivery; not a security prerequisite)

**Review:** Native JSON and CSV exports exist. PDF/branding can improve stakeholder delivery, but is not required to complete security hardening. Build on one shared, versioned report model rather than separate ad-hoc serializers.

- [=] JSON export and port CSV export exist.
- [ ] Define a report data model and output redaction rules before adding formats.
- [ ] Add a branded PDF report with executive summary, technical findings, severity breakdown, risk score, recommendations, metadata, and supported historical comparison.
- [ ] Test export errors, file permissions, and large reports.

**Not required before Phase 1:** PDF generation, logo design, or duplicating the same data in multiple report-specific models.

## Phase 6 — History and comparison (Medium; privacy-sensitive)

**Review:** SQLite history exists, is local, user-only on supported filesystems, capped at 2,000 records, and currently compares the latest two port snapshots. Useful management/search features are missing. The database is not encrypted and URL query strings may contain sensitive data.

- [=] Local SQLite history, retention cap, file permission attempt, and latest-two port diff exist.
- [ ] Review/redact credentials and sensitive URL query values before persistence; document what is retained.
- [ ] Add delete-one and clear-all actions with confirmation and tests.
- [ ] Add search and scan-type filtering; preserve a clear empty state.
- [ ] Add export-history support using the shared report/export model.
- [ ] Extend comparison beyond ports only when comparable snapshots are available and semantics are clear.
- [-] User-configurable retention settings — defer; the current 2,000-record cap bounds storage and settings add migration/UI work.
- [-] SQLite encryption — not an immediate requirement while history contains only local records and file permissions are restricted. Revisit if the threat model requires protection from other local users or if secrets cannot be reliably redacted.

## Phase 7 — Tests, dependencies, CI security (Critical before release)

**Review:** Go unit tests and `go test ./... && go vet ./...` already run in Linux CI; Wails production builds exercise frontend type-check/build; Linux and Windows build jobs exist. Gaps: race detection, explicit front-end test coverage, integration boundaries, workflow write permission scope, and unpinned `latest` package ranges.

- [=] Existing Go unit tests and Linux CI `go test`/`go vet` exist.
- [=] Linux and Windows CI build jobs exist; frontend `build` runs TypeScript checking and Vite build through Wails.
- [ ] Add race-detection CI (`go test -race ./...`) where supported; keep platform-specific constraints documented.
- [ ] Add focused frontend tests for loading/error states and critical UI flows; do not add a test framework unless the coverage provides value.
- [ ] Add integration tests for cancellation, redirects/scope, persistence, and exports using local fixtures/temp directories.
- [ ] Scope workflow permissions to `contents: read` for build/test jobs and grant `contents: write` only to the release job if the release action requires it.
- [ ] Replace floating `latest` frontend dependencies with reviewed, exact compatible versions and regenerate the lockfile.
- [-] A separate test for every static label or trivial getter is unnecessary; prioritize regressions and security boundaries.

## Phase 8 — Installer and release management (High for public distribution)

**Review:** Linux `.deb` packaging and Windows executable artifact builds already exist. Tags create GitHub Releases. The Windows artifact is currently a portable `.exe`, not a conventional installer; signing/update channels are not set up.

- [=] Linux `.deb` package, Windows `.exe` CI artifact, and tag-based GitHub Release exist.
- [ ] Verify install/uninstall, upgrade, application data retention, and dependency behavior on clean supported systems.
- [ ] Decide whether users need a Windows installer in addition to the portable executable; add only after upgrade/uninstall behavior is defined.
- [ ] Add signing/provenance and release checks if required by the distribution threat model.
- [-] macOS package/auto-updater — defer until macOS is an explicitly supported target and signing/notarization can be maintained.

## Code organization

- [-] Moving all Go code under a new `internal/` tree is not needed for the current small application. Preserve current modules and tests; revisit when package boundaries enable independent reuse or testing.

## Progress log

| Date | Step | Result | Verification | Next |
|---|---|---|---|---|
| 2026-11-17 | Roadmap review | Completed; identified existing capabilities and deferred over-scoped work. | Inspected backend, frontend, tests, CI, package config, and packaging. | P1.1 |
| 2026-11-17 | P1.1 | Completed. | `go test ./...`, `go test -race ./...`, `go vet ./...`, and frontend `npm run build` passed. Added scan-limit, overlapping-start, cancellation, and terminal-status tests. | P1.2: pin and document one address per hostname per scan. |
| 2026-11-17 | P1.2 | Completed. | `go test ./...`, `go test -race ./...`, `go vet ./...`, frontend `npm run build`, and `git diff --check` passed. Added deterministic multi-answer selection, literal-IP and in-flight-cancellation tests; README features/how-it-works updated. | P1.3: validate port-scan target syntax and define explicit scope controls. |
