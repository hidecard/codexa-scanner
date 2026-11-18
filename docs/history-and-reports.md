# History and Reports User Guide

## What this module does

History keeps scan results locally in SQLite and lets you inspect recent records. It compares the latest two port snapshots for a normalized target and reports new and removed ports. Web Audit snapshots can be compared for the same normalized URL when two comparable `http` records exist. Exports use a shared, versioned report model with bounded redaction.

## Step-by-step: review history

1. Open **History**. The app loads the newest local records when the tab opens (or when refreshed).
2. Use **Search target** and **type filter** to narrow records by target substring and scan type (`port`, `http`, `subdomain`, `fuzzer`, `tls`, `dns`, `ip`). Select **Refresh / Search** to apply.
3. Enter the target used for a port scan in **Target for port diff** and refresh to compare the latest two port snapshots. Read the latest and previous timestamps. `NEW PORT DETECTED` means the port was in the newest snapshot but not the previous one; `Closed` means the reverse.
4. To compare Web Audit snapshots, enter the audited URL (same target key) in the diff target field and select **Compare Web Audit Diff** (or refresh). The diff shows grade/risk/status changes, missing-header and finding ID additions/resolutions, and certificate days-remaining delta when available.
5. Expand a history row to inspect its stored JSON result. Use **Export** on a row for that record, or **Delete** to remove it (confirmation required). Use the scan type and target shown in the row to distinguish records.

A diff is available only when two comparable snapshots exist for the normalized target. It is not a general network comparison and does not prove that a service changed permanently.

## Step-by-step: export and manage

- **Web Audit (current results):** Export **JSON** (versioned, redacted report envelope), **HTML**, **Markdown**, or **PDF** (branded report with executive summary, technical findings, severity breakdown, risk score, recommendations, metadata/redaction policy, and supported historical comparison when provided in the report payload).
- **Ports:** Export CSV for current findings.
- **History:** Use **Export History JSON** (Dashboard/History) to save currently loaded history records as a versioned, redacted JSON report envelope. Use per-row **Export** for a single stored record.
- **Clear All History** removes all local records (confirmation required).

Choose a destination in native dialogs and verify contents before sharing.

## Report data model and redaction policy (Phase 5)

JSON exports are written as a shared, versioned envelope (schema v1.0) including: `reportVersion`, `generatedAt`, `tool`, `reportType`, `metadata`, `redaction` policy, optional `summary`, optional `comparison`, and `data`. Bounded best-effort redaction is applied before persistence and export:

- Embedded URL credentials (userinfo)
- Sensitive URL query parameters and fragments (token/key/secret/auth/session variants, etc.)
- Sensitive result keys (password, secret, token, authorization, cookie, credential, session, API key variants)

Redaction is **not** a complete guarantee. Hostnames, paths, banners, PTR/RDAP fields, and other scan data may still be sensitive; review and redact manually before delivery. On supported Unix-style systems, the app attempts user-only file permissions for the history database.

## Storage and privacy

History is stored under the operating system user configuration directory in `CodexaScanner/history.sqlite`, capped at 2,000 records. It is not uploaded and is not encrypted. Close the app before manually deleting the database to clear all local history.

## Troubleshooting and limits

If history is unavailable, scanning remains usable but the History/Dashboard views may be empty. If no records match, clear search/filter criteria. If no diff appears, save at least two completed comparable scans for the same normalized target. If an export fails, check destination permissions, available disk space, and that the path is writable, then retry with a smaller result set. Exported reports are observations and heuristics, not formal risk ratings or proof of exploitability. PDF detail is bounded (e.g. limited targets/findings per report) for readability; use JSON export for full redacted data.

## Install, upgrade, and uninstall data behavior

Local history is stored outside the application install directory in the OS user configuration directory (`CodexaScanner/history.sqlite`). Replacing/upgrading binaries should not remove this user-data path, but uninstall/remove behavior can differ by platform and packaging (for example, package remove vs purge, or deleting a portable executable). Verify history retention on clean systems for v1.1.4 `.deb`, `.exe`, and `.dmg` releases; see [Release & Installer Verification (v1.1.4)](release-verification.md).
