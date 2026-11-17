# History and Reports User Guide

## What this module does

History keeps scan results locally in SQLite and lets you inspect recent records. It compares the latest two port snapshots for a normalized target and reports new and removed ports. The application also provides native JSON and port CSV save dialogs.

## Step-by-step: review history

1. Open **History**. The app loads the newest local records when the tab opens (or when refreshed).
2. Use **Search target** and **type filter** to narrow records by target substring and scan type (`port`, `http`, `subdomain`, `fuzzer`, `tls`, `dns`, `ip`). Select **Refresh / Search** to apply.
3. Enter the target used for a port scan in **Target for port diff** and refresh to compare the latest two port snapshots. Read the latest and previous timestamps. `NEW PORT DETECTED` means the port was in the newest snapshot but not the previous one; `Closed` means the reverse.
4. To compare Web Audit snapshots, enter the audited URL (same target key) in the diff target field and select **Compare Web Audit** (or refresh). The diff shows grade/risk/status changes, missing-header and finding ID additions/resolutions, and certificate days-remaining delta when available.
5. Expand a history row to inspect its stored JSON result. Use **Export** on a row for that record, or **Delete** to remove it (confirmation required). Use the scan type and target shown in the row to distinguish records.

A diff is available only when two comparable port snapshots exist for the normalized target. It is not a general network comparison and does not prove that a service changed permanently.

## Step-by-step: export and manage

Use **Export JSON/HTML/Markdown** in Web Audit for current HTTP results (summary reports include grade, risk, findings, and remediation). Use the port export action in Ports for CSV. Use **Export History JSON** (Dashboard/History) to save currently loaded history records. Use **Clear All History** to remove all local records (confirmation required). Choose a destination in native dialogs and verify contents before sharing.

## Storage and privacy

History is stored under the operating system user configuration directory in `CodexaScanner/history.sqlite`, capped at 2,000 records. It is not uploaded and is not encrypted. Before persistence and before JSON export, the app applies bounded redaction for embedded URL credentials, sensitive URL query/fragments (tokens, keys, auth/session values, etc.), and sensitive result keys (e.g. password/secret/token/authorization/cookie/credential fields). This reduces accidental retention but is not a guarantee that all sensitive data is removed. Redact remaining sensitive values manually before delivery. On supported Unix-style systems, the app attempts user-only file permissions. Close the app before manually deleting the database to clear all local history.

## Troubleshooting and limits

If history is unavailable, scanning remains usable but the History/Dashboard views may be empty. If no records match, clear search/filter criteria. If no diff appears, save at least two completed port scans for the same normalized target. If an export fails, check destination permissions and disk space, then retry with a shorter result set. Exported reports are observations and heuristics, not formal risk ratings or proof of exploitability.
