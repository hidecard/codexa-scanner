# History and Reports User Guide

## What this module does

History keeps scan results locally in SQLite and lets you inspect recent records. It compares the latest two port snapshots for a normalized target and reports new and removed ports. The application also provides native JSON and port CSV save dialogs.

## Step-by-step: review history

1. Open **History**. The app loads the newest local records when the tab opens.
2. Enter the target used for a port scan and select **Refresh History & Compare Ports**.
3. Read the latest and previous timestamps. `NEW PORT DETECTED` means the port was in the newest snapshot but not the previous one; `Closed` means the reverse.
4. Expand a history row to inspect its stored JSON result. Use the scan type and target shown in the row to distinguish port, HTTP, DNS, IP, TLS, subdomain, and fuzzer records.

A diff is available only when two comparable port snapshots exist for the normalized target. It is not a general network comparison and does not prove that a service changed permanently.

## Step-by-step: export reports

Use **Export JSON Report** in Web Audit for the current HTTP results. Use the port export action in the Ports results when a CSV is needed. Choose a destination in the native save dialog, then verify the file exists and contains the expected target and timestamp before sharing it.

## Storage and privacy

History is stored under the operating system user configuration directory in `CodexaScanner/history.sqlite`, capped at 2,000 records. It is not uploaded and is not encrypted. URL query strings, internal hostnames, banners, headers, RDAP data, and findings can be sensitive. Redact them before delivery. On supported Unix-style systems, the app attempts user-only file permissions. Close the app before manually deleting the database to clear all local history.

## Troubleshooting and limits

If history is unavailable, scanning remains usable but the History view may be empty. If no diff appears, save at least two completed port scans for the same normalized target. If an export fails, check the destination permissions and available disk space, then retry with a shorter result set. Exported reports are observations and heuristics, not formal risk ratings or proof of exploitability.
