# Engagement Workflows

This guide covers the cross-module workflow features shipped in Codexa Scanner 1.1.7. Use them only within an approved assessment scope.

## Workspaces

Workspaces keep scan-history records grouped by client, project, or engagement. Open **Workspaces**, create a workspace with a name and description, and assign history records from the History view. A workspace uses the local SQLite `workspaces` table and the `scan_history.workspace_id` relationship. Deleting a workspace does not delete its scan records; the foreign key clears the workspace assignment.

## External tool import

Open **Import** to paste or load:

- Nmap XML generated with `nmap -oX`, including hosts, ports, service names, banners, and discovered HTTP/HTTPS endpoints.
- Newline-delimited subdomain output from tools such as `subfinder` or `amass`.

The importer validates entries, removes duplicates, reports invalid lines, and can store results in the selected workspace. Imported HTTP/HTTPS endpoints can be queued for Web Audit. Import does not execute Nmap, DNS brute force, or any external command.

## HTTP Inspector and bounded replay

Open **Inspector** to inspect one authorized URL with safe methods (`GET`, `HEAD`, or `OPTIONS`). The result shows request/response headers, a bounded body preview, TLS details, negotiated HTTP protocol, and weak-cipher warnings when observed. Replay actions can change the method or selected headers, but remain within the original host/port scope and use the same target safety rules. The app never executes shell commands from the Inspector.

Do not paste secrets into headers unnecessarily. Authorization, Cookie, API-key, and similar values are redacted before persistence or report export where applicable.

## Security Playbook

The **Playbook** tab provides bilingual English/Myanmar explanations for finding IDs. It includes the underlying mechanism, common developer mistakes, impact scenarios, remediation snippets for supported stacks, deployment actions, and verification steps. When opened from a finding, the guide attempts to select the detected technology stack. The playbook is remediation guidance, not a claim that the finding is exploitable.

## Visual Attack Surface / Asset Tree

Open **Reports & History → Asset Tree** to build a read-only interactive tree from locally stored history. Records are grouped by root domain and expose subdomains (including takeover clues), open ports and services, web endpoints and grades, technologies, APIs, configuration leaks, CVE/advisory matches, findings, TLS observations, and DNS records. Expand or collapse branches, filter recursively by label/status, and select a finding to open the existing remediation drawer. Use **Export JSON**, **Export SVG**, or **Export PNG** for report material; exports contain only the local history model and do not trigger a scan.

## Command palette

Press `Ctrl+K` on Windows/Linux or `Cmd+K` on macOS to open the command palette. It provides navigation to Dashboard, Ports, Web Audit, History, Workspaces, Import, Inspector, Playbook, and other modules, plus shortcuts for refresh, workspace actions, and report workflows. `Escape` closes the palette.

## Rate control and pause/resume

Web Audit, Path Fuzzer, and CIDR Sweep support bounded RPS controls and optional jitter. Use `0` RPS for the module's unlimited mode only when allowed by the target owner; otherwise set a conservative cap. Pause/resume controls apply to supported long-running operations. Rate controls reduce request pressure but do not replace authorization, scope confirmation, or provider terms.

## Reports and analyst triage

History records can be tagged `Verified`, `False Positive`, `Needs Review`, or `Accepted Risk`, and analysts can attach notes to findings. Tags and notes persist locally and are included in relevant report exports. Review and redact reports before sharing because banners, URLs, hostnames, and registry data may still be sensitive.
