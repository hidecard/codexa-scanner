# Subdomain Discovery User Guide

## What this module does

The module queries Certificate Transparency data from crt.sh for an authorized root domain. It normalizes, validates, deduplicates, sorts, and caps names at 500. An optional DNS wordlist mode performs active single-label DNS lookups.

## Step-by-step

1. Open **Subdomains** and enter an authorized root domain such as `example.com`. Do not enter a URL, IP address, path, or credentials.
2. Leave DNS wordlist mode off for a passive CT-only lookup, or enable it when active DNS queries are explicitly in scope.
3. If enabled, place one candidate label per line, such as `api`, `mail`, or `staging`. The backend accepts safe labels only and caps the list at 500.
4. Select **Query Certificate Transparency** and wait for the result.
5. Review errors separately from names. CT errors do not necessarily mean the domain has no certificates.
6. Select **Send first 100 to Web Audit** only after confirming that HTTP checks for those names are authorized.

## How to read results

A returned name means it was observed in CT data or answered a bounded DNS lookup. It does not prove that the host is currently live, owned by the expected organization, or safe to visit. A missing name does not prove that no subdomain exists. CT data can be stale, duplicated, or incomplete.

## External requests and limits

The passive lookup contacts crt.sh. Wordlist mode generates DNS traffic to candidate names and uses bounded concurrency. Results are capped at 500 names, and at most the first 100 are transferred to Web Audit. Use a narrow wordlist and approved domain to avoid unnecessary traffic.

## Troubleshooting

If the domain is rejected, enter only the bare ASCII domain name and remove a scheme or trailing path. If crt.sh is unavailable, the module reports an error and may return no CT names; retry later. If DNS wordlist results are empty, verify that the labels are valid and that the authoritative DNS service answers those names.
