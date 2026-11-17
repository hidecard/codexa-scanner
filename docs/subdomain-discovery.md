# Subdomain Discovery

The module queries Certificate Transparency data from crt.sh for an authorized root domain. Names are normalized, deduplicated, validated as subdomains of the requested domain, sorted, and capped at 500.

An optional DNS wordlist mode performs bounded single-label lookups, also capped at 500 labels and limited concurrency. This is active DNS traffic and must be explicitly in scope.

Results can be sent to Web Audit as up to the first 100 HTTPS URLs. CT data can be stale or incomplete, and a missing name does not prove that no subdomain exists.
