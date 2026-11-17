# Web Audit

Web Audit performs bounded passive HTTP/HTTPS inspection for submitted URLs. It reports response metadata, page title, common security headers, cookie flags, HTTPS/TLS information, mixed-content clues, and passive technology/edge fingerprints.

Each submitted URL defines its own hostname and port scope. Same-host redirects are allowed, standard HTTP 80 to HTTPS 443 upgrades are allowed, cross-host redirects and HTTPS downgrades are blocked, and the chain is capped at five hops. DNS answers are checked as a complete set and one deterministic address is pinned through the chain. Ambient proxies are bypassed. Results display each observed redirect hop with its source URL, destination URL, and HTTP status; hops already observed are retained even when a later redirect is blocked.

Private RFC1918, IPv6 ULA, and loopback targets require the default-off one-shot lab opt-in. Link-local, multicast, unspecified, and reserved/special-use addresses remain blocked.

Findings include evidence and remediation text. The grade and risk score are bounded heuristics, not CVSS and not proof of vulnerability. The module does not log in, crawl routes, submit forms, test authorization, or exploit vulnerabilities.
