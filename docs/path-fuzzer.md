# Path Fuzzer User Guide

## What this module does

Path Fuzzer performs bounded, read-only path checks using `HEAD` requests only. It never reads or returns response bodies, follows redirects, or accepts traversal, query, fragment, encoded-traversal, or external-URL syntax. It is intended to identify candidate routes for authorized review, not to prove a vulnerability.

## Step-by-step

1. Open **Path Fuzzer** and enter an authorized HTTP or HTTPS base URL without credentials.
2. Add one relative path per line. Safe examples include `/admin`, `/robots.txt`, and `v1/items.json`. You can use built-in framework presets (Next.js, Vite/SPA, Laravel, Django, Spring, Env/VCS/API) to append common HEAD-only discovery paths within authorized scope.
3. Set concurrency and optional request delay (ms) conservatively. The backend defaults to 5 workers and caps concurrency at 20. Delay helps reduce rate-limit/WAF blocking risk.
4. Select **Run HEAD-only Path Checks**.
5. Review candidate paths by status code and content length. Open the path manually only if that follow-up is separately authorized.

## How filtering works

Before testing the wordlist, the module requests a randomized missing path with `HEAD`. A candidate with the same status and content length as that baseline is treated as a likely catch-all response and filtered. When the server omits content length, the comparison is conservative. Redirects are not followed.

A candidate status such as 200, 401, 403, or a redirect indicates an observable response, not a sensitive file, access control flaw, or vulnerability. Content length is server metadata and can be absent or inaccurate.

## Limits

The input list is capped at 500 paths and invalid or duplicate entries are skipped. The module deliberately does not fetch response bodies.

## Troubleshooting

If the base URL is rejected, add `http://` or `https://` and remove credentials, fragments, and query strings. If every candidate is filtered, the site may use a catch-all response; compare with an approved known path rather than assuming there are no routes. If the server does not support HEAD correctly, results may be incomplete and should be verified through a separately authorized method.

