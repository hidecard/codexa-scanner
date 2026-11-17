# Path Fuzzer

Path Fuzzer performs bounded, read-only path checks using `HEAD` requests only. It never reads or returns response bodies, follows redirects, or accepts path values containing traversal, query, fragment, encoded traversal, or external URL syntax.

A randomized missing-path baseline compares status and Content-Length to filter likely catch-all responses. Candidate results show the URL, status code, and content length. The input list is capped at 500 paths and concurrency at 20.

Use only on an authorized base URL. A candidate path is an observation, not proof of a sensitive file or vulnerability.
