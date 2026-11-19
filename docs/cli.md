# Headless CLI

Codexa Scanner's existing executable can run Web Audit without starting the Wails desktop UI. It reuses the same bounded Web Audit backend, URL/redirect scope validation, destination policy, and versioned report redaction.

## Build

Build the application executable with the usual Wails build prerequisites:

```sh
wails build
```

The CLI is part of the same executable; no separate binary or service is required. During development, `go run . help` displays top-level usage.

## Run an audit

```sh
./build/bin/CodexaScanner audit --url https://example.com --fail-on high --json report.json
```

`--url` may be repeated, up to 100 targets. Every submitted URL is its own scope; cross-host redirects, HTTPS downgrades, and out-of-scope ports remain blocked. The tool does not crawl linked pages, log in, submit forms, or exploit findings.

Options:

- `--fail-on critical|high|medium|low|info` sets the minimum finding severity that causes exit code `1`; default is `high`.
- `--json <path>` writes a shared, versioned, redacted JSON report with file mode restricted to the current user where supported. Use `--json -` to write only the JSON envelope to standard output.
- `--timeout 3..60` sets the per-request timeout in seconds; default is 10.
- `--allow-private` opts this run into authorized private/loopback lab targets. It does not permit link-local, multicast, unspecified, or special-use/reserved addresses.
- `--help` prints command usage. A leading `--cli` is optional, for example `CodexaScanner --cli audit --url https://example.com`.

## Exit codes

- `0`: audit completed and no finding met the selected `--fail-on` threshold.
- `1`: at least one finding met the selected threshold.
- `2`: invalid CLI arguments, invalid/out-of-scope target, request error, or report output error.

A finding is a bounded heuristic and must be reviewed in context. Use this command only for systems you own or have explicit authorization to assess. Network requests may be logged or trigger defensive controls. The CLI does not ask interactively for authorization; `--allow-private` is an explicit one-run opt-in for private/lab destinations.
