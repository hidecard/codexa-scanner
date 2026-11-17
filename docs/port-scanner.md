# Port Scanner User Guide

## What this module does

The Ports module performs bounded TCP connection checks and best-effort banner collection. It is useful for confirming which approved services are reachable on one target. It is not a vulnerability scanner and does not perform UDP scanning, exploitation, authentication, or comprehensive service fingerprinting.

## Before you start

Confirm the exact hostname or IP address and port range in your authorization. The target must be a bare IPv4 address, IPv6 address, or ASCII DNS hostname. Do not enter a URL, brackets, credentials, or an embedded port. Private and lab targets are allowed when authorized; there is no blanket private-IP block.

## Step-by-step

1. Open **Ports** and enter the approved target.
2. Set **Start Port** and **End Port** to the smallest approved range. Values must be between 1 and 65535.
3. Choose worker count and connection timeout. The backend caps workers at 512 and timeout at 30 seconds.
4. Read the scope statement and confirm authorization for that exact target and range. Changing the target or either port resets the confirmation.
5. Select **Start Scan**. Reachable ports appear as they are found, with progress and the resolved address.
6. Review the service guess and banner. Use **Stop** to cancel a running scan when the scope changes or the result is no longer needed.

## How to read results

`Port` is the TCP port that accepted a connection. `Service` is a common-port label and may be `unknown`; it is not proof of the running software. `Banner` is a short, best-effort first response or HTTP server line and can be empty, incomplete, or deliberately misleading. A hostname is resolved once per scan. IPv4 is preferred, then addresses are ordered numerically, and one address is pinned for the entire run.

A completed scan means the requested port work finished. Cancelled means the user or context stopped it. Failed means the scan could not complete normally. Closed or filtered ports are not proof of a firewall rule, and an open port is not proof of a vulnerability.

## Limits and privacy

The scanner uses a bounded worker pool, per-connection timeout, cancellable lifecycle, and local history when history is available. Port findings may include service banners, so review them before exporting or sharing. Use only within the approved scope and rate limits.

## Troubleshooting

If the target is rejected, remove URL syntax, brackets, whitespace, credentials, and port syntax. If the hostname cannot be resolved, verify DNS and try the authorized literal address if appropriate. If a scan appears slow, reduce the range or timeout; filtered ports commonly consume the connection timeout. If another scan is active, wait for it to reach a terminal state before starting a new one.
