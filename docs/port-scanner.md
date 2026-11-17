# Port Scanner

The Ports module performs bounded TCP connection checks and best-effort banner collection.

## Use

Enter a bare IPv4/IPv6 address or ASCII DNS hostname, choose a port range, review workers/timeout, and confirm authorization for that exact target and range. Start the scan, watch streamed findings, and use Stop when needed.

Targets are resolved once per scan. IPv4 is preferred, then addresses are ordered numerically; one address is pinned for every port in that run and shown in the UI. Literal IPs skip DNS. Private and lab targets are not blanket-blocked.

## Limits and output

The worker count is capped at 512, connection timeout at 30 seconds, and the scan uses an independent cancellable context. Findings include port, common-service guess, and a short banner where available. Banners can be absent or misleading.

The scanner does not perform UDP scanning, exploitation, authentication, or comprehensive service fingerprinting. A closed or filtered result is not a guarantee about firewall policy.
