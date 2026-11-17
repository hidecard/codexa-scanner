# TLS Inspector

TLS Inspector reports negotiated protocol and cipher, certificate subject/issuer, expiry, SANs, self-signed state, and system trust validation for an authorized hostname or host:port.

TLS 1.0 and TLS 1.1 probes use version-specific handshakes. `Supported` means the requested version was negotiated exactly. `Not supported` is reserved for an explicit peer `protocol_version` alert. Timeouts, other TLS alerts, network failures, local crypto policy errors, and unexpected negotiation are `Inconclusive` and retain diagnostic text.

Legacy protocol results are best-effort and should be interpreted with the local Go/OpenSSL/OS policy in mind. Certificate trust status is independent from the legacy probe result.
