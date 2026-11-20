# TLS Inspector User Guide

## What this module does

TLS Inspector reports the negotiated protocol and cipher, certificate subject and issuer, expiry, SANs, self-signed state, and system trust validation for an authorized hostname or host:port. It also reports HTTP/2 when `h2` is negotiated through ALPN, and reports HTTP/3 only when the HTTPS response advertises an `h3`/`h3-*` `Alt-Svc` value. It performs bounded handshake/header inspection only; it does not claim that an HTTP/3 QUIC connection was successfully established.

## Step-by-step

1. Open **TLS** and enter an authorized hostname or `host:port`. A hostname without a port uses 443.
2. Select **Inspect Certificate & Protocols**.
3. Review the certificate trust state, subject, issuer, expiry, SANs, negotiated protocol, and cipher.
4. Review the HTTP/2 and HTTP/3 status cards. Treat HTTP/3 as an advertisement clue, not proof of QUIC reachability.
5. Review the TLS 1.0 and TLS 1.1 cards separately. Keep the diagnostic text when a result is inconclusive.
6. Review any accepted legacy TLS 1.2 cipher suites. These are bounded, handshake-only probes and should be verified against the service owner’s configuration.

## Probe interpretation

`Supported` means the requested legacy version was negotiated exactly. `Not supported` is used only when the peer explicitly returns a TLS `protocol_version` alert. `Inconclusive` covers timeouts, network failures, other TLS alerts, local crypto policy restrictions, and unexpected negotiation. Inconclusive is not evidence that a legacy protocol is enabled. Certificate trust is independent from the legacy probe result.

CBC, 3DES, RC4, and NULL cipher names are treated as legacy/weak indicators when negotiated or accepted by the bounded TLS 1.2 cipher probes. This is a compatibility warning, not a formal vulnerability score. Modern AEAD suites such as AES-GCM and ChaCha20-Poly1305 are not flagged by this heuristic.

## Troubleshooting

A hostname mismatch means the certificate SANs do not match the requested name. An untrusted result may be caused by a private CA, self-signed certificate, missing chain, or local trust-store policy. A timeout or handshake failure can be caused by a firewall, non-TLS service, rate limit, or local policy. Try the approved port explicitly and compare with the service owner’s configuration; do not disable verification in order to force a result.

If HTTP/2 is not negotiated, the endpoint may not advertise `h2`, may prefer HTTP/1.1, or an intermediary may have changed the ALPN result. If HTTP/3 is not shown, the endpoint may not publish an `h3` `Alt-Svc` advertisement even if QUIC is available through another configuration path.

## Limits

The inspector reports the certificate presented by the selected endpoint and the local system’s trust decision. It checks a fixed list of legacy TLS 1.2 suites and does not enumerate every cipher combination, perform a QUIC handshake, or prove that a service is free of TLS weaknesses. HTTP/3 is only reported when advertised by the HTTPS response’s `Alt-Svc` header.

