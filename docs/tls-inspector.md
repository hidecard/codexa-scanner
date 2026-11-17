# TLS Inspector User Guide

## What this module does

TLS Inspector reports the negotiated protocol and cipher, certificate subject and issuer, expiry, SANs, self-signed state, and system trust validation for an authorized hostname or host:port. It performs handshake and certificate inspection only; it does not send application data.

## Step-by-step

1. Open **TLS** and enter an authorized hostname or `host:port`. A hostname without a port uses 443.
2. Select **Inspect Certificate & Protocols**.
3. Review the certificate trust state, subject, issuer, expiry, SANs, negotiated protocol, and cipher.
4. Review the TLS 1.0 and TLS 1.1 cards separately. Keep the diagnostic text when a result is inconclusive.

## Probe interpretation

`Supported` means the requested legacy version was negotiated exactly. `Not supported` is used only when the peer explicitly returns a TLS `protocol_version` alert. `Inconclusive` covers timeouts, network failures, other TLS alerts, local crypto policy restrictions, and unexpected negotiation. Inconclusive is not evidence that a legacy protocol is enabled. Certificate trust is independent from the legacy probe result.

## Troubleshooting

A hostname mismatch means the certificate SANs do not match the requested name. An untrusted result may be caused by a private CA, self-signed certificate, missing chain, or local trust-store policy. A timeout or handshake failure can be caused by a firewall, non-TLS service, rate limit, or local policy. Try the approved port explicitly and compare with the service owner’s configuration; do not disable verification in order to force a result.

## Limits

The inspector reports the certificate presented by the selected endpoint and the local system’s trust decision. It does not enumerate every certificate served by every address, test every cipher combination, or prove that a service is free of TLS weaknesses.
