# DNS Intelligence User Guide

## What this module does

DNS Intelligence collects A, AAAA, MX, NS, TXT, SPF, DMARC, and reverse PTR information for an authorized domain. The optional RDAP checkbox adds registry network and country metadata for public IP answers.

## Step-by-step

1. Open **DNS** and enter an authorized bare domain such as `example.com`.
2. Leave RDAP disabled for DNS-only collection, or enable it when external registry requests are acceptable.
3. Select **Inspect DNS Records**.
4. Review each record family separately. Empty sections mean no record was returned during this lookup, not necessarily that the domain has no configuration.
5. Review errors and RDAP entries independently. Save or export only after checking whether the data contains sensitive internal names.

## How to read records

A and AAAA are address records. MX lists mail exchangers and preference values. NS lists authoritative nameservers. TXT contains arbitrary text; SPF is the subset beginning with `v=spf1`. DMARC is queried at `_dmarc.<domain>`. PTR is reverse DNS for returned address records. DNS answers can vary by resolver, location, TTL, and time.

RDAP data is sourced from an external service and is registry metadata. It is not precise geolocation and does not guarantee an ASN or provider mapping. The module does not modify DNS records.

## Troubleshooting and limits

If the domain is rejected, remove the scheme, path, credentials, and IP address. If one record family fails, other families may still be returned. Resolver timeouts and DNSSEC/provider behavior can produce partial results. RDAP is optional, contacts an external service only for public addresses, and may be unavailable or omit fields. Use the smallest authorized domain scope and avoid treating stale records as current infrastructure proof.

