# DNS Intelligence

DNS Intelligence collects A, AAAA, MX, NS, TXT, SPF, DMARC, and reverse PTR information for an authorized domain. Optional RDAP lookups add registry network/country metadata for public IP addresses.

RDAP data is sourced from an external service and is registry metadata, not precise geolocation or a guaranteed ASN mapping. DNS records can change during or after a run, and missing records can reflect provider behavior or delegation choices.

The module is read-only from the target's perspective, but RDAP and other lookups still generate external requests. Use the optional RDAP checkbox only when that disclosure is acceptable.
