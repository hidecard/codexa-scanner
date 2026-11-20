# IP Information User Guide

## What this module does

IP Information accepts one IPv4 or IPv6 address and shows three bounded categories: local address classification, reverse DNS/PTR data, and public-IP RDAP registration metadata. It does not provide geolocation or perform a broad provider database lookup.

## Step-by-step

1. Open **IP Info** and enter an authorized IPv4 or IPv6 address, such as `8.8.8.8` or `2001:4860:4860::8888`.
2. Select **Inspect IP Information**.
3. Read the address-class badge first. It identifies `public`, `private`, `loopback`, `link-local`, or `special-use` using local standard-library classification.
4. Review Reverse DNS. Names are returned by the system DNS resolver and may be empty.
5. For public addresses, review the RDAP registration metadata and its explicit source label. For private or special-use addresses, the app intentionally does not query RDAP.
6. Read warnings and source labels before saving or sharing the result. IP results are stored locally under the `ip` history type.

## How to interpret results

PTR names are administrative DNS labels, not proof of ownership, physical location, or service identity. RDAP network handle, name, and country fields are registry metadata supplied by the response and can be absent, stale, or different from an application provider. A public classification means the address is globally routable according to local rules; it does not mean the host is reachable.

## Privacy

The feature can generate a DNS PTR request and, for public addresses, an external RDAP request. Use it only when those requests are acceptable.

## Troubleshooting

If the input is rejected, enter only a literal IPv4 or IPv6 address without a scheme, port, brackets, or hostname. If PTR or RDAP is unavailable, the address classification remains useful and the result will show the corresponding warning. A missing PTR name is normal for many addresses and is not evidence that the address is unused.

