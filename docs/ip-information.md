# IP Information

IP Information accepts one IPv4 or IPv6 address and displays three bounded data categories.

The local address classification identifies public, private, loopback, link-local, or special-use addresses using the standard library. Reverse DNS is queried through the system resolver and is labeled as PTR data. Public addresses may receive RDAP registration metadata from `rdap.org` and the response identifies that source explicitly.

The module does not query RDAP for private or special-use addresses. It does not provide geolocation, claim a precise physical location, or infer an ASN/provider beyond the fields returned by the labeled RDAP response. RDAP country and network fields are registry metadata and may be absent or change over time.

Use the feature only for an authorized address. External RDAP and DNS requests may be visible to those services. Results are also saved in local history under the `ip` scan type.
