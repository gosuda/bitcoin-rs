# Linked IPv4 ASMap fixture

Generated with Bitcoin Core v31.1 (`9be056a8a72b624dae9623b2f7bded92c2a21c91`), `contrib/asmap/asmap.py`, using `ASMap([(net_to_prefix(ipaddress.ip_network(net)), asn), ...]).to_binary()` and these entries:

| Prefix | ASN |
| --- | ---: |
| `::/0` | 64500 |
| `8.8.0.0/16` | 15169 |
| `9.9.0.0/16` | 19281 |
| `8.8.8.0/24` | 64501 |

The 47-byte output has SHA-256 `d48d9fdf03384965143d50747585c0b68d40db5e8ce228c0d27d17477bb9f991`. The default IPv6 ASN differs from the IPv4 mappings, so native-IPv6 interpretation of linked forms fails the expected-ASN tests. Expected extraction follows `src/netaddress.cpp::HasLinkedIPv4`/`GetLinkedIPv4`; the mapped lookup follows `src/netgroup.cpp::GetMappedAS`. Prefix-only vectors are copied from `src/test/netbase_tests.cpp::netbase_getgroup` (Bitcoin Core, MIT).

`asmap-source-quota-core-v31.1.raw` uses the same reference generator with default ASN 0 and mappings `8.8.0.0/24` to 15169, `8.8.1.0/24` to 64501, and `9.9.0.0/16` to 15169. Its 45 bytes have SHA-256 `c5fd313c52b38a14822eda591ee382cc0a61336009edd75c4becd68a5eaaadb8`. The first two sources share a raw /16 but not an ASN; the first and third share an ASN across raw prefixes. Unmapped destinations permit testing incoming-source corroboration and the persistent-TCP connectivity census: the first/third sources share a Core ASN group, while the second supplies an independent group. The corrected base uses Core bucket geometry; no 64-endpoint source quota or 16-slot custom placement remains.
