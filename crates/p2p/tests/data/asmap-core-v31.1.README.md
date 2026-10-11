# Bitcoin Core ASMap fixture

The 413 bytes in `asmap-core-v31.1.raw` are the unchanged `ASMAP_DATA` hex literal from Bitcoin Core v31.1 `src/test/netbase_tests.cpp::asmap_test_vectors`. The nineteen address/ASN expectations in `netgroup.rs` are from that same independent reference. Source: https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/netbase_tests.cpp . Copyright Bitcoin Core developers, MIT license. The format decoder follows https://github.com/bitcoin/bitcoin/blob/v31.1/src/util/asmap.cpp .
