# Address-book migration bytes

These are genuine files emitted through the original immutable AddressBook
writers in isolated scratch executables. They are synthetic regression fixtures,
not retained operator production data. The original addrman.rs/netgroup.rs files
were compiled unchanged; only a module-local fixture entry point was appended.
No current Stored value was serialized with a historical version number.

| File | Original writer commit | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| addrman-historical-v2.dat | cc6172301 | 531 | fb8061e7da32e22aa77f6f1413d9e240b96bbd529ca63c771a3fef0acc757c33 |
| addrman-historical-v3.dat | 5444581efdfcdd9bc9478a4b82ded39e452474d8 | 531 | 32a715d577da62853826e3c2cf22d8a81e58e9109111ce6ce0403bb03917cad2 |
| addrman-core-v5-eight-refs.dat | 73c6f7aec0b5bb3f5ecabffeda63a51b01a5cbfe | 328 | c588a6f8fb59cc145bdfbb9f33b47d5e28d875d6fa6daf9eeb57ea4ba9c92b1a |
| addrman-historical-v2-asmap.dat | cc6172301 | 644 | 1372f5477f9458ff9b0cd1a8d8010c20bc7616492d846eb7bbf61c5291ae6b04 |
| addrman-historical-v3-asmap.dat | 5444581efdfcdd9bc9478a4b82ded39e452474d8 | 644 | 05d821055c40415a937f09b777d4496aa33e1e4ff4e0826b72443e7733c2ead8 |

All use magic `[1;4]` and secret `[7;32]`. For v2/v3 the original writer learns
8.8.8.8:8333 from 1.1.1.1 at 1700000000 and records Good at 1700000001, then learns
9.9.9.9:8333 from DNS `historical.seed` and records three attempts. The `-asmap`
variants repeat those calls with the unchanged linked-IPv4 map configured,
retaining its original asmap_id in the historical file.

The v5 writer uses StdRng seed 17, learns 8.8.8.8:8333 from IP sources 1.n.1.1
at 1700000000 (the normal gossip time penalty applies), retries reports until
eight distinct references are admitted, records one counted attempt, and saves.
Its ordered New references are 634, 268, 292, 948, 782, 987, 905, 711. The v6 no-map
migration must preserve those values exactly, along with source/health/secret.

The trailing 32 bytes are the original writer's SHA256 checksum. Migration tests
read the files unchanged and compare preserved backup bytes, health, runtime
attempt reset and the resulting reference/index invariants.

The anchor integration adds genuine original-writer files:

| File | Original writer commit | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| addrman-historical-v3-anchors.dat | 20e9064e5a41b64be44720bf1d816d8534d2d280 | 966 | 46c8b0e3de798d2e423224aa13b68a6841d4b15d23744e5ff1d59861f9530759 |
| addrman-historical-v4-anchors.dat | fba4ddef612cca0b7764d07646f3301ea1897674 | 966 | 9ad97094335dd17c0d4e6d2293a12c74b8c2e28667a11c29d524bbb1983b4f81 |
| addrman-core-v6-eight-refs.dat | 0597de4da9df6d20da0acf4b2c2a4ebc99a7ca3a | 344 | f0293ecbe561dadfb3780ec63fed9608ea5de13cc11565188ebe4d1182aefbce |

The original v3/v4 writers learn and confirm `[2002:808:808::1]:8333`
from `2002:101:101::1` and `8.8.4.4:8333` from `2.2.2.2`, retain the linked
IPv4 ASMap identity, and remember both anchors at 1700000006. They also retain
three failed DNS attempts for `9.9.9.9:8333`. The v6 producer repeats the v5
reference sequence above. All files were saved and reopened by their original
writer; their schema numbers were not relabelled. Compiled with Rust1.99.0;
source addrman blob IDs are respectively `570d5d44af8089891f0a6fdceb9ac26f2e2f3b65`,
`676273fd73a7c5daf0fef09328f44e7e7f6e89d8`, and
`883694c2c3db06273602558959efdac83e6c5d43`.
